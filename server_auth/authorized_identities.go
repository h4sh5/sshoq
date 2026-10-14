package server_auth

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"

	ssh3 "github.com/h4sh5/sshoq"
	"github.com/h4sh5/sshoq/auth"
	"github.com/h4sh5/sshoq/auth/oidc"
	"github.com/h4sh5/sshoq/internal"
	"github.com/h4sh5/sshoq/util"
	"github.com/h4sh5/sshoq/util/unix_util"

	"github.com/rs/zerolog/log"
)

const (
	// maxAcceptedOIDCTokens bounds the replay cache of accepted ID tokens.
	maxAcceptedOIDCTokens = 8192
	// conversationIDClaim is the claim an issuer puts in an ID token to bind it to the
	// sshoq conversation it was requested for. "jti" is accepted too, and is what the
	// public key authentication expects.
	conversationIDClaim = "ssh3_conv_id"
	uniqueTokenIDClaim  = "jti"
)

// acceptedOIDCTokens remembers the OpenID Connect tokens which have been accepted, so
// that one token cannot be used more than once. A raw ID token is a bearer credential:
// nothing in it prevents a copy from being handed over again after it was already used.
var acceptedOIDCTokens = oidc.NewAcceptedTokenStore(maxAcceptedOIDCTokens)

type IdentityVerifier interface {
	// returns whether the provided candidate contains a sufficient proof to
	// be considered as equivalent to this identity
	Verify(candidate interface{}, base64ConversationID string) bool
}

func DefaultIdentitiesFileNames(user *unix_util.User) []string {
	return []string{path.Join(user.Dir, ".ssh3", "authorized_identities"), path.Join(user.Dir, ".ssh", "authorized_keys")}
}

type OpenIDConnectIdentity struct {
	clientID  string
	issuerURL string
	email     string
	// jwksSHA256 optionally pins the signing key set of the issuer (the
	// "jwks_sha256=<hex>" attribute of the identity line): without it, the signature of a
	// token is checked against keys fetched from the issuer itself, so whoever can steer
	// that fetch (a man in the middle on a non-TLS path, or the issuer itself once
	// compromised) can sign a token for any user.
	jwksSHA256 []byte
}

func (i *OpenIDConnectIdentity) Verify(genericCandidate interface{}, base64ConversationID string) bool {
	log.Debug().Msgf("verifying openid connect idenitity")
	switch candidate := genericCandidate.(type) {
	case util.JWTTokenString:
		token, err := oidc.VerifyRawToken(context.Background(), i.clientID, i.issuerURL, candidate.Token, i.jwksSHA256)
		if err != nil {
			log.Error().Msgf("cannot verify raw token: %s", err.Error())
			return false
		}

		log.Debug().Msgf("token signature verification successful")

		if token.Issuer != i.issuerURL {
			log.Error().Msgf("cannot verify idendity: bad issuer: %s != %s", token.Issuer, i.issuerURL)
			return false
		}

		var claims struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			UniqueID      string `json:"jti"`
			Conversation  string `json:"ssh3_conv_id"`
		}
		if err := token.Claims(&claims); err != nil {
			log.Error().Msgf("error verifying claims: %s", err)
			return false
		}

		valid := token != nil && claims.EmailVerified && claims.Email == i.email

		if !valid {
			log.Error().Msgf("invalid token: email should be: %s received claims: %+v", i.email, claims)
			return false
		}

		// The token was verified, but verification alone does not say *where* it may be
		// used: a raw ID token is a bearer credential, and one which carries nothing tying
		// it to this conversation can be replayed on any conversation of the server, by
		// anybody holding a copy of it, for its whole validity. Requiring the binding claim
		// - and refusing a token which carries none - is what makes a captured token usable
		// for the one connection it was issued for, and for nothing else.
		bound := claims.Conversation
		if bound == "" {
			bound = claims.UniqueID
		}
		if bound == "" {
			log.Error().Msgf("rejecting OIDC token of %s: it carries no %s nor %s claim, so it cannot be bound to "+
				"conversation %s instead of being replayable on any conversation of this server",
				claims.Email, conversationIDClaim, uniqueTokenIDClaim, base64ConversationID)
			return false
		}
		if bound != base64ConversationID {
			log.Error().Msgf("rejecting OIDC token of %s: it is bound to conversation %q but is presented on %q",
				claims.Email, bound, base64ConversationID)
			return false
		}

		// And the very same token must not be usable twice, even on the conversation it
		// belongs to: what was accepted once is remembered until it expires.
		unique := claims.UniqueID
		if unique == "" {
			unique = bound
		}
		if !acceptedOIDCTokens.Accept(token.Issuer, unique, token.Expiry) {
			log.Error().Msgf("rejecting OIDC token of %s from issuer %s: this token has already been accepted, "+
				"it is a replay", claims.Email, token.Issuer)
			return false
		}

		return true
	default:
		return false
	}
}

type WrappedPluginVerifier struct {
	auth.RequestIdentityVerifier
}

// IdentityOptions returns the restrictions carried by the wrapped identity, if it has
// any: they must be applied to the conversation which authenticated with it.
func (w *WrappedPluginVerifier) IdentityOptions() *ssh3.IdentityOptions {
	if withOptions, ok := w.RequestIdentityVerifier.(ssh3.EnforcesOptions); ok {
		return withOptions.IdentityOptions()
	}
	return nil
}

var _ ssh3.EnforcesOptions = &WrappedPluginVerifier{}

func (w *WrappedPluginVerifier) Verify(genericCandidate interface{}, base64ConversationID string) bool {
	switch candidate := genericCandidate.(type) {
	case *http.Request:
		return w.RequestIdentityVerifier.Verify(candidate, base64ConversationID)
	}
	return false
}

func ParseIdentity(user *unix_util.User, identityStr string) (ret []IdentityVerifier, err error) {
	pluginIdentities := internal.FindIdentitiesFromAuthorizedIdentityString(user.Username, identityStr)
	log.Debug().Msgf("found %d identities from plugins", len(pluginIdentities))
	for _, pluginIdentity := range pluginIdentities {
		ret = append(ret, &WrappedPluginVerifier{RequestIdentityVerifier: pluginIdentity})
	}
	// now parse the oidc identity which is not implemented by a plugin yet
	if strings.HasPrefix(identityStr, "oidc") {
		// oidc <client id> <issuer url> <email> [jwks_sha256=<hex>]
		minExpectedTokens := 4
		maxExpectedTokens := 5
		log.Debug().Msg("parsing oidc identity")
		tokens := strings.Fields(identityStr)
		if len(tokens) < minExpectedTokens || len(tokens) > maxExpectedTokens {
			return nil, fmt.Errorf("bad identity format for oidc identity, %d tokens instead of the %d to %d expected tokens, identity: %s",
				len(tokens),
				minExpectedTokens,
				maxExpectedTokens,
				identityStr)
		}
		clientID := tokens[1]
		issuerURL := tokens[2]
		email := tokens[3]
		// The issuer is what the whole authentication rests on: its discovery document and
		// its signing keys are fetched from it, so an issuer reached over plain HTTP lets
		// anybody on the path become the issuer. The line is refused here rather than at the
		// first login attempt, so the administrator sees the problem in the server log.
		if err := oidc.ValidateIssuerURL(issuerURL); err != nil {
			return nil, fmt.Errorf("invalid oidc identity: %w", err)
		}
		var jwksSHA256 []byte
		if len(tokens) == maxExpectedTokens {
			const pinPrefix = "jwks_sha256="
			if !strings.HasPrefix(tokens[4], pinPrefix) {
				return nil, fmt.Errorf("invalid oidc identity: unexpected attribute %q, only %s<hex> is accepted",
					tokens[4], pinPrefix)
			}
			pin, err := hex.DecodeString(strings.TrimPrefix(tokens[4], pinPrefix))
			if err != nil || len(pin) != sha256.Size {
				return nil, fmt.Errorf("invalid oidc identity: jwks_sha256 must be the hexadecimal SHA-256 of the issuer JWKS")
			}
			jwksSHA256 = pin
		}
		log.Debug().Msgf("oidc identity parsing success: client_id: %s, issuer_url: %s, email: %s", clientID, issuerURL, email)
		ret = append(ret, &OpenIDConnectIdentity{
			clientID:   clientID,
			issuerURL:  issuerURL,
			email:      email,
			jwksSHA256: jwksSHA256,
		})
	}
	if len(ret) == 0 {
		// either error or identity not implemented
		return nil, fmt.Errorf("unknown identity format")
	}
	return ret, nil
}

func ParseAuthorizedIdentitiesFile(user *unix_util.User, file *os.File) (identities []IdentityVerifier, err error) {
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber += 1
		line := scanner.Text()
		if len(strings.TrimSpace(line)) == 0 {
			log.Info().Msgf("%s:%d: skip empty line", file.Name(), lineNumber)
			continue
		} else if line[0] == '#' {
			// commented line
			log.Info().Msgf("%s:%d: skip commented identity", file.Name(), lineNumber)
			continue
		}
		parsedIdentities, err := ParseIdentity(user, line)
		if err == nil {
			identities = append(identities, parsedIdentities...)
		} else {
			log.Error().Msgf("cannot parse identity line: %s: %s", err.Error(), line)
		}
	}
	return identities, nil
}

func GetAuthorizedIdentities(user *unix_util.User) ([]IdentityVerifier, error) {
	filenames := DefaultIdentitiesFileNames(user)
	var identities []IdentityVerifier
	for _, filename := range filenames {
		identitiesFile, err := os.Open(filename)
		if err == nil {
			newIdentities, err := ParseAuthorizedIdentitiesFile(user, identitiesFile)
			if err != nil {
				// TODO: logging
				log.Error().Msgf("error when parsing authorized identities: %s", err)
				return nil, err
			}
			identities = append(identities, newIdentities...)
		} else if !os.IsNotExist(err) {
			log.Error().Msgf("error could not open %s: %s", filename, err)
			return nil, err
		}
	}
	return identities, nil
}
