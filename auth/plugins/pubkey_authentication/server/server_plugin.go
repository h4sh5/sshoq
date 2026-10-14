package server_pubkey_authentication

import (
	"crypto"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	ssh3 "github.com/h4sh5/sshoq"
	"github.com/h4sh5/sshoq/auth"
	"github.com/h4sh5/sshoq/auth/plugins"
	"github.com/h4sh5/sshoq/server_auth"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// impements server-side pubkey-based authentication

const PLUGIN_NAME = "github.com/h4sh5/sshoq-server_pubkey_auth"

func init() {
	if err := plugins.RegisterServerAuthPlugin(PLUGIN_NAME, PubkeyAuthPlugin); err != nil {
		log.Error().Msgf("could not register plugin %s: %s", PLUGIN_NAME, err)
	}
}

type PubkeyJWTIdentityVerifier struct {
	username string
	pubkey   crypto.PublicKey
	// options holds the authorized_keys options of the identity line this verifier was
	// built from (command=, from=, restrict, no-pty, ...), nil when it had none. They are
	// part of the authorisation the file asks for, so they must be enforced, not skipped.
	options *ssh3.IdentityOptions
}

// IdentityOptions returns the restrictions the session layer must apply to a
// conversation authenticated by this identity.
func (v *PubkeyJWTIdentityVerifier) IdentityOptions() *ssh3.IdentityOptions {
	return v.options
}

var _ ssh3.EnforcesOptions = &PubkeyJWTIdentityVerifier{}

func (v *PubkeyJWTIdentityVerifier) Verify(request *http.Request, base64ConversationID string) bool {
	jwtToken, wellFormattedB64Token := server_auth.ParseBearerAuth(request.Header.Get("Authorization"))
	if !wellFormattedB64Token {
		return false
	}

	token, err := jwt.Parse(jwtToken,
		func(unvalidatedToken *jwt.Token) (interface{}, error) {
			log.Debug().Msgf("token method: %s, pubkey = %T %+v", unvalidatedToken.Method.Alg(), v.pubkey, v.pubkey)
			switch unvalidatedToken.Method.Alg() {
			case "RS256", "EdDSA", "ES256":
				return v.pubkey, nil
			}
			return nil, fmt.Errorf("unsupported signature algorithm '%s' for %T", unvalidatedToken.Method.Alg(), v)
		},
		jwt.WithIssuer(v.username),
		jwt.WithSubject("ssh3"),
		jwt.WithIssuedAt(),
		jwt.WithAudience("unused"),
		jwt.WithLeeway(60*time.Second),
		jwt.WithValidMethods([]string{"RS256", "EdDSA", "ES256"}))
	if err != nil || !token.Valid {
		log.Error().Msgf("invalid private key token: %s", err)
		return false
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if _, ok = claims["exp"]; !ok {
			return false
		}
		if clientId, ok := claims["client_id"]; !ok || clientId != fmt.Sprintf("ssh3-%s", v.username) {
			return false
		}
		if jti, ok := claims["jti"]; !ok || jti != base64ConversationID {
			log.Error().Msgf("rsa verification failed: the jti claim does not contain the base64-encoded conversation ID")
			return false
		}
	} else {
		log.Error().Msgf("bad JWT claims type: %T", token.Claims)
		return false
	}

	// the key signed a valid token, but it may still be restricted to a set of source
	// addresses (OpenSSH "from=..."): the proof of ownership is not enough
	if err := v.options.CheckSource(request.RemoteAddr); err != nil {
		log.Warn().Msgf("rejecting pubkey identity of user %s: %s", v.username, err)
		return false
	}

	return true
}

func PubkeyAuthPlugin(username string, identityStr string) (auth.RequestIdentityVerifier, error) {
	log.Debug().Msgf("pubkey auth plugin: parse identity string")
	pubkey, _, options, _, err := ssh.ParseAuthorizedKey([]byte(identityStr))
	// we should not return an error when the format does not match a public key, we should just return a nil RequestIdentityVerifier
	if err != nil {
		log.Debug().Msgf("the identity string is not a compatible pubkey string")
		return nil, nil
	}

	log.Debug().Msg("parsing ssh authorized key")

	// The options of the identity line (command=, from=, restrict, no-pty, ...) are part
	// of what the owner of the file asked for: they are parsed here and then enforced,
	// and an option which cannot be enforced makes the identity be refused instead of
	// silently ignored, so that a restricted key never grants a full shell.
	identityOptions, err := ssh3.ParseIdentityOptions(options)
	if err != nil {
		log.Error().Msgf("refusing authorized identity: %s", err)
		return nil, err
	}

	switch pubkey.Type() {
	case "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519":
		log.Debug().Msgf("parsing %s identity", pubkey.Type())
		cryptoPublicKey := pubkey.(ssh.CryptoPublicKey)
		return &PubkeyJWTIdentityVerifier{
			pubkey:   cryptoPublicKey.CryptoPublicKey(),
			username: username,
			options:  identityOptions,
		}, nil

	default:
		return nil, fmt.Errorf("SSH authorized identity \"%s\" not implemented", pubkey.Type())
	}
}
