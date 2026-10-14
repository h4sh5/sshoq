package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v3"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const (
	// issuerRequestTimeout bounds every HTTP exchange done with an OIDC issuer. The
	// verification of a token a client handed us must never be able to park a server
	// goroutine for the duration of a default (unbounded) HTTP client.
	issuerRequestTimeout = 10 * time.Second
	// maxJWKSSize is how much is read from a JWKS endpoint: a signing key set is small by
	// construction, so a larger body is not a key set and must not be buffered.
	maxJWKSSize = 1 << 20
)

// issuerHTTPClient returns the client used to talk to an issuer.
func issuerHTTPClient() *http.Client {
	return &http.Client{Timeout: issuerRequestTimeout}
}

// ValidateIssuerURL checks that an issuer URL can be used safely: it must parse, have a
// host, carry no credentials and be HTTPS. Plain HTTP is only accepted for a loopback
// issuer, which is where a developer runs a test IdP: on any other host the discovery
// document and the signing keys could be replaced by anybody able to observe the
// network path, who could then hand out tokens verified as genuine for any user.
func ValidateIssuerURL(issuerURL string) error {
	parsed, err := url.Parse(issuerURL)
	if err != nil {
		return fmt.Errorf("invalid OIDC issuer URL %q: %w", issuerURL, err)
	}
	if parsed.Host == "" {
		return fmt.Errorf("invalid OIDC issuer URL %q: the host is missing", issuerURL)
	}
	if parsed.User != nil {
		return fmt.Errorf("invalid OIDC issuer URL %q: credentials in the URL are not allowed", issuerURL)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		host := parsed.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("insecure OIDC issuer URL %q: the issuer must be reached over HTTPS, otherwise its "+
			"signing keys can be replaced by anybody on the network path and forged tokens accepted for any user "+
			"(only a loopback issuer is accepted over plain HTTP)", issuerURL)
	default:
		return fmt.Errorf("invalid OIDC issuer URL %q: unsupported scheme %q", issuerURL, parsed.Scheme)
	}
}

type OIDCIssuerConfig = []*OIDCConfig
type OIDCConfig struct {
	IssuerUrl    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

/*
 *	Gets an OpenID Connect authorization token from the authorization provider (issuer).
 *  It firsts discuvers the authorization endppoint from the issuerURL. Then, it
 *  opens a browser window towards the authorization endpoint. A local webserver is temporarily
 *  started at a random port to retrieve the issued authorization token.
 *	This token is then returned as an http url-encoded string.
 */
// Connect gets an ID token from an OIDC issuer, by opening the authorization URL in a
// browser and catching the code on a local listener.
//
// conversationID is the ID of the sshoq conversation the token is meant for. It is sent
// to the issuer as the "ssh3_conversation_id" authorization parameter, so that the issuer
// can bind the ID token it hands back to that single conversation (as the "jti" or
// "ssh3_conv_id" claim). A token bound to a conversation cannot be replayed against
// another one, which is what the server requires (see server_auth.OpenIDConnectIdentity).
func Connect(ctx context.Context, oidcConfig *OIDCConfig, issuerURL string, conversationID string, doPKCE bool) (rawIDTokey string, err error) {
	// the issuer of the token used to authenticate must be reached over HTTPS, and its
	// discovery document must not be able to block the connection forever
	if err := ValidateIssuerURL(issuerURL); err != nil {
		return "", err
	}
	ctx = oidc.ClientContext(ctx, issuerHTTPClient())
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return "", err
	}

	providerEndpoint := provider.Endpoint()

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	path := "/ssh"
	listeningPort := listener.Addr().(*net.TCPAddr).Port

	secretUrl := fmt.Sprintf("http://localhost:%d%s", listeningPort, path)

	// Configure an OpenID Connect aware OAuth2 client.
	oauthConfig := oauth2.Config{
		ClientID:     oidcConfig.ClientID,
		ClientSecret: oidcConfig.ClientSecret,
		RedirectURL:  secretUrl,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: providerEndpoint,

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{"openid email"},
	}

	challengeVerifierBytes := [64]byte{}
	_, err = rand.Read(challengeVerifierBytes[:])
	if err != nil {
		return "", fmt.Errorf("error when generating random verifier: %s", err.Error())
	}

	verifier := oauth2.GenerateVerifier()

	tokenChannel := make(chan string)
	mux := http.NewServeMux()
	mux.Handle(path, getOAuth2Callback(ctx, provider, oidcConfig.ClientID, &oauthConfig, tokenChannel, verifier, doPKCE))
	server := http.Server{Handler: mux}
	go server.Serve(listener)
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}

	options := []oauth2.AuthCodeOption{}
	if doPKCE {
		options = append(options, oauth2.S256ChallengeOption(verifier))
	}
	if conversationID != "" {
		// ask the issuer to bind the token to the conversation it will be used on
		options = append(options, oauth2.SetAuthURLParam("ssh3_conversation_id", conversationID))
	}

	authCodeURL := oauthConfig.AuthCodeURL("state", options...)

	args = append(args, authCodeURL)
	log.Debug().Msgf("spawning browser at %s\n", authCodeURL)
	command := exec.Command(cmd, args...)
	err = command.Start()
	if err != nil {
		return "", err
	}

	rawIDToken := <-tokenChannel
	// the ID token is a bearer credential: it must never end up in a log file, not even
	// at debug level, since anybody able to read the log could connect as that user
	log.Debug().Msgf("got ID token of %d bytes", len(rawIDToken))
	server.Close()
	// todo: trigger a browser on localhost on the listeningPort and fetch the token, and then close the http server
	return rawIDToken, nil
}

func getOAuth2Callback(ctx context.Context, provider *oidc.Provider, clientID string, oauth2Config *oauth2.Config,
	tokenChannel chan string, challengeVerifier string, doPKCE bool) http.HandlerFunc {

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return func(w http.ResponseWriter, r *http.Request) {
		defer w.(http.Flusher).Flush()
		// Verify state and errors.

		options := []oauth2.AuthCodeOption{}
		if doPKCE {
			options = append(options, oauth2.VerifierOption(challengeVerifier))
		}
		// every exchange with the issuer is bounded: a token endpoint which never answers
		// must not hang the client, nor the server waiting for the token it authenticated
		exchangeCtx, cancel := context.WithTimeout(ctx, issuerRequestTimeout)
		defer cancel()
		exchangeCtx = context.WithValue(exchangeCtx, oauth2.HTTPClient, issuerHTTPClient())

		oauth2Token, err := oauth2Config.Exchange(exchangeCtx, r.URL.Query().Get("code"), options...)
		if err != nil {
			log.Error().Msgf("error when parsing oauth token: %s", err.Error())
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Error().Msgf("missing id token in the retrieved oauth2 token")
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Error().Msgf("error when verifying oauth token: %s", err.Error())
			return
		}

		// Extract custom claims
		var claims struct {
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := idToken.Claims(&claims); err != nil {
			log.Error().Msgf("error when parsing the oauth token claims: %s", err.Error())
			return
		}

		w.Write([]byte("you can now close this tab")) // status 200 is implicit
		tokenChannel <- rawIDToken
	}
}

// VerifyRawToken verifies a token obtained from an OpenID connect issuer.
//
// When pinnedJWKSSHA256 is not empty the signing keys of the issuer are not trusted on
// the spot: the JWKS the discovery document points at is fetched and its SHA-256 must
// equal the pinned value, so neither a man in the middle nor a compromised issuer can
// substitute a key set it just generated. When it is empty the keys are taken from the
// issuer itself, which then relies on the TLS channel to the issuer being authenticated
// (hence the HTTPS requirement).
func VerifyRawToken(ctx context.Context, clientID string, issuerURL string, rawIDToken string, pinnedJWKSSHA256 []byte) (*oidc.IDToken, error) {
	if err := ValidateIssuerURL(issuerURL); err != nil {
		return nil, err
	}

	// the discovery document and the JWKS are what the authentication rests on: fetch
	// them with a client which gives up instead of blocking forever
	ctx = oidc.ClientContext(ctx, issuerHTTPClient())

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	config := &oidc.Config{ClientID: clientID}

	var verifier *oidc.IDTokenVerifier
	if len(pinnedJWKSSHA256) > 0 {
		keySet, err := pinnedKeySet(ctx, issuerURL, provider, pinnedJWKSSHA256)
		if err != nil {
			return nil, err
		}
		verifier = oidc.NewVerifier(issuerURL, keySet, config)
	} else {
		verifier = provider.Verifier(config)
	}

	// Parse and verify ID Token payload (signature, issuer, audience, expiry).
	idToken, err := verifier.Verify(ctx, rawIDToken)

	return idToken, err
}

// pinnedKeySet builds the set of keys a token must be verified against out of the JWKS
// of the issuer, and refuses it unless its SHA-256 is the pinned one.
func pinnedKeySet(ctx context.Context, issuerURL string, provider *oidc.Provider, pinnedJWKSSHA256 []byte) (oidc.KeySet, error) {
	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&discovery); err != nil || discovery.JWKSURI == "" {
		return nil, fmt.Errorf("cannot read jwks_uri in the discovery document of issuer %s", issuerURL)
	}
	if err := ValidateIssuerURL(discovery.JWKSURI); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery.JWKSURI, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot build the JWKS request: %w", err)
	}
	resp, err := issuerHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch the JWKS of issuer %s: %w", issuerURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot fetch the JWKS of issuer %s: HTTP status %d", issuerURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSSize))
	if err != nil {
		return nil, fmt.Errorf("cannot read the JWKS of issuer %s: %w", issuerURL, err)
	}

	digest := sha256.Sum256(body)
	if !bytes.Equal(digest[:], pinnedJWKSSHA256) {
		return nil, fmt.Errorf("the JWKS of issuer %s does not match the pinned key set: its SHA-256 is %x but %x was pinned",
			issuerURL, digest, pinnedJWKSSHA256)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("cannot parse the pinned JWKS of issuer %s: %w", issuerURL, err)
	}
	publicKeys := make([]crypto.PublicKey, 0, len(keySet.Keys))
	for i := range keySet.Keys {
		switch key := keySet.Keys[i].Public().Key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			publicKeys = append(publicKeys, key)
		default:
			log.Warn().Msgf("ignoring key %s of the pinned JWKS of issuer %s: unsupported key type %T",
				keySet.Keys[i].KeyID, issuerURL, keySet.Keys[i].Key)
		}
	}
	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("the pinned JWKS of issuer %s contains no usable key", issuerURL)
	}
	return &oidc.StaticKeySet{PublicKeys: publicKeys}, nil
}
