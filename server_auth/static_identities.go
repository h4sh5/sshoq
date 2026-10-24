package server_auth

import (
	"sync"

	"github.com/h4sh5/sshoq/util/unix_util"
	"github.com/rs/zerolog/log"
)

// staticIdentities are authorized identity lines (typically public keys) which are
// authorized in the memory of the running server only, and in no file. This is what
// the -pubkey and -rpub flags of sshoq-server install, so that a key can be made
// usable for the lifetime of one server run without touching
// ~/.ssh3/authorized_identities nor ~/.ssh/authorized_keys.
var staticIdentities struct {
	mu    sync.RWMutex
	lines []string
}

// AddStaticAuthorizedIdentities registers identity lines, in the
// authorized_keys / authorized_identities format, which GetAuthorizedIdentities
// returns on top of the ones of the user's files, for as long as the process
// lives. Lines are parsed, exactly like the lines of an identities file, when a
// user authenticates, so a line only ever has an effect on the identities which
// can make sense of it.
func AddStaticAuthorizedIdentities(lines ...string) {
	staticIdentities.mu.Lock()
	defer staticIdentities.mu.Unlock()
	staticIdentities.lines = append(staticIdentities.lines, lines...)
}

// StaticAuthorizedIdentities returns a copy of the lines registered so far.
func StaticAuthorizedIdentities() []string {
	staticIdentities.mu.RLock()
	defer staticIdentities.mu.RUnlock()
	return append([]string{}, staticIdentities.lines...)
}

// parseStaticIdentities turns the registered lines into verifiers for the given
// user. A line no identity format recognizes is logged and ignored, exactly like
// an unparsable line of an identities file.
func parseStaticIdentities(user *unix_util.User) []IdentityVerifier {
	var identities []IdentityVerifier
	for _, line := range StaticAuthorizedIdentities() {
		verifiers, err := ParseIdentity(user, line)
		if err != nil {
			log.Error().Msgf("ignoring the static authorized identity %q: %s", line, err)
			continue
		}
		identities = append(identities, verifiers...)
	}
	return identities
}
