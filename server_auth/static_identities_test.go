package server_auth

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/h4sh5/sshoq/auth"
	"github.com/h4sh5/sshoq/internal"
	"github.com/h4sh5/sshoq/util/unix_util"
)

// stub identity verifier, standing for the pubkey plugin which the real binary
// registers from its main (importing that plugin from here would be an import
// cycle, its package depending on server_auth)
type stubIdentityVerifier struct{}

func (v *stubIdentityVerifier) Verify(request *http.Request, base64ConversationID string) bool {
	return true
}

func init() {
	err := internal.RegisterServerAuthPlugin("test-static-identities",
		func(username string, identityStr string) (auth.RequestIdentityVerifier, error) {
			if strings.HasPrefix(identityStr, "stubkey ") {
				return &stubIdentityVerifier{}, nil
			}
			return nil, nil
		})
	if err != nil {
		panic(err)
	}
}

// Keys registered with AddStaticAuthorizedIdentities are authorized in the
// memory of the running server: GetAuthorizedIdentities returns them on top of
// the ones of the user's files, without any file being involved.
func TestStaticAuthorizedIdentities(t *testing.T) {
	user := &unix_util.User{Username: "alice", Dir: t.TempDir()}

	before, err := GetAuthorizedIdentities(user)
	if err != nil {
		t.Fatalf("a user with no identities file must not be an error: %s", err)
	}

	AddStaticAuthorizedIdentities("stubkey alice")
	t.Cleanup(func() {
		staticIdentities.mu.Lock()
		staticIdentities.lines = staticIdentities.lines[:len(staticIdentities.lines)-1]
		staticIdentities.mu.Unlock()
	})

	after, err := GetAuthorizedIdentities(user)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("the static key was not authorized: %d identities instead of %d", len(after), len(before)+1)
	}
}

// An identities file the server cannot read authorizes nobody, but it must not
// forbid the identities known by other means either. A server running
// unprivileged, asked for an account whose home it may not enter, used to give up
// on the unreadable file and refuse everybody - including the keys handed to it on
// its own command line, which have nothing to do with that file and are the only
// way such a server can be reached at all.
func TestUnreadableIdentitiesFileDoesNotVetoTheStaticOnes(t *testing.T) {
	// a regular file where a directory is expected: the open of the identities file
	// below it fails with "not a directory", which is neither a success nor a
	// "does not exist" - and it fails that way for root too, unlike a chmod
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".ssh3"), []byte("not a directory"), 0600); err != nil {
		t.Fatalf("could not make the identities path unusable: %s", err)
	}
	user := &unix_util.User{Username: "carol", Dir: home}

	AddStaticAuthorizedIdentities("stubkey carol")
	t.Cleanup(func() {
		staticIdentities.mu.Lock()
		staticIdentities.lines = staticIdentities.lines[:len(staticIdentities.lines)-1]
		staticIdentities.mu.Unlock()
	})

	identities, err := GetAuthorizedIdentities(user)
	if err != nil {
		t.Fatalf("an unreadable identities file must not fail the whole authentication: %s", err)
	}
	if len(identities) != 1 {
		t.Fatalf("the static identity should have been authorized despite the unreadable file: %d identities", len(identities))
	}
}

// A static line which no registered identity format recognizes is logged and
// ignored, exactly like an unparsable line of an identities file: it must
// neither break authentication nor inflate the identity list.
func TestStaticAuthorizedIdentitiesBogusLine(t *testing.T) {
	user := &unix_util.User{Username: "bob", Dir: t.TempDir()}
	before, err := GetAuthorizedIdentities(user)
	if err != nil {
		t.Fatal(err)
	}

	AddStaticAuthorizedIdentities("this is not an identity")
	t.Cleanup(func() {
		staticIdentities.mu.Lock()
		staticIdentities.lines = staticIdentities.lines[:len(staticIdentities.lines)-1]
		staticIdentities.mu.Unlock()
	})

	after, err := GetAuthorizedIdentities(user)
	if err != nil {
		t.Fatalf("a bogus static line must not break authentication: %s", err)
	}
	if len(after) != len(before) {
		t.Fatalf("the bogus line produced an identity: %d instead of %d", len(after), len(before))
	}
}
