package sftp

import (
	"testing"
)

func TestParseGroups(t *testing.T) {
	groups := parseGroups("1000,1001,42")
	if len(groups) != 3 || groups[0] != 1000 || groups[1] != 1001 || groups[2] != 42 {
		t.Fatalf("unexpected group list %v", groups)
	}

	// an empty list must yield nil, so that the group list is looked up on demand
	if got := parseGroups(""); got != nil {
		t.Errorf("expected nil for an empty group list, got %v", got)
	}

	// malformed entries are ignored, and a fully malformed list behaves like an
	// empty one
	if got := parseGroups("1000,not-a-gid,"); len(got) != 1 || got[0] != 1000 {
		t.Errorf("unexpected group list %v", got)
	}
	if got := parseGroups("nope"); got != nil {
		t.Errorf("expected nil when no group could be parsed, got %v", got)
	}
}

// the SFTP child must reuse the group list the parent applied to it, instead of
// only knowing its primary group
func TestUserFromEnvRestoresGroups(t *testing.T) {
	t.Setenv(sftpUIDEnv, "1001")
	t.Setenv(sftpGIDEnv, "1002")
	t.Setenv(sftpUsernameEnv, "someone")
	t.Setenv(sftpGroupsEnv, formatGroups([]int{1002, 1003, 1004}))

	user, err := userFromEnv()
	if err != nil {
		t.Fatalf("userFromEnv error: %v", err)
	}
	groups := user.GroupList()
	if len(groups) != 3 || groups[0] != 1002 || groups[1] != 1003 || groups[2] != 1004 {
		t.Fatalf("expected the groups of the parent, got %v", groups)
	}
}

// without the groups environment variable, the group list falls back to the
// primary group only (the child cannot look up another user's groups)
func TestUserFromEnvWithoutGroups(t *testing.T) {
	t.Setenv(sftpUIDEnv, "1001")
	t.Setenv(sftpGIDEnv, "1002")
	t.Setenv(sftpUsernameEnv, "")
	t.Setenv(sftpGroupsEnv, "")

	user, err := userFromEnv()
	if err != nil {
		t.Fatalf("userFromEnv error: %v", err)
	}
	if ids, err := buildGroupIDs(user); err != nil || len(ids) != 1 || ids[0] != 1002 {
		t.Fatalf("expected the primary group only, got %v (err %v)", ids, err)
	}
}
