package unix_util

import (
	osuser "os/user"
	"slices"
	"strconv"
	"testing"
)

func TestLookupGroupsAlwaysStartsWithPrimaryGroup(t *testing.T) {
	// an unknown user must not prevent a login: only the primary group is applied
	groups := lookupGroups("sshoq-user-that-does-not-exist", 4242)
	if len(groups) != 1 || groups[0] != 4242 {
		t.Fatalf("expected the primary group only, got %v", groups)
	}

	// same thing when the username is unknown/empty
	groups = lookupGroups("", 1000)
	if len(groups) != 1 || groups[0] != 1000 {
		t.Fatalf("expected the primary group only, got %v", groups)
	}
}

func currentUser(t *testing.T) *User {
	t.Helper()
	current, err := osuser.Current()
	if err != nil {
		t.Skipf("cannot lookup the current user: %s", err)
	}
	uid, err := strconv.ParseUint(current.Uid, 10, 64)
	if err != nil {
		t.Skipf("invalid uid %s: %s", current.Uid, err)
	}
	gid, err := strconv.ParseUint(current.Gid, 10, 64)
	if err != nil {
		t.Skipf("invalid gid %s: %s", current.Gid, err)
	}
	return &User{
		Username: current.Username,
		Uid:      uid,
		Gid:      gid,
	}
}

// GroupList must return the whole group list of the user (what initgroups(3)
// computes for a login), not only its primary group.
func TestGroupListContainsEveryGroupOfTheUser(t *testing.T) {
	u := currentUser(t)
	lookupUser, err := osuser.Lookup(u.Username)
	if err != nil {
		t.Skipf("cannot lookup user %s: %s", u.Username, err)
	}
	memberOf, err := lookupUser.GroupIds()
	if err != nil {
		t.Skipf("cannot lookup the groups of %s: %s", u.Username, err)
	}

	gids := u.GroupList()
	if len(gids) == 0 {
		t.Fatal("group list must never be empty")
	}
	if gids[0] != uint32(u.Gid) {
		t.Errorf("expected the primary group %d first, got %v", u.Gid, gids)
	}

	for _, gidStr := range memberOf {
		gid, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			continue
		}
		if !slices.Contains(gids, uint32(gid)) {
			t.Errorf("group %s of user %s is missing from the group list %v", gidStr, u.Username, gids)
		}
	}

	for i, gid := range gids {
		if slices.Contains(gids[i+1:], gid) {
			t.Errorf("group %d appears twice in the group list %v", gid, gids)
		}
	}
}

// The group list must be handed over to setgroups(2) through
// syscall.Credential.Groups, otherwise the Go runtime drops every
// supplementary group and `id` only reports the primary group.
func TestCredentialCarriesTheWholeGroupList(t *testing.T) {
	u := currentUser(t)
	cred := u.credential()

	if cred.Uid != uint32(u.Uid) || cred.Gid != uint32(u.Gid) {
		t.Errorf("unexpected uid/gid in credential: %+v", cred)
	}
	if cred.NoSetGroups {
		t.Error("NoSetGroups must not be set, it drops the supplementary groups")
	}

	groups := cred.Groups
	if len(groups) != len(u.GroupList()) {
		t.Fatalf("credential groups %v differ from the group list %v", groups, u.GroupList())
	}
	for _, gid := range u.GroupList() {
		if !slices.Contains(groups, gid) {
			t.Errorf("group %d is missing from the credential groups %v", gid, groups)
		}
	}
}

// A User built by hand (without GetUser) must get its group list resolved when
// the credential is built, and must not fall back to a primary-group-only list
// when the username is known.
func TestGroupListIsResolvedOnDemand(t *testing.T) {
	u := currentUser(t)
	if len(u.Groups) != 0 {
		t.Fatalf("test precondition: %v should not have a group list yet", u.Groups)
	}

	groups := u.GroupList()
	if len(groups) == 0 {
		t.Fatal("group list must never be empty")
	}
	if len(u.Groups) != len(groups) {
		t.Errorf("GroupList should memoize the resolved group list, got %v", u.Groups)
	}
}
