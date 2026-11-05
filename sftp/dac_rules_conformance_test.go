package sftp

// Conformance for the discretionary-access rule in dac_rules.go: the verified rule, the
// switch form a reader looks at, the reference reading of what Unix does, and the function the
// SFTP request loop actually calls all have to say the same thing for every mode and every
// request.
//
// The domain is small enough to be finished with: nine permission bits, two identity facts,
// three bits an operation may ask for. That makes 512 * 4 * 8 = 16 384 cases for the rule
// itself, and 4096 modes once the bits above the nine are included. Exhausting it is not a
// substitute for the proof in this case, it is the same strength and cheaper - which is why the
// properties Gobra v26.09 could not take (the ones about `&` and `>>` across two different
// modes) are settled here rather than left out, as the header of dac_rules.go records.
//
// What is *not* in this domain is what the numbers are about: whether the uid, gid and mode the
// server passes in are the ones the file really has, and whether the session's group list is the
// one the child process will run under. TestConformanceCheckStatPermissionUsesTheRule pins the
// first for a real file on a real filesystem; the second is child_groups_test.go's.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// requestsAreEveryCombination is every combination of bits an operation can ask for, which is
// what the twelve call sites pick from.
func requestsAreEveryCombination() []int {
	return []int{0, dacRead, dacWrite, dacExec, dacRead | dacWrite, dacRead | dacExec,
		dacWrite | dacExec, dacAskedFor}
}

func TestConformanceLiftedConstantsMatchTheServer(t *testing.T) {
	// The rule re-declares the bit constants because server.go's live behind imports Gobra cannot
	// read. If the two lists ever disagree, the rule proves something about different numbers than
	// the ones the server asks with, and no test below would notice.
	if dacRead != accessR || dacWrite != accessW || dacExec != accessX {
		t.Errorf("the lifted bits are %o/%o/%o but the server asks with %o/%o/%o",
			dacRead, dacWrite, dacExec, accessR, accessW, accessX)
	}
	if dacAskedFor != accessR|accessW|accessX {
		t.Errorf("dacAskedFor = %o, want %o", dacAskedFor, accessR|accessW|accessX)
	}
	if dacModePerm != 0o777 || dacTriadMask != 0o7 {
		t.Errorf("the masks are %o and %o, want 0o777 and 0o7", dacModePerm, dacTriadMask)
	}
	// The server hands over the mode masked to these nine bits; were the mask ever narrowed, a
	// permission would silently stop being consulted.
	if got := accessIsAllowed(int(0o777&dacModePerm), false, false, dacAskedFor); !got {
		t.Error("a mode of 0o777 does not grant read, write and execute to everybody")
	}
}

func TestConformanceTriadSelectionAgrees(t *testing.T) {
	// triadOf is the switch a reader trusts; triadGrantsBit is what is proved. They must select the
	// same bits, and the selection must be the one server.go wrote before this split: owner at
	// bits 6-8, group at 3-5, everybody at 0-2.
	for mode := 0; mode <= dacModePerm; mode++ {
		for _, ownerMatch := range []bool{false, true} {
			for _, groupMember := range []bool{false, true} {
				triad := triadOf(mode, ownerMatch, groupMember)
				want := mode & dacTriadMask
				if ownerMatch {
					want = (mode >> ownerTriadShift) & dacTriadMask
				} else if groupMember {
					want = (mode >> groupTriadShift) & dacTriadMask
				}
				if triad != want {
					t.Fatalf("triadOf(%o, %v, %v) = %o, want %o", mode, ownerMatch, groupMember, triad, want)
				}
				for _, bit := range []int{dacRead, dacWrite, dacExec} {
					if got := triadGrantsBit(mode, ownerMatch, groupMember, bit); got != (triad&bit != 0) {
						t.Fatalf("triadGrantsBit(%o, %v, %v, %o) = %v but the selected triad %o says otherwise",
							mode, ownerMatch, groupMember, bit, got, triad)
					}
				}
			}
		}
	}
}

// referenceAllows reads the mode the way the documentation of Unix does, written here from that
// description rather than from the code, so that agreeing means something.
func referenceAllows(mode int, ownerMatch, groupMember bool, required int) bool {
	triad := mode & 0o7
	if ownerMatch {
		triad = (mode / 0o100) % 8
	} else if groupMember {
		triad = (mode / 0o10) % 8
	}
	if required&0o4 != 0 && triad&0o4 == 0 {
		return false
	}
	if required&0o2 != 0 && triad&0o2 == 0 {
		return false
	}
	if required&0o1 != 0 && triad&0o1 == 0 {
		return false
	}
	return true
}

func TestConformanceAccessRuleIsTheReferenceDecision(t *testing.T) {
	cases := 0
	for mode := 0; mode <= dacModePerm; mode++ {
		for _, ownerMatch := range []bool{false, true} {
			for _, groupMember := range []bool{false, true} {
				for _, required := range requestsAreEveryCombination() {
					got := accessIsAllowed(mode, ownerMatch, groupMember, required)
					want := referenceAllows(mode, ownerMatch, groupMember, required)
					if got != want {
						t.Fatalf("accessIsAllowed(%o, owner=%v, group=%v, %o) = %v, reference says %v",
							mode, ownerMatch, groupMember, required, got, want)
					}
					cases++
				}
			}
		}
	}
	t.Logf("%d combinations of mode, ownership, group membership and request, all agreeing", cases)
}

func TestConformanceOnlyTheNinePermissionBitsMatter(t *testing.T) {
	// The property Gobra could not take (see dac_rules.go): st.Mode carries the file type above the
	// nine permission bits, and a setuid file has more above that. None of it may matter. Checked
	// over every 12-bit mode, including the directory and setuid shapes, and over the file-type
	// values stat actually reports.
	shapes := []int{0, syscall.S_IFDIR, syscall.S_IFREG, syscall.S_IFLNK, syscall.S_ISUID,
		syscall.S_ISGID, syscall.S_ISVTX}
	cases := 0
	for low := 0; low <= 0o7777; low++ {
		for _, shape := range shapes {
			mode := low | (shape & 0o170000)
			for _, ownerMatch := range []bool{false, true} {
				for _, groupMember := range []bool{false, true} {
					for _, required := range requestsAreEveryCombination() {
						got := accessIsAllowed(mode&dacModePerm, ownerMatch, groupMember, required)
						if want := accessIsAllowed(low, ownerMatch, groupMember, required); got != want {
							t.Fatalf("mode %o behaves differently from %o: %v vs %v (%o asked)",
								mode, low, got, want, required)
						}
						cases++
					}
				}
			}
		}
	}
	t.Logf("%d modes with type and setuid bits, none of which changed a decision", cases)
}

func TestConformanceAMissingBitRefusesTheOperation(t *testing.T) {
	// One absent bit is enough to refuse, and one present bit is never enough on its own: the
	// decision is per bit, in both directions.
	for mode := 0; mode <= dacModePerm; mode++ {
		for _, ownerMatch := range []bool{false, true} {
			for _, groupMember := range []bool{false, true} {
				for _, bit := range []int{dacRead, dacWrite, dacExec} {
					granted := triadGrantsBit(mode, ownerMatch, groupMember, bit)
					if got := accessIsAllowed(mode, ownerMatch, groupMember, bit); got != granted {
						t.Fatalf("asking only for %o on mode %o (owner=%v, group=%v): %v, triad says %v",
							bit, mode, ownerMatch, groupMember, got, granted)
					}
				}
				if !anOperationAskingAMissingBitIsRefused(mode, ownerMatch, groupMember) {
					t.Fatalf("mode %o (owner=%v, group=%v): a missing bit did not refuse on its own",
						mode, ownerMatch, groupMember)
				}
				if !aGrantIsTheConjunctionOfItsBits(mode, ownerMatch, groupMember, dacRead|dacWrite, dacExec) {
					t.Fatalf("mode %o (owner=%v, group=%v): a grant was not the conjunction of its bits",
						mode, ownerMatch, groupMember)
				}
				if !aRefusalNamesTheBitItMissed(mode, ownerMatch, groupMember, dacAskedFor) {
					t.Fatalf("mode %o (owner=%v, group=%v): a refusal named no missing bit",
						mode, ownerMatch, groupMember)
				}
			}
		}
	}
}

func TestConformanceSmallerRequestNeverHurts(t *testing.T) {
	for mode := 0; mode <= dacModePerm; mode++ {
		for _, ownerMatch := range []bool{false, true} {
			for _, groupMember := range []bool{false, true} {
				for _, asked := range requestsAreEveryCombination() {
					for _, less := range requestsAreEveryCombination() {
						if !askedForBitsWithin(less, asked) {
							continue
						}
						if !aSmallerRequestNeverHurts(mode, ownerMatch, groupMember, asked, less) {
							t.Fatalf("mode %o: asking %o was granted but the smaller request %o was not",
								mode, asked, less)
						}
					}
				}
			}
		}
	}
}

func TestConformanceAskedForBitsWithinIsTheSubsetRelation(t *testing.T) {
	// The verified definition is bit by bit; the formula a reader expects is `less & ^asked == 0`.
	for less := 0; less <= 0o777; less++ {
		for asked := 0; asked <= 0o777; asked++ {
			want := less&dacAskedFor&^asked == 0
			if got := askedForBitsWithin(less, asked); got != want {
				t.Fatalf("askedForBitsWithin(%o, %o) = %v, the bit formula says %v", less, asked, got, want)
			}
		}
	}
}

func TestConformanceCheckStatPermissionUsesTheRule(t *testing.T) {
	// The rule is only worth having if the function the twelve call sites use consults it. This
	// drives checkStatPermission directly, with the session's group list under test's control, and
	// checks the answer against the rule for every mode, both ownership cases, group membership
	// either way, and every request.
	const otherUID = uint32(200200200)
	const memberGID = uint32(7)
	const outsiderGID = uint32(8)

	for _, tc := range []struct {
		name        string
		uid         uint32
		gid         uint32
		groupMember bool
	}{
		{"session owns the file", uint32(os.Getuid()), outsiderGID, false},
		{"someone else owns it, session is in its group", otherUID, memberGID, true},
		{"someone else owns it, session is not in its group", otherUID, outsiderGID, false},
		{"session owns it and is in its group", uint32(os.Getuid()), memberGID, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := &ServerSession{groups: map[uint32]bool{memberGID: tc.groupMember}}
			for mode := 0; mode <= dacModePerm; mode++ {
				for _, required := range requestsAreEveryCombination() {
					err := session.checkStatPermission(tc.uid, tc.gid, uint32(mode), required)
					want := accessIsAllowed(mode, tc.uid == uint32(os.Getuid()), tc.groupMember, required)
					if got := err == nil; got != want {
						t.Fatalf("checkStatPermission(mode %o, ask %o) returned %v, rule says allowed=%v",
							mode, required, err, want)
					}
					if err != nil && !errors.Is(err, os.ErrPermission) {
						t.Fatalf("a refusal must be the permission error the client maps to EACCES, got %v", err)
					}
				}
			}
		})
	}
}

func TestConformanceFileModesOnDiskBehaveAsTheRuleSays(t *testing.T) {
	// The same decision, on files that exist, with the mode read back from the filesystem rather
	// than handed in: this is the path a get, a put or a readdir takes.
	if os.Geteuid() != 0 {
		t.Skip("needs to create a file owned by another uid, which needs root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	otherUID := 123456
	for _, mode := range []os.FileMode{0o600, 0o644, 0o044, 0o006, 0o000, 0o755} {
		path := filepath.Join(dir, fmt.Sprintf("f%o", mode))
		if err := os.WriteFile(path, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, otherUID, os.Getgid()); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}

		session := &ServerSession{} // no user: the session is this process, as in a non-root server

		var stT syscall.Stat_t
		if err := syscall.Stat(path, &stT); err != nil {
			t.Fatal(err)
		}
		// Which triad applies depends on a fact about this process, not about the file: whether it
		// belongs to the group the file belongs to. The files are created with the test's own gid,
		// so for root that is true - and a file at 0o006 then reads as group-triad 0, which the
		// kernel also honours for a non-root member of that group. The expectation asks the rule the
		// same question the function does.
		groupMember := buildGroupSet(nil)[stT.Gid]
		// The mode the server reads back is st.Mode with the file type in it; the rule must give the
		// answer for the permission bits alone.
		for _, required := range []int{dacRead, dacRead | dacWrite} {
			got := session.checkStatPermission(stT.Uid, stT.Gid, uint32(stT.Mode), required)
			want := accessIsAllowed(int(mode.Perm()), stT.Uid == uint32(os.Getuid()), groupMember, required)
			if (got == nil) != want {
				t.Fatalf("file %s (mode %o on disk, st.Mode %o): checkStatPermission ask %o gave %v, rule says %v",
					path, mode, stT.Mode, required, got, want)
			}
		}

		// The deviation, recorded rather than proved: the kernel lets root read what the emulation
		// refuses. The emulation may be stricter; it may not be looser.
		if granted := session.checkStatPermission(stT.Uid, stT.Gid, uint32(stT.Mode), dacRead) == nil; granted {
			if err := syscall.Access(path, 4); err != nil {
				t.Fatalf("%s: the emulation granted a read the kernel refused (%v) - it invented an access", path, err)
			}
		}
	}
}
