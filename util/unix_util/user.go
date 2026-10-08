package unix_util

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"
)

type User struct {
	Username string
	Uid      uint64
	Gid      uint64
	Dir      string
	Shell    string

	// Groups is the complete group list of the user: the primary group (Gid)
	// first, then every group the user is a member of. It mirrors what
	// initgroups(3) computes for a real login, and is what allows processes
	// spawned for that user to use the rights granted to their supplementary
	// groups (sudo, docker, lxd, ...).
	Groups []uint32
}

// GetUser looks up username and resolves its full group list, so that the
// processes spawned for that user run in a complete login context.
func GetUser(username string) (*User, error) {
	u, err := getUser(username)
	if err != nil {
		return nil, err
	}
	// resolve the full group list once, so that every process spawned for that
	// user runs in a complete login context
	u.GroupList()
	return u, nil
}

// lookupGroups returns the group list of the user called username: its primary
// group followed by the groups it is a member of. It always contains at least
// the primary group: a failing group lookup must not prevent a user from
// logging in, it only degrades the process to the primary group.
func lookupGroups(username string, primaryGid uint32) []uint32 {
	groups := []uint32{primaryGid}
	if username == "" {
		return groups
	}

	// os/user uses getgrouplist(3) when cgo is enabled (and therefore honours
	// NSS/LDAP/AD groups), and falls back to parsing /etc/group otherwise.
	lookupUser, err := osuser.Lookup(username)
	if err != nil {
		log.Warn().Msgf("could not lookup user %s to build its group list, only its primary group %d is applied: %s", username, primaryGid, err)
		return groups
	}

	gidStrs, err := lookupUser.GroupIds()
	if err != nil {
		log.Warn().Msgf("could not read the group list of user %s, only its primary group %d is applied: %s", username, primaryGid, err)
		return groups
	}

	seen := map[uint32]bool{primaryGid: true}
	for _, gidStr := range gidStrs {
		gid, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil {
			continue
		}
		if !seen[uint32(gid)] {
			seen[uint32(gid)] = true
			groups = append(groups, uint32(gid))
		}
	}

	return groups
}

// GroupList returns the group list of u: its primary group followed by the
// groups it is a member of. It looks the list up if it has not been resolved
// yet (e.g. for a User built by hand rather than with GetUser).
func (u *User) GroupList() []uint32 {
	if len(u.Groups) == 0 {
		u.Groups = lookupGroups(u.Username, uint32(u.Gid))
	}
	return u.Groups
}

// credential returns the credentials to run a process as u. The whole group
// list is passed to it: the Go runtime hands it over to setgroups(2), which is
// exactly what initgroups(3) does during a login. Leaving Groups empty would
// make the runtime call setgroups(0, NULL) and drop every supplementary group,
// so that `id` would only report the primary group of the user.
func (u *User) credential() *syscall.Credential {
	return &syscall.Credential{
		Uid:    uint32(u.Uid),
		Gid:    uint32(u.Gid),
		Groups: u.GroupList(),
	}
}

func (u *User) CreateCommand(addEnv string, stdout, stderr io.Writer, stdin io.Reader, loginShell bool, command string, args ...string) (*exec.Cmd, io.Reader, io.Reader, io.Writer, error) {
	cmd := exec.Command(command, args...)
	cmd.Env = append(cmd.Env, addEnv)
	cmd.Dir = u.Dir

	if loginShell {
		// from man bash: A  login shell is one whose first character of argument zero is a -, or
		// 				  one started with the --login option.
		// We chose to start it with a preprended "-"
		cmd.Args[0] = fmt.Sprintf("-%s", filepath.Base(cmd.Args[0]))
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{}
	// check if current running user is same as uid, if so skip this step so that sshoq server can run without root
	if uint64(os.Getuid()) != u.Uid { // need to spawn shell as someone else
		// set the primary group *and* the supplementary groups of the user, like
		// a full login would (see credential and the loginShell handling above)
		cmd.SysProcAttr.Credential = u.credential()
	}

	var err error
	var stdoutR, stderrR io.Reader
	var stdinW io.Writer

	if stdout == nil {
		stdoutR, err = cmd.StdoutPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		cmd.Stdout = stdout
	}
	if stderr == nil {
		stderrR, err = cmd.StderrPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		cmd.Stderr = stderr
	}
	if stdin == nil {
		stdinW, err = cmd.StdinPipe()
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else {
		cmd.Stdin = stdin
	}

	return cmd, stdoutR, stderrR, stdinW, err
}

func (u *User) CreateCommandPipeOutput(addEnv string, loginShell bool, command string, args ...string) (*exec.Cmd, io.Reader, io.Reader, io.Writer, error) {
	// passing nil writers/readers makes CreateCommand return the pipes of the
	// command it creates, along with the working directory, the environment and
	// the credentials (full group list included)
	return u.CreateCommand(addEnv, nil, nil, nil, loginShell, command, args...)
}

/*
 *  Returns a boolean stating whether the user is correctly authenticated on this
 *  server. May return a UserNotFound error when the user does not exist.
 */
func UserPasswordAuthentication(username, password string) (bool, error) {
	return userPasswordAuthentication(username, password)
}

func PasswordAuthAvailable() bool {
	return passwordAuthAvailable()
}
