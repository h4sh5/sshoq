//go:build linux && !disable_password_auth

// partially copied from https://github.com/google/minions/blob/v0.1.0/src/go/minions/passwd/minion.go

package unix_util

/*
#cgo LDFLAGS: -lcrypt
#include <stdlib.h>
#include <unistd.h>
#include <shadow.h>
#include <crypt.h>
#include <errno.h>
#include <pwd.h>
size_t size_of_passwd() { return sizeof(struct passwd); }
size_t size_of_shadow() { return sizeof(struct spwd); }
int get_errno() { return errno; }
*/
import "C"
import (
	"crypto/subtle"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/h4sh5/sshoq/util"
	"github.com/rs/zerolog/log"
)

type ShadowEntry struct {
	Username string
	Password string
	// LastChange is sp_lstchg: day of the last password change (days since 1970-01-01),
	// -1 when unset.
	LastChange int64
	// MaxAge is sp_max: how many days the password stays valid after a change, -1 when it
	// never expires.
	MaxAge int64
	// ExpireDate is sp_expire: day from which the account is no longer accessible, -1
	// when the account never expires.
	ExpireDate int64
	// Flags is sp_flag, the account flags of shadow(5).
	Flags uint64
}

/*
 * Wrapper around libshadow's getspnam function
 * copied from https://stackoverflow.com/questions/38790092/call-a-c-function-from-go
 */
func Getspnam(name string) (*ShadowEntry, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	cspwd := (*C.struct_spwd)(C.malloc(C.size_of_shadow()))
	defer C.free(unsafe.Pointer(cspwd))

	buf := (*C.char)(C.malloc(1024))
	defer C.free(unsafe.Pointer(buf))

	_, err := C.getspnam_r(cname, cspwd, buf, 1024, &cspwd)

	if unsafe.Pointer(cspwd) == unsafe.Pointer(uintptr(0)) {
		if err == nil {
			err = util.UserNotFound{Username: name}
		}

		return nil, err
	}

	s := ShadowEntry{
		Username:   C.GoString(cspwd.sp_namp),
		Password:   C.GoString(cspwd.sp_pwdp),
		LastChange: int64(cspwd.sp_lstchg),
		MaxAge:     int64(cspwd.sp_max),
		ExpireDate: int64(cspwd.sp_expire),
		Flags:      uint64(cspwd.sp_flag),
	}

	return &s, nil
}

/*
 * Wrapper around libc's crypt function
 * Similarly to the original function, the setting string
 * can also be a fully hashed password, crypt() will only
 * look at the three first components.
 */
func Crypt(clearPassword, setting string) (string, error) {
	cPassword := C.CString(clearPassword)
	defer C.free(unsafe.Pointer(cPassword))

	cSetting := C.CString(string(setting))
	defer C.free(unsafe.Pointer(cSetting))

	ccrypt_ret := C.crypt(cPassword, cSetting)
	if ccrypt_ret == nil {
		// crypt(3) returns NULL on error; indexing the converted string used to panic on
		// the empty result it produced
		return "", fmt.Errorf("bad password hashing: crypt() failed")
	}

	hashedPassword := C.GoString(ccrypt_ret)
	if hashedPassword == "" || hashedPassword[0] == '*' {
		return "", fmt.Errorf("bad password hashing")
	}
	return hashedPassword, nil
}

func GetEUid() int32 {
	return int32(C.geteuid())
}

func GetUid() int32 {
	return int32(C.getuid())
}

func GetEGid() int32 {
	return int32(C.geteuid())
}

func GetGid() int32 {
	return int32(C.getgid())
}

/*
 * Compares the provided password with the one stored in the shadow passwords table (generally /etc/shadow)
 *
 * The comparison is constant time: comparing hashes with == stops at the first differing
 * byte, which tells an attacker how much of a guess is right. A hashing failure is a
 * hard denial as well, never a mismatch to ignore.
 */
func ComparePasswordWithHashedPassword(candidatePassword string, hashedPassword string) (bool, error) {
	candidateHashedPassword, err := Crypt(candidatePassword, string(hashedPassword))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(candidateHashedPassword), []byte(hashedPassword)) == 1, nil
}

/*
 *  Returns a boolean stating whether the user is correctly authenticated on this
 *  server. May return a UserNotFound error when the user does not exist.
 */
func userPasswordAuthentication(username, password string) (bool, error) {
	shadowEntry, err := Getspnam(username)
	if err != nil {
		// an unreadable or missing shadow entry is not "no password needed": the error is
		// returned instead of being dropped on the floor, and no comparison is attempted
		return false, err
	}

	user, err := getUser(username)
	if err != nil {
		return false, err
	}

	// The password being right is not enough: an account which is locked, expired, or
	// without a login shell must not open a session, as nologin(8) and PAM would refuse
	// it. This is checked before the hash, so a locked account cannot even be probed
	// against its password.
	policy := AccountPolicy{
		PasswordHash: shadowEntry.Password,
		LastChange:   shadowEntry.LastChange,
		MaxAge:       shadowEntry.MaxAge,
		ExpireDate:   shadowEntry.ExpireDate,
		Flags:        uint32(shadowEntry.Flags),
		Shell:        user.Shell,
		IsRoot:       user.Uid == 0,
	}
	if err := CheckAccountUsable(policy, time.Now()); err != nil {
		log.Warn().Msgf("refusing password login of user %s: %s", username, err)
		return false, err
	}

	return ComparePasswordWithHashedPassword(password, shadowEntry.Password)
}

func getUser(username string) (*User, error) {
	return getpwnam(username)
}

/*
 * Wrapper around libc's getpwnam function
 */
func getpwnam(name string) (*User, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	cpasswd := (*C.struct_passwd)(C.malloc(C.size_of_passwd()))
	defer C.free(unsafe.Pointer(cpasswd))

	bufLen := uint64(1024)
	cBufLen := C.sysconf(C._SC_GETPW_R_SIZE_MAX)
	if cBufLen > C.long(0) {
		bufLen = uint64(cBufLen)
	}

	buf := (*C.char)(C.malloc(C.size_t(bufLen)))
	defer C.free(unsafe.Pointer(buf))

	ret, err := C.getpwnam_r(cname, cpasswd, buf, C.size_t(bufLen), &cpasswd)

	if int(ret) != 0 {
		return nil, syscall.Errno(ret)
	}

	if unsafe.Pointer(cpasswd) == unsafe.Pointer(uintptr(0)) {
		if err == nil {
			err = util.UserNotFound{Username: name}
		}

		return nil, err
	}

	s := User{
		Username: C.GoString(cpasswd.pw_name),
		Uid:      uint64(cpasswd.pw_uid),
		Gid:      uint64(cpasswd.pw_gid),
		Dir:      C.GoString(cpasswd.pw_dir),
		Shell:    C.GoString(cpasswd.pw_shell),
	}

	return &s, nil
}

func passwordAuthAvailable() bool {
	return true
}
