package util

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rs/zerolog/log"
)

// secretFilePerm is the permission a file holding sensitive material gets: its owner
// alone, whatever the umask of the process is.
const secretFilePerm = os.FileMode(0600)

// MakePrivateDir creates a directory which must not be readable by the rest of the box,
// and takes back the permissions of one which already exists but is group- or
// world-accessible - the client configuration directory holding known_hosts and the OIDC
// client secret, for instance, which an earlier version may have created 0755.
//
// A directory which does not belong to the caller is left alone: pointing -config-dir at
// somebody else's directory is not a reason to change its permissions, and only its owner
// (or root) could answer for them anyway.
func MakePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if path == "/" || path == "." {
		// never tighten a directory the whole system depends on being traversable
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsDir() {
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
			log.Warn().Msgf("%s holds sensitive data but belongs to another user, its permissions are left at %s",
				path, info.Mode().Perm())
			return nil
		}
		if err := os.Chmod(path, 0700); err != nil {
			log.Warn().Msgf("%s holds sensitive data but could not be made private: %s", path, err)
			return nil
		}
		log.Warn().Msgf("%s holds sensitive data and was accessible to group or others (%s): its permissions have "+
			"just been tightened to 0700", path, info.Mode().Perm())
	}
	return nil
}

// OpenSecretFile opens a file whose content must stay private to its owner - the server
// log (usernames, peer addresses, conversation IDs) or the TLS key log (the master
// secrets, i.e. the means to decrypt a recorded session) - creating it 0600 and taking
// back the permissions of an existing file which were more open.
//
// These files used to be created 0644 / 0666&^umask, which on a multi-user host hands
// the traffic keys and the list of users of the server to anybody able to read the
// directory. Silently fixing the mode at the next write is not enough: say what was
// changed, because content may have been readable until now.
func OpenSecretFile(path string, flags int) (*os.File, error) {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// only created when missing, and never 0755: a directory holding secrets must not
		// be traversable by other users either
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("could not create the directory %s of %s: %w", dir, path, err)
		}
	}

	file, err := os.OpenFile(path, flags|os.O_CREATE|os.O_WRONLY, secretFilePerm)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	// only a regular file is a file we own and may tighten: /dev/null, for instance, is
	// legitimately world-writable and must certainly not be chmod'ed by us
	if perm := info.Mode().Perm(); info.Mode().IsRegular() && perm&0077 != 0 {
		if chmodErr := os.Chmod(path, secretFilePerm); chmodErr != nil {
			log.Warn().Msgf("%s holds sensitive data but is readable by group or others (%s) and could not be "+
				"tightened: %s", path, perm, chmodErr)
		} else {
			log.Warn().Msgf("%s holds sensitive data and was readable by group or others (%s): its permissions "+
				"have just been tightened to %s, but anything written before was readable by them", path, perm, secretFilePerm)
		}
	}

	return file, nil
}

// OpenSecretAppendFile opens a sensitive file for appending, see OpenSecretFile.
func OpenSecretAppendFile(path string) (*os.File, error) {
	return OpenSecretFile(path, os.O_APPEND)
}

// CreateSecretFile creates a sensitive file, truncating it, see OpenSecretFile.
func CreateSecretFile(path string) (*os.File, error) {
	return OpenSecretFile(path, os.O_TRUNC)
}
