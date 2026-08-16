//go:build aix || linux || solaris || zos

package sftp

import "golang.org/x/sys/unix"

// ioctlReadTermios and ioctlWriteTermios are the ioctl numbers used to read
// and write terminal settings.
const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
)
