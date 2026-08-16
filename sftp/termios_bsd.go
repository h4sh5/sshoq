//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package sftp

import "golang.org/x/sys/unix"

// ioctlReadTermios and ioctlWriteTermios are the ioctl numbers used to read
// and write terminal settings. BSD-derived systems (darwin, freebsd, openbsd,
// ...) use TIOCGETA/TIOCSETA where Linux uses TCGETS/TCSETS.
const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)
