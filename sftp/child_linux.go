//go:build linux

package sftp

import "syscall"

func childSysProcAttr(uid, gid uint32, groups []uint32) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uid,
			Gid:    gid,
			Groups: groups,
		},
		Pdeathsig: syscall.SIGKILL,
	}
}
