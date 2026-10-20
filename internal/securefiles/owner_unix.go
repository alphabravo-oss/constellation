//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package securefiles

import (
	"errors"
	"os"
	"syscall"
)

func checkDirectoryOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("artifact directory must be owned by the current user")
	}
	return nil
}
