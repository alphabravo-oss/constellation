//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package securefiles

import "os"

func checkDirectoryOwner(os.FileInfo) error { return nil }
