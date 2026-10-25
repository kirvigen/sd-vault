//go:build !windows

package update

import (
	"errors"
	"syscall"
)

func diskFree(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC)
}

// noSpaceErrno is what a write to a full disk fails with, for tests.
var noSpaceErrno error = syscall.ENOSPC
