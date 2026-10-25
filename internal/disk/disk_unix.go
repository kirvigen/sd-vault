//go:build !windows

package disk

import (
	"errors"
	"syscall"
)

// Usage returns the bytes free in dir and the filesystem's allocation unit:
// every file takes a whole number of these. On FAT and exFAT, macOS and
// Linux report the cluster as the block size.
func Usage(dir string) (free, cluster int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), sane(int64(st.Bsize)), nil
}

// IsFull reports whether err is a write to a full disk.
func IsFull(err error) bool {
	return errors.Is(err, syscall.ENOSPC)
}

// FullErrno is what a write to a full disk fails with, for tests.
var FullErrno error = syscall.ENOSPC
