package disk

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// x/sys has only the Ex variant, which does not tell the cluster size.
var getDiskFreeSpace = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetDiskFreeSpaceW")

// Usage returns the bytes free in dir and the filesystem's allocation unit:
// every file takes a whole number of these.
func Usage(dir string) (free, cluster int64, err error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, err
	}
	var avail uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, nil, nil); err != nil {
		return 0, 0, err
	}
	return int64(avail), clusterSize(p), nil
}

// clusterSize asks the volume holding dir; GetDiskFreeSpaceW wants its root.
func clusterSize(dir *uint16) int64 {
	var root [windows.MAX_PATH + 1]uint16
	if windows.GetVolumePathName(dir, &root[0], uint32(len(root))) != nil {
		return defaultCluster
	}
	var sectors, bytes, freeClusters, clusters uint32
	ok, _, _ := getDiskFreeSpace.Call(uintptr(unsafe.Pointer(&root[0])),
		uintptr(unsafe.Pointer(&sectors)), uintptr(unsafe.Pointer(&bytes)),
		uintptr(unsafe.Pointer(&freeClusters)), uintptr(unsafe.Pointer(&clusters)))
	if ok == 0 {
		return defaultCluster
	}
	return sane(int64(sectors) * int64(bytes))
}

// IsFull reports whether err is a write to a full disk.
func IsFull(err error) bool {
	return errors.Is(err, windows.ERROR_DISK_FULL) || errors.Is(err, windows.ERROR_HANDLE_DISK_FULL)
}

// FullErrno is what a write to a full disk fails with, for tests.
var FullErrno error = windows.ERROR_DISK_FULL
