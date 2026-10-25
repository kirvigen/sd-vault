package disk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiskFullIsRecognised(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x")
	full := &os.PathError{Op: "write", Path: path, Err: FullErrno}
	if !IsFull(full) {
		t.Error("write error for a full disk not recognised")
	}
	if IsFull(os.ErrNotExist) {
		t.Error("unrelated error taken for a full disk")
	}
	free, cluster, err := Usage(t.TempDir())
	if err != nil || free <= 0 || cluster < 512 {
		t.Errorf("Usage = %d, %d, %v", free, cluster, err)
	}
}
