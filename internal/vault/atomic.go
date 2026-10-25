package vault

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// tmpMarker is part of every temporary file name, so leftovers from an
// interrupted write can be recognised and removed on the next unlock.
const tmpMarker = ".tmp-"

// writeAtomic writes path via a temporary file in the same directory:
// write → fsync → close → rename → fsync of the directory. A reader (or a
// card pulled out mid-write) sees either the old file or the new one, never a
// half-written mix.
func writeAtomic(path string, write func(w io.Writer) error) error {
	return writeFile(path, "", true, write)
}

// writeAtomicKeepingBackup is writeAtomic that, when backup is set, first
// moves the current file to backup. If the process dies between the two
// renames, path is missing and the loader falls back to backup.
func writeAtomicKeepingBackup(path, backup string, write func(w io.Writer) error) error {
	return writeFile(path, backup, true, write)
}

// writeUnsynced is writeAtomic without the fsyncs, for content that nothing
// names yet: the commit that adds it to the index syncs it first. Until
// then a pulled card can leave it partly written, and the next unlock
// removes it as garbage.
func writeUnsynced(path string, write func(w io.Writer) error) error {
	return writeFile(path, "", false, write)
}

func writeFile(path, backup string, sync bool, write func(w io.Writer) error) (err error) {
	dir := filepath.Dir(path)
	tmp := path + tmpMarker + randomHex(6)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err = write(f); err != nil {
		return err
	}
	if sync {
		if err = f.Sync(); err != nil {
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}
	if backup != "" {
		if _, statErr := os.Stat(path); statErr == nil {
			if err = os.Rename(path, backup); err != nil {
				return err
			}
		}
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if sync {
		syncDir(dir)
	}
	return nil
}

// syncDir makes a rename durable. Windows cannot fsync a directory, and some
// filesystems refuse it; the rename has happened either way, so errors are
// ignored.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	d.Sync()
	d.Close()
}

func isTmpName(name string) bool {
	return strings.Contains(name, tmpMarker)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
