package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const password = "correct horse battery staple"

func newVault(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Create(dir, password)
	if err != nil {
		t.Fatal(err)
	}
	return v, dir
}

func reopen(t *testing.T, v *Vault, dir string) *Vault {
	t.Helper()
	v.Close()
	v2, err := Open(dir, password)
	if err != nil {
		t.Fatal(err)
	}
	return v2
}

func randomBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func readAll(t *testing.T, v *Vault, id string) []byte {
	t.Helper()
	f, _, err := v.Open(id)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func findByName(t *testing.T, v *Vault, dir, name string) Entry {
	t.Helper()
	list, err := v.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("%q not found in %q", name, dir)
	return Entry{}
}

func TestRoundTrip(t *testing.T) {
	v, dir := newVault(t)
	docs, err := v.Mkdir(RootID, "Документы")
	if err != nil {
		t.Fatal(err)
	}
	small := []byte("привет, сейф")
	big := randomBytes(t, 3*64*1024+123) // spans several age chunks
	if _, err := v.Put(docs.ID, "заметка.txt", bytes.NewReader(small)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(RootID, "video.mp4", bytes.NewReader(big)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(RootID, "empty", bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}

	v = reopen(t, v, dir)

	docs = findByName(t, v, RootID, "Документы")
	note := findByName(t, v, docs.ID, "заметка.txt")
	if got := readAll(t, v, note.ID); !bytes.Equal(got, small) {
		t.Fatalf("small file: got %q", got)
	}
	vid := findByName(t, v, RootID, "video.mp4")
	if vid.Size != int64(len(big)) {
		t.Fatalf("size %d, want %d", vid.Size, len(big))
	}
	if got := readAll(t, v, vid.ID); !bytes.Equal(got, big) {
		t.Fatal("big file differs after round trip")
	}
	if got := readAll(t, v, findByName(t, v, RootID, "empty").ID); len(got) != 0 {
		t.Fatalf("empty file: got %d bytes", len(got))
	}

	// Random access across a chunk boundary, as a video Range request does.
	f, _, err := v.Open(vid.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 1000)
	off := int64(64*1024 - 500)
	if _, err := f.ReadAt(buf, off); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, big[off:off+1000]) {
		t.Fatal("ReadAt returned wrong bytes")
	}

	p, err := v.Path(note.ID)
	if err != nil || len(p) != 2 || p[0].Name != "Документы" {
		t.Fatalf("Path = %v, %v", p, err)
	}
}

func TestWrongPassword(t *testing.T) {
	v, dir := newVault(t)
	v.Close()
	if _, err := Open(dir, "not the password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("got %v, want ErrWrongPassword", err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "nothing"), password); !errors.Is(err, ErrNoVault) {
		t.Fatalf("got %v, want ErrNoVault", err)
	}
	if _, err := Create(dir, password); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("got %v, want ErrVaultExists", err)
	}
}

func TestCorruptedFileIsDetected(t *testing.T) {
	v, dir := newVault(t)
	data := randomBytes(t, 200*1024)
	e, err := v.Put(RootID, "photo.jpg", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(dir, filepath.FromSlash(e.Blob))
	raw, err := os.ReadFile(blob)
	if err != nil {
		t.Fatal(err)
	}

	// One flipped bit in the middle of the payload.
	flipped := bytes.Clone(raw)
	flipped[len(flipped)/2] ^= 1
	os.WriteFile(blob, flipped, 0o600)
	f, _, err := v.Open(e.ID)
	if err == nil {
		_, err = io.ReadAll(f)
		f.Close()
	}
	if err == nil {
		t.Fatal("flipped bit was not detected")
	}

	// Truncated file.
	os.WriteFile(blob, raw[:len(raw)-100], 0o600)
	if f, _, err := v.Open(e.ID); err == nil {
		_, err = io.ReadAll(f)
		f.Close()
		if err == nil {
			t.Fatal("truncation was not detected")
		}
	}

	// Intact file reads again.
	os.WriteFile(blob, raw, 0o600)
	if got := readAll(t, v, e.ID); !bytes.Equal(got, data) {
		t.Fatal("restored file differs")
	}
}

func TestDamagedIndexFallsBackToBackup(t *testing.T) {
	v, dir := newVault(t)
	if _, err := v.Put(RootID, "a.txt", strings.NewReader("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(RootID, "b.txt", strings.NewReader("b")); err != nil {
		t.Fatal(err)
	}
	v.Close()

	idx := filepath.Join(dir, indexFile)
	raw, _ := os.ReadFile(idx)
	raw[len(raw)-10] ^= 0xff
	os.WriteFile(idx, raw, 0o600)

	v, err := Open(dir, password)
	if err != nil {
		t.Fatal(err)
	}
	// The backup is the state before the last save: a.txt only.
	findByName(t, v, RootID, "a.txt")
	if list, _ := v.List(RootID); len(list) != 1 {
		t.Fatalf("got %d entries, want 1", len(list))
	}
	// The restored index is written back, so the next unlock is clean.
	v = reopen(t, v, dir)
	findByName(t, v, RootID, "a.txt")
}

func TestMissingIndexUsesBackup(t *testing.T) {
	// A crash between "index → backup" and "tmp → index" leaves no index.
	v, dir := newVault(t)
	v.Put(RootID, "a.txt", strings.NewReader("a"))
	v.Put(RootID, "b.txt", strings.NewReader("b"))
	v.Close()
	os.Remove(filepath.Join(dir, indexFile))
	v, err := Open(dir, password)
	if err != nil {
		t.Fatal(err)
	}
	findByName(t, v, RootID, "a.txt")
}

func TestAtomicWriteFailureKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if err := writeAtomic(p, func(w io.Writer) error {
		_, err := w.Write([]byte("old"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("card pulled out")
	err := writeAtomic(p, func(w io.Writer) error {
		w.Write([]byte("new and half-wri"))
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "old" {
		t.Fatalf("file is %q after failed write", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary file left behind: %v", entries)
	}
}

type failingReader struct{ n int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("connection lost")
	}
	n := min(len(p), r.n)
	r.n -= n
	return n, nil
}

func countFiles(t *testing.T, root string) int {
	n := 0
	filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

func TestInterruptedUploadLeavesNothing(t *testing.T) {
	v, dir := newVault(t)
	keep, err := v.Put(RootID, "keep.txt", strings.NewReader("keep"))
	if err != nil {
		t.Fatal(err)
	}
	before := countFiles(t, filepath.Join(dir, blobsDir))

	if _, err := v.Put(RootID, "broken.bin", &failingReader{n: 100_000}); err == nil {
		t.Fatal("upload of a failing stream succeeded")
	}
	if after := countFiles(t, filepath.Join(dir, blobsDir)); after != before {
		t.Fatalf("blobs: %d before, %d after failed upload", before, after)
	}
	if list, _ := v.List(RootID); len(list) != 1 {
		t.Fatalf("index has %d entries, want 1", len(list))
	}

	// Leftovers of a process killed mid-write are swept on the next unlock.
	orphanDir := filepath.Join(dir, blobsDir, "ff")
	os.MkdirAll(orphanDir, 0o700)
	os.WriteFile(filepath.Join(orphanDir, "ff00.age"), []byte("orphan"), 0o600)
	os.WriteFile(filepath.Join(orphanDir, "ff01.age"+tmpMarker+"abc"), []byte("tmp"), 0o600)
	os.WriteFile(filepath.Join(dir, indexFile+tmpMarker+"abc"), []byte("tmp"), 0o600)
	v = reopen(t, v, dir)
	if after := countFiles(t, filepath.Join(dir, blobsDir)); after != before {
		t.Fatalf("garbage not collected: %d blobs, want %d", after, before)
	}
	if _, err := os.Stat(filepath.Join(dir, indexFile+tmpMarker+"abc")); err == nil {
		t.Fatal("index temp file not collected")
	}
	if got := readAll(t, v, keep.ID); string(got) != "keep" {
		t.Fatal("referenced blob was collected")
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	v, dir := newVault(t)
	secret := "SECRET-CONTENT-7f3a9c"
	name := "SECRET-NAME-b81e.txt"
	folder, _ := v.Mkdir(RootID, "SECRET-FOLDER-4d2c")
	if _, err := v.Put(folder.ID, name, strings.NewReader(strings.Repeat(secret, 1000))); err != nil {
		t.Fatal(err)
	}
	v.Close()
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(p, "SECRET") {
			t.Errorf("plaintext name on disk: %s", p)
		}
		if d.IsDir() {
			return nil
		}
		raw, _ := os.ReadFile(p)
		if bytes.Contains(raw, []byte("SECRET")) {
			t.Errorf("plaintext in %s", p)
		}
		return nil
	})
}

func TestRenameReplaceDelete(t *testing.T) {
	v, dir := newVault(t)
	a, _ := v.Put(RootID, "a.txt", strings.NewReader("one"))
	v.Put(RootID, "b.txt", strings.NewReader("b"))
	if _, err := v.Rename(a.ID, "b.txt"); !errors.Is(err, ErrExists) {
		t.Fatalf("rename onto existing: %v", err)
	}
	if _, err := v.Rename(a.ID, "../x"); !errors.Is(err, ErrBadName) {
		t.Fatalf("rename with slash: %v", err)
	}
	if _, err := v.Rename(a.ID, "c.txt"); err != nil {
		t.Fatal(err)
	}

	// Uploading the same name replaces the content and frees the old blob.
	oldBlob := filepath.Join(dir, filepath.FromSlash(a.Blob))
	c, err := v.Put(RootID, "c.txt", strings.NewReader("two"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != a.ID || string(readAll(t, v, c.ID)) != "two" {
		t.Fatal("replace did not update the existing entry")
	}
	if _, err := os.Stat(oldBlob); err == nil {
		t.Fatal("old blob kept after replace")
	}

	folder, _ := v.Mkdir(RootID, "dir")
	if _, err := v.Put(RootID, "dir", strings.NewReader("x")); !errors.Is(err, ErrIsDir) {
		t.Fatalf("file over folder: %v", err)
	}
	sub, _ := v.MkdirAll(folder.ID, "x/y")
	inner, _ := v.Put(sub, "deep.txt", strings.NewReader("deep"))
	if err := v.Delete(folder.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(inner.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("child survived folder delete")
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(inner.Blob))); err == nil {
		t.Fatal("blob survived folder delete")
	}
	v = reopen(t, v, dir)
	if list, _ := v.List(RootID); len(list) != 2 {
		t.Fatalf("after reopen: %v", list)
	}
}

func TestClosedVaultRefusesWork(t *testing.T) {
	v, _ := newVault(t)
	v.Close()
	if _, err := v.List(RootID); !errors.Is(err, ErrClosed) {
		t.Fatalf("List after Close: %v", err)
	}
	if _, err := v.Put(RootID, "x", strings.NewReader("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Put after Close: %v", err)
	}
}

// TestStandardAgeCLI follows the recovery steps from the README with the
// official age tools, to prove the data is readable without this program.
func TestStandardAgeCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the age CLI")
	}
	ver, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", "filippo.io/age").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	ageVersion := strings.TrimSpace(string(ver))
	bin := t.TempDir()
	// go install with @version builds against age's own go.mod, so the CLI's
	// extra dependencies stay out of this module.
	build := exec.Command("go", "install", "filippo.io/age/cmd/age@"+ageVersion, "filippo.io/age/cmd/age-plugin-batchpass@"+ageVersion)
	build.Env = append(os.Environ(), "GOBIN="+bin)
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build age CLI: %v\n%s", err, out)
	}
	age := filepath.Join(bin, "age")

	v, dir := newVault(t)
	content := randomBytes(t, 100*1024)
	e, err := v.Put(RootID, "file.bin", bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	run := func(args ...string) []byte {
		cmd := exec.Command(age, args...)
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "AGE_PASSPHRASE="+password)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("age %v: %v\n%s", args, err, stderr.String())
		}
		return out
	}
	// The interactive `age -d -i key.age` asks for the password on the
	// terminal; the batchpass plugin is the same scrypt decryption, scripted.
	key := run("-d", "-j", "batchpass", filepath.Join(dir, keyFile))
	keyPath := filepath.Join(t.TempDir(), "key.txt")
	os.WriteFile(keyPath, key, 0o600)

	index := run("-d", "-i", keyPath, filepath.Join(dir, indexFile))
	if !bytes.Contains(index, []byte(`"name": "file.bin"`)) || !bytes.Contains(index, []byte(e.Blob)) {
		t.Fatalf("index does not list the file:\n%s", index)
	}
	got := run("-d", "-i", keyPath, filepath.Join(dir, filepath.FromSlash(e.Blob)))
	if !bytes.Equal(got, content) {
		t.Fatal("age CLI decrypted different content")
	}
}
