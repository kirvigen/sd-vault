package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
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

func TestDeferredPut(t *testing.T) {
	v, dir := newVault(t)
	blobs := filepath.Join(dir, blobsDir)
	old, err := v.Put(RootID, "a.txt", strings.NewReader("old"))
	if err != nil {
		t.Fatal(err)
	}
	folder, err := v.MkdirAllDeferred(RootID, "Фото/2024")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutDeferred(folder, "b.txt", strings.NewReader("b")); err != nil {
		t.Fatal(err)
	}
	a, err := v.PutDeferred(RootID, "a.txt", strings.NewReader("new"))
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, v, a.ID); string(got) != "new" {
		t.Fatalf("deferred content: %q", got)
	}
	// The replaced blob must outlive the on-disk index that still names it.
	if _, err := os.Stat(filepath.Join(dir, old.Blob)); err != nil {
		t.Fatalf("replaced blob removed before flush: %v", err)
	}

	// A pulled card: a fresh unlock sees the state before the batch.
	crashed, err := Open(dir, password)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, crashed, findByName(t, crashed, RootID, "a.txt").ID); string(got) != "old" {
		t.Fatalf("after crash: %q, want the old content", got)
	}
	if list, _ := crashed.List(RootID); len(list) != 1 {
		t.Fatalf("after crash: %d root entries, want 1", len(list))
	}
	if n := countFiles(t, blobs); n != 1 {
		t.Fatalf("after crash: %d blobs, want 1 (unflushed ones are garbage)", n)
	}
	crashed.Close()
}

func TestFlushAndCloseWriteDeferred(t *testing.T) {
	v, dir := newVault(t)
	old, _ := v.Put(RootID, "a.txt", strings.NewReader("old"))
	if _, err := v.PutDeferred(RootID, "a.txt", strings.NewReader("new")); err != nil {
		t.Fatal(err)
	}
	if err := v.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, old.Blob)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("replaced blob kept after flush: %v", err)
	}
	if _, err := v.PutDeferred(RootID, "b.txt", strings.NewReader("b")); err != nil {
		t.Fatal(err)
	}
	v = reopen(t, v, dir) // Close writes what is pending
	if got := readAll(t, v, findByName(t, v, RootID, "a.txt").ID); string(got) != "new" {
		t.Fatalf("a.txt: %q", got)
	}
	findByName(t, v, RootID, "b.txt")
	// Each flush sealed a pack of its own; the replaced blob is gone.
	if b, p := countFiles(t, filepath.Join(dir, blobsDir)), countFiles(t, filepath.Join(dir, packsDir)); b != 0 || p != 2 {
		t.Fatalf("%d blobs and %d packs, want 0 and 2", b, p)
	}
}

func TestVerify(t *testing.T) {
	v, dir := newVault(t)
	folder, _ := v.MkdirAll(RootID, "Фото/2024")
	good, _ := v.Put(folder, "good.jpg", bytes.NewReader(randomBytes(t, 200_000)))
	flipped, _ := v.Put(folder, "flipped.jpg", bytes.NewReader(randomBytes(t, 200_000)))
	gone, _ := v.Put(RootID, "gone.txt", strings.NewReader("gone"))

	// One byte in the middle of the second chunk, as a bad card would do.
	p := filepath.Join(dir, flipped.Blob)
	data, _ := os.ReadFile(p)
	data[len(data)-50_000] ^= 1
	os.WriteFile(p, data, 0o600)
	os.Remove(filepath.Join(dir, gone.Blob))

	var first, last Progress
	problems, done, err := v.Verify(func(p Progress) {
		if first.TotalFiles == 0 {
			first = p
		}
		last = p
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Progress{Files: 3, TotalFiles: 3, Bytes: 400_004, TotalBytes: 400_004}
	if done != want || last != want {
		t.Fatalf("done %+v, last progress %+v", done, last)
	}
	if first != (Progress{TotalFiles: 3, TotalBytes: 400_004}) {
		t.Fatalf("first progress %+v: totals must be known from the start", first)
	}
	got := map[string]Problem{}
	for _, pr := range problems {
		got[pr.Path] = pr
	}
	if len(problems) != 2 || got["Фото/2024/flipped.jpg"].ID != flipped.ID || got["gone.txt"].ID != gone.ID {
		t.Fatalf("problems: %+v", problems)
	}
	if !strings.Contains(got["gone.txt"].Err, "пропал") || !strings.Contains(got["Фото/2024/flipped.jpg"].Err, "поврежд") {
		t.Fatalf("messages: %+v", problems)
	}
	if _, ok := got["Фото/2024/good.jpg"]; ok || good.ID == "" {
		t.Fatal("intact file reported")
	}

	v.Close()
	if _, _, err := v.Verify(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Verify after Close: %v", err)
	}
}

func readRange(t *testing.T, v *Vault, id string, off, n int64) []byte {
	t.Helper()
	f, _, err := v.Open(id)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPacks(t *testing.T) {
	v, dir := newVault(t)
	want := map[string][]byte{}
	ids := map[string]string{}
	put := func(folder, name string, data []byte) {
		t.Helper()
		parent, err := v.MkdirAllDeferred(RootID, folder)
		if err != nil {
			t.Fatal(err)
		}
		e, err := v.PutDeferred(parent, name, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		want[folder+"/"+name], ids[folder+"/"+name] = data, e.ID
	}
	for i := 0; i < 300; i++ {
		put(fmt.Sprintf("Заметки/%d", i%7), fmt.Sprintf("n%03d.txt", i), randomBytes(t, 1+i*37))
	}
	put("Видео", "big.mp4", randomBytes(t, packFileMax+1)) // one byte over: a blob
	put("Видео", "edge.bin", randomBytes(t, packFileMax))  // exactly the limit: packed

	// Before the flush the small files live only in memory and still read.
	if n := countFiles(t, filepath.Join(dir, packsDir)); n != 0 {
		t.Fatalf("%d packs written before flush", n)
	}
	if got := readAll(t, v, ids["Заметки/5/n005.txt"]); !bytes.Equal(got, want["Заметки/5/n005.txt"]) {
		t.Fatal("in-memory member reads wrong")
	}
	if err := v.Flush(); err != nil {
		t.Fatal(err)
	}
	if b, p := countFiles(t, filepath.Join(dir, blobsDir)), countFiles(t, filepath.Join(dir, packsDir)); b != 1 || p != 1 {
		t.Fatalf("%d blobs and %d packs, want 1 and 1", b, p)
	}

	v = reopen(t, v, dir)
	for path, data := range want {
		if got := readAll(t, v, ids[path]); !bytes.Equal(got, data) {
			t.Fatalf("%s reads wrong after reopen", path)
		}
	}
	// Random access into a packed file, across a 64 KiB chunk boundary.
	edge := want["Видео/edge.bin"]
	if got := readRange(t, v, ids["Видео/edge.bin"], 65_000, 2_000); !bytes.Equal(got, edge[65_000:67_000]) {
		t.Fatal("ranged read of a packed file is wrong")
	}

	// Deleting some members keeps the pack; deleting the rest removes it.
	notes := findByName(t, v, RootID, "Заметки")
	if err := v.Delete(notes.ID); err != nil {
		t.Fatal(err)
	}
	if n := countFiles(t, filepath.Join(dir, packsDir)); n != 1 {
		t.Fatalf("%d packs after deleting some members, want 1", n)
	}
	if got := readAll(t, v, ids["Видео/edge.bin"]); !bytes.Equal(got, edge) {
		t.Fatal("surviving member reads wrong")
	}
	if err := v.Delete(ids["Видео/edge.bin"]); err != nil {
		t.Fatal(err)
	}
	if n := countFiles(t, filepath.Join(dir, packsDir)); n != 0 {
		t.Fatalf("%d packs after deleting every member, want 0", n)
	}
}

func TestPackSplitsAndReplace(t *testing.T) {
	v, dir := newVault(t)
	data := map[string][]byte{}
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("f%02d", i)
		data[name] = randomBytes(t, 900_000)
		if _, err := v.PutDeferred(RootID, name, bytes.NewReader(data[name])); err != nil {
			t.Fatal(err)
		}
	}
	// A pack is sealed once it reaches 8 MiB: 10 members of 900 KB each.
	if n := countFiles(t, filepath.Join(dir, packsDir)); n != 2 {
		t.Fatalf("%d packs sealed during the batch, want 2", n)
	}
	// Replacing every member of the first pack empties it.
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("f%02d", i)
		data[name] = []byte("replaced " + name)
		if _, err := v.PutDeferred(RootID, name, bytes.NewReader(data[name])); err != nil {
			t.Fatal(err)
		}
	}
	v = reopen(t, v, dir)
	if n := countFiles(t, filepath.Join(dir, packsDir)); n != 2 {
		t.Fatalf("%d packs, want 2: the emptied one removed, a new one for the replacements", n)
	}
	for name, want := range data {
		if got := readAll(t, v, findByName(t, v, RootID, name).ID); !bytes.Equal(got, want) {
			t.Fatalf("%s reads wrong", name)
		}
	}
}

func TestUnflushedPackIsLostCleanly(t *testing.T) {
	v, dir := newVault(t)
	v.Put(RootID, "kept.txt", strings.NewReader("kept"))
	for i := 0; i < 10; i++ {
		v.PutDeferred(RootID, fmt.Sprintf("lost%d", i), strings.NewReader("lost"))
	}
	v.PutDeferred(RootID, "big.bin", bytes.NewReader(randomBytes(t, packFileMax+10)))
	// A pulled card: what a fresh unlock sees.
	crashed, err := Open(dir, password)
	if err != nil {
		t.Fatal(err)
	}
	defer crashed.Close()
	if list, _ := crashed.List(RootID); len(list) != 1 {
		t.Fatalf("after crash: %d entries, want 1", len(list))
	}
	if b, p := countFiles(t, filepath.Join(dir, blobsDir)), countFiles(t, filepath.Join(dir, packsDir)); b != 1 || p != 0 {
		t.Fatalf("after crash: %d blobs and %d packs, want 1 and 0", b, p)
	}
}

func TestGarbageCollectionKeepsAppleDouble(t *testing.T) {
	v, dir := newVault(t)
	e, _ := v.Put(RootID, "a.txt", strings.NewReader("a"))
	v.PutDeferred(RootID, "b.txt", strings.NewReader("b"))
	v.Flush()
	sidecars := []string{
		filepath.Join(filepath.Dir(filepath.Join(dir, e.Blob)), "._"+filepath.Base(e.Blob)),
		filepath.Join(dir, packsDir, "._0123.age"),
	}
	for _, p := range sidecars {
		os.WriteFile(p, []byte("attrs"), 0o600)
	}
	orphan := filepath.Join(dir, packsDir, "0123.age")
	os.WriteFile(orphan, []byte("orphan"), 0o600)
	v = reopen(t, v, dir)
	defer v.Close()
	for _, p := range sidecars {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("AppleDouble file removed: %s", p)
		}
	}
	if _, err := os.Stat(orphan); err == nil {
		t.Error("orphan pack kept")
	}
}

func TestVerifyPackFindsDamagedMembers(t *testing.T) {
	v, dir := newVault(t)
	const n, size = 40, 10_000
	var ids []string
	for i := 0; i < n; i++ {
		e, err := v.PutDeferred(RootID, fmt.Sprintf("f%02d", i), bytes.NewReader(randomBytes(t, size)))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	v.Flush()
	packs, _ := filepath.Glob(filepath.Join(dir, packsDir, "*.age"))
	if len(packs) != 1 {
		t.Fatalf("%d packs", len(packs))
	}
	// Ciphertext: header, 16-byte nonce, then 64 KiB chunks with 16-byte tags.
	data, _ := os.ReadFile(packs[0])
	const chunk = 64 << 10
	plain := n * size
	chunks := (plain + chunk - 1) / chunk
	header := len(data) - plain - 16 - chunks*16
	const bad = 3
	data[header+16+bad*(chunk+16)+100] ^= 1
	os.WriteFile(packs[0], data, 0o600)

	problems, done, err := v.Verify(nil)
	if err != nil {
		t.Fatal(err)
	}
	if done.Files != n || done.Bytes != n*size {
		t.Fatalf("progress %+v", done)
	}
	got := map[string]bool{}
	for _, p := range problems {
		got[p.ID] = true
	}
	for i, id := range ids {
		start, end := i*size, (i+1)*size
		hit := start < (bad+1)*chunk && end > bad*chunk
		if got[id] != hit {
			t.Errorf("f%02d [%d, %d): reported %v, want %v", i, start, end, got[id], hit)
		}
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
	v.PutDeferred(RootID, "before.txt", strings.NewReader("first member"))
	small := randomBytes(t, 3000)
	packed, err := v.PutDeferred(RootID, "small.bin", bytes.NewReader(small))
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
	if !bytes.Contains(index, []byte(`"name":"file.bin"`)) || !bytes.Contains(index, []byte(e.Blob)) {
		t.Fatalf("index does not list the file:\n%s", index)
	}
	got := run("-d", "-i", keyPath, filepath.Join(dir, filepath.FromSlash(e.Blob)))
	if !bytes.Equal(got, content) {
		t.Fatal("age CLI decrypted different content")
	}
	// A packed file is the slice [offset, offset+size) of the decrypted
	// pack, as the card README tells to cut it.
	if packed.Pack == "" || packed.Offset == 0 {
		t.Fatalf("small file not packed after another member: %+v", packed)
	}
	pack := run("-d", "-i", keyPath, filepath.Join(dir, filepath.FromSlash(packed.Pack)))
	if got := pack[packed.Offset : packed.Offset+packed.Size]; !bytes.Equal(got, small) {
		t.Fatal("slice of the CLI-decrypted pack differs")
	}
}

func TestEncryptedSizeBoundsAge(t *testing.T) {
	v, _ := newVault(t)
	for _, n := range []int64{0, 1, ageChunk - 1, ageChunk, ageChunk + 1, 3*ageChunk + 5, packMax} {
		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, v.identity.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		w.Write(make([]byte, n))
		w.Close()
		got, est := int64(buf.Len()), encryptedSize(n)
		if est < got || est-got > 128 {
			t.Errorf("%d bytes: age wrote %d, estimated %d", n, got, est)
		}
	}
}

func TestRoom(t *testing.T) {
	v, _ := newVault(t)
	const cluster = 32 << 10
	v.DiskUsage = func(string) (int64, int64, error) { return 50 << 20, cluster, nil }

	empty, err := v.Room(nil)
	if err != nil || !empty.Fits() || empty.Err() != nil {
		t.Fatalf("empty batch: %+v, %v", empty, err)
	}
	big, _ := v.Room([]int64{40 << 20})
	if !big.Fits() || big.Need < empty.Need+40<<20 {
		t.Errorf("40 MB of 50: %+v", big)
	}
	tooBig, _ := v.Room([]int64{30 << 20, 30 << 20})
	if tooBig.Fits() || !errors.Is(tooBig.Err(), ErrNoSpace) {
		t.Errorf("60 MB of 50: %+v, %v", tooBig, tooBig.Err())
	}

	// Small files share packs, so they do not cost a cluster each.
	small := make([]int64, 1000)
	for i := range small {
		small[i] = 1 << 10
	}
	packed, _ := v.Room(small)
	if extra := packed.Need - empty.Need - 1000<<10; extra > 1000*indexEntry+4*cluster {
		t.Errorf("1000 small files: %d bytes over their size", extra)
	}

	// What a batch holds in memory still has to reach the card.
	if _, err := v.PutDeferred(RootID, "a", bytes.NewReader(make([]byte, 500<<10))); err != nil {
		t.Fatal(err)
	}
	pending, _ := v.Room(nil)
	if pending.Need < empty.Need+500<<10 {
		t.Errorf("open pack not counted: %d, was %d", pending.Need, empty.Need)
	}
}
