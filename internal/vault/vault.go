// Package vault stores files encrypted with age on a removable drive.
//
// On-disk layout (everything is a standard age file):
//
//	key.age             X25519 identity, encrypted with the password (scrypt)
//	index.age           JSON index: names, folders, sizes, blob paths
//	index.age.bak       previous index, used if index.age is missing or damaged
//	blobs/ab/<id>.age   one file per stored file, encrypted to the identity
//
// The password only unlocks key.age, so scrypt runs once per unlock instead of
// once per file, and random access into big files (video seeking) stays cheap.
// The age CLI reads passphrase-encrypted identity files natively, so
// `age -d -i key.age blobs/…/x.age` works without this program.
package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"filippo.io/age"
)

const (
	keyFile   = "key.age"
	indexFile = "index.age"
	indexBak  = "index.age.bak"
	blobsDir  = "blobs"

	// RootID is the ID of the top-level folder.
	RootID = ""
)

var (
	ErrWrongPassword = errors.New("неверный пароль")
	ErrNoVault       = errors.New("сейф не найден")
	ErrVaultExists   = errors.New("сейф уже существует")
	ErrClosed        = errors.New("сейф закрыт")
	ErrNotFound      = errors.New("не найдено")
	ErrNotDir        = errors.New("это не папка")
	ErrIsDir         = errors.New("это папка")
	ErrExists        = errors.New("с таким именем уже есть элемент")
	ErrBadName       = errors.New("недопустимое имя")
)

// Entry is a file or folder in the index.
type Entry struct {
	ID       string    `json:"id"`
	Parent   string    `json:"parent"`
	Name     string    `json:"name"`
	Dir      bool      `json:"dir,omitempty"`
	Size     int64     `json:"size,omitempty"`
	Modified time.Time `json:"modified"`
	// Blob is the encrypted content, relative to the vault folder, with
	// forward slashes: "blobs/ab/ab12….age".
	Blob string `json:"blob,omitempty"`
}

type index struct {
	Version int               `json:"version"`
	Entries map[string]*Entry `json:"entries"`
}

// Vault is an unlocked vault. All methods are safe for concurrent use.
type Vault struct {
	dir string

	mu       sync.RWMutex
	identity *age.X25519Identity
	idx      *index
	// dirty means idx has deferred changes that are not on disk yet.
	dirty bool
	// doomed are blobs that deferred puts replaced. They are removed only
	// once an index that no longer names them is on disk.
	doomed []string
}

// Exists reports whether dir already holds a vault.
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, keyFile))
	return err == nil
}

// Create makes a new empty vault in dir, protected by password.
func Create(dir, password string) (*Vault, error) {
	if Exists(dir) {
		return nil, ErrVaultExists
	}
	if err := os.MkdirAll(filepath.Join(dir, blobsDir), 0o700); err != nil {
		return nil, err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, err
	}
	err = writeAtomic(filepath.Join(dir, keyFile), func(w io.Writer) error {
		ew, err := age.Encrypt(w, recipient)
		if err != nil {
			return err
		}
		fmt.Fprintf(ew, "# sd-vault key, created %s\n", time.Now().UTC().Format(time.RFC3339))
		fmt.Fprintf(ew, "# public key: %s\n", identity.Recipient())
		fmt.Fprintf(ew, "%s\n", identity)
		return ew.Close()
	})
	if err != nil {
		return nil, err
	}
	v := &Vault{dir: dir, identity: identity, idx: &index{Version: 1, Entries: map[string]*Entry{}}}
	if err := v.saveIndex(); err != nil {
		return nil, err
	}
	return v, nil
}

// Open unlocks the vault in dir. A wrong password returns ErrWrongPassword.
func Open(dir, password string) (*Vault, error) {
	data, err := os.ReadFile(filepath.Join(dir, keyFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoVault
	}
	if err != nil {
		return nil, err
	}
	scrypt, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(data), scrypt)
	var noMatch *age.NoIdentityMatchError
	if errors.As(err, &noMatch) {
		return nil, ErrWrongPassword
	}
	if err != nil {
		return nil, fmt.Errorf("ключ сейфа повреждён: %w", err)
	}
	ids, err := age.ParseIdentities(r)
	if err != nil {
		return nil, fmt.Errorf("ключ сейфа повреждён: %w", err)
	}
	identity, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("ключ сейфа неизвестного типа")
	}

	v := &Vault{dir: dir, identity: identity}
	idx, primaryErr := v.loadIndex(indexFile)
	if primaryErr == nil {
		v.idx = idx
		v.collectGarbage()
		return v, nil
	}
	idx, bakErr := v.loadIndex(indexBak)
	if bakErr != nil {
		return nil, fmt.Errorf("индекс сейфа не читается: %v; резервная копия: %v", primaryErr, bakErr)
	}
	// The primary index is damaged; restore it from the backup. Remove it
	// first so saveIndex does not rotate the damaged copy over the good one.
	// No garbage collection here: blobs the lost index referenced stay on
	// disk and can still be recovered by hand.
	v.idx = idx
	os.Remove(filepath.Join(dir, indexFile))
	if err := v.saveIndex(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Vault) loadIndex(name string) (*index, error) {
	f, err := os.Open(filepath.Join(v.dir, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, v.identity)
	if err != nil {
		return nil, err
	}
	idx := &index{}
	if err := json.NewDecoder(r).Decode(idx); err != nil {
		return nil, err
	}
	if idx.Entries == nil {
		idx.Entries = map[string]*Entry{}
	}
	return idx, nil
}

// saveIndex must be called with mu held for writing (or before v is shared).
func (v *Vault) saveIndex() error {
	data, err := json.Marshal(v.idx)
	if err != nil {
		return err
	}
	return writeAtomicKeepingBackup(filepath.Join(v.dir, indexFile), filepath.Join(v.dir, indexBak), func(w io.Writer) error {
		ew, err := age.Encrypt(w, v.identity.Recipient())
		if err != nil {
			return err
		}
		if _, err := ew.Write(data); err != nil {
			return err
		}
		return ew.Close()
	})
}

// commit makes the index change durable, or, when deferred, only marks it
// for the next Flush. mu must be held for writing.
func (v *Vault) commit(deferred bool) error {
	if deferred {
		v.dirty = true
		return nil
	}
	if err := v.saveIndex(); err != nil {
		return err
	}
	v.dirty = false
	for _, b := range v.doomed {
		os.Remove(filepath.Join(v.dir, filepath.FromSlash(b)))
	}
	v.doomed = nil
	return nil
}

// Flush writes the index if deferred changes are pending.
func (v *Vault) Flush() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(); err != nil {
		return err
	}
	if !v.dirty {
		return nil
	}
	return v.commit(false)
}

// collectGarbage removes what an interrupted operation left behind:
// temporary files and blobs that no index entry points to.
func (v *Vault) collectGarbage() {
	used := map[string]bool{}
	for _, e := range v.idx.Entries {
		if e.Blob != "" {
			used[e.Blob] = true
		}
	}
	root, _ := os.ReadDir(v.dir)
	for _, de := range root {
		if !de.IsDir() && isTmpName(de.Name()) {
			os.Remove(filepath.Join(v.dir, de.Name()))
		}
	}
	filepath.WalkDir(filepath.Join(v.dir, blobsDir), func(p string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(v.dir, p)
		if err != nil {
			return nil
		}
		if isTmpName(de.Name()) || (strings.HasSuffix(de.Name(), ".age") && !used[filepath.ToSlash(rel)]) {
			os.Remove(p)
		}
		return nil
	})
}

// Close writes pending deferred changes and forgets the key and the index.
// A failed write is not reported here: call Flush first to see it.
func (v *Vault) Close() {
	v.mu.Lock()
	if v.idx != nil && v.dirty {
		v.commit(false)
	}
	v.identity = nil
	v.idx = nil
	v.mu.Unlock()
	runtime.GC()
}

func (v *Vault) check() error {
	if v.idx == nil {
		return ErrClosed
	}
	return nil
}

// Get returns a copy of an entry. RootID returns a synthetic root folder.
func (v *Vault) Get(id string) (Entry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.check(); err != nil {
		return Entry{}, err
	}
	e, err := v.get(id)
	if err != nil {
		return Entry{}, err
	}
	return *e, nil
}

func (v *Vault) get(id string) (*Entry, error) {
	if id == RootID {
		return &Entry{ID: RootID, Dir: true}, nil
	}
	e, ok := v.idx.Entries[id]
	if !ok {
		return nil, ErrNotFound
	}
	return e, nil
}

func (v *Vault) getDir(id string) (*Entry, error) {
	e, err := v.get(id)
	if err != nil {
		return nil, err
	}
	if !e.Dir {
		return nil, ErrNotDir
	}
	return e, nil
}

// List returns the children of a folder: folders first, then by name.
func (v *Vault) List(dirID string) ([]Entry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.check(); err != nil {
		return nil, err
	}
	if _, err := v.getDir(dirID); err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range v.idx.Entries {
		if e.Parent == dirID {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Path returns the folders from the root down to id, excluding the root.
func (v *Vault) Path(id string) ([]Entry, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.check(); err != nil {
		return nil, err
	}
	var out []Entry
	for id != RootID {
		e, err := v.get(id)
		if err != nil {
			return nil, err
		}
		out = append([]Entry{*e}, out...)
		id = e.Parent
	}
	return out, nil
}

func (v *Vault) child(dirID, name string) *Entry {
	for _, e := range v.idx.Entries {
		if e.Parent == dirID && e.Name == name {
			return e
		}
	}
	return nil
}

func validName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 255 ||
		!utf8.ValidString(name) || strings.ContainsAny(name, "/\\\x00") {
		return ErrBadName
	}
	return nil
}

func (v *Vault) newID() string {
	for {
		id := randomHex(8)
		if _, taken := v.idx.Entries[id]; !taken {
			return id
		}
	}
}

// Mkdir creates a folder, or returns the existing folder with that name.
func (v *Vault) Mkdir(parentID, name string) (Entry, error) {
	return v.mkdir(parentID, name, false)
}

func (v *Vault) mkdir(parentID, name string, deferred bool) (Entry, error) {
	if err := validName(name); err != nil {
		return Entry{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(); err != nil {
		return Entry{}, err
	}
	if _, err := v.getDir(parentID); err != nil {
		return Entry{}, err
	}
	if existing := v.child(parentID, name); existing != nil {
		if existing.Dir {
			return *existing, nil
		}
		return Entry{}, ErrExists
	}
	e := &Entry{ID: v.newID(), Parent: parentID, Name: name, Dir: true, Modified: time.Now().UTC()}
	v.idx.Entries[e.ID] = e
	if err := v.commit(deferred); err != nil {
		delete(v.idx.Entries, e.ID)
		return Entry{}, err
	}
	return *e, nil
}

// MkdirAll creates every folder of a slash-separated relative path under
// parentID and returns the ID of the deepest one.
func (v *Vault) MkdirAll(parentID, rel string) (string, error) {
	return v.mkdirAll(parentID, rel, false)
}

// MkdirAllDeferred is MkdirAll that leaves the index for Flush.
func (v *Vault) MkdirAllDeferred(parentID, rel string) (string, error) {
	return v.mkdirAll(parentID, rel, true)
}

func (v *Vault) mkdirAll(parentID, rel string, deferred bool) (string, error) {
	for _, name := range strings.Split(rel, "/") {
		if name == "" {
			continue
		}
		e, err := v.mkdir(parentID, name, deferred)
		if err != nil {
			return "", err
		}
		parentID = e.ID
	}
	return parentID, nil
}

// Put stores the content of r as file name in folder parentID. An existing
// file with that name is replaced. The content is encrypted on the fly and
// never touches the disk in plain text.
func (v *Vault) Put(parentID, name string, r io.Reader) (Entry, error) {
	return v.put(parentID, name, r, false)
}

// PutDeferred is Put that changes the index only in memory: the file is
// listed and readable at once, but survives a pulled card only after Flush
// (or any other mutation, which saves the whole index). Uploading a folder
// this way writes the index once instead of once per file, and on a slow
// card each write is a full copy of the index plus several fsyncs.
func (v *Vault) PutDeferred(parentID, name string, r io.Reader) (Entry, error) {
	return v.put(parentID, name, r, true)
}

func (v *Vault) put(parentID, name string, r io.Reader, deferred bool) (Entry, error) {
	if err := validName(name); err != nil {
		return Entry{}, err
	}
	v.mu.RLock()
	err := v.check()
	var recipient age.Recipient
	if err == nil {
		recipient = v.identity.Recipient()
		_, err = v.getDir(parentID)
	}
	if err == nil {
		if e := v.child(parentID, name); e != nil && e.Dir {
			err = ErrIsDir
		}
	}
	v.mu.RUnlock()
	if err != nil {
		return Entry{}, err
	}

	blobID := randomHex(16)
	blob := path.Join(blobsDir, blobID[:2], blobID+".age")
	full := filepath.Join(v.dir, filepath.FromSlash(blob))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return Entry{}, err
	}
	var size int64
	err = writeAtomic(full, func(w io.Writer) error {
		ew, err := age.Encrypt(w, recipient)
		if err != nil {
			return err
		}
		if size, err = io.Copy(ew, r); err != nil {
			return err
		}
		return ew.Close()
	})
	if err != nil {
		return Entry{}, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	fail := func(err error) (Entry, error) {
		os.Remove(full)
		return Entry{}, err
	}
	if err := v.check(); err != nil {
		return fail(err)
	}
	if _, err := v.getDir(parentID); err != nil {
		return fail(err)
	}
	e := &Entry{Parent: parentID, Name: name, Size: size, Modified: time.Now().UTC(), Blob: blob}
	old := v.child(parentID, name)
	if old != nil && old.Dir {
		return fail(ErrIsDir)
	}
	if old != nil {
		e.ID = old.ID
		prev := *old
		*old = *e
		// The old blob goes only after the index stops naming it.
		v.doomed = append(v.doomed, prev.Blob)
		if err := v.commit(deferred); err != nil {
			v.doomed = v.doomed[:len(v.doomed)-1]
			*old = prev
			return fail(err)
		}
		return *old, nil
	}
	e.ID = v.newID()
	v.idx.Entries[e.ID] = e
	if err := v.commit(deferred); err != nil {
		delete(v.idx.Entries, e.ID)
		return fail(err)
	}
	return *e, nil
}

// Rename gives an entry a new name within the same folder.
func (v *Vault) Rename(id, name string) (Entry, error) {
	if err := validName(name); err != nil {
		return Entry{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(); err != nil {
		return Entry{}, err
	}
	if id == RootID {
		return Entry{}, ErrBadName
	}
	e, err := v.get(id)
	if err != nil {
		return Entry{}, err
	}
	if other := v.child(e.Parent, name); other != nil && other.ID != id {
		return Entry{}, ErrExists
	}
	prev := e.Name
	e.Name = name
	if err := v.commit(false); err != nil {
		e.Name = prev
		return Entry{}, err
	}
	return *e, nil
}

// Delete removes an entry; folders are removed with everything inside.
func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(); err != nil {
		return err
	}
	if id == RootID {
		return ErrBadName
	}
	if _, err := v.get(id); err != nil {
		return err
	}
	doomed := map[string]*Entry{}
	var walk func(string)
	walk = func(id string) {
		doomed[id] = v.idx.Entries[id]
		for cid, c := range v.idx.Entries {
			if c.Parent == id {
				walk(cid)
			}
		}
	}
	walk(id)
	for did := range doomed {
		delete(v.idx.Entries, did)
	}
	if err := v.commit(false); err != nil {
		for did, e := range doomed {
			v.idx.Entries[did] = e
		}
		return err
	}
	// Blobs go only after the index no longer points at them. If the card is
	// pulled in between, the next unlock collects them as garbage.
	for _, e := range doomed {
		if e.Blob != "" {
			os.Remove(filepath.Join(v.dir, filepath.FromSlash(e.Blob)))
		}
	}
	return nil
}

// File is decrypted content with random access. Close it when done.
type File struct {
	*io.SectionReader
	f *os.File
}

func (f *File) Close() error { return f.f.Close() }

// Open decrypts a stored file for reading. Chunks are decrypted on demand,
// so seeking into a large video does not decrypt what comes before it.
// Damaged content fails authentication: either here or on Read.
func (v *Vault) Open(id string) (*File, Entry, error) {
	v.mu.RLock()
	err := v.check()
	var e *Entry
	var identity age.Identity
	if err == nil {
		e, err = v.get(id)
		identity = v.identity
	}
	var entry Entry
	if err == nil {
		entry = *e
		if entry.Dir {
			err = ErrIsDir
		}
	}
	v.mu.RUnlock()
	if err != nil {
		return nil, Entry{}, err
	}

	f, err := os.Open(filepath.Join(v.dir, filepath.FromSlash(entry.Blob)))
	if err != nil {
		return nil, Entry{}, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, Entry{}, err
	}
	ra, size, err := age.DecryptReaderAt(f, st.Size(), identity)
	if err != nil {
		f.Close()
		return nil, Entry{}, fmt.Errorf("файл повреждён: %w", err)
	}
	return &File{SectionReader: io.NewSectionReader(ra, 0, size), f: f}, entry, nil
}

// Problem is a stored file that cannot be read back intact.
type Problem struct {
	ID     string `json:"id"`
	Parent string `json:"parent"`
	Path   string `json:"path"` // "Фото/2024/clip.mp4"
	Err    string `json:"error"`
}

// Progress of Verify.
type Progress struct {
	Files      int   `json:"files"` // checked so far
	TotalFiles int   `json:"totalFiles"`
	Bytes      int64 `json:"bytes"`
	TotalBytes int64 `json:"totalBytes"`
}

// Verify decrypts every stored file to the end, so each chunk is
// authenticated, and reports the files that fail. progress, if set, is
// called as data is read. Only a closed vault stops it early; damaged files
// are what it is for.
func (v *Vault) Verify(progress func(Progress)) (problems []Problem, done Progress, err error) {
	type item struct {
		e    Entry
		path string
	}
	v.mu.RLock()
	if err := v.check(); err != nil {
		v.mu.RUnlock()
		return nil, done, err
	}
	identity := v.identity
	var items []item
	for _, e := range v.idx.Entries {
		if e.Dir {
			continue
		}
		names := []string{e.Name}
		for p := e.Parent; p != RootID; {
			pe, ok := v.idx.Entries[p]
			if !ok {
				break
			}
			names = append([]string{pe.Name}, names...)
			p = pe.Parent
		}
		items = append(items, item{*e, strings.Join(names, "/")})
		done.TotalBytes += e.Size
	}
	done.TotalFiles = len(items)
	v.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].path < items[j].path })

	report := func(n int64) {
		done.Bytes += n
		if progress != nil {
			progress(done)
		}
	}
	report(0)
	for _, it := range items {
		if v.closed() {
			return problems, done, ErrClosed
		}
		n, err := verifyBlob(filepath.Join(v.dir, filepath.FromSlash(it.e.Blob)), identity, report)
		if err == nil && n != it.e.Size {
			err = errors.New("size differs from the index")
		}
		if err != nil {
			problems = append(problems, Problem{ID: it.e.ID, Parent: it.e.Parent, Path: it.path, Err: describe(err)})
		}
		done.Files++
		report(it.e.Size - n) // keep the byte count in step with the total
	}
	return problems, done, nil
}

func (v *Vault) closed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.idx == nil
}

func verifyBlob(path string, identity age.Identity, report func(int64)) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r, err := age.Decrypt(f, identity)
	if err != nil {
		return 0, err
	}
	return io.CopyBuffer(countWriter(report), r, make([]byte, 1<<20))
}

type countWriter func(int64)

func (c countWriter) Write(p []byte) (int, error) {
	c(int64(len(p)))
	return len(p), nil
}

// describe says what is wrong in the user's words. The cause from age is
// always the same for them: the bytes on the card are not what was written.
func describe(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "зашифрованный файл пропал с карты"
	}
	return "содержимое повреждено"
}
