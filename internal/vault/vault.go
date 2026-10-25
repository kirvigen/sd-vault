// Package vault stores files encrypted with age on a removable drive.
//
// On-disk layout (everything is a standard age file):
//
//	key.age             X25519 identity, encrypted with the password (scrypt)
//	index.age           JSON index: names, folders, sizes, blob paths
//	index.age.bak       previous index, used if index.age is missing or damaged
//	blobs/ab/<id>.age   one file per stored file, encrypted to the identity
//	packs/<id>.age      many small files back to back, encrypted to the identity
//
// A card spends far more time on creating a file (FAT entries, an fsync,
// and on macOS an AppleDouble "._" companion for the provenance attribute)
// than on its bytes. So small files of a batch upload are gathered in memory
// and written as one pack; the index keeps each file's offset in the pack's
// plaintext, and age's 64 KiB chunks still give random access into it.
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
	packsDir  = "packs"

	// packFileMax is the largest file a deferred put packs; bigger ones
	// get a blob of their own. packMax is the plaintext size at which the
	// open pack is written out. Both bound the memory a batch holds.
	packFileMax = 1 << 20
	packMax     = 8 << 20

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
	// Pack, when set instead of Blob, is the pack holding the content at
	// Offset of its plaintext: "packs/cd34….age".
	Pack   string `json:"pack,omitempty"`
	Offset int64  `json:"offset,omitempty"`
}

// indexVersion 2 added packs. Older programs ignore the version and cannot
// read packed files, so an update is one way.
const indexVersion = 2

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
	// emptied are packs that lost a member; each is removed at the next
	// commit if no entry uses it any more.
	emptied map[string]bool
	// open is the pack being gathered in memory, nil when there is none.
	open *openPack
	// unsynced are files written without fsync by deferred puts. The next
	// commit syncs them before the index that names them.
	unsynced map[string]bool
}

type openPack struct {
	path string // "packs/<id>.age"
	buf  []byte // plaintext of the members, back to back
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
	v := &Vault{dir: dir, identity: identity, idx: &index{Version: indexVersion, Entries: map[string]*Entry{}}}
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
	v.idx.Version = indexVersion
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
//
// A durable commit writes the open pack, syncs every file deferred puts
// wrote without fsync, and only then saves the index, so the index on disk
// never names content that a pulled card could lose. One fsync per batch
// instead of one per file is most of what makes a batch fast on a card.
func (v *Vault) commit(deferred bool) error {
	if deferred {
		v.dirty = true
		return nil
	}
	if err := v.sealPack(); err != nil {
		return err
	}
	if err := v.syncWritten(); err != nil {
		return err
	}
	if err := v.saveIndex(); err != nil {
		return err
	}
	v.dirty = false
	for _, b := range v.doomed {
		os.Remove(v.abs(b))
	}
	v.doomed = nil
	if len(v.emptied) > 0 {
		used := v.usedPacks()
		for p := range v.emptied {
			if !used[p] {
				os.Remove(v.abs(p))
			}
		}
		v.emptied = nil
	}
	return nil
}

func (v *Vault) abs(rel string) string {
	return filepath.Join(v.dir, filepath.FromSlash(rel))
}

func (v *Vault) usedPacks() map[string]bool {
	used := map[string]bool{}
	for _, e := range v.idx.Entries {
		if e.Pack != "" {
			used[e.Pack] = true
		}
	}
	return used
}

// forget marks the content of an entry that is being replaced or deleted
// for removal after the next durable commit.
func (v *Vault) forget(e Entry) {
	switch {
	case e.Blob != "":
		v.doomed = append(v.doomed, e.Blob)
	case e.Pack != "":
		if v.emptied == nil {
			v.emptied = map[string]bool{}
		}
		v.emptied[e.Pack] = true
	}
}

// sealPack encrypts the open pack to the card. A pack whose members were all
// replaced or deleted meanwhile is dropped instead. mu must be held for
// writing.
func (v *Vault) sealPack() error {
	p := v.open
	if p == nil {
		return nil
	}
	if !v.usedPacks()[p.path] {
		v.open = nil
		return nil
	}
	full := v.abs(p.path)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	err := writeUnsynced(full, func(w io.Writer) error {
		ew, err := age.Encrypt(w, v.identity.Recipient())
		if err != nil {
			return err
		}
		if _, err := ew.Write(p.buf); err != nil {
			return err
		}
		return ew.Close()
	})
	if err != nil {
		return err
	}
	v.markUnsynced(full)
	v.open = nil
	return nil
}

func (v *Vault) markUnsynced(full string) {
	if v.unsynced == nil {
		v.unsynced = map[string]bool{}
	}
	v.unsynced[full] = true
}

// syncWritten makes the files deferred puts wrote, and their renames,
// durable. On macOS each fsync is a full flush of the card's cache, so after
// the first one the rest find nothing to write.
func (v *Vault) syncWritten() error {
	dirs := map[string]bool{}
	for full := range v.unsynced {
		f, err := os.Open(full)
		if err != nil {
			return err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return err
		}
		dirs[filepath.Dir(full)] = true
	}
	for d := range dirs {
		syncDir(d)
	}
	v.unsynced = nil
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
// temporary files, and blobs and packs that no index entry points to.
// AppleDouble files ("._x.age", where macOS keeps attributes on FAT) are not
// ours: macOS removes each one with its file, and deleting them one by one
// once took minutes on a slow card.
func (v *Vault) collectGarbage() {
	used := v.usedPacks()
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
	sweep := func(p string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() || strings.HasPrefix(de.Name(), "._") {
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
	}
	filepath.WalkDir(filepath.Join(v.dir, blobsDir), sweep)
	filepath.WalkDir(filepath.Join(v.dir, packsDir), sweep)
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
	if deferred {
		// Small files go to the open pack. Reading one byte past the limit
		// tells a small file from a big one without knowing the size.
		head := make([]byte, packFileMax+1)
		n, err := io.ReadFull(r, head)
		switch err {
		case io.EOF, io.ErrUnexpectedEOF:
			return v.putPacked(parentID, name, head[:n])
		case nil:
			r = io.MultiReader(bytes.NewReader(head), r)
		default:
			return Entry{}, err
		}
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
	write := writeAtomic
	if deferred {
		write = writeUnsynced
	}
	var size int64
	err = write(full, func(w io.Writer) error {
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
	if err := v.store(e, old, deferred); err != nil {
		return fail(err)
	}
	if deferred {
		v.markUnsynced(full)
	}
	return *e, nil
}

// store adds e to the index, replacing old if set, and commits. On failure
// the index is as before. mu must be held for writing.
func (v *Vault) store(e, old *Entry, deferred bool) error {
	if old != nil {
		e.ID = old.ID
		prev := *old
		*old = *e
		// The old content goes only after the index stops naming it.
		doomed := len(v.doomed)
		v.forget(prev)
		if err := v.commit(deferred); err != nil {
			v.doomed = v.doomed[:doomed]
			*old = prev
			return err
		}
		*e = *old
		return nil
	}
	e.ID = v.newID()
	v.idx.Entries[e.ID] = e
	if err := v.commit(deferred); err != nil {
		delete(v.idx.Entries, e.ID)
		return err
	}
	return nil
}

// putPacked appends a small file to the open pack. Until the pack is sealed
// its members are read from memory, so they are listed and readable at once.
func (v *Vault) putPacked(parentID, name string, data []byte) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.check(); err != nil {
		return Entry{}, err
	}
	if _, err := v.getDir(parentID); err != nil {
		return Entry{}, err
	}
	old := v.child(parentID, name)
	if old != nil && old.Dir {
		return Entry{}, ErrIsDir
	}
	if v.open == nil {
		v.open = &openPack{path: path.Join(packsDir, randomHex(16)+".age")}
	}
	p := v.open
	e := &Entry{Parent: parentID, Name: name, Size: int64(len(data)), Modified: time.Now().UTC(),
		Pack: p.path, Offset: int64(len(p.buf))}
	p.buf = append(p.buf, data...)
	if err := v.store(e, old, true); err != nil {
		return Entry{}, err
	}
	if len(p.buf) >= packMax {
		if err := v.sealPack(); err != nil {
			return Entry{}, err
		}
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
	// Content goes only after the index no longer points at it. If the card
	// is pulled in between, the next unlock collects it as garbage.
	before := len(v.doomed)
	for did, e := range doomed {
		delete(v.idx.Entries, did)
		v.forget(*e)
	}
	if err := v.commit(false); err != nil {
		v.doomed = v.doomed[:before]
		for did, e := range doomed {
			v.idx.Entries[did] = e
		}
		return err
	}
	return nil
}

// File is decrypted content with random access. Close it when done.
type File struct {
	*io.SectionReader
	f *os.File // nil for a member of the pack still in memory
}

func (f *File) Close() error {
	if f.f == nil {
		return nil
	}
	return f.f.Close()
}

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
	var inMemory []byte
	if err == nil {
		entry = *e
		if entry.Dir {
			err = ErrIsDir
		} else if v.open != nil && entry.Pack == v.open.path {
			// Appending to buf never changes bytes already in it, so the
			// slice stays valid after the lock is released.
			inMemory = v.open.buf[entry.Offset : entry.Offset+entry.Size]
		}
	}
	v.mu.RUnlock()
	if err != nil {
		return nil, Entry{}, err
	}
	if inMemory != nil {
		return &File{SectionReader: io.NewSectionReader(bytes.NewReader(inMemory), 0, entry.Size)}, entry, nil
	}

	content, offset := entry.Blob, int64(0)
	if entry.Pack != "" {
		content, offset = entry.Pack, entry.Offset
	}
	f, ra, size, err := openAge(v.abs(content), identity)
	if err != nil {
		return nil, Entry{}, fmt.Errorf("файл повреждён: %w", err)
	}
	if entry.Pack == "" {
		entry.Size = size
	} else if offset+entry.Size > size {
		f.Close()
		return nil, Entry{}, fmt.Errorf("файл повреждён: пакет короче записи")
	}
	return &File{SectionReader: io.NewSectionReader(ra, offset, entry.Size), f: f}, entry, nil
}

// openAge opens an age file for random access to its plaintext.
func openAge(full string, identity age.Identity) (*os.File, io.ReaderAt, int64, error) {
	f, err := os.Open(full)
	if err != nil {
		return nil, nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, 0, err
	}
	ra, size, err := age.DecryptReaderAt(f, st.Size(), identity)
	if err != nil {
		f.Close()
		return nil, nil, 0, err
	}
	return f, ra, size, nil
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
// are what it is for. Pending deferred changes are written first: the check
// is of what is on the card.
func (v *Vault) Verify(progress func(Progress)) (problems []Problem, done Progress, err error) {
	if err := v.Flush(); err != nil {
		return nil, done, err
	}
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
	var blobs []item
	packs := map[string][]Entry{}
	paths := map[string]string{}
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
		paths[e.ID] = strings.Join(names, "/")
		if e.Pack != "" {
			packs[e.Pack] = append(packs[e.Pack], *e)
		} else {
			blobs = append(blobs, item{*e, paths[e.ID]})
		}
		done.TotalFiles++
		done.TotalBytes += e.Size
	}
	v.mu.RUnlock()

	report := func(n int64) {
		done.Bytes += n
		if progress != nil {
			progress(done)
		}
	}
	bad := func(e Entry, err error) {
		problems = append(problems, Problem{ID: e.ID, Parent: e.Parent, Path: paths[e.ID], Err: describe(err)})
	}
	report(0)

	packNames := make([]string, 0, len(packs))
	for p := range packs {
		packNames = append(packNames, p)
	}
	sort.Strings(packNames)
	for _, p := range packNames {
		if v.closed() {
			return problems, done, ErrClosed
		}
		members := packs[p]
		sort.Slice(members, func(i, j int) bool { return members[i].Offset < members[j].Offset })
		for i, err := range verifyPack(v.abs(p), identity, members, func(n int64) { report(n) }) {
			if err != nil {
				bad(members[i], err)
			}
		}
		done.Files += len(members)
		report(0)
	}

	sort.Slice(blobs, func(i, j int) bool { return blobs[i].path < blobs[j].path })
	for _, it := range blobs {
		if v.closed() {
			return problems, done, ErrClosed
		}
		n, err := verifyBlob(v.abs(it.e.Blob), identity, report)
		if err == nil && n != it.e.Size {
			err = errors.New("size differs from the index")
		}
		if err != nil {
			bad(it.e, err)
		}
		done.Files++
		report(it.e.Size - n) // keep the byte count in step with the total
	}
	sort.Slice(problems, func(i, j int) bool { return problems[i].Path < problems[j].Path })
	return problems, done, nil
}

// verifyPack checks the members of one pack, sorted by offset, and returns
// an error, or nil, for each. The pack is read once from start to end; only
// when that fails are the members past the failure read one by one, so a
// damaged chunk condemns just the files it holds. report gets each member's
// size once.
func verifyPack(full string, identity age.Identity, members []Entry, report func(int64)) []error {
	errs := make([]error, len(members))
	reported := 0
	reportUpTo := func(k int) {
		for ; reported < k; reported++ {
			report(members[reported].Size)
		}
	}
	defer reportUpTo(len(members))

	f, err := os.Open(full)
	if err != nil {
		for i := range errs {
			errs[i] = err
		}
		return errs
	}
	defer f.Close()
	r, err := age.Decrypt(f, identity)
	if err != nil {
		for i := range errs {
			errs[i] = err
		}
		return errs
	}
	buf := make([]byte, 1<<20)
	var pos int64
	next := 0 // first member not yet fully read
	for {
		n, rerr := r.Read(buf)
		pos += int64(n)
		for next < len(members) && members[next].Offset+members[next].Size <= pos {
			next++
		}
		reportUpTo(next)
		if rerr == io.EOF {
			for i := next; i < len(members); i++ {
				errs[i] = errors.New("pack shorter than the index says")
			}
			return errs
		}
		if rerr != nil {
			break
		}
	}

	// The stream stopped at a bad chunk. Members before it are fine; each of
	// the others is read on its own, which skips the bad chunk.
	pf, ra, size, err := openAge(full, identity)
	if err == nil {
		defer pf.Close()
	}
	for i := next; i < len(members); i++ {
		m := members[i]
		switch {
		case err != nil:
			errs[i] = err
		case m.Offset+m.Size > size:
			errs[i] = errors.New("pack shorter than the index says")
		default:
			_, errs[i] = io.CopyBuffer(io.Discard, io.NewSectionReader(ra, m.Offset, m.Size), buf)
		}
		reportUpTo(i + 1)
	}
	return errs
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
