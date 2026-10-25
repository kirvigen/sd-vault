// Package update replaces the programs on the card with a newer GitHub
// release. A release is trusted only through release.txt, a list of file
// hashes signed with an ed25519 key that never leaves the author's computer;
// GitHub itself is just transport. A compromised GitHub account can at most
// offer an old signed release, and versions only ever go up.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is where releases are published.
const Repo = "kirvigen/sd-vault"

// PublicKey verifies release.txt.sig. The private half is kept by the author
// (see README.md, "Releases").
const PublicKey = "Iyh+Df2erONN4tHvJWEA4VtSVfRJVE3RzqfZBP/ntRo="

const (
	manifestName = "release.txt"
	sigName      = manifestName + ".sig"
	manifestHead = "sd-vault "
	maxAsset     = 256 << 20
	newSuffix    = ".new"
	oldSuffix    = ".old"
)

// fileName limits what a manifest may write next to the program.
var fileName = regexp.MustCompile(`^(vault-[a-z0-9-]+(\.exe)?|README\.txt)$`)

// Updater checks and installs releases. The zero value is not usable; see New.
type Updater struct {
	API     string // URL of the "latest release" endpoint
	Key     ed25519.PublicKey
	Current string // running version, "v1.2.3"
	Exe     string // path of the running program
	Client  *http.Client
	Log     io.Writer
	// FreeSpace reports the bytes free in a directory; nil means the real
	// disk. Tests replace it.
	FreeSpace func(dir string) (int64, error)
}

// New returns an Updater for the official repository.
func New(current, exe string, log io.Writer) *Updater {
	key, err := base64.StdEncoding.DecodeString(PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		panic("update: bad PublicKey")
	}
	return &Updater{
		API:     "https://api.github.com/repos/" + Repo + "/releases/latest",
		Key:     key,
		Current: current,
		Exe:     exe,
		Client:  &http.Client{Timeout: 10 * time.Minute},
		Log:     log,
	}
}

// Release is a newer version found by Check.
type Release struct {
	Version string
	Notes   string
	assets  map[string]string // file name → download URL
	sizes   map[string]int64  // file name → size, as GitHub reports it
}

// Check returns the latest release when it is newer than the running
// version, or nil. Development builds (version not "vX.Y.Z") never update.
func (u *Updater) Check(ctx context.Context) (*Release, error) {
	cur, ok := parseVersion(u.Current)
	if !ok {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.API, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no releases yet
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	var gh struct {
		Tag    string `json:"tag_name"`
		Body   string `json:"body"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&gh); err != nil {
		return nil, err
	}
	latest, ok := parseVersion(gh.Tag)
	if !ok || !newer(latest, cur) {
		return nil, nil
	}
	r := &Release{Version: gh.Tag, Notes: printable(gh.Body), assets: map[string]string{}, sizes: map[string]int64{}}
	for _, a := range gh.Assets {
		r.assets[a.Name] = a.URL
		r.sizes[a.Name] = a.Size
	}
	return r, nil
}

// Install downloads and verifies every file the release has for this card,
// then swaps them in. Nothing is replaced unless all of them verified.
// Afterwards the running process is still the old program; call Restart.
func (u *Updater) Install(ctx context.Context, r *Release) error {
	manifest, err := u.fetch(ctx, r, manifestName, 1<<16)
	if err != nil {
		return err
	}
	sig, err := u.fetch(ctx, r, sigName, 1<<10)
	if err != nil {
		return err
	}
	sums, err := Verify(u.Key, manifest, sig, r.Version)
	if err != nil {
		return err
	}

	self := AssetName(runtime.GOOS, runtime.GOARCH)
	if _, ok := sums[self]; !ok {
		return fmt.Errorf("в версии %s нет программы для этой системы (%s)", r.Version, self)
	}
	// The running program is replaced whatever it is called; the other
	// programs and the README only when they are already on the card.
	targets := map[string]string{self: u.Exe}
	dir := filepath.Dir(u.Exe)
	for name := range sums {
		path := filepath.Join(dir, name)
		if name == self || sameFile(path, u.Exe) {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			targets[name] = path
		}
	}

	if err := u.checkSpace(dir, r, targets); err != nil {
		return err
	}

	var ready []string
	defer func() {
		for _, p := range ready {
			os.Remove(p + newSuffix)
		}
	}()
	for name, path := range targets {
		fmt.Fprintf(u.Log, "  скачиваю %s…\n", name)
		if err := u.download(ctx, r, name, sums[name], path+newSuffix); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		ready = append(ready, path)
	}
	for _, path := range ready {
		if err := swap(path); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
	}
	ready = nil
	syncDir(dir)
	return nil
}

// Every new file is downloaded next to the old one before any is swapped
// in, so for a moment the card holds both. perFileSlack covers a file's last
// cluster (up to 128 KiB on exFAT) and the "._" file macOS adds on FAT.
const perFileSlack = 256 << 10

// checkSpace refuses to start an update that cannot fit: running out of
// space on the last file wastes minutes of downloading to a slow card and
// ends in an error from the OS. GitHub's sizes are not signed, but they
// only decide whether to try; the hashes still decide what is installed.
func (u *Updater) checkSpace(dir string, r *Release, targets map[string]string) error {
	freeSpace := u.FreeSpace
	if freeSpace == nil {
		freeSpace = diskFree
	}
	free, err := freeSpace(dir)
	if err != nil {
		return nil // cannot tell; let the download try
	}
	need := int64(1 << 20)
	for name := range targets {
		need += r.sizes[name] + perFileSlack
	}
	if free >= need {
		return nil
	}
	return fmt.Errorf("на карте не хватает места для обновления: нужно %s, свободно %s. %s",
		megabytes(need), megabytes(free), freeHint(need-free))
}

func freeHint(missing int64) string {
	how := "Освободите место"
	if missing > 0 {
		how = "Освободите ещё " + megabytes(missing)
	}
	return how + " и запустите программу снова. Если удаляли файлы с карты, очистите Корзину: " +
		"пока удалённое лежит в ней, оно занимает место на карте"
}

func megabytes(n int64) string {
	return fmt.Sprintf("%.1f МБ", float64(n)/(1<<20))
}

// Verify checks the signature of a manifest and returns its file hashes.
// The manifest is "sd-vault <version>" followed by sha256sum lines.
func Verify(key ed25519.PublicKey, manifest, sig []byte, version string) (map[string]string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(key, manifest, raw) {
		return nil, errors.New("подпись обновления не сходится — обновление отклонено")
	}
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	if !sc.Scan() || sc.Text() != manifestHead+version {
		return nil, errors.New("подписанный список файлов от другой версии — обновление отклонено")
	}
	sums := map[string]string{}
	for sc.Scan() {
		hash, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(hash) != 64 || !fileName.MatchString(name) {
			return nil, fmt.Errorf("плохая строка в %s: %q", manifestName, sc.Text())
		}
		sums[name] = hash
	}
	return sums, nil
}

// Manifest builds the text that release.txt holds, for the release tool.
func Manifest(version string, sums map[string]string, names []string) []byte {
	var b bytes.Buffer
	b.WriteString(manifestHead + version + "\n")
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", sums[n], n)
	}
	return b.Bytes()
}

// AssetName is the release file that runs on goos/goarch.
func AssetName(goos, goarch string) string {
	switch goos {
	case "windows":
		return "vault-windows.exe"
	case "darwin":
		return "vault-macos" // universal binary
	default:
		return "vault-" + goos + "-" + goarch
	}
}

// Cleanup removes what an earlier update left next to the program: the old
// program, which Windows does not let delete while it runs, and downloads
// interrupted by a pulled card.
func Cleanup(exe string) {
	dir := filepath.Dir(exe)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		base := strings.TrimSuffix(strings.TrimSuffix(n, oldSuffix), newSuffix)
		if base != n && (fileName.MatchString(base) || base == filepath.Base(exe)) {
			os.Remove(filepath.Join(dir, n))
		}
	}
}

func (u *Updater) fetch(ctx context.Context, r *Release, name string, limit int64) ([]byte, error) {
	resp, err := u.get(ctx, r, name)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func (u *Updater) get(ctx context.Context, r *Release, name string) (*http.Response, error) {
	url, ok := r.assets[name]
	if !ok {
		return nil, fmt.Errorf("в версии %s нет файла %s", r.Version, name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", name, resp.Status)
	}
	return resp, nil
}

func (u *Updater) download(ctx context.Context, r *Release, name, want, dst string) (err error) {
	resp, err := u.get(ctx, r, name)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(dst)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxAsset+1))
	if isNoSpace(err) {
		return errors.New("на карте кончилось место. " + freeHint(0))
	}
	if err != nil {
		return err
	}
	if n > maxAsset {
		return errors.New("файл слишком большой")
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("скачанный файл не совпал с подписанным — обновление отклонено")
	}
	if err = f.Sync(); err != nil {
		if isNoSpace(err) {
			return errors.New("на карте кончилось место. " + freeHint(0))
		}
		return err
	}
	return f.Close()
}

// swap puts path.new in place of path. The current file is renamed rather
// than overwritten: Windows refuses to overwrite a running program but lets
// it be renamed.
func swap(path string) error {
	old := path + oldSuffix
	os.Remove(old)
	if err := os.Rename(path, old); err != nil {
		return err
	}
	if err := os.Rename(path+newSuffix, path); err != nil {
		os.Rename(old, path)
		return err
	}
	os.Remove(old) // fails for the running program on Windows; Cleanup gets it
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

func sameFile(a, b string) bool {
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}

func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if !strings.HasPrefix(s, "v") || len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func newer(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// printable keeps release notes from writing terminal escape sequences.
func printable(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= ' ' && r != 0x7f && (r < 0x80 || r > 0x9f) {
			return r
		}
		return -1
	}, s)
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 15 {
		lines = append(lines[:15], "…")
	}
	return strings.Join(lines, "\n")
}
