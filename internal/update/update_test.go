package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// fakeRelease serves a GitHub "latest release" endpoint and its assets.
type fakeRelease struct {
	tag     string
	files   map[string][]byte // published binaries and README
	key     ed25519.PrivateKey
	tamper  func(name string, b []byte) []byte
	srv     *httptest.Server
	fetched []string
}

func newFake(t *testing.T, tag string, files map[string][]byte) (*fakeRelease, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRelease{tag: tag, files: files, key: priv}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f, pub
}

func (f *fakeRelease) assets() map[string][]byte {
	sums := map[string]string{}
	var names []string
	for n, b := range f.files {
		h := sha256.Sum256(b)
		sums[n] = hex.EncodeToString(h[:])
		names = append(names, n)
	}
	slices.Sort(names)
	m := Manifest(f.tag, sums, names)
	out := map[string][]byte{
		manifestName: m,
		sigName:      []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.key, m))),
	}
	for n, b := range f.files {
		out[n] = b
	}
	return out
}

func (f *fakeRelease) serve(w http.ResponseWriter, r *http.Request) {
	assets := f.assets()
	if r.URL.Path == "/latest" {
		type asset struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}
		var list []asset
		for n := range assets {
			list = append(list, asset{n, f.srv.URL + "/dl/" + n})
		}
		json.NewEncoder(w).Encode(map[string]any{"tag_name": f.tag, "body": "fixes\x1b[2J", "assets": list})
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/dl/")
	b, ok := assets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	f.fetched = append(f.fetched, name)
	if f.tamper != nil {
		b = f.tamper(name, b)
	}
	w.Write(b)
}

// card lays out a fake SD card and returns the path of the running program.
func card(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("old "+n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, AssetName(runtime.GOOS, runtime.GOARCH))
}

func newUpdater(f *fakeRelease, key ed25519.PublicKey, current, exe string) *Updater {
	return &Updater{API: f.srv.URL + "/latest", Key: key, Current: current, Exe: exe,
		Client: f.srv.Client(), Log: io.Discard}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var self = AssetName(runtime.GOOS, runtime.GOARCH)

func published() map[string][]byte {
	return map[string][]byte{
		self:                []byte("new " + self),
		"vault-windows.exe": []byte("new win"),
		"vault-linux-arm64": []byte("new arm"),
		"README.txt":        []byte("new readme"),
	}
}

func TestInstallReplacesProgramsOnTheCard(t *testing.T) {
	exe := card(t, self, "vault-windows.exe", "README.txt", "photo.jpg")
	f, key := newFake(t, "v1.1.0", published())
	u := newUpdater(f, key, "v1.0.0", exe)

	r, err := u.Check(context.Background())
	if err != nil || r == nil {
		t.Fatalf("Check = %v, %v; want a release", r, err)
	}
	if strings.ContainsRune(r.Notes, 0x1b) {
		t.Errorf("notes keep an escape sequence: %q", r.Notes)
	}
	if err := u.Install(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(exe)
	for name, want := range map[string]string{
		self: "new " + self, "vault-windows.exe": "new win", "README.txt": "new readme", "photo.jpg": "old photo.jpg",
	} {
		if got := read(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	// Not on the card before, so not added.
	if _, err := os.Stat(filepath.Join(dir, "vault-linux-arm64")); !os.IsNotExist(err) {
		t.Errorf("vault-linux-arm64 was added")
	}
	Cleanup(exe)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), oldSuffix) || strings.HasSuffix(e.Name(), newSuffix) {
			t.Errorf("leftover %s", e.Name())
		}
	}
}

func TestInstallReplacesRenamedProgram(t *testing.T) {
	// Linux users copy the program off a noexec card, e.g. to /tmp/vault.
	dir := t.TempDir()
	exe := filepath.Join(dir, "vault")
	os.WriteFile(exe, []byte("old"), 0o755)
	f, key := newFake(t, "v1.1.0", published())
	u := newUpdater(f, key, "v1.0.0", exe)
	r, _ := u.Check(context.Background())
	if err := u.Install(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := read(t, exe); got != "new "+self {
		t.Errorf("program = %q", got)
	}
}

func TestInstallRejectsTampering(t *testing.T) {
	cases := map[string]func(name string, b []byte) []byte{
		"binary": func(name string, b []byte) []byte {
			if name == "vault-windows.exe" {
				return []byte("evil")
			}
			return b
		},
		"manifest": func(name string, b []byte) []byte {
			if name == manifestName {
				// Point a file at another hash without re-signing.
				return []byte(strings.Replace(string(b), "\n", "\n0", 1)[:len(b)])
			}
			return b
		},
		"signature": func(name string, b []byte) []byte {
			if name == sigName {
				return []byte(base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
			}
			return b
		},
	}
	for what, tamper := range cases {
		t.Run(what, func(t *testing.T) {
			exe := card(t, self, "vault-windows.exe")
			f, key := newFake(t, "v1.1.0", published())
			f.tamper = tamper
			u := newUpdater(f, key, "v1.0.0", exe)
			r, _ := u.Check(context.Background())
			if err := u.Install(context.Background(), r); err == nil {
				t.Fatal("tampered release installed")
			}
			for _, n := range []string{self, "vault-windows.exe"} {
				if got := read(t, filepath.Join(filepath.Dir(exe), n)); got != "old "+n {
					t.Errorf("%s = %q, card changed", n, got)
				}
			}
			entries, _ := os.ReadDir(filepath.Dir(exe))
			if len(entries) != 2 {
				t.Errorf("leftover files: %v", entries)
			}
		})
	}
}

func TestInstallRejectsForeignKey(t *testing.T) {
	exe := card(t, self)
	f, _ := newFake(t, "v1.1.0", published())
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	u := newUpdater(f, other, "v1.0.0", exe)
	r, _ := u.Check(context.Background())
	if err := u.Install(context.Background(), r); err == nil {
		t.Fatal("release signed by another key installed")
	}
}

func TestVerifyRejectsReplayedManifest(t *testing.T) {
	// An old signed manifest re-published under a new tag must not pass.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest("v1.0.0", map[string]string{"README.txt": strings.Repeat("0", 64)}, []string{"README.txt"})
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, m)))
	if _, err := Verify(pub, m, sig, "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub, m, sig, "v2.0.0"); err == nil {
		t.Fatal("manifest of v1.0.0 accepted for v2.0.0")
	}
	bad := Manifest("v1.0.0", map[string]string{"../evil": strings.Repeat("0", 64)}, []string{"../evil"})
	if _, err := Verify(pub, bad, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bad))), "v1.0.0"); err == nil {
		t.Fatal("path outside the card accepted")
	}
}

func TestCheckOffersOnlyNewer(t *testing.T) {
	for _, c := range []struct {
		current, latest string
		offer           bool
	}{
		{"v1.0.0", "v1.0.1", true},
		{"v1.9.0", "v1.10.0", true},
		{"v1.0.0", "v1.0.0", false},
		{"v2.0.0", "v1.9.9", false},
		{"dev", "v9.0.0", false},
		{"v1.0.0-3-gabc", "v9.0.0", false},
		{"v1.0.0", "nightly", false},
	} {
		f, key := newFake(t, c.latest, published())
		r, err := newUpdater(f, key, c.current, card(t, self)).Check(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if (r != nil) != c.offer {
			t.Errorf("%s → %s: offered %v, want %v", c.current, c.latest, r != nil, c.offer)
		}
	}
}

func TestPublicKeyIsValid(t *testing.T) {
	New("v1.0.0", "x", io.Discard) // panics on a malformed key
}
