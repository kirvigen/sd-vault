package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sd-vault/internal/vault"
)

const token = "test-token"

type env struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	client *http.Client // carries the session cookie
}

func setup(t *testing.T) *env {
	t.Helper()
	v, err := vault.Create(filepath.Join(t.TempDir(), "vault"), "password123")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	ts := httptest.NewUnstartedServer(nil)
	srv := New(v, token, ts.Listener.Addr().String())
	ts.Config.Handler = srv.Handler()
	ts.Start()
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(ts.URL + "/?t=" + token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	return &env{t: t, srv: srv, ts: ts, client: client}
}

func (e *env) do(method, path string, body io.Reader, hdr ...string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.ts.URL+path, body)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func (e *env) list(dir string) listResponse {
	e.t.Helper()
	resp := e.do("GET", "/api/list?dir="+url.QueryEscape(dir), nil)
	defer resp.Body.Close()
	var l listResponse
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		e.t.Fatal(err)
	}
	return l
}

func (e *env) upload(dir, path, content string) vault.Entry {
	e.t.Helper()
	resp := e.do("POST", "/api/upload?dir="+url.QueryEscape(dir)+"&path="+url.QueryEscape(path), strings.NewReader(content))
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("upload %s: %d %s", path, resp.StatusCode, b)
	}
	var ent vault.Entry
	json.NewDecoder(resp.Body).Decode(&ent)
	return ent
}

func TestAccessNeedsToken(t *testing.T) {
	e := setup(t)
	for _, path := range []string{"/", "/api/list", "/static/app.js", "/?t=wrong"} {
		resp, err := http.Get(e.ts.URL + path) // no cookie
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without cookie: %d", path, resp.StatusCode)
		}
	}

	// DNS rebinding: a page on evil.example resolving to 127.0.0.1.
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/list", nil)
	req.Host = "evil.example"
	resp, _ := e.client.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("foreign Host: %d", resp.StatusCode)
	}

	// Cross-site POST.
	resp = e.do("POST", "/api/mkdir", strings.NewReader(`{"name":"x"}`), "Origin", "https://evil.example")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("foreign Origin: %d", resp.StatusCode)
	}

	resp = e.do("GET", "/", nil)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("index with cookie: %d, Cache-Control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
}

func TestUploadFolderListAndRange(t *testing.T) {
	e := setup(t)
	content := strings.Repeat("0123456789", 20_000)
	e.upload("", "Фото/2024/clip.mp4", content)

	root := e.list("")
	if len(root.Entries) != 1 || root.Entries[0].Name != "Фото" || !root.Entries[0].Dir {
		t.Fatalf("root: %+v", root.Entries)
	}
	y := e.list(e.list(root.Entries[0].ID).Entries[0].ID)
	if len(y.Path) != 2 || y.Path[1].Name != "2024" || len(y.Entries) != 1 {
		t.Fatalf("2024: %+v", y)
	}
	clip := y.Entries[0]

	resp := e.do("GET", "/api/file/"+clip.ID, nil, "Range", "bytes=100000-100009")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || string(b) != content[100000:100010] {
		t.Fatalf("range: %d %q", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "video/mp4" {
		t.Errorf("Content-Type %q", ct)
	}

	resp = e.do("GET", "/api/file/"+clip.ID+"?dl=1", nil)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != content || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %d bytes, %q", len(b), resp.Header.Get("Content-Disposition"))
	}
}

func TestStoredHTMLIsNotExecuted(t *testing.T) {
	e := setup(t)
	ent := e.upload("", "page.html", "<script>alert(1)</script>")
	resp := e.do("GET", "/api/file/"+ent.ID, nil)
	resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type %q", ct)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); csp != "sandbox" {
		t.Errorf("CSP %q", csp)
	}
}

func TestMkdirRenameDelete(t *testing.T) {
	e := setup(t)
	post := func(path, body string) int {
		resp := e.do("POST", path, strings.NewReader(body), "Content-Type", "application/json")
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post("/api/mkdir", `{"dir":"","name":"Docs"}`); c != 200 {
		t.Fatalf("mkdir: %d", c)
	}
	docs := e.list("").Entries[0]
	f := e.upload(docs.ID, "a.txt", "a")
	if c := post("/api/rename", `{"id":"`+f.ID+`","name":"b.txt"}`); c != 200 {
		t.Fatalf("rename: %d", c)
	}
	if got := e.list(docs.ID).Entries[0].Name; got != "b.txt" {
		t.Fatalf("after rename: %q", got)
	}
	if c := post("/api/rename", `{"id":"`+f.ID+`","name":"a/b"}`); c != http.StatusBadRequest {
		t.Fatalf("bad name: %d", c)
	}
	if c := post("/api/delete", `{"id":"`+docs.ID+`"}`); c != 200 {
		t.Fatalf("delete: %d", c)
	}
	if n := len(e.list("").Entries); n != 0 {
		t.Fatalf("%d entries after delete", n)
	}
	resp := e.do("GET", "/api/file/"+f.ID, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted file: %d", resp.StatusCode)
	}
}

func TestCloseButton(t *testing.T) {
	e := setup(t)
	resp := e.do("POST", "/api/close", strings.NewReader("{}"))
	resp.Body.Close()
	select {
	case <-e.srv.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed channel not signalled")
	}
}

func TestContentType(t *testing.T) {
	for name, want := range map[string]string{
		"a.JPG": "image/jpeg", "doc.pdf": "application/pdf", "x.html": "text/plain; charset=utf-8",
		"song.mp3": "audio/mpeg", "noext": "application/octet-stream",
	} {
		if got := ContentType(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
}
