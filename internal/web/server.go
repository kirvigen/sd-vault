// Package web serves the vault UI on 127.0.0.1.
//
// Access needs the one-time token from the URL printed in the terminal. The
// first visit trades it for an HttpOnly cookie, so the token does not stay in
// the address bar or the browser history entry the user keeps looking at.
package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"sd-vault/internal/vault"
)

//go:embed ui
var uiFiles embed.FS

// Server is the HTTP side of an unlocked vault.
type Server struct {
	v      *vault.Vault
	token  string
	host   string // expected Host header, "127.0.0.1:port"
	cookie string

	closeOnce sync.Once
	closed    chan struct{}

	// Uploads with batch=1 leave the index in memory. It is written on
	// /api/flush, which the UI sends when its queue empties, after flushIdle
	// without uploads (a closed tab), and at least every flushEvery while
	// uploads keep coming, which bounds what a pulled card can lose.
	batchMu      sync.Mutex
	flushTimer   *time.Timer
	pendingSince time.Time

	verifyMu sync.Mutex
	verify   verifyState
}

// verifyState is the last or running "Проверить сейф". On a slow card it
// can take many minutes, so it runs in the background and the UI polls it.
type verifyState struct {
	vault.Progress
	Running  bool            `json:"running"`
	Started  bool            `json:"started"` // false until the first run
	Problems []vault.Problem `json:"problems"`
	Err      string          `json:"error,omitempty"`
}

// Variables so tests can shorten them.
var (
	flushIdle  = 3 * time.Second
	flushEvery = 30 * time.Second
)

// New returns a server for v. host is the address the browser will use; any
// other Host header is refused, which blocks DNS-rebinding attacks.
func New(v *vault.Vault, token, host string) *Server {
	return &Server{
		v:      v,
		token:  token,
		host:   host,
		cookie: "vault_" + strings.ReplaceAll(strings.ReplaceAll(host, ":", "_"), ".", "_"),
		closed: make(chan struct{}),
	}
}

// Closed is closed when the user presses "Закрыть сейф".
func (s *Server) Closed() <-chan struct{} { return s.closed }

func (s *Server) Handler() http.Handler {
	ui, _ := fs.Sub(uiFiles, "ui")
	static := http.FileServerFS(ui)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.Handle("GET /static/", s.auth(http.StripPrefix("/static/", static)))
	mux.Handle("GET /api/list", s.auth(http.HandlerFunc(s.handleList)))
	mux.Handle("GET /api/file/{id}", s.auth(http.HandlerFunc(s.handleFile)))
	mux.Handle("POST /api/upload", s.auth(http.HandlerFunc(s.handleUpload)))
	mux.Handle("POST /api/flush", s.auth(http.HandlerFunc(s.handleFlush)))
	mux.Handle("POST /api/verify", s.auth(http.HandlerFunc(s.handleVerifyStart)))
	mux.Handle("GET /api/verify", s.auth(http.HandlerFunc(s.handleVerifyStatus)))
	mux.Handle("POST /api/mkdir", s.auth(http.HandlerFunc(s.handleMkdir)))
	mux.Handle("POST /api/rename", s.auth(http.HandlerFunc(s.handleRename)))
	mux.Handle("POST /api/delete", s.auth(http.HandlerFunc(s.handleDelete)))
	mux.Handle("POST /api/close", s.auth(http.HandlerFunc(s.handleClose)))
	return s.guard(mux)
}

// guard applies to every request: right Host, no caching, no sniffing.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.host {
			http.Error(w, "wrong host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+s.host {
				http.Error(w, "wrong origin", http.StatusForbidden)
				return
			}
		}
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	c, err := r.Cookie(s.cookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.token)) == 1
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			http.Error(w, "нет доступа: откройте ссылку из окна программы", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if t := r.URL.Query().Get("t"); t != "" {
		if subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) != 1 {
			http.Error(w, "неверная ссылка", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: s.cookie, Value: s.token, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.authorized(r) {
		http.Error(w, "нет доступа: откройте ссылку из окна программы", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; img-src 'self' blob:; media-src 'self'; frame-src 'self'; object-src 'self'; style-src 'self'; script-src 'self'")
	data, _ := uiFiles.ReadFile("ui/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

type listResponse struct {
	Dir     vault.Entry   `json:"dir"`
	Path    []vault.Entry `json:"path"`
	Entries []vault.Entry `json:"entries"`
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("dir")
	dir, err := s.v.Get(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	p, err := s.v.Path(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	entries, err := s.v.List(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	if p == nil {
		p = []vault.Entry{}
	}
	if entries == nil {
		entries = []vault.Entry{}
	}
	writeJSON(w, listResponse{Dir: dir, Path: p, Entries: entries})
}

func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	f, e, err := s.v.Open(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	defer f.Close()
	ctype := ContentType(e.Name)
	h := w.Header()
	h.Set("Content-Type", ctype)
	disposition := "inline"
	if r.URL.Query().Get("dl") != "" {
		disposition = "attachment"
	}
	h.Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": e.Name}))
	// A stored HTML or SVG file opened directly must not run scripts with
	// access to this origin. Chrome refuses to show PDFs under a sandbox, and
	// its viewer does not run the document's scripts anyway.
	if ctype != "application/pdf" {
		h.Set("Content-Security-Policy", "sandbox")
	}
	http.ServeContent(w, r, "", e.Modified, f)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dir := q.Get("dir")
	rel := strings.Trim(q.Get("path"), "/")
	if rel == "" {
		writeErr(w, vault.ErrBadName)
		return
	}
	batch := q.Get("batch") != ""
	mkdirAll, put := s.v.MkdirAll, s.v.Put
	if batch {
		mkdirAll, put = s.v.MkdirAllDeferred, s.v.PutDeferred
	}
	folder, name := path.Split(rel)
	if folder != "" {
		var err error
		if dir, err = mkdirAll(dir, folder); err != nil {
			writeErr(w, err)
			return
		}
	}
	// The body is read as a stream straight into the encryptor. No multipart
	// parsing: Go's multipart form code spills big uploads to a temp file in
	// plain text.
	e, err := put(dir, name, r.Body)
	if batch {
		// Folders made above are pending even when the put failed.
		s.scheduleFlush()
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, e)
}

func (s *Server) scheduleFlush() {
	s.batchMu.Lock()
	if s.pendingSince.IsZero() {
		s.pendingSince = time.Now()
	}
	due := time.Since(s.pendingSince) >= flushEvery
	if s.flushTimer == nil {
		s.flushTimer = time.AfterFunc(flushIdle, func() { s.flush() })
	} else {
		s.flushTimer.Reset(flushIdle)
	}
	s.batchMu.Unlock()
	if due {
		if err := s.flush(); err != nil {
			log.Printf("индекс не записан: %v", err)
		}
	}
}

func (s *Server) flush() error {
	s.batchMu.Lock()
	if s.flushTimer != nil {
		s.flushTimer.Stop()
	}
	s.pendingSince = time.Time{}
	s.batchMu.Unlock()
	err := s.v.Flush()
	if errors.Is(err, vault.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) handleFlush(w http.ResponseWriter, r *http.Request) {
	if err := s.flush(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleVerifyStart(w http.ResponseWriter, r *http.Request) {
	s.verifyMu.Lock()
	if !s.verify.Running {
		s.verify = verifyState{Running: true, Started: true, Problems: []vault.Problem{}}
		go s.runVerify()
	}
	st := s.verify
	s.verifyMu.Unlock()
	writeJSON(w, st)
}

func (s *Server) runVerify() {
	problems, done, err := s.v.Verify(func(p vault.Progress) {
		s.verifyMu.Lock()
		s.verify.Progress = p
		s.verifyMu.Unlock()
	})
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	s.verify.Running = false
	s.verify.Progress = done
	if problems != nil {
		s.verify.Problems = problems
	}
	if err != nil {
		s.verify.Err = err.Error()
	}
}

func (s *Server) handleVerifyStatus(w http.ResponseWriter, r *http.Request) {
	s.verifyMu.Lock()
	st := s.verify
	s.verifyMu.Unlock()
	if st.Problems == nil {
		st.Problems = []vault.Problem{}
	}
	writeJSON(w, st)
}

type nameRequest struct {
	ID   string `json:"id"`
	Dir  string `json:"dir"`
	Name string `json:"name"`
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(v)
}

func (s *Server) handleMkdir(w http.ResponseWriter, r *http.Request) {
	var req nameRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e, err := s.v.Mkdir(req.Dir, strings.TrimSpace(req.Name))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, e)
}

func (s *Server) handleRename(w http.ResponseWriter, r *http.Request) {
	var req nameRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e, err := s.v.Rename(req.ID, strings.TrimSpace(req.Name))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, e)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req nameRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.v.Delete(req.ID); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"ok": true})
	s.closeOnce.Do(func() { close(s.closed) })
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, vault.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, vault.ErrExists), errors.Is(err, vault.ErrIsDir):
		code = http.StatusConflict
	case errors.Is(err, vault.ErrBadName), errors.Is(err, vault.ErrNotDir):
		code = http.StatusBadRequest
	case errors.Is(err, vault.ErrClosed):
		code = http.StatusGone
	default:
		log.Printf("ошибка: %v", err)
	}
	http.Error(w, err.Error(), code)
}

var types = map[string]string{
	".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif",
	".webp": "image/webp", ".bmp": "image/bmp", ".avif": "image/avif", ".svg": "image/svg+xml",
	".ico": "image/x-icon", ".heic": "image/heic", ".heif": "image/heif",
	".pdf": "application/pdf",
	".mp4": "video/mp4", ".m4v": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime",
	".mkv": "video/x-matroska", ".ogv": "video/ogg",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac", ".wav": "audio/wav",
	".ogg": "audio/ogg", ".oga": "audio/ogg", ".opus": "audio/ogg", ".flac": "audio/flac",
}

// Shown as plain text even when the real type is HTML or script: the browser
// must display them, not run them.
var textExts = map[string]bool{
	".txt": true, ".md": true, ".markdown": true, ".log": true, ".csv": true, ".tsv": true,
	".json": true, ".yaml": true, ".yml": true, ".toml": true, ".ini": true, ".conf": true,
	".cfg": true, ".env": true, ".xml": true, ".html": true, ".htm": true, ".css": true,
	".js": true, ".ts": true, ".go": true, ".py": true, ".sh": true, ".rb": true, ".java": true,
	".kt": true, ".swift": true, ".c": true, ".h": true, ".cpp": true, ".rs": true, ".sql": true,
	".srt": true, ".vtt": true,
}

// ContentType picks the Content-Type for a stored file by its name.
func ContentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if textExts[ext] {
		return "text/plain; charset=utf-8"
	}
	if t, ok := types[ext]; ok {
		return t
	}
	return "application/octet-stream"
}
