package web

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"sd-vault/internal/vault"
)

// problemsFile is added to an archive that could not take every file.
const problemsFile = "НЕ СКАЧАЛОСЬ.txt"

// handleZip sends a folder with everything in it as one zip archive. The
// archive is made while it is sent, so nothing is written to the card or
// to a temporary file, and a big folder starts downloading at once. Files
// are stored, not compressed: photos and videos do not shrink, and
// deflating would only slow the download.
//
// Once the first byte is out the status cannot change, so a file that
// fails to decrypt is listed in problemsFile at the end of the archive.
func (s *Server) handleZip(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("dir")
	dir, err := s.v.Get(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !dir.Dir {
		writeErr(w, vault.ErrNotDir)
		return
	}
	name := dir.Name
	if id == vault.RootID {
		name = "Сейф"
	}
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name + ".zip"}))

	zw := zip.NewWriter(w)
	var problems []string
	walkErr := s.addDir(zw, id, name+"/", &problems)
	if walkErr != nil {
		// The connection is gone or the vault was closed: the archive is
		// cut off anyway, and the browser reports a failed download.
		log.Printf("архив «%s» прерван: %v", name, walkErr)
		return
	}
	if len(problems) > 0 {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: name + "/" + problemsFile, Method: zip.Store, Modified: time.Now()})
		if err == nil {
			fmt.Fprintf(f, "Эти файлы не удалось расшифровать, в архиве их нет или они неполные:\r\n\r\n%s\r\n",
				strings.Join(problems, "\r\n"))
		}
	}
	zw.Close()
}

// addDir writes folder id under prefix. It returns only errors that end
// the whole archive; a damaged file is noted in problems instead.
func (s *Server) addDir(zw *zip.Writer, id, prefix string, problems *[]string) error {
	if _, err := zw.CreateHeader(&zip.FileHeader{Name: prefix, Modified: time.Now()}); err != nil {
		return err
	}
	entries, err := s.v.List(id)
	if err != nil {
		return err
	}
	for _, e := range entries {
		rel := path.Join(prefix, e.Name)
		if e.Dir {
			if err := s.addDir(zw, e.ID, rel+"/", problems); err != nil {
				return err
			}
			continue
		}
		f, _, err := s.v.Open(e.ID)
		if errors.Is(err, vault.ErrClosed) {
			return err
		}
		if err != nil {
			*problems = append(*problems, rel+": "+err.Error())
			continue
		}
		// Zip's own time field has no zone and unpackers read it as local
		// time; the index keeps UTC, which would shift every file by hours.
		dst, err := zw.CreateHeader(&zip.FileHeader{Name: rel, Method: zip.Store, Modified: e.Modified.Local()})
		if err != nil {
			f.Close()
			return err
		}
		readErr, writeErr := copyApart(dst, f)
		f.Close()
		if writeErr != nil {
			return writeErr
		}
		if readErr != nil {
			*problems = append(*problems, rel+": "+readErr.Error())
		}
	}
	return nil
}

// copyApart is io.Copy that tells a failed read from a failed write: a
// damaged file is skipped, a closed connection ends the archive.
func copyApart(dst io.Writer, src io.Reader) (readErr, writeErr error) {
	buf := make([]byte, 256<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return nil, werr
			}
		}
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return err, nil
		}
	}
}
