package web

import (
	"bytes"
	"fmt"
	"image/jpeg"
	"io"
	"path"
	"strings"

	"github.com/gen2brain/heic"
)

// Only Safari shows HEIC, the format iPhones take photos in, so the viewer
// gets a JPEG made in memory; downloads stay the original file. The decoder
// is a Rust HEVC decoder compiled to WASM and transpiled to Go (build tags
// nodynamic,wasm2go in the Makefile), so no C library is needed and the
// programs still cross-compile. A 12 MP photo takes about half a second.

// heicSlots bounds the photos converted at once: each holds its pixels,
// 48 MB for 12 MP, and flipping quickly through a folder starts many.
var heicSlots = make(chan struct{}, 2)

func isHEIC(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".heic", ".heif":
		return true
	}
	return false
}

// heicToJPEG decodes a HEIC image, with its rotation applied, into a JPEG.
func heicToJPEG(r io.Reader) ([]byte, error) {
	heicSlots <- struct{}{}
	defer func() { <-heicSlots }()
	img, err := heic.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать HEIC: %w", err)
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 90}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
