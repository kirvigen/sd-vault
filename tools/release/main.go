// Command release makes the signing key and signs dist/ for a GitHub release.
//
//	go run ./tools/release keygen -key ~/.config/sd-vault/release.key
//	go run ./tools/release sign -key ~/.config/sd-vault/release.key -version v1.2.3 dist
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"sd-vault/internal/update"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: release keygen|sign …")
	}
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file")
	version := fs.String("version", "", "release tag, vX.Y.Z")
	fs.Parse(args[1:])
	if *keyPath == "" {
		return errors.New("-key is required")
	}
	switch args[0] {
	case "keygen":
		return keygen(*keyPath)
	case "sign":
		if *version == "" || fs.NArg() != 1 {
			return errors.New("usage: release sign -key K -version vX.Y.Z DIR")
		}
		return sign(*keyPath, *version, fs.Arg(0))
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func keygen(path string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err // never overwrite a key: old releases would stop verifying
	}
	fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed()))
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("private key: %s (back it up)\npublic key for update.PublicKey: %s\n",
		path, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func sign(keyPath, version, dir string) error {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(string(trimNL(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("bad key file")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if pub != update.PublicKey {
		return errors.New("key does not match update.PublicKey: programs would reject this release")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	sums := map[string]string{}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || n == "release.txt" || n == "release.txt.sig" {
			continue
		}
		sum, err := hashFile(filepath.Join(dir, n))
		if err != nil {
			return err
		}
		sums[n] = sum
		names = append(names, n)
	}
	slices.Sort(names)
	manifest := update.Manifest(version, sums, names)
	sig := ed25519.Sign(priv, manifest)
	// Round-trip through the client's own check before publishing.
	if _, err := update.Verify(priv.Public().(ed25519.PublicKey), manifest, []byte(base64.StdEncoding.EncodeToString(sig)), version); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "release.txt"), manifest, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "release.txt.sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %d files for %s\n", len(names), version)
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
