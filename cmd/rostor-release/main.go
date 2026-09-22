// Command rostor-release is the operator-side half of the release channel:
// it keeps the signing key on the operator's machine, builds a manifest from
// a directory of release files, and signs it. The appliance only ever sees
// the public key (deploy/release.pub).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rostor.org/app/internal/update"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "manifest":
		err = manifest(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  rostor-release keygen  --out ~/.rostor/release-signing.key      # prints the public key
  rostor-release manifest --key FILE --channel stable --version vX.Y.Z --base-url URL --dir DIST [--notes TEXT] > manifest.json`)
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "private key file to create (0600)")
	fs.Parse(args)
	if *out == "" {
		return errors.New("--out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a signing key", *out)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(pub))
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s is not a hex ed25519 private key", path)
	}
	return ed25519.PrivateKey(b), nil
}

// manifest expects files named rostor-<os>-<arch> (and optionally
// rostor-agent-windows-amd64.exe) in --dir and publishes them at --base-url/<name>.
func manifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	key := fs.String("key", "", "private key file")
	channel := fs.String("channel", "stable", "")
	ver := fs.String("version", "", "vX.Y.Z")
	base := fs.String("base-url", "", "URL prefix where the files will be served")
	dir := fs.String("dir", "dist", "")
	notes := fs.String("notes", "", "")
	urlMap := fs.String("url-map", "", "optional name=url,name=url overrides (e.g. GitHub asset API URLs)")
	fs.Parse(args)
	if *key == "" || *ver == "" || (*base == "" && *urlMap == "") {
		return errors.New("--key, --version and --base-url (or --url-map) are required")
	}
	overrides := map[string]string{}
	for _, kv := range strings.Split(*urlMap, ",") {
		if name, u, ok := strings.Cut(kv, "="); ok {
			overrides[name] = u
		}
	}
	priv, err := loadKey(*key)
	if err != nil {
		return err
	}
	m := update.Manifest{Channel: *channel, Version: *ver, Published: time.Now().UTC(), Notes: *notes, Files: map[string]update.File{}}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "rostor-") || strings.HasSuffix(name, ".json") {
			continue
		}
		f, err := os.Open(filepath.Join(*dir, name))
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		f.Close()
		if err != nil {
			return err
		}
		// key: strip the "rostor-" prefix and any extension → "linux-amd64", "agent-windows-amd64"
		k := strings.TrimSuffix(strings.TrimPrefix(name, "rostor-"), filepath.Ext(name))
		u := strings.TrimRight(*base, "/") + "/" + name
		if o, ok := overrides[name]; ok {
			u = o
		}
		m.Files[k] = update.File{URL: u, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}
	}
	if len(m.Files) == 0 {
		return fmt.Errorf("no rostor-* files in %s", *dir)
	}
	if err := update.Sign(&m, priv); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	fmt.Println(string(out))
	return nil
}
