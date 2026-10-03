package verify

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Limits on what the verifier reads: an input is untrusted, and a zip can expand.
const (
	maxMember  = 64 << 20  // one file
	maxTotal   = 512 << 20 // a whole bundle, uncompressed
	maxMembers = 20000
)

// ErrInput is an input the verifier cannot read at all (a usage error, not a failed check).
var ErrInput = errors.New("verify: unreadable input")

// Bundle member names (docs/18 A5; the reviewer bundle writes exactly these).
const (
	MemberManifest  = "manifest.json"
	MemberReport    = "report.json"
	MemberReportSig = "report.json.sig"
	MemberSnapshot  = "snapshot.json"
	MemberChain     = "chain.json"
	MemberKeys      = "keys.json"
	MemberAnchors   = "anchors"
	MemberRules     = "rules"
	MemberCorpus    = "corpus/records.json"
)

// source is the opened input: a bundle (directory or zip) or a single JSON file whose siblings may
// be read (report.json.sig beside a report, anchors/ beside a chain export).
type source struct {
	kind  string
	name  string
	fsys  fs.FS  // bundle root, or the directory holding the single file
	file  string // the single file's name inside fsys ("" for a bundle)
	data  []byte // the single file's bytes
	close func() error
	// listed is the manifest's path → sha256 once the manifest verified its members; nil means
	// every member may be read (no manifest).
	listed map[string]string
}

func (s *source) Close() error {
	if s.close != nil {
		return s.close()
	}
	return nil
}

func (s *source) bundle() bool { return s.kind == KindBundleDir || s.kind == KindBundleZip }

// open opens path as a bundle directory, a bundle zip or a JSON file.
func open(p string) (*source, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInput, err)
	}
	if st.IsDir() {
		root := bundleRoot(os.DirFS(p))
		return &source{kind: KindBundleDir, name: p, fsys: root}, nil
	}
	f, err := os.Open(filepath.Clean(p)) // #nosec G304 -- the reviewer names the file to verify on the command line
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInput, err)
	}
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInput, err)
	}
	if n == 4 && bytes.Equal(head, []byte("PK\x03\x04")) {
		return openZip(p)
	}
	if st.Size() > maxMember {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrInput, p, maxMember)
	}
	data, err := os.ReadFile(filepath.Clean(p)) // #nosec G304 -- as above
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInput, err)
	}
	kind, err := sniff(data)
	if err != nil {
		return nil, err
	}
	return &source{kind: kind, name: p, fsys: os.DirFS(filepath.Dir(p)), file: filepath.Base(p), data: data}, nil
}

func openZip(p string) (*source, error) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return nil, fmt.Errorf("%w: not a readable zip: %w", ErrInput, err)
	}
	if len(zr.File) > maxMembers {
		_ = zr.Close()
		return nil, fmt.Errorf("%w: the zip holds more than %d members", ErrInput, maxMembers)
	}
	var total uint64
	for _, f := range zr.File {
		name := strings.TrimSuffix(f.Name, "/")
		if !fs.ValidPath(name) || strings.Contains(f.Name, `\`) {
			_ = zr.Close()
			return nil, fmt.Errorf("%w: the zip holds an unsafe member path %q", ErrInput, oneLine(f.Name))
		}
		total += f.UncompressedSize64
	}
	if total > maxTotal {
		_ = zr.Close()
		return nil, fmt.Errorf("%w: the zip expands to more than %d bytes", ErrInput, maxTotal)
	}
	return &source{kind: KindBundleZip, name: p, fsys: bundleRoot(zr), close: zr.Close}, nil
}

// bundleRoot accepts a bundle whose members sit under one top-level directory (<bundle id>/…).
func bundleRoot(fsys fs.FS) fs.FS {
	if _, err := fs.Stat(fsys, MemberManifest); err == nil {
		return fsys
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return fsys
	}
	sub, err := fs.Sub(fsys, entries[0].Name())
	if err != nil {
		return fsys
	}
	if _, err := fs.Stat(sub, MemberManifest); err != nil {
		return fsys
	}
	return sub
}

// sniff tells what a JSON file is by the keys it carries.
func sniff(data []byte) (string, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("%w: not a JSON object, a directory or a zip: %w", ErrInput, err)
	}
	has := func(k string) bool { _, ok := probe[k]; return ok }
	switch {
	case has("receipt") && has("snapshot"):
		return KindSpotCheck, nil
	case has("events") && (has("head_hash") || has("anchors")):
		return KindChain, nil
	case has("findings") && (has("architecture") || has("schema")):
		return KindReport, nil
	}
	return "", fmt.Errorf("%w: the JSON is neither an Assurance Report, a spot-check receipt nor a chain export", ErrInput)
}

// read returns a bundle member (or a sibling of a single file) and whether it exists. A member the
// manifest does not list is not read once the manifest has been checked.
func (s *source) read(name string) ([]byte, bool, error) {
	name = path.Clean(name)
	if s.listed != nil {
		if _, ok := s.listed[name]; !ok {
			return nil, false, nil
		}
	}
	f, err := s.fsys.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if st.IsDir() {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxMember+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxMember {
		return nil, false, fmt.Errorf("%s is larger than %d bytes", name, maxMember)
	}
	return data, true, nil
}
