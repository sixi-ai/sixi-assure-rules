package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ---- any file against its detached signature (-signature: a board summary's PDF, an exit bundle's zip) ----------

// maxSignature bounds a signature file: an envelope is well under a kilobyte.
const maxSignature = 64 << 10

// runDetached checks one file against a detached signature and the key list, and nothing else: the file's sha256, the
// signed message, the Ed25519 signature against the listed key, and the signing time inside the key's validity window.
// What the file says is not read; it is bytes.
func runDetached(o Options, now time.Time, tool string) (*Report, error) {
	data, err := readCapped(o.Path, maxTotal)
	if err != nil {
		return nil, err
	}
	sig, err := readCapped(o.SignatureFile, maxSignature)
	if err != nil {
		return nil, fmt.Errorf("%w (-signature)", err)
	}
	r := &Report{Tool: tool, Version: Version, Input: o.Path, Kind: KindSignedFile, VerifiedAt: now.UTC()}
	var e envelope
	if json.Unmarshal(sig, &e) == nil && e.Kind != "" {
		r.add(SectionInput, "signed file", Info, "%s %s (%s), signed %s by key %s", oneLine(e.Kind), orNA(oneLine(e.ExportID)),
			orNA(oneLine(e.Format)), e.SignedAt.UTC().Format(time.RFC3339), orNA(oneLine(e.KeyID)))
	}
	var kr *keyring
	if o.KeysFile == "" {
		r.add(SectionKeys, "key list", NotChecked, "the key list is %s (pass --keys with the organisation's saved GET /evidence/keys): the signature cannot be checked against a key", NotPresent)
	} else {
		raw, err := os.ReadFile(filepath.Clean(o.KeysFile)) // #nosec G304 -- the reviewer names the key list
		if err != nil {
			return nil, fmt.Errorf("%w: --keys: %w", ErrInput, err)
		}
		keys, err := ParseKeys(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: --keys %s: %w", ErrInput, o.KeysFile, err)
		}
		r.add(SectionKeys, "key list", Info, "%d key(s) from %s", len(keys), o.KeysFile)
		kr = newKeyring(o.KeysFile, keys)
	}
	checkEnvelope(r, kr, "file", data, sig, stated{})
	if kr != nil {
		kr.custody(r)
	}
	r.finish()
	return r, nil
}

// readCapped reads one named file of at most limit bytes.
func readCapped(p string, limit int64) ([]byte, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInput, err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%w: %s is a directory, not a file", ErrInput, p)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrInput, p, limit)
	}
	data, err := os.ReadFile(filepath.Clean(p)) // #nosec G304 -- the reviewer names the file on the command line
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInput, err)
	}
	return data, nil
}
