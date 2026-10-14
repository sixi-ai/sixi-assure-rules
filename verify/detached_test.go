package verify

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A board summary is a PDF signed with the organisation's key (ADR-107): `assure verify -signature x.pdf.sig x.pdf`
// checks the bytes against the signature and the published keys, and nothing it cannot see.
func TestMainDetachedSignature(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key := newTestKey(t, CustodyVendor, "sealed", t0.Add(-24*time.Hour), nil)
	other := newTestKey(t, CustodyVendor, "sealed", t0.Add(-24*time.Hour), nil)
	pdf := []byte("%PDF-1.7\n% a board summary\n")
	file := filepath.Join(dir, "sixi-assure-board-summary-acme-20261014.pdf")
	require.NoError(t, os.WriteFile(file, pdf, 0o600))
	sig := file + ".sig"
	require.NoError(t, os.WriteFile(sig, signEnvelope(t, key, pdf, envelope{ExportID: "bs_1", Kind: "board_summary", Format: "pdf",
		PackHash: "p", CorpusHash: "c", SignedAt: t0.Add(time.Hour)}), 0o600))
	keys := filepath.Join(dir, "keys.json")
	writeJSON(t, keys, map[string]any{"keys": []Key{key.pub}})
	otherKeys := filepath.Join(dir, "other-keys.json")
	writeJSON(t, otherKeys, map[string]any{"keys": []Key{other.pub}})
	changed := filepath.Join(dir, "changed.pdf")
	require.NoError(t, os.WriteFile(changed, append(bytes.Clone(pdf), ' '), 0o600))

	tests := []struct {
		name   string
		args   []string
		code   int
		stdout []string
		stderr string
	}{
		{name: "verifies against the published keys", args: []string{"-signature", sig, "-keys", keys, file}, code: ExitVerified,
			stdout: []string{"board_summary bs_1 (pdf)", "file signature", "pass"}},
		{name: "a changed file fails", args: []string{"-signature", sig, "-keys", keys, changed}, code: ExitFailed, stdout: []string{"the file changed"}},
		{name: "another organisation's keys fail", args: []string{"-signature", sig, "-keys", otherKeys, file}, code: ExitFailed, stdout: []string{"not in the key list"}},
		{name: "without keys nothing is checked", args: []string{"-signature", sig, file}, code: ExitVerified, stdout: []string{"NOT CHECKED"}},
		{name: "strict without keys fails", args: []string{"-strict", "-signature", sig, file}, code: ExitFailed},
		{name: "missing signature", args: []string{"-signature", filepath.Join(dir, "absent.sig"), "-keys", keys, file}, code: ExitUsage, stderr: "no such file"},
		{name: "a directory is not a file", args: []string{"-signature", sig, "-keys", keys, dir}, code: ExitUsage, stderr: "is a directory"},
	}
	for _, tc := range tests {
		var out, errOut bytes.Buffer
		code := Main("assure verify", tc.args, &out, &errOut)
		assert.Equal(t, tc.code, code, "%s: stdout %s stderr %s", tc.name, out.String(), errOut.String())
		for _, s := range tc.stdout {
			assert.Contains(t, out.String(), s, tc.name)
		}
		assert.Contains(t, errOut.String(), tc.stderr, tc.name)
	}

	var out bytes.Buffer
	require.Equal(t, ExitVerified, Main("assure verify", []string{"-json", "-signature", sig, "-keys", keys, file}, &out, &bytes.Buffer{}))
	var rep Report
	require.NoError(t, json.Unmarshal(out.Bytes(), &rep))
	assert.Equal(t, KindSignedFile, rep.Kind)
	assert.Equal(t, Pass, checkOf(t, &rep, SectionSignatures, "file signature").Status)
}
