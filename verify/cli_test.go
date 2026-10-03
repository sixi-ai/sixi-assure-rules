package verify

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainExitCodesAndOutput(t *testing.T) {
	t.Parallel()
	dir := tinyReport(t, nil)
	report := filepath.Join(dir, "report.json")
	packs := filepath.Join(dir, "packs")
	tests := []struct {
		name     string
		args     []string
		code     int
		stdout   []string
		stderr   string
		notInOut []string
	}{
		{name: "no path", args: nil, code: ExitUsage, stderr: "usage:"},
		{name: "two paths", args: []string{report, report}, code: ExitUsage, stderr: "usage:"},
		{name: "unknown flag", args: []string{"-nope", report}, code: ExitUsage},
		{name: "help", args: []string{"-h"}, code: ExitVerified},
		{name: "missing input", args: []string{filepath.Join(dir, "absent.json")}, code: ExitUsage, stderr: "no such file"},
		{name: "not an input", args: []string{filepath.Join(packs, "tiny.yaml")}, code: ExitUsage, stderr: "not a JSON object"},
		{name: "flags after the path", args: []string{report, "-rules", packs}, code: ExitVerified,
			stdout: []string{"pass", "rules re-run on the snapshot", "NOT CHECKED", NotPresent, "What this verification does not establish:",
				"that the model matches the operated system", "that a key held by Sixi (custody vendor) was not misused by its custodian"},
			notInOut: []string{"certif", "guarantee", "confirm", "compliant", "attest"}},
		{name: "strict refuses checks not made", args: []string{"-strict", report, "-rules", packs}, code: ExitFailed},
		{name: "bad -at", args: []string{"-at", "yesterday", report}, code: ExitUsage},
	}
	for _, tc := range tests {
		var out, errOut bytes.Buffer
		code := Main("assure verify", tc.args, &out, &errOut)
		assert.Equal(t, tc.code, code, "%s: stdout %s stderr %s", tc.name, out.String(), errOut.String())
		for _, s := range tc.stdout {
			assert.Contains(t, out.String(), s, tc.name)
		}
		for _, s := range tc.notInOut {
			assert.NotContains(t, strings.ToLower(out.String()), s, tc.name)
		}
		assert.Contains(t, errOut.String(), tc.stderr, tc.name)
	}
}

func TestMainJSON(t *testing.T) {
	t.Parallel()
	dir := tinyReport(t, nil)
	var out, errOut bytes.Buffer
	code := Main("assure-check verify", []string{"-json", "-rules", filepath.Join(dir, "packs"), filepath.Join(dir, "report.json")}, &out, &errOut)
	require.Equal(t, ExitVerified, code, errOut.String())
	var rep Report
	require.NoError(t, json.Unmarshal(out.Bytes(), &rep))
	assert.Equal(t, "assure-check verify", rep.Tool)
	assert.Equal(t, Version, rep.Version)
	assert.Equal(t, KindReport, rep.Kind)
	assert.Equal(t, ResultIncomplete, rep.Result)
	assert.Equal(t, DoesNotEstablish, rep.DoesNotEstablish)
	assert.Positive(t, rep.NotChecked)
	require.NotNil(t, rep.Reproduction)
	assert.Len(t, rep.Reproduction.Matched, 2)
}

func TestOneLineKeepsInputOnOneLine(t *testing.T) {
	t.Parallel()
	r := &Report{Tool: "assure verify", Input: "x\n::set-output name=x::y", Kind: KindReport}
	r.add(SectionInput, "name\r\nwith break", Info, "detail %s", "\x1b[31mred")
	r.finish()
	var b bytes.Buffer
	require.NoError(t, r.WriteText(&b))
	for _, line := range strings.Split(b.String(), "\n") {
		assert.False(t, strings.HasPrefix(strings.TrimSpace(line), "::"), line)
	}
	assert.NotContains(t, b.String(), "\x1b")
}

// TestVerifierImportsNothingThatTalks: the verifier package and the mirrored token code import the
// standard library, internal/model (and model/migrate), internal/rules and each other — nothing that opens a socket,
// starts a process or reaches the product's configuration, store or HTTP stack (docs/18 A4: no
// network). The kernel-level check that a run opens no socket is in cmd/assure.
func TestVerifierImportsNothingThatTalks(t *testing.T) {
	t.Parallel()
	// internal/model/migrate upgrades a snapshot to the current schema before the re-run (docs/18
	// D1); it imports the standard library only.
	allowedLocal := map[string]bool{"github.com/sixi-ai/sixi-assure-rules/model": true, "github.com/sixi-ai/sixi-assure-rules/rules": true,
		"github.com/sixi-ai/sixi-assure-rules/model/migrate": true, "github.com/sixi-ai/sixi-assure-rules/verify/tsp": true}
	forbidden := []string{"net", "net/", "os/exec", "syscall", "plugin", "unsafe", "crypto/tls"}
	for _, dir := range []string{".", "tsp"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		require.NoError(t, err)
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			require.NoError(t, err)
			pf, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
			require.NoError(t, err)
			for _, imp := range pf.Imports {
				p, err := strconv.Unquote(imp.Path.Value)
				require.NoError(t, err)
				if strings.Contains(strings.Split(p, "/")[0], ".") {
					assert.True(t, allowedLocal[p], "%s imports %s", f, p)
					continue
				}
				for _, bad := range forbidden {
					assert.False(t, p == bad || (strings.HasSuffix(bad, "/") && strings.HasPrefix(p, bad)), "%s imports %s", f, p)
				}
			}
		}
	}
}
