package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/rules/sarif"
)

func ciReports() []fileReport {
	return []fileReport{{
		File: "models/a.sixi.json", OK: true,
		raw: []byte("{\n  \"nodes\": [\n    {\"id\": \"n_agent\"}\n  ]\n}\n"),
		Findings: []finding{
			{RuleID: "AI-003", Pack: "ai", Severity: "high", IDs: []string{"n_agent"}, Title: "No human approval",
				Message: "The agent writes without approval.", Remediation: "Add an approval step.",
				Clauses: []clause{{ID: "AIACT:2024/1689:Art14", Known: true}, {ID: "NOPE:0:0", Known: false}}},
			{RuleID: "LOG-005", Pack: "log", Severity: "medium", IDs: []string{"e1"}, Message: "Tool calls not logged."},
		},
	}}
}

func TestCIOutputs(t *testing.T) {
	tests := []struct {
		name     string
		reports  []fileReport
		failOn   string
		code     int
		mdHas    []string
		mdHasNot []string
	}{
		{name: "gate refused", reports: ciReports(), failOn: "high", code: 1,
			mdHas: []string{"`models/a.sixi.json`", "**2 open findings**", "**Gate: refused** at high", "`NOPE:0:0` (no clause found)"}},
		{name: "no gate", reports: ciReports(),
			mdHas: []string{"| high | 1 |", "| medium | 1 |"}, mdHasNot: []string{"Gate:"}},
		{name: "an invalid file is listed and there is no gate line", failOn: "high", code: 1,
			reports: append(ciReports(), fileReport{File: "models/broken.json"}),
			mdHas:   []string{"Assessed 1 of 2 model files: `models/a.sixi.json`", "1 of 2 model files failed validation", "`models/broken.json`"}, mdHasNot: []string{"Gate:"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			step := filepath.Join(dir, "step")
			t.Setenv(stepSummaryEnv, step)
			o := ciOutputs{sarifPath: filepath.Join(dir, "out.sarif"), summaryPath: filepath.Join(dir, "s.md"), stepSummary: true}
			var stdout, stderr strings.Builder
			require.NoError(t, o.write(tc.reports, tc.failOn, tc.code, &stdout, &stderr))

			raw, err := os.ReadFile(o.sarifPath)
			require.NoError(t, err)
			var log sarif.Log
			require.NoError(t, json.Unmarshal(raw, &log))
			res := log.Runs[0].Results
			require.Len(t, res, 2)
			assert.Equal(t, "error", res[0].Level)
			assert.Equal(t, "models/a.sixi.json", res[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
			assert.Equal(t, 3, res[0].Locations[0].PhysicalLocation.Region.StartLine)
			assert.Equal(t, 1, res[1].Locations[0].PhysicalLocation.Region.StartLine, "an element the file does not declare → line 1")
			assert.Contains(t, res[0].Message.Text, "NOPE:0:0 (no clause found)")

			md, err := os.ReadFile(o.summaryPath)
			require.NoError(t, err)
			appended, err := os.ReadFile(step)
			require.NoError(t, err)
			assert.Equal(t, string(md)+"\n", string(appended))
			for _, s := range tc.mdHas {
				assert.Contains(t, string(md), s)
			}
			for _, s := range tc.mdHasNot {
				assert.NotContains(t, string(md), s)
			}
			for _, w := range []string{"compliant", "certified", "guarantee", "confirms"} {
				assert.NotContains(t, strings.ToLower(string(md)), w)
			}
		})
	}
}

func TestStepSummaryUnset(t *testing.T) {
	t.Setenv(stepSummaryEnv, "")
	var stdout, stderr strings.Builder
	require.NoError(t, ciOutputs{stepSummary: true}.write(ciReports(), "", 0, &stdout, &stderr))
	assert.Contains(t, stderr.String(), "is not set")
}

func TestSummaryToStdout(t *testing.T) {
	var stdout, stderr strings.Builder
	require.NoError(t, ciOutputs{summaryPath: "-"}.write(ciReports(), "", 0, &stdout, &stderr))
	assert.Contains(t, stdout.String(), "## Sixi Assure design assessment")
}

// TestSummaryFileNameCannotInjectMarkdown: a file name is untrusted. A newline in it would end the
// code span in $GITHUB_STEP_SUMMARY and let the rest render as Markdown.
func TestSummaryFileNameCannotInjectMarkdown(t *testing.T) {
	evil := "models/x.json\n## Pwned\n[click](https://evil.example)\r`|"
	reports := append(ciReports(), fileReport{File: evil})
	md := summary(reports, sarifFindings(reports), "high", 1)
	assert.NotContains(t, md, "\n## Pwned")
	assert.NotContains(t, md, "\r")
	assert.Contains(t, md, "`models/x.json ## Pwned [click](https:/evil.example) '\\|`", "cleaned path, one code span")
	for _, line := range strings.Split(md, "\n") {
		assert.False(t, strings.HasPrefix(line, "## Pwned"), "no line starts with the injected heading")
	}
}

// TestPlainReportKeepsModelTextOnOneLine: stdout is parsed by the runner for workflow commands, so
// model text with a newline must never start a line of its own.
func TestPlainReportKeepsModelTextOnOneLine(t *testing.T) {
	r := fileReport{File: "m.json\n::error::file", OK: true, Findings: []finding{{
		RuleID: "AI-003\n::add-mask::x", Severity: "high", IDs: []string{"n1\n::warning::y"},
		Message: "ok\n::set-output name=x::1\r\x1b[31m", Remediation: "fix\n::stop-commands::t",
		Clauses: []clause{{ID: "X:1\n::group::g", Known: true, Cite: "c\n::endgroup::"}, {ID: "Y\n::debug::d"}},
	}}}
	fail := fileReport{File: "bad.json", Problems: []model.Problem{{Path: "/\n::error::p", Message: "m\n::error::q"}}}
	var b strings.Builder
	print(&b, r)
	print(&b, fail)
	for _, line := range strings.Split(b.String(), "\n") {
		assert.False(t, strings.HasPrefix(strings.TrimSpace(line), "::"), "line %q starts a workflow command", line)
	}
	assert.NotContains(t, b.String(), "\x1b")
	assert.NotContains(t, b.String(), "\r")
}
