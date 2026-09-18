package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

func TestRatiosAndKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tp, fp, fn int
		p, r       float64
	}{{0, 0, 0, 1, 1}, {2, 0, 0, 1, 1}, {1, 1, 0, 0.5, 1}, {1, 0, 3, 1, 0.25}, {0, 2, 1, 0, 0}}
	for _, tc := range tests {
		p, r := ratios(tc.tp, tc.fp, tc.fn)
		assert.InDelta(t, tc.p, p, 1e-9)
		assert.InDelta(t, tc.r, r, 1e-9)
	}
	assert.Equal(t, "ZT-001:a,b", key("ZT-001", []string{"b", "a"}))
	assert.Equal(t, []string{"AI-005:n_agent", "AI-005:n_llm"}, keys("AI-005", []string{"n_llm", "n_agent", "n_llm"}))
	assert.Equal(t, "cra?", packOfUnknown("CRA-001"))
	assert.Equal(t, "?", packOfUnknown("weird"))
}

func TestRunAgainstRepositoryGoldenSet(t *testing.T) {
	if _, err := os.Stat(repoPath("packs")); err != nil {
		t.Skip("rules packs not present")
	}
	rep, err := run(repoPath("packs"), repoPath("policy.yaml"), repoPath("golden-set", "models"), repoPath("golden-set", "expected"))
	require.NoError(t, err)
	assert.Positive(t, rep.Rules)
	assert.Len(t, rep.Fixtures, 2*rep.Rules, "every rule has a positive and a negative fixture")
	for _, f := range rep.Fixtures {
		assert.True(t, f.OK, "%s %s: %s", f.RuleID, f.Kind, f.Error)
	}
	assert.True(t, rep.Pass, strings.Join(rep.Failures, "\n"))
	var buf bytes.Buffer
	printReport(&buf, rep, true)
	assert.Contains(t, buf.String(), "PASS")
	assert.Regexp(t, `rule\s+pack\s+TP\s+FP\s+FN\s+precision\s+recall`, buf.String())
}

func TestRunReportsMissingExpectedAndThresholds(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat(repoPath("packs")); err != nil {
		t.Skip("rules packs not present")
	}
	models := t.TempDir()
	expected := t.TempDir()
	bad, err := os.ReadFile(repoPath("golden-set", "models", "rag-chatbot-bad.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(models, "twin.json"), bad, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(models, "orphan.json"), bad, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(models, "broken.json"), []byte("{"), 0o600))
	// Expect a rule that will not fire (FN) and nothing else → every fired rule is an FP.
	require.NoError(t, os.WriteFile(filepath.Join(expected, "twin.json"), []byte(`[{"rule_id":"ZT-003","ids":["e_user_web"]},{"rule_id":"XYZ-001","ids":["n_user"]}]`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(expected, "broken.json"), []byte(`[]`), 0o600))

	rep, err := run(repoPath("packs"), repoPath("policy.yaml"), models, expected)
	require.NoError(t, err)
	assert.False(t, rep.Pass)
	status := map[string]string{}
	for _, m := range rep.Models {
		status[m.Name] = m.Status
	}
	assert.Equal(t, "no expected file", status["orphan"])
	assert.Equal(t, "evaluated", status["twin"])
	assert.Equal(t, "error", status["broken"])
	joined := strings.Join(rep.Failures, "\n")
	assert.Contains(t, joined, "pack zt: precision")
	assert.Contains(t, joined, "pack zt: recall")
	// A pack that expects nothing but raises findings fails on precision too (it once passed silently).
	assert.Contains(t, joined, "pack ai: precision 0.000")
	assert.Contains(t, joined, "model broken")
	byRule := map[string]counter{}
	for _, c := range rep.ByRule {
		byRule[c.Rule] = c
	}
	assert.Equal(t, 1, byRule["ZT-003"].FN)
	assert.Equal(t, "xyz?", byRule["XYZ-001"].Pack, "expected rule outside every pack is reported, not silently dropped")
	assert.Positive(t, byRule["ZT-001"].FP)

	var buf bytes.Buffer
	printReport(&buf, rep, true)
	assert.Contains(t, buf.String(), "FAIL")
	assert.Contains(t, buf.String(), "FN twin:ZT-003:e_user_web")

	_, err = run(t.TempDir(), repoPath("policy.yaml"), models, expected)
	require.Error(t, err, "empty packs dir has no rules → load error")
}
