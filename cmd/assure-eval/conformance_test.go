package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/rules"
)

// conformanceCase is one row of testdata/conformance/cases.json. The same rows drive `assure eval`
// (server/cmd/assure/eval_test.go TestEvalConformance): the two commands are one measurement (docs/18 B4), so they
// must reach the same verdict, counts, authors and unexercised rules on the same inputs.
type conformanceCase struct {
	Name             string          `json:"name"`
	Expected         json.RawMessage `json:"expected"`
	Pass             bool            `json:"pass"`
	TP               int             `json:"tp"`
	FP               int             `json:"fp"`
	FN               int             `json:"fn"`
	Failure          string          `json:"failure"`
	Authors          map[string]int  `json:"authors"`
	UnexercisedRules []string        `json:"unexercised_rules"`
}

func conformanceCases(t *testing.T) []conformanceCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "conformance", "cases.json"))
	require.NoError(t, err)
	var cases []conformanceCase
	require.NoError(t, json.Unmarshal(raw, &cases))
	require.NotEmpty(t, cases)
	return cases
}

func TestConformance(t *testing.T) {
	t.Parallel()
	requireRepo(t)
	dir := filepath.Join("testdata", "conformance")
	for _, tc := range conformanceCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			expected := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(expected, "twin-bad.json"), tc.Expected, 0o600))
			rep, err := run(filepath.Join(dir, "packs"), repoPath("policy.yaml"), filepath.Join(dir, "models"), expected)
			require.NoError(t, err)
			assert.Equal(t, tc.Pass, rep.Pass, "verdict (cmd/eval exits 1 when it is false): %v", rep.Failures)
			if tc.Failure != "" {
				assert.True(t, slices.ContainsFunc(rep.Failures, func(f string) bool { return strings.Contains(f, tc.Failure) }),
					"a failure names %q: %v", tc.Failure, rep.Failures)
			}
			i := slices.IndexFunc(rep.ByPack, func(c counter) bool { return c.Pack == "tst" })
			require.GreaterOrEqual(t, i, 0)
			assert.Equal(t, []int{tc.TP, tc.FP, tc.FN}, []int{rep.ByPack[i].TP, rep.ByPack[i].FP, rep.ByPack[i].FN})
			assert.Equal(t, tc.Authors, rep.Authors)
			assert.Equal(t, tc.UnexercisedRules, rep.UnexercisedRules)
			assert.Equal(t, tc.UnexercisedRules, rep.ByPack[i].UnexercisedRules)
			var out strings.Builder
			printReport(&out, rep, false)
			assert.NotContains(t, out.String(), "\x1b", "no terminal escape reaches the output")
		})
	}
}

// golden-set/results/latest.json is the result of the packs on disk: a change to a pack, a golden model or an
// expected file without a re-run of `make eval` (which rewrites it on a passing run) fails here, so the published
// numbers cannot go stale silently (docs/18 B4). A checkout without golden-set/results (the public mirror) skips.
func TestPublishedResultIsCurrent(t *testing.T) {
	t.Parallel()
	requireRepo(t)
	path := resultsPath("auto", repoPath("golden-set", "expected"))
	if path == "" {
		t.Skip("no golden-set/results directory in this checkout")
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "golden-set/results exists but holds no latest.json: run `make eval`")
	var got published
	require.NoError(t, json.Unmarshal(raw, &got))
	rep, err := run(repoPath("packs"), repoPath("policy.yaml"), repoPath("golden-set", "models"), repoPath("golden-set", "expected"))
	require.NoError(t, err)
	require.True(t, rep.Pass, "the golden set fails, so no result can be published: %v", rep.Failures)
	want := publishedOf(rep, time.Now())
	want.RunDate = got.RunDate
	a, err := json.Marshal(want)
	require.NoError(t, err)
	b, err := json.Marshal(got)
	require.NoError(t, err)
	assert.JSONEq(t, string(a), string(b), "golden-set/results/latest.json is stale: run `make eval` and commit the file")
}

// Every rule of a pack with published numbers either has a golden expectation or is listed as unexercised, read
// independently of run(): from the expected files themselves.
func TestEveryPublishedRuleIsExpectedOrListedUnexercised(t *testing.T) {
	t.Parallel()
	requireRepo(t)
	catalog, err := rules.LoadDir(repoPath("packs"))
	require.NoError(t, err)
	expectedRules := map[string]bool{}
	files, err := filepath.Glob(repoPath("golden-set", "expected", "*.json"))
	require.NoError(t, err)
	for _, f := range files {
		if _, err := os.Stat(repoPath("golden-set", "models", filepath.Base(f))); err != nil {
			continue // an expected file without its model is not evaluated
		}
		exp, err := readExpected(f)
		require.NoError(t, err)
		for _, x := range exp {
			expectedRules[x.RuleID] = true
		}
	}
	rep, err := run(repoPath("packs"), repoPath("policy.yaml"), repoPath("golden-set", "models"), repoPath("golden-set", "expected"))
	require.NoError(t, err)
	listed := map[string]bool{}
	for _, id := range rep.UnexercisedRules {
		listed[id] = true
	}
	for _, r := range catalog.Rules() {
		assert.True(t, expectedRules[r.ID] != listed[r.ID],
			"%s (pack %s): expected by the golden set=%v, listed unexercised=%v: exactly one must hold", r.ID, r.Pack, expectedRules[r.ID], listed[r.ID])
	}
	pub := publishedOf(&report{Pass: true, PackMeta: rep.PackMeta, ByPack: rep.ByPack, UnexercisedRules: rep.UnexercisedRules}, time.Now())
	for _, p := range pub.ByPack {
		for _, id := range p.UnexercisedRules {
			assert.True(t, listed[id], "%s is listed under pack %s", id, p.Pack)
		}
		assert.NotNil(t, p.UnexercisedRules, "pack %s states its unexercised rules, even none", p.Pack)
	}
}
