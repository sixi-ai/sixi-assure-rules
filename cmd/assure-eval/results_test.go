package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResultsPath(t *testing.T) {
	t.Parallel()
	withResults := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(withResults, "golden-set", "results"), 0o750))
	without := t.TempDir()
	tests := []struct {
		flag, expected, want string
	}{
		{"auto", filepath.Join(withResults, "golden-set", "expected"), filepath.Join(withResults, "golden-set", "results", "latest.json")},
		{"auto", filepath.Join(withResults, "golden-set", "expected") + "/", filepath.Join(withResults, "golden-set", "results", "latest.json")},
		{"auto", filepath.Join(without, "golden-set", "expected"), ""}, // no results directory (the public mirror)
		{"off", filepath.Join(withResults, "golden-set", "expected"), ""},
		{"", filepath.Join(withResults, "golden-set", "expected"), ""},
		{"/tmp/x.json", "../golden-set/expected", "/tmp/x.json"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, resultsPath(tc.flag, tc.expected), "%q %q", tc.flag, tc.expected)
	}
}

func sampleReport() *report {
	return &report{
		Rules: 3, Pass: true, CatalogHash: "c0ffee",
		Models:   []modelResult{{Name: "a", Status: "evaluated"}, {Name: "b", Status: "no expected file"}},
		PackMeta: []packMeta{{Pack: "ai", Version: "0.3.0", Hash: "aaaa", Rules: 2}, {Pack: "zt", Version: "0.2.0", Hash: "bbbb", Rules: 3}},
		ByPack: []counter{{Rule: "*", Pack: "ai", TP: 9, Precision: 1, Recall: 1}, {Rule: "*", Pack: "zt", TP: 3, FN: 1, Precision: 1, Recall: 0.75, UnexercisedRules: []string{"ZT-009"}},
			{Rule: "*", Pack: "xyz?", FN: 1, Precision: 1, Recall: 0}},
		Authors:          map[string]int{ruleAuthors: 13},
		UnexercisedRules: []string{"ZT-009"},
	}
}

func TestWriteResultsIsStableAndPublishesPerPack(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "results", "latest.json")
	day1 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	written, err := writeResults(path, sampleReport(), day1)
	require.NoError(t, err)
	assert.True(t, written)
	var got published
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, resultsSchema, got.Schema)
	assert.Equal(t, "2026-10-01", got.RunDate)
	assert.Equal(t, "c0ffee", got.CatalogHash)
	assert.Equal(t, 1, got.Models, "only evaluated models count")
	require.Len(t, got.ByPack, 2, "a pack outside the catalog is not published")
	// Review fix (B4): each pack states its rule count and the rules no expectation exercises (none is [], not absent).
	assert.Equal(t, publishedPack{Pack: "zt", Version: "0.2.0", Hash: "bbbb", TP: 3, FN: 1, Precision: 1, Recall: 0.75,
		Rules: 3, UnexercisedRules: []string{"ZT-009"}}, got.ByPack[1])
	assert.Equal(t, []string{}, got.ByPack[0].UnexercisedRules)
	assert.Equal(t, []string{"ZT-009"}, got.UnexercisedRules)
	assert.Equal(t, map[string]int{ruleAuthors: 13}, got.Authors)

	// The bundle's LIMITATIONS.md reads by_pack's pack, precision and recall (internal/export readGolden).
	var asBundle struct {
		ByPack []struct {
			Pack      string  `json:"pack"`
			Precision float64 `json:"precision"`
			Recall    float64 `json:"recall"`
		} `json:"by_pack"`
	}
	require.NoError(t, json.Unmarshal(raw, &asBundle))
	assert.Equal(t, "ai", asBundle.ByPack[0].Pack)

	// Same packs, same numbers, a later day: the file (and its run date) stays.
	written, err = writeResults(path, sampleReport(), day1.AddDate(0, 0, 3))
	require.NoError(t, err)
	assert.False(t, written)
	raw2, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(raw), string(raw2))

	// A changed pack hash is a new measurement.
	changed := sampleReport()
	changed.PackMeta[0].Hash = "aaab"
	written, err = writeResults(path, changed, day1.AddDate(0, 0, 3))
	require.NoError(t, err)
	assert.True(t, written)
	raw3, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw3, &got))
	assert.Equal(t, "2026-10-04", got.RunDate)

	failing := sampleReport()
	failing.Pass = false
	_, err = writeResults(path, failing, day1)
	require.Error(t, err, "a failing run publishes nothing")
}

func TestReadExpectedAuthorship(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body, wantErr string
	}{
		{"no author", `[{"rule_id":"AI-001","ids":["e1"]}]`, ""},
		{"author and date", `[{"rule_id":"AI-001","ids":["e1"],"author":"A. Reviewer (external)","authored_at":"2026-10-01"}]`, ""},
		{"author without date", `[{"rule_id":"AI-001","ids":["e1"],"author":"rule-authors"}]`, ""},
		{"bad date", `[{"rule_id":"AI-001","ids":["e1"],"author":"x","authored_at":"01.10.2026"}]`, "not a YYYY-MM-DD date"},
		{"date without author", `[{"rule_id":"AI-001","ids":["e1"],"authored_at":"2026-10-01"}]`, "authored_at without an author"},
		{"multi-line author", `[{"rule_id":"AI-001","ids":["e1"],"author":"a\nb"}]`, "one line"},
		{"terminal escape in author", `[{"rule_id":"AI-001","ids":["e1"],"author":"\u001b[2Jx"}]`, "printable"},
		{"200 characters, not bytes", `[{"rule_id":"AI-001","ids":["e1"],"author":"` + strings.Repeat("ü", 200) + `"}]`, ""},
		{"201 characters", `[{"rule_id":"AI-001","ids":["e1"],"author":"` + strings.Repeat("a", 201) + `"}]`, "at most 200"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "x.json")
			require.NoError(t, os.WriteFile(path, []byte(tc.body), 0o600))
			_, err := readExpected(path)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestRunCountsExpectationsPerAuthor(t *testing.T) {
	t.Parallel()
	requireRepo(t)
	models, expected := t.TempDir(), t.TempDir()
	bad, err := os.ReadFile(repoPath("golden-set", "models", "a2a-agent-mesh-bad.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(models, "twin.json"), bad, 0o600))
	exp, err := os.ReadFile(repoPath("golden-set", "expected", "a2a-agent-mesh-bad.json"))
	require.NoError(t, err)
	var entries []map[string]any
	require.NoError(t, json.Unmarshal(exp, &entries))
	require.NotEmpty(t, entries)
	entries[0]["author"], entries[0]["authored_at"] = "Independent Reader", "2026-10-01"
	b, err := json.Marshal(entries)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(expected, "twin.json"), b, 0o600))

	rep, err := run(repoPath("packs"), repoPath("policy.yaml"), models, expected)
	require.NoError(t, err)
	assert.Equal(t, len(entries[0]["ids"].([]any)), rep.Authors["Independent Reader"])
	others := 0
	for _, e := range entries[1:] {
		others += len(e["ids"].([]any))
	}
	assert.Equal(t, others, rep.Authors[ruleAuthors], "every other entry counts under the rule authors")
	assert.NotEmpty(t, rep.CatalogHash)
	assert.Len(t, rep.PackMeta, rep.Packs)
}
