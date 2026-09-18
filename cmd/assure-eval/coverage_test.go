package main

// Golden-set coverage gate (docs/09 §2, Phase 6). `make eval` already fails below the
// precision/recall thresholds; these tests assert the *shape* of the evidence behind those
// numbers, so a rule or a pack cannot be shipped without a case that exercises it:
//
//	10 models, each with an expected file        (docs/09 §2: 5 templates + 5 bad twins)
//	every rule id has a positive and a negative fixture that exists and behaves
//	every pack is exercised by at least one golden model (documented exceptions only)

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/rules"
)

// goldenModelCount is the size of the golden set (docs/09 §2).
const goldenModelCount = 12

// packsNotInGoldenModels are packs no hand-authored golden model can exercise, with the reason
// and where they are covered instead. Every entry is a deliberate gap: keep this list empty
// unless a rule can only fire on machine-generated input.
var packsNotInGoldenModels = map[string]string{
	"imp": "IMP-001 fires on x_unmapped_style, an attribute only the draw.io importer writes " +
		"(the draw.io importer in the Sixi Assure product); covered by packs/fixtures/IMP-001.{pos,neg}.json, " +
		"the importer golden files (the importer golden files in the Sixi Assure product)",
	"drift": "drift rules need knowledge facts (kb.available); the golden set is evaluated without facts " +
		"so every DRF rule is silent there by design; exercised by packs/fixtures/DRF-00N.{pos,neg,kb}.json " +
		"and the A6 curator test",
}

func requireRepo(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(repoPath("packs")); err != nil {
		t.Skip("rules packs not present")
	}
}

// TestGoldenSetModelsHaveExpectations: 12/12, no orphans in either direction.
func TestGoldenSetModelsHaveExpectations(t *testing.T) {
	t.Parallel()
	requireRepo(t)
	models := jsonNames(t, repoPath("golden-set", "models"))
	expected := jsonNames(t, repoPath("golden-set", "expected"))
	assert.Len(t, models, goldenModelCount, "the golden set is %d architectures (docs/09 §2): %v", goldenModelCount, models)
	assert.Equal(t, models, expected, "every model needs an expected file and vice versa")

	// The bad twins must actually expect findings; the clean templates may expect none.
	for _, name := range models {
		exp, err := readExpected(filepath.Join(repoPath("golden-set", "expected"), name+".json"))
		require.NoError(t, err, name)
		if strings.HasSuffix(name, "-bad") {
			assert.NotEmpty(t, exp, "%s: a bad twin with no expected finding proves nothing", name)
		}
		for _, e := range exp {
			assert.NotEmpty(t, e.RuleID, "%s: an expectation without a rule id", name)
			assert.NotEmpty(t, e.IDs, "%s: %s expects no element ids", name, e.RuleID)
		}
	}
}

// TestEveryRuleHasWorkingFixtures: one positive and one negative file per rule, both present on
// disk and both behaving (the behaviour check is the eval run itself).
func TestEveryRuleHasWorkingFixtures(t *testing.T) {
	t.Parallel()
	requireRepo(t)
	catalog, err := rules.LoadDir(repoPath("packs"))
	require.NoError(t, err)
	require.NotEmpty(t, catalog.Rules())

	for _, r := range catalog.Rules() {
		for kind, path := range map[string]string{"positive": r.Fixtures.Positive, "negative": r.Fixtures.Negative} {
			require.NotEmpty(t, path, "%s: no %s fixture declared", r.ID, kind)
			_, err := os.Stat(path)
			assert.NoError(t, err, "%s: %s fixture %s is missing", r.ID, kind, path)
		}
	}

	rep, err := run(repoPath("packs"), repoPath("policy.yaml"),
		repoPath("golden-set", "models"), repoPath("golden-set", "expected"))
	require.NoError(t, err)
	seen := map[string]int{}
	for _, f := range rep.Fixtures {
		assert.True(t, f.OK, "%s %s: %s", f.RuleID, f.Kind, f.Error)
		seen[f.RuleID]++
	}
	for _, r := range catalog.Rules() {
		assert.Equal(t, 2, seen[r.ID], "%s: expected a positive and a negative fixture result", r.ID)
	}
}

// TestEveryPackIsExercisedByAGoldenModel: a pack with no expected finding anywhere in the golden
// set is only measured by its fixtures, so its thresholds are vacuous. Such a pack must be listed
// in packsNotInGoldenModels with a reason.
func TestEveryPackIsExercisedByAGoldenModel(t *testing.T) {
	t.Parallel()
	requireRepo(t)
	rep, err := run(repoPath("packs"), repoPath("policy.yaml"),
		repoPath("golden-set", "models"), repoPath("golden-set", "expected"))
	require.NoError(t, err)
	require.True(t, rep.Pass, strings.Join(rep.Failures, "\n"))

	exercised := map[string]int{}
	for _, p := range rep.ByPack {
		exercised[p.Pack] = p.TP + p.FN
		t.Logf("pack %-5s TP=%d FP=%d FN=%d precision=%.3f recall=%.3f", p.Pack, p.TP, p.FP, p.FN, p.Precision, p.Recall)
	}
	for pack, n := range exercised {
		if why, exempt := packsNotInGoldenModels[pack]; exempt {
			assert.Zero(t, n, "pack %s is exercised by the golden set now: remove the exemption (%s)", pack, why)
			continue
		}
		assert.Positive(t, n, "pack %s has no expected finding in any golden model: add one to a bad twin "+
			"or document the gap in packsNotInGoldenModels", pack)
	}
	for pack := range packsNotInGoldenModels {
		_, ok := exercised[pack]
		assert.True(t, ok, "packsNotInGoldenModels names %q, which is not a loaded pack", pack)
	}

	// Thresholds, restated here so a failure names them (docs/09 §2).
	for _, p := range rep.ByPack {
		if p.TP+p.FN == 0 {
			continue
		}
		assert.GreaterOrEqual(t, p.Precision, minPrecision, "pack %s precision", p.Pack)
		assert.GreaterOrEqual(t, p.Recall, minRecall, "pack %s recall", p.Pack)
	}
}

// TestGoldenSetRuleCoverageIsReported lists the rules that only fixtures exercise, so the gap is
// visible in the eval log instead of hiding behind a green run.
func TestGoldenSetRuleCoverageIsReported(t *testing.T) {
	t.Parallel()
	requireRepo(t)
	rep, err := run(repoPath("packs"), repoPath("policy.yaml"),
		repoPath("golden-set", "models"), repoPath("golden-set", "expected"))
	require.NoError(t, err)

	var fixturesOnly []string
	for _, c := range rep.ByRule {
		if c.TP+c.FN == 0 {
			fixturesOnly = append(fixturesOnly, c.Rule)
		}
	}
	sort.Strings(fixturesOnly)
	t.Logf("rules exercised by fixtures only (%d/%d): %s", len(fixturesOnly), rep.Rules, strings.Join(fixturesOnly, ", "))
	assert.LessOrEqual(t, len(fixturesOnly), rep.Rules/4,
		"more than a quarter of the rules are never exercised by a golden model: %v", fixturesOnly)
}

func jsonNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(out)
	return out
}
