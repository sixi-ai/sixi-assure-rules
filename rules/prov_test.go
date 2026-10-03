package rules

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// docs/18 C5, ADR-086 §7: `prov` is built like `kb`, once per evaluation, from the provenance sidecar with the clock
// pinned to Policy.AsOf.

func TestProvenanceVars(t *testing.T) {
	fx := loadModel(t, repoPath("packs", "fixtures", "PRV-005.pos.json"))
	drift := loadModel(t, repoPath("packs", "fixtures", "PRV-006.pos.json"))
	fetched := time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		a         *model.Architecture
		asOf      time.Time
		available bool
		id        string
		kind      string
		expired   bool
		drifted   bool
	}{
		{"no sidecar: unavailable, no elements", testModel(), fetched, false, "", "", false, false},
		{"within the cadence", fx, fetched.AddDate(0, 0, 30), true, "n_db", model.ProvenanceImported, false, false},
		{"past the cadence", fx, fetched.AddDate(0, 0, 31), true, "n_db", model.ProvenanceImported, true, false},
		{"edges are elements too", fx, fetched.AddDate(0, 0, 31), true, "e_app_db", model.ProvenanceImported, true, false},
		{"left behind by a later import", drift, fetched, true, "n_old", model.ProvenanceImported, false, true},
		{"carried by the later import", drift, fetched, true, "n_new", model.ProvenanceImported, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := ProvenanceVars(tc.a, tc.asOf)
			assert.Equal(t, tc.available, v["available"])
			assert.Equal(t, tc.asOf.Format(time.RFC3339), v["as_of"])
			elements := v["elements"].(map[string]any)
			if !tc.available {
				assert.Empty(t, elements)
				return
			}
			el, ok := elements[tc.id].(map[string]any)
			require.True(t, ok, tc.id)
			assert.Equal(t, tc.kind, el["kind"])
			assert.Equal(t, tc.expired, el["expired"])
			assert.Equal(t, tc.drifted, el["drifted"])
			assert.Equal(t, tc.expired || tc.drifted, el["stale"])
		})
	}
	assert.NotEmpty(t, ProvenanceVars(fx, time.Time{})["as_of"], "zero AsOf is the time of evaluation")
}

// The clock is pinned: the same model and policy give the same findings whatever day it is (assure verify).
func TestProvenanceRulesUseThePinnedClock(t *testing.T) {
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	table, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	eng := New(c, table)
	a := loadModel(t, repoPath("packs", "fixtures", "PRV-005.pos.json"))
	fetched := time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		asOf time.Time
		want []string
	}{
		{"before the cadence elapses", fetched.AddDate(0, 0, 29), nil},
		{"after it elapses: the critical store and the service writing to it", fetched.AddDate(0, 0, 31), []string{"n_app", "n_db"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := policyFromAttrs(a)
			p.AsOf = tc.asOf
			fs, err := eng.Evaluate(context.Background(), a, p)
			require.NoError(t, err)
			assert.Equal(t, tc.want, findingsByRule(fs)["PRV-005"])
		})
	}
}

// The message names the source and the pinned clock, never an actor.
func TestProvenanceRuleMessage(t *testing.T) {
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	a := loadModel(t, repoPath("packs", "fixtures", "PRV-006.pos.json"))
	fs, err := eng.Evaluate(context.Background(), a, policyFromAttrs(a))
	require.NoError(t, err)
	var msg string
	for _, f := range fs {
		if f.RuleID == "PRV-006" {
			msg = f.Message
		}
	}
	assert.Contains(t, msg, "sixi_registry:claims")
	assert.NotContains(t, msg, "usr_fixture")
}

// ADR-086 Acceptance: every golden model evaluates to the same findings and the same coverage with and without a
// materialised sidecar (the upgrade mapping carries no fetch date and no cadence, so nothing is stale), and without
// one the prov rules decide nothing.
func TestGoldenModelsWithAndWithoutSidecar(t *testing.T) {
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	table, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	eng := New(c, table)
	files, err := filepath.Glob(repoPath("golden-set", "models", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	asOf := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			a := loadModel(t, f)
			p := policyFromAttrs(a)
			p.AsOf = asOf
			without, cov, err := eng.EvaluateCoverage(context.Background(), a, p)
			require.NoError(t, err)
			// docs/18 WS-I I2 (team 01): only the sidecar rules (PRV-005, PRV-006: conditions on `prov.`) are silent
			// without one; PRV-001 to PRV-004 read node source and the import record on every model. The
			// team01-import-provenance pair carries a stored sidecar, so its sidecar rules decide.
			for id, n := range cov.Decided {
				r, ok := c.Rule(id)
				if ok && strings.HasPrefix(id, "PRV-") && strings.Contains(r.Condition, "prov.") && !a.HasProvenance() {
					assert.Zero(t, n, "%s decides nothing without a sidecar", id)
				}
			}
			with, err := a.Clone()
			require.NoError(t, err)
			with.MaterializeProvenance(nil)
			with.SyncSources()
			require.NoError(t, model.Validate(with))
			got, _, err := eng.EvaluateCoverage(context.Background(), with, p)
			require.NoError(t, err)
			assert.Equal(t, findingsByRule(without), findingsByRule(got))
		})
	}
}
