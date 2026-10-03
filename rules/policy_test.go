package rules

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

func TestParsePolicyTable(t *testing.T) {
	t.Parallel()
	tbl, err := ParsePolicyTable([]byte(`
retention_days:
  default: 365
  FINMA: 3650
  CH-CO: 3650
  AIACT_deployer: 180
log_days:
  default: 30
regions:
  allowed_default: [switzerlandnorth, switzerlandwest]
`))
	require.NoError(t, err)
	assert.Equal(t, []string{"log_days", "retention_days"}, tbl.Keys())
	assert.Equal(t, []string{"switzerlandnorth", "switzerlandwest"}, tbl.AllowedRegionsDefault())

	tests := []struct {
		name string
		code string
		p    Policy
		want int
	}{
		{"default without regimes", "retention_days", Policy{}, 365},
		{"FINMA minimum", "retention_days", Policy{Regimes: []string{"FINMA"}}, 3650},
		{"CH-CO minimum", "retention_days", Policy{Regimes: []string{"CH-CO"}}, 3650},
		{"AIACT deployer (role suffix)", "retention_days", Policy{Regimes: []string{"AIACT"}}, 180},
		{"max over regimes", "retention_days", Policy{Regimes: []string{"AIACT", "FINMA"}}, 3650},
		{"unrelated regime → default", "retention_days", Policy{Regimes: []string{"DORA"}}, 365},
		{"alias", "retention_days", Policy{Regimes: []string{"finma"}}, 3650},
		{"tenant raises", "retention_days", Policy{Regimes: []string{"AIACT"}, Requirements: map[string]int{"retention_days": 400}}, 400},
		{"tenant cannot lower", "retention_days", Policy{Regimes: []string{"FINMA"}, Requirements: map[string]int{"retention_days": 10}}, 3650},
		{"other key default", "log_days", Policy{Regimes: []string{"FINMA"}}, 30},
		{"unknown key", "nope", Policy{}, 0},
		{"unknown key with tenant value", "nope", Policy{Requirements: map[string]int{"nope": 5}}, 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tbl.Required(tc.code, tc.p))
		})
	}
}

func TestParsePolicyTableErrors(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"not a mapping":     "retention_days: 3",
		"non-integer":       "retention_days: {default: many}",
		"regions not map":   "regions: [a]",
		"regions not lists": "regions: {allowed_default: [1]}",
		"invalid yaml":      "a: [",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePolicyTable([]byte(in))
			require.Error(t, err)
		})
	}
}

func TestLoadPolicyTableFromRepo(t *testing.T) {
	t.Parallel()
	tbl, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	assert.Equal(t, 3650, tbl.Required("retention_days", Policy{Regimes: []string{"FINMA"}}))
	assert.Equal(t, 180, tbl.Required("retention_days", Policy{Regimes: []string{"AIACT"}}))
	assert.Equal(t, 365, tbl.Required("retention_days", Policy{}))
	assert.NotEmpty(t, tbl.AllowedRegionsDefault())
	// The identity rules' spec defaults (final polish item 3): WIS-003's rotation and HAC-002's token lifetime.
	for _, tc := range []struct {
		key    string
		policy Policy
		want   int
	}{
		{"credential_rotation_days", Policy{}, 90},
		{"credential_rotation_days", Policy{Regimes: []string{"FINMA"}}, 90},
		{"credential_rotation_days", Policy{Requirements: map[string]int{"credential_rotation_days": 180}}, 180},
		{"human_token_lifetime_s", Policy{}, 3600},
		{"human_token_lifetime_s", Policy{Regimes: []string{"DORA"}}, 3600},
	} {
		assert.Equal(t, tc.want, tbl.Required(tc.key, tc.policy), "%s %v", tc.key, tc.policy)
	}
	_, err = LoadPolicyTable(repoPath("rules", "nope.yaml"))
	require.Error(t, err)
}

func TestDefaultPolicyTableMatchesRepo(t *testing.T) {
	t.Parallel()
	repo, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	def := DefaultPolicyTable()
	for _, regs := range [][]string{nil, {"FINMA"}, {"AIACT"}, {"CH-CO"}, {"DORA"}} {
		for _, key := range []string{"retention_days", "credential_rotation_days", "human_token_lifetime_s"} {
			assert.Equal(t, repo.Required(key, Policy{Regimes: regs}), def.Required(key, Policy{Regimes: regs}), "%s %v", key, regs)
		}
	}
	assert.Equal(t, repo.AllowedRegionsDefault(), def.AllowedRegionsDefault())
	assert.Equal(t, repo.Keys(), def.Keys())
	for _, regs := range [][]string{nil, {"FINMA"}, {"AIACT"}} {
		rc, rok := repo.Cap("blast_radius_writers", Policy{Regimes: regs})
		dc, dok := def.Cap("blast_radius_writers", Policy{Regimes: regs})
		assert.Equal(t, rc, dc, regs)
		assert.Equal(t, rok, dok, regs)
	}
}

// TestPolicyTableCap: a cap key is an upper bound. A regime entry is a ceiling (the smallest enabled one wins), the
// tenant's value replaces the default and may be lower, 0 included, and is higher only where no regime caps it.
func TestPolicyTableCap(t *testing.T) {
	t.Parallel()
	tbl, err := ParsePolicyTable([]byte(`
writers:
  default: 3
  FINMA: 2
  DORA: 1
open_key:
  default: 1
`))
	require.NoError(t, err)
	tests := []struct {
		name   string
		code   string
		p      Policy
		want   int
		wantOK bool
	}{
		{"default without regimes", "writers", Policy{}, 3, true},
		{"a regime caps below the default", "writers", Policy{Regimes: []string{"FINMA"}}, 2, true},
		{"the smallest enabled ceiling wins", "writers", Policy{Regimes: []string{"FINMA", "DORA"}}, 1, true},
		{"tenant lowers to zero", "writers", Policy{Requirements: map[string]int{"writers": 0}}, 0, true},
		{"tenant lowers under a ceiling", "writers", Policy{Regimes: []string{"FINMA"}, Requirements: map[string]int{"writers": 1}}, 1, true},
		{"tenant cannot exceed a ceiling", "writers", Policy{Regimes: []string{"DORA"}, Requirements: map[string]int{"writers": 5}}, 1, true},
		{"tenant raises where no regime caps", "open_key", Policy{Requirements: map[string]int{"open_key": 4}}, 4, true},
		{"negative tenant value reads zero", "open_key", Policy{Requirements: map[string]int{"open_key": -2}}, 0, true},
		{"unknown key", "nope", Policy{}, 0, false},
		{"unknown key with tenant value", "nope", Policy{Requirements: map[string]int{"nope": 2}}, 2, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := tbl.Cap(tc.code, tc.p)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

// TestCappedHelper: capped() in CEL reads PolicyTable.Cap, and -1 when neither the table nor the tenant names the key.
func TestCappedHelper(t *testing.T) {
	t.Parallel()
	tbl, err := ParsePolicyTable([]byte("writers: {default: 2}\n"))
	require.NoError(t, err)
	cat := mustInline(t, `
pack: capped
version: 0.1.0
rules:
  - id: CAP-001
    title: cap read
    scope: graph
    severity: low
    condition: capped("writers") == 0 && capped("nope") == -1
    message: "cap"
    clauses: [A:B]
`)
	for _, tc := range []struct {
		name string
		p    Policy
		fire bool
	}{{"default 2", Policy{}, false}, {"tenant 0", Policy{Requirements: map[string]int{"writers": 0}}, true}} {
		fs, err := New(cat, tbl).Evaluate(context.Background(), model.Empty("arch_cap", "t", "cap"), tc.p)
		require.NoError(t, err)
		assert.Equal(t, tc.fire, len(fs) == 1, tc.name)
	}
}
