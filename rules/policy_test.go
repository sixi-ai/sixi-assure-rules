package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	_, err = LoadPolicyTable(repoPath("rules", "nope.yaml"))
	require.Error(t, err)
}

func TestDefaultPolicyTableMatchesRepo(t *testing.T) {
	t.Parallel()
	repo, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	def := DefaultPolicyTable()
	for _, regs := range [][]string{nil, {"FINMA"}, {"AIACT"}, {"CH-CO"}, {"DORA"}} {
		assert.Equal(t, repo.Required("retention_days", Policy{Regimes: regs}), def.Required("retention_days", Policy{Regimes: regs}), regs)
	}
	assert.Equal(t, repo.AllowedRegionsDefault(), def.AllowedRegionsDefault())
}
