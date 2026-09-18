package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// The GXP pack (docs/03 §GXP) speaks only where 21 CFR Part 11 or GMP Annex 11 is declared: each rule fires under
// either regime and its aliases, and stays silent under every other regime and on a model that declares none.
func TestGXPRulesOnlyUnderGxPRegimes(t *testing.T) {
	t.Parallel()
	gxpModel := func(regimes ...any) *model.Architecture {
		a := model.Empty("arch_gxp", "t", "batch records")
		a.Attrs = model.Attrs{"owner": "x", "regimes": regimes, "incident_reporting": "x"}
		a.Nodes = []model.Node{
			otNode("n_db", "datastore", "data", model.Attrs{"engine": "sql", "data_class": "confidential", "region": "switzerlandnorth"}),
			otNode("n_audit", "log_sink", "platform", model.Attrs{"retention_days": 3650}),
			otNode("n_release", "human_step", "human", model.Attrs{"approval_for": []any{"batch release"}}),
		}
		return a
	}
	want := map[string][]string{"GXP-001": {"arch_gxp"}, "GXP-002": {"n_release"}, "GXP-003": {"n_db"}}
	for _, tc := range []struct {
		name    string
		regimes []any
		fire    bool
	}{
		{"FDA", []any{"FDA"}, true}, {"EU-GMP", []any{"EU-GMP"}, true}, {"alias 21CFR11", []any{"21CFR11"}, true},
		{"alias GMP", []any{"gmp"}, true}, {"ISO only", []any{"ISO"}, false}, {"IEC and CRA", []any{"IEC", "CRA"}, false},
		{"no regimes", []any{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := evaluateWith(t, gxpModel(tc.regimes...))
			for rule, ids := range want {
				if tc.fire {
					assert.Equal(t, ids, got[rule], rule)
				} else {
					assert.NotContains(t, got, rule)
				}
			}
		})
	}
}

// The GxP invariants of GlassBox Edge: the template declares FDA and EU-GMP and is silent; each mutation breaks one
// record-keeping control and must raise the rule that evidences it.
func TestGlassBoxGxPControlsAreEvidenced(t *testing.T) {
	t.Parallel()
	base := loadModel(t, repoPath("golden-set", "models", "glassbox-ot-agent.json"))
	require.Contains(t, base.Attrs["regimes"], "FDA")
	require.Contains(t, base.Attrs["regimes"], "EU-GMP")
	require.Empty(t, evaluateWith(t, base), "the template is silent")
	tests := []struct {
		name   string
		node   string
		mutate func(attrs model.Attrs)
		rule   string
		id     string
	}{
		{"audit trail no longer immutable", "n_audit", func(a model.Attrs) { a["immutable"] = false }, "GXP-001", "arch_tpl_glassbox_ot_agent"},
		{"operator confirmation under a shared identity", "n_interrupt", func(a model.Attrs) { a["approval_identity"] = "shared" }, "GXP-002", "n_interrupt"},
		{"SQL without backups", "n_sql", func(a model.Attrs) { delete(a, "backup") }, "GXP-003", "n_sql"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := base.Clone()
			require.NoError(t, err)
			n := a.Node(tc.node)
			require.NotNil(t, n, tc.node)
			tc.mutate(n.Attrs)
			got := evaluateWith(t, a)
			assert.Contains(t, got[tc.rule], tc.id, "%s should name %s; got %v", tc.rule, tc.id, got)
		})
	}
}

// GXP-004 reads the GAMP software category: it fires on configured and custom software without a supplier assessment,
// under GAMP as well as under the two GxP regimes, and stays silent where the category is not declared.
func TestGXP004ReadsTheGAMPCategory(t *testing.T) {
	t.Parallel()
	build := func(category string, assessed bool, regimes ...any) *model.Architecture {
		a := model.Empty("arch_gamp", "t", "LIMS")
		a.Attrs = model.Attrs{"owner": "x", "regimes": regimes, "incident_reporting": "x"}
		attrs := model.Attrs{"exposure": "internal"}
		if category != "" {
			attrs["gamp_category"] = category
		}
		if assessed {
			attrs["supplier_assessed"] = true
		}
		a.Nodes = []model.Node{otNode("n_lims", "app", "app", attrs)}
		return a
	}
	for _, tc := range []struct {
		name     string
		category string
		assessed bool
		regimes  []any
		fire     bool
	}{
		{"configured, not assessed", "configured", false, []any{"GAMP"}, true},
		{"custom, not assessed", "custom", false, []any{"GAMP"}, true},
		{"custom under EU-GMP", "custom", false, []any{"EU-GMP"}, true},
		{"alias GAMP5", "custom", false, []any{"GAMP5"}, true},
		{"custom, assessed", "custom", true, []any{"GAMP"}, false},
		{"non-configured product", "non_configured", false, []any{"GAMP"}, false},
		{"category not declared", "", false, []any{"GAMP"}, false},
		{"custom outside GxP", "custom", false, []any{"ISO"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := evaluateWith(t, build(tc.category, tc.assessed, tc.regimes...))
			if tc.fire {
				assert.Equal(t, []string{"n_lims"}, got["GXP-004"])
			} else {
				assert.NotContains(t, got, "GXP-004")
			}
		})
	}
}

// The GlassBox example records the GAMP categories of its custom agent and configured database; the template also
// records that both were assessed, so GXP-004 is silent there.
func TestGlassBoxRecordsGAMPCategories(t *testing.T) {
	t.Parallel()
	tpl := loadModel(t, repoPath("golden-set", "models", "glassbox-ot-agent.json"))
	require.Contains(t, tpl.Attrs["regimes"], "GAMP")
	assert.Equal(t, "custom", tpl.Node("n_agent").Attrs.String("gamp_category", ""))
	assert.Equal(t, "configured", tpl.Node("n_sql").Attrs.String("gamp_category", ""))
	assert.NotContains(t, evaluateWith(t, tpl), "GXP-004")

	bad := loadModel(t, repoPath("golden-set", "models", "glassbox-ot-agent-bad.json"))
	assert.Equal(t, []string{"n_agent", "n_sql"}, evaluateWith(t, bad)["GXP-004"])
}
