package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// The MR pack (docs/03 §MR) speaks only where the Machinery Regulation is declared: each rule fires under MR and its
// aliases, and stays silent under other regimes and on a model that declares none.
func TestMRRulesOnlyUnderTheMachineryRegulation(t *testing.T) {
	t.Parallel()
	mrModel := func(regimes ...any) *model.Architecture {
		a := model.Empty("arch_mr", "t", "robot cell")
		a.Attrs = model.Attrs{"owner": "x", "regimes": regimes, "incident_reporting": "x"}
		a.Nodes = []model.Node{
			otNode("n_agent", "agent", "ai", nil),
			otNode("n_writer", "app", "edge", model.Attrs{"command_validation": true}),
			otNode("n_plc", "edge_device", "edge", nil),
			otNode("n_guard", "edge_model", "edge", model.Attrs{"safety_function": true, "self_evolving": true}),
		}
		a.Edges = []model.Edge{otEdge("e_agent_writer", "n_agent", "n_writer", "writes", "tls"), otEdge("e_writer_plc", "n_writer", "n_plc", "writes", "tls")}
		return a
	}
	want := map[string][]string{"MR-001": {"n_guard"}, "MR-002": {"e_writer_plc"}, "MR-003": {"n_guard"}, "MR-004": {"arch_mr"}}
	for _, tc := range []struct {
		name    string
		regimes []any
		fire    bool
	}{
		{"MR", []any{"MR"}, true}, {"alias MACHINERY", []any{"machinery"}, true}, {"IEC and CRA", []any{"IEC", "CRA"}, false},
		{"AIACT", []any{"AIACT"}, false}, {"no regimes", []any{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := evaluateWith(t, mrModel(tc.regimes...))
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

// The Machinery Regulation controls of GlassBox Edge: the template declares MR and is silent; each mutation breaks one
// control and must raise the rule that evidences it.
func TestGlassBoxMachineryControlsAreEvidenced(t *testing.T) {
	t.Parallel()
	base := loadModel(t, repoPath("golden-set", "models", "glassbox-ot-agent.json"))
	require.Contains(t, base.Attrs["regimes"], "MR")
	require.Empty(t, evaluateWith(t, base), "the template is silent")
	tests := []struct {
		name   string
		mutate func(a *model.Architecture)
		rule   string
		id     string
	}{
		{"validator keeps no tracing log", func(a *model.Architecture) { delete(a.Node("n_validator_a").Attrs, "intervention_log") }, "MR-002", "e_validator_plc_a"},
		{"substantial modification not assessed", func(a *model.Architecture) { a.Attrs["substantial_modification"] = "unknown" }, "MR-004", "arch_tpl_glassbox_ot_agent"},
		{"anomaly model becomes a learning safety function", func(a *model.Architecture) {
			a.Node("n_model_a").Attrs["safety_function"] = true
			a.Node("n_model_a").Attrs["self_evolving"] = true
		}, "MR-001", "n_model_a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := base.Clone()
			require.NoError(t, err)
			tc.mutate(a)
			got := evaluateWith(t, a)
			assert.Contains(t, got[tc.rule], tc.id, "%s should name %s; got %v", tc.rule, tc.id, got)
		})
	}
}
