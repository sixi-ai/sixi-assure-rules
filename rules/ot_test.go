package rules

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// The OT pack and the rule changes that came with it (docs/03 §OT), assessed with the real catalog on the shapes the
// fixtures do not cover: co-located components, CRA on edge gateways, reporting duties under NIS2 and CRA, and the
// third-party pack staying silent where it has no clause.

func otNode(id, typ, layer string, attrs model.Attrs) model.Node {
	if attrs == nil {
		attrs = model.Attrs{}
	}
	return model.Node{ID: id, Type: typ, Name: "N " + id, Layer: layer, Source: "design", Attrs: attrs}
}

func otEdge(id, from, to, kind, enc string) model.Edge {
	return model.Edge{ID: id, From: from, To: to, Kind: kind, Auth: "none", Encryption: enc, Attrs: model.Attrs{}}
}

func evaluateWith(t *testing.T, a *model.Architecture) map[string][]string {
	t.Helper()
	catalog, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	table, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	fs, err := New(catalog, table).Evaluate(context.Background(), a, policyFromAttrs(a))
	require.NoError(t, err)
	return findingsByRule(fs)
}

func TestNET006ExemptsCoLocatedCalls(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		hostA    string
		hostB    string
		enc      string
		wantFire bool
	}{
		{"component on its host (to → from)", "", "a", "none", false},
		{"host calls its component", "b", "", "none", false},
		{"two components on the same host", "h", "h", "none", false},
		{"not co-located", "", "", "none", true},
		{"different hosts", "h1", "h2", "none", true},
		{"co-located but unknown encryption", "", "a", "unknown", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := model.Empty("arch_net006", "t", "co-location")
			a.Attrs = model.Attrs{"owner": "x", "regimes": []any{"ISO"}}
			hosted := func(h string) model.Attrs {
				if h == "" {
					return model.Attrs{}
				}
				return model.Attrs{"hosted_on": h}
			}
			a.Nodes = []model.Node{
				otNode("a", "edge_gateway", "edge", hosted(tc.hostA)), otNode("b", "edge_model", "edge", hosted(tc.hostB)),
				otNode("h", "edge_gateway", "edge", nil), otNode("h1", "edge_gateway", "edge", nil), otNode("h2", "edge_gateway", "edge", nil),
			}
			a.Edges = []model.Edge{otEdge("e_ab", "a", "b", "calls", tc.enc)}
			_, fired := evaluateWith(t, a)["NET-006"]
			assert.Equal(t, tc.wantFire, fired)
		})
	}
}

func TestCRARulesCoverEdgeGateways(t *testing.T) {
	t.Parallel()
	a := model.Empty("arch_cra_gw", "t", "gateway in CRA scope")
	a.Attrs = model.Attrs{"owner": "x", "regimes": []any{"CRA"}, "incident_reporting": "PSIRT within 24 h"}
	a.Nodes = []model.Node{otNode("gw", "edge_gateway", "edge", model.Attrs{"cra_scope": true, "ota_signed": true})}
	got := evaluateWith(t, a)
	assert.Equal(t, []string{"gw"}, got["CRA-001"], "no SBOM")
	assert.Equal(t, []string{"gw"}, got["CRA-002"], "no secure boot")
}

func TestGOV002CoversNIS2AndCRA(t *testing.T) {
	t.Parallel()
	for _, regime := range []string{"NIS2", "CRA", "DORA", "CH-ISG"} {
		t.Run(regime, func(t *testing.T) {
			t.Parallel()
			a := model.Empty("arch_gov002", "t", "reporting")
			a.Attrs = model.Attrs{"owner": "x", "regimes": []any{regime}}
			_, fired := evaluateWith(t, a)["GOV-002"]
			assert.True(t, fired)
		})
	}
	a := model.Empty("arch_gov002_iso", "t", "no reporting duty")
	a.Attrs = model.Attrs{"owner": "x", "regimes": []any{"ISO"}}
	_, fired := evaluateWith(t, a)["GOV-002"]
	assert.False(t, fired, "ISO alone names no reporting duty")
}

func TestTPRRulesOnlyWhereTheirClausesApply(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		regime string
		fire   bool
	}{{"FINMA", true}, {"DORA", true}, {"CRA", false}, {"IEC", false}, {"ISO", false}} {
		t.Run(tc.regime, func(t *testing.T) {
			t.Parallel()
			a := model.Empty("arch_tpr", "t", "external LLM")
			a.Attrs = model.Attrs{"owner": "x", "regimes": []any{tc.regime}, "incident_reporting": "x"}
			a.Nodes = []model.Node{otNode("llm", "llm_endpoint", "ai", model.Attrs{"provider": "azure", "region": "switzerlandnorth", "network": "private"})}
			_, fired := evaluateWith(t, a)["TPR-001"]
			assert.Equal(t, tc.fire, fired)
		})
	}
}

// The OT rules stay silent on every template of the golden set: none of them has an AI component on a command path.
func TestOTRulesSilentOnTemplates(t *testing.T) {
	t.Parallel()
	for _, file := range []string{"rag-chatbot.json", "foundry-agent-tools.json", "webapp-sql-keyvault.json", "edge-iot-glassbox.json", "multi-agent-fleet.json"} {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, repoPath("golden-set", "models", file))
			for rule := range evaluateWith(t, a) {
				assert.NotContains(t, rule, "OT-", "%s fired on %s", rule, file)
			}
		})
	}
}

// TestGlassBoxInvariantsAreEvidenced replays the validation of GlassBox Edge (docs/03 §OT): each mutation breaks one
// invariant of the reference design, which is silent under every rule, and must raise the rule that evidences it.
func TestGlassBoxInvariantsAreEvidenced(t *testing.T) {
	t.Parallel()
	base := loadModel(t, repoPath("golden-set", "models", "glassbox-ot-agent.json"))
	require.Empty(t, evaluateWith(t, base), "the template is silent")

	edge := func(id, from, to, kind string, attrs model.Attrs) model.Edge {
		if attrs == nil {
			attrs = model.Attrs{}
		}
		return model.Edge{ID: id, From: from, To: to, Kind: kind, Auth: "managed_identity", Encryption: "tls", Attrs: attrs}
	}
	nodeAttrs := func(a *model.Architecture, id string) model.Attrs {
		n := a.Node(id)
		require.NotNil(t, n, id)
		return n.Attrs
	}
	tests := []struct {
		name   string
		mutate func(a *model.Architecture)
		want   map[string]string // rule → element it must name
	}{
		{"agent calls the command broker", func(a *model.Architecture) {
			a.Edges = append(a.Edges, edge("e_x", "n_agent", "n_broker", "calls", nil))
		}, map[string]string{"OT-001": "n_agent", "OT-003": "n_kv"}},
		{"agent reads the signing key", func(a *model.Architecture) {
			a.Edges = append(a.Edges, edge("e_x", "n_agent", "n_kv", "reads", nil))
		}, map[string]string{"OT-003": "n_kv"}},
		{"an MCP tool sends cloud-to-device commands", func(a *model.Architecture) {
			a.Edges = append(a.Edges, edge("e_x", "n_mcp", "n_hub", "calls", model.Attrs{"consequence": "high"}))
		}, map[string]string{"OT-001": "n_mcp"}},
		{"device validator removed", func(a *model.Architecture) {
			kept := make([]model.Edge, 0, len(a.Edges))
			for _, e := range a.Edges {
				if e.ID != "e_validator_plc_a" && e.ID != "e_jetson_validator_a" {
					kept = append(kept, e)
				}
			}
			kept = append(kept, edge("e_x", "n_jetson_a", "n_plc_a", "writes", nil))
			a.Edges = kept
		}, map[string]string{"OT-002": "e_x"}},
		{"OT text reaches the model unscreened", func(a *model.Architecture) {
			nodeAttrs(a, "n_agent")["content_safety"] = false
		}, map[string]string{"OT-005": "n_agent"}},
		{"the model writes the PLC, consequence not declared", func(a *model.Architecture) {
			a.Edges = append(a.Edges, edge("e_x", "n_agent", "n_plc_a", "writes", nil))
		}, map[string]string{"OT-001": "n_agent", "OT-002": "e_x"}},
		{"line A node writes line B's PLC", func(a *model.Architecture) {
			a.Edges = append(a.Edges, edge("e_x", "n_validator_a", "n_plc_b", "writes", nil))
		}, map[string]string{"OT-004": "e_x"}},
		{"shared SAS key instead of a device identity", func(a *model.Architecture) {
			for i := range a.Edges {
				if a.Edges[i].ID == "e_jetson_hub_a" {
					a.Edges[i].Auth = "connection_string"
				}
			}
		}, map[string]string{"STR-006": "e_jetson_hub_a"}},
		{"approval signed under the agent's identity", func(a *model.Architecture) {
			nodeAttrs(a, "n_approval")["approval_identity"] = "agent"
		}, map[string]string{"OT-006": "n_approval"}},
		{"no row-level security per line", func(a *model.Architecture) {
			delete(nodeAttrs(a, "n_sql"), "row_level_security")
		}, map[string]string{"OT-007": "n_sql"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := base.Clone()
			require.NoError(t, err)
			tc.mutate(a)
			got := evaluateWith(t, a)
			for rule, id := range tc.want {
				assert.Contains(t, got[rule], id, "%s should name %s; got %v", rule, id, got)
			}
		})
	}
}
