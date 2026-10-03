package rules

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Team 09's sector rules (docs/18 WS-I I2, agents/swarm/09-sector-packs): GXP-005 to GXP-008 speak only under FDA or
// EU-GMP (and their aliases), MR-005 to MR-008 only under MR (MR-008 also needs AIACT); OT-008 to OT-011 follow the ot
// pack's regimes.
func TestTeam09RulesOnlyUnderTheirRegimes(t *testing.T) {
	t.Parallel()
	gxp := func(regimes ...any) *model.Architecture {
		a := model.Empty("arch_gxp9", "t", "batch records")
		a.Attrs = model.Attrs{"owner": "x", "regimes": regimes, "incident_reporting": "x"}
		a.Nodes = []model.Node{
			otNode("n_agent", "agent", "ai", model.Attrs{"autonomy": "autonomous", "identity": "agent_id"}),
			otNode("n_app", "app", "app", nil),
			otNode("n_db", "datastore", "data", model.Attrs{"engine": "sql", "data_class": "confidential", "region": "switzerlandnorth", "backup": true, "retention_days": 3650}),
			otNode("n_audit", "log_sink", "platform", model.Attrs{"retention_days": 365, "immutable": true}),
			otNode("n_qa", "human_step", "human", model.Attrs{"approval_for": []any{"batch release"}, "approval_identity": "separate"}),
		}
		a.Edges = []model.Edge{
			team09Edge("e_agent_app", "n_agent", "n_app", "calls"),
			team09Edge("e_app_db", "n_app", "n_db", "writes"),
			team09Edge("e_qa_app", "n_qa", "n_app", "executes"),
		}
		return a
	}
	gxpWant := map[string][]string{"GXP-005": {"n_db"}, "GXP-006": {"e_app_db"}, "GXP-007": {"n_qa"}, "GXP-008": {"e_app_db"}}
	mr := func(regimes ...any) *model.Architecture {
		a := model.Empty("arch_mr9", "t", "guard")
		a.Attrs = model.Attrs{"owner": "x", "regimes": regimes, "ai_act_tier": "limited", "incident_reporting": "x"}
		a.Nodes = []model.Node{
			otNode("n_train", "app", "app", nil),
			otNode("n_guard", "edge_model", "edge", model.Attrs{"safety_function": true, "self_evolving": true, "conformity_route": "module_b_c"}),
			otNode("n_log", "log_sink", "platform", model.Attrs{"retention_days": 730}),
		}
		a.Edges = []model.Edge{team09Edge("e_train_guard", "n_train", "n_guard", "writes"), team09Edge("e_guard_log", "n_guard", "n_log", "writes")}
		return a
	}
	mrWant := map[string][]string{"MR-005": {"n_guard"}, "MR-006": {"n_guard"}, "MR-007": {"n_log"}}
	for _, tc := range []struct {
		name    string
		arch    *model.Architecture
		want    map[string][]string
		fire    bool
		alsoMR8 bool
	}{
		{"FDA", gxp("FDA"), gxpWant, true, false}, {"EU-GMP", gxp("EU-GMP"), gxpWant, true, false},
		{"alias PART11", gxp("PART11"), gxpWant, true, false}, {"alias gmp", gxp("gmp"), gxpWant, true, false},
		{"GAMP alone", gxp("GAMP"), gxpWant, false, false}, {"ISO only", gxp("ISO"), gxpWant, false, false},
		{"no regimes", gxp(), gxpWant, false, false},
		{"MR", mr("MR"), mrWant, true, false}, {"alias MACHINERY", mr("MACHINERY"), mrWant, true, false},
		{"MR and AIACT", mr("MR", "AIACT"), mrWant, true, true}, {"AIACT only", mr("AIACT"), mrWant, false, false},
		{"IEC only", mr("IEC"), mrWant, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := evaluateWith(t, tc.arch)
			for rule, ids := range tc.want {
				if tc.fire {
					assert.Equal(t, ids, got[rule], rule)
				} else {
					assert.NotContains(t, got, rule)
				}
			}
			if tc.alsoMR8 {
				assert.Equal(t, []string{"n_guard"}, got["MR-008"])
			} else {
				assert.NotContains(t, got, "MR-008")
			}
		})
	}
}

func team09Edge(id, from, to, kind string) model.Edge {
	return model.Edge{ID: id, From: from, To: to, Kind: kind, Auth: "managed_identity", Encryption: "tls", Attrs: model.Attrs{}}
}

// The breaks of agents/swarm/09-sector-packs on GlassBox Edge, which is silent under every rule: each mutation breaks
// one control the team-09 rules evidence and must raise the rule on the element the spec names.
func TestGlassBoxTeam09ControlsAreEvidenced(t *testing.T) {
	t.Parallel()
	base := loadModel(t, repoPath("golden-set", "models", "glassbox-ot-agent.json"))
	// The template is meant to be silent; whatever it raises today is the base each break is compared to.
	baseFindings := evaluateWith(t, base)
	attrs := func(a *model.Architecture, id string) model.Attrs {
		n := a.Node(id)
		require.NotNil(t, n, id)
		return n.Attrs
	}
	edgeAttrs := func(a *model.Architecture, id string) model.Attrs {
		for i := range a.Edges {
			if a.Edges[i].ID == id {
				return a.Edges[i].Attrs
			}
		}
		t.Fatalf("no edge %s", id)
		return nil
	}
	// also lists the findings a break raises beyond its own rule (collateral the spec's "exactly that rule" claim
	// does not cover; recorded in the phase report). Every other break raises its rule on its element and nothing else.
	tests := []struct {
		name   string
		mutate func(a *model.Architecture)
		rule   string
		id     string
		also   map[string][]string
	}{
		{"records kept longer than the audit trail", func(a *model.Architecture) { attrs(a, "n_sql")["retention_days"] = 7300 }, "GXP-005", "n_sql", nil},
		{"record write no longer logged", func(a *model.Architecture) { delete(edgeAttrs(a, "e_mcp_sql_write"), "logged") }, "GXP-006", "e_mcp_sql_write", nil},
		{"command approval no longer logged", func(a *model.Architecture) { delete(edgeAttrs(a, "e_approval_broker"), "logged") }, "GXP-007", "n_approval", nil},
		{"the agent becomes autonomous", func(a *model.Architecture) { attrs(a, "n_agent")["autonomy"] = "autonomous" }, "GXP-008", "e_mcp_sql_write",
			// HOV-003: the autonomous agent's tool call through the API gateway has no human step either.
			// BLR-003 (team 03): an autonomous agent now reaches more state-changing writers than the policy's
			// blast_radius_writers cap allows.
			map[string][]string{"HOV-003": {"e_apim_mcp"}, "BLR-003": {"n_agent"}}},
		{"audit trail no longer immutable", func(a *model.Architecture) { delete(attrs(a, "n_audit"), "immutable") }, "OT-008", "n_approval",
			// n_audit is the model's only immutable sink: dropping the flag also leaves GxP with no audit trail (GXP-001),
			// the ingest write with none (GXP-006) and the agent's records with none (LOG-007).
			map[string][]string{"GXP-001": {"arch_tpl_glassbox_ot_agent"}, "GXP-006": {"e_ingest_sql"}, "LOG-007": {"n_agent"}}},
		{"a reporting app reads the signing key", func(a *model.Architecture) {
			a.Nodes = append(a.Nodes, otNode("n_report", "app", "app", model.Attrs{"exposure": "internal"}))
			a.Edges = append(a.Edges, team09Edge("e_report_kv", "n_report", "n_kv", "reads"))
			// The reporting app runs in the key's zone: the template declares zones, so an unzoned app would also
			// raise STR-009 (structure-quality), which is not the break this case evidences.
			for i := range a.Groups {
				if a.Groups[i].Kind == "zone" && slices.Contains(a.Groups[i].NodeIDs, "n_kv") {
					a.Groups[i].NodeIDs = append(a.Groups[i].NodeIDs, "n_report")
				}
			}
		}, "OT-009", "n_kv", nil},
		{"the broker sends to line A directly, bypassing the hub", func(a *model.Architecture) {
			kept := make([]model.Edge, 0, len(a.Edges))
			for _, e := range a.Edges {
				if e.ID != "e_broker_hub" {
					kept = append(kept, e)
				}
			}
			kept = append(kept, team09Edge("e_broker_jetson", "n_broker", "n_jetson_a", "calls"))
			a.Edges = kept
		}, "OT-010", "n_approval", nil},
		{"the validator moves to the app tier", func(a *model.Architecture) { a.Node("n_validator_a").Layer = "app" }, "OT-011", "e_validator_plc_a", nil},
		{"a safety model without a version", func(a *model.Architecture) {
			at := attrs(a, "n_model_a")
			at["safety_function"] = true
			delete(at, "version")
		}, "MR-005", "n_model_a", nil},
		{"a learning safety function the cloud can reach", func(a *model.Architecture) {
			at := attrs(a, "n_model_a")
			at["safety_function"], at["self_evolving"], at["conformity_route"] = true, true, "module_b_c"
		}, "MR-006", "n_model_a",
			// The same declaration makes the model a learning safety function everywhere: its data reaches the
			// mutable n_appins (MR-007) and the architecture's tier is limited (MR-008).
			map[string][]string{"MR-007": {"n_appins"}, "MR-008": {"n_model_a"}}},
		{"a learning safety function under a limited tier", func(a *model.Architecture) {
			at := attrs(a, "n_model_a")
			at["safety_function"], at["self_evolving"], at["conformity_route"] = true, true, "module_b_c"
		}, "MR-008", "n_model_a",
			// The MR-006 break's declaration, read for the tier: MR-006 and MR-007 follow from it as above.
			map[string][]string{"MR-006": {"n_model_a"}, "MR-007": {"n_appins"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := base.Clone()
			require.NoError(t, err)
			tc.mutate(a)
			added := findingsAdded(evaluateWith(t, a), baseFindings)
			want := map[string][]string{tc.rule: {tc.id}}
			for r, ids := range tc.also {
				want[r] = append(want[r], ids...)
			}
			assert.Equal(t, want, added, "the break adds exactly %s on %s over the base (plus its recorded collateral)", tc.rule, tc.id)
		})
	}
}

// Review fixes of 2026-10-01 on the team 09 path rules: one walk avoids every control together (OT-010, MR-006), and
// OT-009 counts distinct readers, not edges. Each case starts from the rule's negative fixture.
func TestTeam09PathRulesReadOneWalk(t *testing.T) {
	t.Parallel()
	fixture := func(name string) *model.Architecture {
		return loadModel(t, repoPath("packs", "fixtures", name))
	}
	addNode := func(a *model.Architecture, n model.Node, zone string) {
		n.Zone = zone
		a.Nodes = append(a.Nodes, n)
		for i := range a.Groups {
			if a.Groups[i].ID == zone {
				a.Groups[i].NodeIDs = append(a.Groups[i].NodeIDs, n.ID)
			}
		}
	}
	tests := []struct {
		name    string
		fixture string
		mutate  func(a *model.Architecture)
		rule    string
		want    []string // nil: the rule stays silent
	}{
		{"OT-010: a broker on one path and a DMZ on a parallel one are both conduits", "OT-010.neg.json", func(a *model.Architecture) {
			addNode(a, otNode("n_dmz", "dmz", "platform", model.Attrs{"network_exposure": "private"}), "z_conduit")
			a.Edges = append(a.Edges, team09Edge("e_hs_dmz", "n_hs", "n_dmz", "executes"), team09Edge("e_dmz_gw", "n_dmz", "n_gw", "publishes"))
		}, "OT-010", nil},
		{"OT-010: a direct hop beside the conduits is a walk with none", "OT-010.neg.json", func(a *model.Architecture) {
			addNode(a, otNode("n_dmz", "dmz", "platform", model.Attrs{"network_exposure": "private"}), "z_conduit")
			a.Edges = append(a.Edges, team09Edge("e_hs_dmz", "n_hs", "n_dmz", "executes"), team09Edge("e_dmz_gw", "n_dmz", "n_gw", "publishes"),
				team09Edge("e_hs_gw", "n_hs", "n_gw", "executes"))
		}, "OT-010", []string{"n_hs"}},
		{"MR-006: a validator on one path and a release step on a parallel one are both controls", "MR-006.neg.json", func(a *model.Architecture) {
			a.Nodes = append(a.Nodes, otNode("n_val", "app", "app", model.Attrs{"exposure": "internal", "command_validation": true}))
			a.Edges = append(a.Edges, team09Edge("e_train_val", "n_train", "n_val", "writes"), team09Edge("e_val_guard", "n_val", "n_guard", "writes"))
		}, "MR-006", nil},
		{"MR-006: a direct upload beside both controls is a walk with neither", "MR-006.neg.json", func(a *model.Architecture) {
			a.Nodes = append(a.Nodes, otNode("n_val", "app", "app", model.Attrs{"exposure": "internal", "command_validation": true}))
			a.Edges = append(a.Edges, team09Edge("e_train_val", "n_train", "n_val", "writes"), team09Edge("e_val_guard", "n_val", "n_guard", "writes"),
				team09Edge("e_train_guard", "n_train", "n_guard", "writes"))
		}, "MR-006", []string{"n_guard"}},
		{"OT-009: one reader with two edges into the store is one reader", "OT-009.neg.json", func(a *model.Architecture) {
			a.Edges = append(a.Edges, team09Edge("e_brk_kv_2", "n_brk", "n_kv", "calls"))
		}, "OT-009", nil},
		{"OT-009: a second reader on the command path is a second identity", "OT-009.neg.json", func(a *model.Architecture) {
			a.Nodes = append(a.Nodes, otNode("n_brk2", "app", "edge", model.Attrs{"exposure": "internal", "command_validation": true}))
			a.Edges = append(a.Edges, team09Edge("e_brk2_kv", "n_brk2", "n_kv", "reads"), team09Edge("e_brk2_plc", "n_brk2", "n_plc", "writes"))
		}, "OT-009", []string{"n_kv"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := fixture(tc.fixture)
			require.Empty(t, evaluateWith(t, a)[tc.rule], "the negative fixture is silent")
			tc.mutate(a)
			_, err := model.ValidateJSON(mustJSON(t, a))
			require.NoError(t, err, "the mutated fixture is a valid model")
			assert.Equal(t, tc.want, evaluateWith(t, a)[tc.rule])
		})
	}
}

func mustJSON(t *testing.T, a *model.Architecture) []byte {
	t.Helper()
	b, err := json.Marshal(a)
	require.NoError(t, err)
	return b
}

// findingsAdded returns the findings of got that base does not hold, per rule (element ids in got's order).
func findingsAdded(got, base map[string][]string) map[string][]string {
	out := map[string][]string{}
	for rule, ids := range got {
		for _, id := range ids {
			if !slices.Contains(base[rule], id) {
				out[rule] = append(out[rule], id)
			}
		}
	}
	return out
}
