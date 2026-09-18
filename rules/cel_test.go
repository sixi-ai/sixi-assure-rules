package rules

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

func TestHelpers(t *testing.T) {
	t.Parallel()
	a := testModel()
	pol := Policy{AllowedRegions: []string{"switzerlandnorth"}, Regimes: []string{"FINMA", "ISG"}}
	tests := []struct {
		name    string
		scope   string
		element string
		expr    string
		want    any
		wantErr string
	}{
		// g.has / g.nodes / g.edges
		{"has agent", ScopeGraph, "", `g.has("agent")`, true, ""},
		{"has missing type", ScopeGraph, "", `g.has("evaluation")`, false, ""},
		{"nodes count", ScopeGraph, "", `g.nodes("datastore").size()`, int64(2), ""},
		{"nodes empty list", ScopeGraph, "", `g.nodes("queue").size()`, int64(0), ""},
		{"nodes exists macro", ScopeGraph, "", `g.nodes("datastore").exists(d, attr(d,"data_class","") == "pii")`, true, ""},
		{"nodes all macro", ScopeGraph, "", `g.nodes("datastore").all(d, d.layer == "data")`, true, ""},
		{"nodes filter+map", ScopeGraph, "", `g.nodes("user").filter(u, attr(u,"mfa",false)).map(u, u.id)`, []any{"u1"}, ""},
		{"edges by kind", ScopeGraph, "", `g.edges("writes").size()`, int64(3), ""},
		{"edges none", ScopeGraph, "", `g.edges("delegates").size()`, int64(0), ""},
		{"edges have resolved endpoints", ScopeGraph, "", `g.edges("calls").exists(x, x.from.type == "user" && x.to.type == "agent")`, true, ""},
		// g.in / g.out (docs/03 spelling and the inEdges alias)
		{"in docs spelling", ScopeGraph, "", `g.in("ag", "calls").size()`, int64(2), ""},
		{"in alias", ScopeGraph, "", `g.inEdges("ag", "calls").size()`, int64(2), ""},
		{"in any kind", ScopeGraph, "", `g.in("db", "").size()`, int64(1), ""},
		{"in unknown node", ScopeGraph, "", `g.in("nope", "calls").size()`, int64(0), ""},
		{"in from user (AI-007)", ScopeNode, "ag", `g.in(n.id,"calls").exists(x, x.from.type == "user")`, true, ""},
		{"out writes", ScopeGraph, "", `g.out("ag", "writes").map(x, x.to.id)`, []any{"db", "hs"}, ""},
		{"out alias", ScopeGraph, "", `g.outEdges("ag", "calls").size()`, int64(1), ""},
		{"out none", ScopeGraph, "", `g.out("sec", "calls").size()`, int64(0), ""},
		// reachable
		{"reachable direct", ScopeGraph, "", `g.reachable("u1", "web")`, true, ""},
		{"reachable transitive", ScopeGraph, "", `g.reachable("u1", "llm")`, true, ""},
		{"reachable self", ScopeGraph, "", `g.reachable("u1", "u1")`, true, ""},
		{"reachable reverse", ScopeGraph, "", `g.reachable("llm", "u1")`, false, ""},
		{"reachable isolated", ScopeGraph, "", `g.reachable("sec", "db")`, false, ""},
		{"reachable unknown from", ScopeGraph, "", `g.reachable("nope", "db")`, false, ""},
		// pathThrough (endpoints count)
		{"pathThrough via intermediate", ScopeGraph, "", `g.pathThrough("u1", "ag", "gateway")`, true, ""},
		{"pathThrough direct edge without via", ScopeGraph, "", `g.pathThrough("ag", "llm", "gateway")`, false, ""},
		{"pathThrough unreachable", ScopeGraph, "", `g.pathThrough("llm", "u1", "gateway")`, false, ""},
		{"pathThrough endpoint to counts", ScopeGraph, "", `g.pathThrough("ag", "hs", "human_step")`, true, ""},
		{"pathThrough endpoint from counts", ScopeGraph, "", `g.pathThrough("hs", "db2", "human_step")`, true, ""},
		{"pathThrough via node on path", ScopeGraph, "", `g.pathThrough("ag", "db2", "human_step")`, true, ""},
		{"pathThrough no via on any path", ScopeGraph, "", `g.pathThrough("ag", "db", "human_step")`, false, ""},
		{"pathThrough unknown via type", ScopeGraph, "", `g.pathThrough("u1", "llm", "broker")`, false, ""},
		{"pathThrough in edge rule (AI-003 clean)", ScopeEdge, "e6", `!g.pathThrough(e.from.id, e.to.id, "human_step")`, false, ""},
		{"pathThrough in edge rule (AI-003 hit)", ScopeEdge, "e5", `!g.pathThrough(e.from.id, e.to.id, "human_step")`, true, ""},
		// inZone
		{"inZone zone", ScopeNode, "u1", `n.inZone("zone")`, true, ""},
		{"inZone trust boundary", ScopeNode, "ag", `n.inZone("trust_boundary")`, true, ""},
		{"inZone not member", ScopeNode, "u1", `n.inZone("trust_boundary")`, false, ""},
		{"inZone ungrouped node", ScopeNode, "sec", `n.inZone("zone")`, false, ""},
		{"inZone on edge endpoint", ScopeEdge, "e1", `e.from.inZone("zone") && e.to.inZone("zone")`, true, ""},
		// description: declared free text, readable by rules through RE2 matches (docs/03 AGT-002).
		{"description projected", ScopeNode, "ag", `n.description.startsWith("Plans the work")`, true, ""},
		{"description empty when unset", ScopeNode, "web", `n.description`, "", ""},
		{"description matches hidden behaviour", ScopeNode, "ag",
			`n.description.matches("(?i)\\balso\\s+(uploads?|sends?)\\b")`, true, ""},
		{"description does not match on a clean node", ScopeNode, "web",
			`n.description.matches("(?i)\\balso\\s+(uploads?|sends?)\\b")`, false, ""},
		{"description on an edge endpoint", ScopeEdge, "e3", `e.to.description != ""`, true, ""},
		{"groups list", ScopeNode, "ag", `n.groups`, []any{"zone", "trust_boundary"}, ""},
		{"group ids", ScopeNode, "ag", `n.group_ids`, []any{"z_cloud", "tb_agent"}, ""},
		// attr
		{"attr present", ScopeNode, "web", `attr(n, "exposure", "")`, "public", ""},
		{"attr missing default", ScopeNode, "web", `attr(n, "waf", false)`, false, ""},
		{"attr null → default", ScopeNode, "db2", `attr(n, "x_null", "dflt")`, "dflt", ""},
		{"attr empty string counts as present", ScopeNode, "db2", `attr(n, "x_empty", "dflt")`, "", ""},
		{"attr bool", ScopeNode, "u1", `attr(n, "mfa", false)`, true, ""},
		{"attr negated missing bool", ScopeNode, "web", `!attr(n, "waf", false)`, true, ""},
		{"attr on edge", ScopeEdge, "e5", `attr(e, "consequence", "") == "high"`, true, ""},
		{"attr on edge endpoint", ScopeEdge, "e1", `attr(e.to, "exposure", "") == "public"`, true, ""},
		{"attr on graph", ScopeGraph, "", `attr(g, "criticality", "")`, "high", ""},
		{"attr on graph empty", ScopeGraph, "", `attr(g, "owner", "x") == ""`, true, ""},
		{"attr on graph missing", ScopeGraph, "", `attr(g, "dr_tested_at", "")`, "", ""},
		{"attr number vs int compare", ScopeNode, "ls", `attr(n, "retention_days", 0) < 365`, true, ""},
		{"attr number vs required", ScopeNode, "ls", `attr(n, "retention_days", 0) < required("retention_days")`, true, ""},
		{"attr float graph", ScopeGraph, "", `attr(g, "x_ratio", 0) > 2`, true, ""},
		{"attr int graph", ScopeGraph, "", `attr(g, "x_count", 0) == 3`, true, ""},
		{"attr region in tenant list", ScopeNode, "db", `attr(n, "region", "") in tenant.allowed_regions`, true, ""},
		{"attr region not in tenant list (DATA-003)", ScopeNode, "llm", `!(attr(n, "region", "") in tenant.allowed_regions)`, true, ""},
		{"attr on string errors", ScopeNode, "web", `attr("x", "a", "")`, nil, "first argument must be a node"},
		// direct field access
		{"edge fields", ScopeEdge, "e4", `e.kind == "calls" && e.auth == "api_key" && e.encryption == "tls" && e.data_class == ""`, true, ""},
		{"edge from/to names", ScopeEdge, "e4", `e.from.name + " -> " + e.to.name`, "N ag -> N llm", ""},
		{"node fields", ScopeNode, "web", `n.type == "app" && n.layer == "app" && n.zone == "" && n.source == "design"`, true, ""},
		{"graph id", ScopeGraph, "", `g.id`, "arch_t", ""},
		{"graph name", ScopeGraph, "", `g.name`, "helpers", ""},
		{"graph nodes field", ScopeGraph, "", `g.nodes.size()`, int64(10), ""},
		{"has macro on attrs", ScopeNode, "u1", `has(n.attrs.mfa) && !has(n.attrs.pim)`, true, ""},
		{"missing attr key errors without attr()", ScopeNode, "u1", `n.attrs.pim`, nil, "no such key"},
		// regime / required
		{"regime enabled", ScopeGraph, "", `regime("FINMA")`, true, ""},
		{"regime disabled", ScopeGraph, "", `regime("DORA")`, false, ""},
		{"regime alias ISG", ScopeGraph, "", `regime("CH-ISG") && regime("ISG")`, true, ""},
		{"regime alias ISO", ScopeGraph, "", `regime("ISO27001")`, false, ""},
		{"regime case-insensitive", ScopeGraph, "", `regime("finma")`, true, ""},
		{"required FINMA", ScopeGraph, "", `required("retention_days")`, int64(3650), ""},
		{"required unknown code", ScopeGraph, "", `required("nope")`, int64(0), ""},
		{"tenant regions", ScopeGraph, "", `tenant.allowed_regions`, []any{"switzerlandnorth"}, ""},
		// scoping
		{"node var not in edge scope", ScopeEdge, "e1", `n.id`, nil, "undeclared reference to 'n'"},
		{"edge var not in node scope", ScopeNode, "u1", `e.id`, nil, "undeclared reference to 'e'"},
		{"bad syntax", ScopeGraph, "", `g.has(`, nil, "Syntax error"},
		{"unknown helper", ScopeGraph, "", `g.nope("x")`, nil, "undeclared reference"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := evalExpr(t, tc.scope, tc.expr, a, pol, tc.element)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRequiredWithoutRegimesUsesDefault(t *testing.T) {
	t.Parallel()
	a := testModel()
	got, err := evalExpr(t, ScopeGraph, `required("retention_days")`, a, Policy{}, "")
	require.NoError(t, err)
	assert.Equal(t, int64(365), got)
	got, err = evalExpr(t, ScopeGraph, `required("retention_days")`, a, Policy{Regimes: []string{"AIACT"}}, "")
	require.NoError(t, err)
	assert.Equal(t, int64(180), got)
}

func TestTenantRegionsFallBackToPolicyTable(t *testing.T) {
	t.Parallel()
	got, err := evalExpr(t, ScopeGraph, `tenant.allowed_regions`, testModel(), Policy{}, "")
	require.NoError(t, err)
	assert.Equal(t, []any{"switzerlandnorth", "switzerlandwest"}, got)
}

func TestNormValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   any
		want any
	}{
		{"integral float → int64", float64(30), int64(30)},
		{"negative integral float", float64(-2), int64(-2)},
		{"fractional float stays", 2.5, 2.5},
		{"huge float stays float", 1e18, 1e18},
		{"int → int64", 7, int64(7)},
		{"uint64 → int64", uint64(9), int64(9)},
		{"bool stays", true, true},
		{"string stays", "x", "x"},
		{"nil stays", nil, nil},
		{"json.Number int", json.Number("12"), int64(12)},
		{"json.Number float", json.Number("1.5"), 1.5},
		{"nested map", map[string]any{"a": float64(1), "b": []any{float64(2), "c"}}, map[string]any{"a": int64(1), "b": []any{int64(2), "c"}}},
		{"attrs type", model.Attrs{"a": float64(1)}, map[string]any{"a": int64(1)}},
		{"string slice → list", []string{"a"}, []any{"a"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, normValue(tc.in))
		})
	}
}

func TestCanonRegime(t *testing.T) {
	t.Parallel()
	tests := map[string]string{"FINMA": "FINMA", "finma": "FINMA", "ISG": "CH-ISG", "CH-ISG": "CH-ISG", "ISO27001": "ISO",
		"ISO42001": "ISO", "ISO": "ISO", "CO": "CH-CO", "AI-ACT": "AIACT", "": ""}
	for in, want := range tests {
		assert.Equal(t, want, CanonRegime(in), in)
	}
	assert.Equal(t, "CH-ISG", CanonRegime(" isg "), "trimmed and upper-cased")
}

func TestRewriteSource(t *testing.T) {
	t.Parallel()
	assert.Equal(t, `g.inEdges(n.id,"calls")`, rewriteSource(`g.in(n.id,"calls")`))
	assert.Equal(t, `g .inEdges(x, y)`, rewriteSource(`g . in (x, y)`))
	assert.Equal(t, `e.kind in ["reads"]`, rewriteSource(`e.kind in ["reads"]`), "the in operator is untouched")
	assert.Equal(t, `g.inEdges(a, b)`, rewriteSource(`g.inEdges(a, b)`))
}

func TestDanglingEdgeEndpointDoesNotPanic(t *testing.T) {
	t.Parallel()
	a := testModel()
	a.Edges = append(a.Edges, model.Edge{ID: "e_bad", From: "ghost", To: "db", Kind: "reads", Auth: "none", Encryption: "none", Attrs: model.Attrs{}})
	got, err := evalExpr(t, ScopeEdge, `e.from.type == "" && e.from.id == "ghost" && attr(e.from, "x", "d") == "d"`, a, Policy{}, "e_bad")
	require.NoError(t, err)
	assert.Equal(t, true, got)
	got, err = evalExpr(t, ScopeGraph, `g.reachable("ghost", "db")`, a, Policy{}, "")
	require.NoError(t, err)
	assert.Equal(t, false, got)
}

// otModel is the command and data shape the OT pack reads (docs/03 §OT):
//
//	hub(broker) ─publishes→ node(edge_gateway) ─calls→ val(app, command_validation) ─writes→ plc(edge_device)
//	                                           ─writes→ plc2(edge_device)
//	node ─publishes→ hub; dev(edge_device) ─publishes→ hub ←subscribes─ ingest ─writes→ db ←reads─ tool ←calls─ ag
//	ag ─executes→ appr(human_step) ─calls→ hub; zones: line A = node, val, plc, plc2; line B = dev
func otModel() *model.Architecture {
	a := model.Empty("arch_ot", "tenant_t", "ot helpers")
	n := func(id, typ, layer string, attrs model.Attrs) model.Node {
		if attrs == nil {
			attrs = model.Attrs{}
		}
		return model.Node{ID: id, Type: typ, Name: "N " + id, Layer: layer, Source: "design", Attrs: attrs}
	}
	a.Nodes = []model.Node{
		n("hub", "broker", "platform", nil),
		n("node", "edge_gateway", "edge", nil),
		n("val", "app", "edge", model.Attrs{"command_validation": true}),
		n("plc", "edge_device", "edge", nil),
		n("plc2", "edge_device", "edge", nil),
		n("dev", "edge_device", "edge", nil),
		n("ingest", "api", "app", nil),
		n("db", "datastore", "data", nil),
		n("tool", "mcp_server", "app", nil),
		n("ag", "agent", "ai", nil),
		n("appr", "human_step", "human", nil),
	}
	e := func(id, from, to, kind string) model.Edge {
		return model.Edge{ID: id, From: from, To: to, Kind: kind, Auth: "managed_identity", Encryption: "tls", Attrs: model.Attrs{}}
	}
	a.Groups = []model.Group{
		{ID: "z_line_a", Kind: "zone", Name: "Line A", NodeIDs: []string{"node", "val", "plc", "plc2"}},
		{ID: "z_line_b", Kind: "zone", Name: "Line B", NodeIDs: []string{"dev"}},
	}
	for i := range a.Nodes {
		for _, g := range a.Groups {
			for _, id := range g.NodeIDs {
				if a.Nodes[i].ID == id {
					a.Nodes[i].Zone = g.ID
				}
			}
		}
	}
	a.Edges = []model.Edge{
		e("c1", "hub", "node", "publishes"), e("c2", "node", "val", "calls"), e("c3", "val", "plc", "writes"),
		e("c4", "node", "plc2", "writes"), e("d1", "dev", "hub", "publishes"), e("d2", "ingest", "hub", "subscribes"),
		e("d3", "ingest", "db", "writes"), e("d4", "tool", "db", "reads"), e("d5", "ag", "tool", "calls"),
		e("a1", "appr", "hub", "calls"), e("a2", "ag", "appr", "executes"), e("d6", "node", "hub", "publishes"),
	}
	return a
}

func TestOTHelpers(t *testing.T) {
	t.Parallel()
	a := otModel()
	tests := []struct {
		name string
		expr string
		want bool
	}{
		{"pathAvoiding: the only way passes the approval step", `g.pathAvoiding("ag", "plc2", "human_step")`, false},
		{"pathAvoiding: the approval step itself reaches the device", `g.pathAvoiding("appr", "plc2", "human_step")`, true},
		{"pathAvoiding: a node reaches itself", `g.pathAvoiding("ag", "ag", "human_step")`, true},
		{"pathAvoiding: a walk ending on the avoided type does not avoid it", `g.pathAvoiding("ag", "appr", "human_step")`, false},
		{"pathAvoiding: unknown from", `g.pathAvoiding("nope", "plc", "human_step")`, false},
		{"pathAvoidingAttr: every way to plc passes the validator", `g.pathAvoidingAttr("hub", "plc", "command_validation")`, false},
		{"pathAvoidingAttr: plc2 is written without validation", `g.pathAvoidingAttr("hub", "plc2", "command_validation")`, true},
		{"pathAvoidingAttr: the validator itself counts as validating", `g.pathAvoidingAttr("hub", "val", "command_validation")`, false},
		{"pathAvoidingAttr: from is not checked", `g.pathAvoidingAttr("val", "plc", "command_validation")`, true},
		{"dataFlows: device data reaches the agent (publish, subscribe, write, read, call)", `g.dataFlows("dev", "ag")`, true},
		{"dataFlows: the agent's data does not reach the device", `g.dataFlows("ag", "dev")`, false},
		{"dataFlows: a reader pulls from its target", `g.dataFlows("db", "tool")`, true},
		{"dataFlows: not against a publish", `g.dataFlows("hub", "dev")`, false},
		{"dataFlows: unknown from", `g.dataFlows("nope", "ag")`, false},
		{"dataSources: an edge device feeds the agent", `g.dataSources("ag", "edge") == ["node", "val", "dev"]`, true},
		{"dataSources: a device that only receives commands feeds nothing upstream", `!("plc" in g.dataSources("ag", "edge"))`, true},
		{"dataSources: nothing on the edge feeds the device that only publishes", `size(g.dataSources("dev", "edge")) == 0`, true},
		{"dataSources: unknown node", `size(g.dataSources("nope", "")) == 0`, true},
		{"dataZones: zones of the sources, distinct", `g.dataZones("db", "edge") == ["z_line_a", "z_line_b"]`, true},
		{"dataZones: layer filter", `size(g.dataZones("db", "data")) == 0`, true},
		{"writersInto: the nodes writing edge devices", `g.writersInto("edge_device") == ["node", "val"]`, true},
		{"writersInto: none into a type nobody writes", `size(g.writersInto("broker")) == 0`, true},
		{"upstreamAvoidingAttr: every source that reaches plc2 around the validator",
			`g.upstreamAvoidingAttr("node", "command_validation").map(c, c.id) == ["hub", "node", "dev", "ingest", "ag", "appr"]`, true},
		{"upstreamAvoidingAttr: agrees with pathAvoidingAttr",
			`g.nodes.all(c, (c in g.upstreamAvoidingAttr("node", "command_validation")) == g.pathAvoidingAttr(c.id, "node", "command_validation"))`, true},
		{"upstreamAvoidingAttr: a validating node is only its own source", `g.upstreamAvoidingAttr("val", "command_validation").map(c, c.id) == ["val"]`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := evalExpr(t, ScopeGraph, tc.expr, a, Policy{}, "")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
