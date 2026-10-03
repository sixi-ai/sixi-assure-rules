package rules

import (
	"encoding/json"
	"testing"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/traits"
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

// gatewayPathModel is the shape the all-paths rules read (ADR-088 §1, docs/03 "path rules"):
//
//	ag(agent) ─calls→ l1(llm)           ag ─calls→ gai(gateway kind ai) ─calls→ l1      (a bypass beside a gated route)
//	ap(app) ─calls→ gapi(gateway kind api) ─calls→ l2                                   (a gateway of another kind)
//	u(user) ─calls→ gnone(gateway, no kind) ─calls→ tool ─calls→ l3; ag ─calls→ tool    (an undeclared kind, a chain)
func gatewayPathModel() *model.Architecture {
	a := model.Empty("arch_paths", "tenant_t", "path helpers")
	n := func(id, typ, layer string, attrs model.Attrs) model.Node {
		if attrs == nil {
			attrs = model.Attrs{}
		}
		return model.Node{ID: id, Type: typ, Name: "N " + id, Layer: layer, Source: "design", Attrs: attrs}
	}
	a.Nodes = []model.Node{
		n("u", "user", "human", nil),
		n("ag", "agent", "ai", nil),
		n("ap", "app", "app", nil),
		n("gai", "gateway", "platform", model.Attrs{"kind": "ai"}),
		n("gapi", "gateway", "platform", model.Attrs{"kind": "api"}),
		n("gnone", "gateway", "platform", nil),
		n("tool", "tool", "app", nil),
		n("l1", "llm_endpoint", "ai", nil),
		n("l2", "llm_endpoint", "ai", nil),
		n("l3", "llm_endpoint", "ai", nil),
	}
	e := func(id, from, to string) model.Edge {
		return model.Edge{ID: id, From: from, To: to, Kind: "calls", Auth: "managed_identity", Encryption: "tls", Attrs: model.Attrs{}}
	}
	a.Edges = []model.Edge{
		e("p1", "ag", "l1"), e("p2", "ag", "gai"), e("p3", "gai", "l1"),
		e("p4", "ap", "gapi"), e("p5", "gapi", "l2"),
		e("p6", "u", "gnone"), e("p7", "gnone", "tool"), e("p8", "tool", "l3"), e("p9", "ag", "tool"),
	}
	return a
}

// functionPathModel: an agent reaches l1 through a gateway of kind api that declares observability and policy, and
// l2 through four AI gateways in series whose declared functions each lack one of observability and policy, except g4
// which declares observability only.
func functionPathModel() *model.Architecture {
	a := gatewayPathModel()
	n := func(id, typ string, attrs model.Attrs) model.Node {
		if attrs == nil {
			attrs = model.Attrs{}
		}
		return model.Node{ID: id, Type: typ, Name: id, Layer: "platform", Source: "design", Attrs: attrs}
	}
	fns := func(f ...any) model.Attrs { return model.Attrs{"kind": "ai", "functions": f} }
	a.Nodes = []model.Node{
		n("ag", "agent", nil),
		n("gfull", "gateway", model.Attrs{"kind": "api", "functions": []any{"observability", "policy"}}),
		n("g1", "gateway", fns("egress")),
		n("g2", "gateway", fns("identity_termination")),
		n("g3", "gateway", fns("policy")),
		n("g4", "gateway", fns("observability")),
		n("l1", "llm_endpoint", nil),
		n("l2", "llm_endpoint", nil),
	}
	e := func(id, from, to string) model.Edge {
		return model.Edge{ID: id, From: from, To: to, Kind: "calls", Auth: "managed_identity", Encryption: "tls", Attrs: model.Attrs{}}
	}
	a.Edges = []model.Edge{
		e("f1", "ag", "gfull"), e("f2", "gfull", "l1"),
		e("f3", "ag", "g1"), e("f4", "g1", "g2"), e("f5", "g2", "g3"), e("f6", "g3", "g4"), e("f7", "g4", "l2"),
	}
	return a
}

func TestUpstreamAvoiding(t *testing.T) {
	t.Parallel()
	paths, ot, fnPaths := gatewayPathModel(), otModel(), functionPathModel()
	tests := []struct {
		name string
		a    *model.Architecture
		expr string
		want bool
	}{
		{"a bypass beside a gated route: the agent reaches the model around the AI gateway",
			paths, `g.upstreamAvoiding("l1", ["gateway"], ["ai"]).map(c, c.id) == ["ag", "gai", "l1"]`, true},
		{"the gateway is a source but is not walked through",
			paths, `!g.upstreamAvoiding("l1", ["gateway"], ["ai"]).exists(c, c.id == "u")`, true},
		{"a blocked start is only its own source",
			paths, `g.upstreamAvoiding("gai", ["gateway"], ["ai"]).map(c, c.id) == ["gai"]`, true},
		{"a gateway of another kind does not block",
			paths, `g.upstreamAvoiding("l2", ["gateway"], ["ai"]).map(c, c.id) == ["ap", "gapi", "l2"]`, true},
		{"empty kinds: any gateway blocks",
			paths, `g.upstreamAvoiding("l2", ["gateway"], []).map(c, c.id) == ["gapi", "l2"]`, true},
		{"kinds as a list (the specs' \"api|waf\")",
			paths, `g.upstreamAvoiding("l2", ["gateway"], ["api", "waf"]).map(c, c.id) == ["gapi", "l2"]`, true},
		{"a gateway with no declared kind is not credited for a kind",
			paths, `g.upstreamAvoiding("l3", ["gateway"], ["ai"]).map(c, c.id) == ["u", "ag", "gnone", "tool", "l3"]`, true},
		{"the same gateway blocks when any kind will do",
			paths, `g.upstreamAvoiding("l3", ["gateway"], []).map(c, c.id) == ["ag", "gnone", "tool", "l3"]`, true},
		{"several blocked types",
			paths, `g.upstreamAvoiding("l3", ["gateway", "tool"], []).map(c, c.id) == ["tool", "l3"] && g.upstreamAvoiding("tool", ["gateway", "tool"], []).map(c, c.id) == ["tool"]`, true},
		{"no blocked type: every node with a walk to the target",
			paths, `g.upstreamAvoiding("l3", [], []).map(c, c.id) == ["u", "ag", "gnone", "tool", "l3"]`, true},
		{"unknown node", paths, `size(g.upstreamAvoiding("nope", ["gateway"], [])) == 0`, true},
		{"cel.bind names a value once (ext.Bindings, used by ZT-001 and STR-006)",
			paths, `cel.bind(blocked, ["gateway"], size(g.upstreamAvoiding("l2", blocked, [])) == 2)`, true},
		{"cached walk answers the same", paths,
			`g.upstreamAvoiding("l1", ["gateway"], ["ai"]) == g.upstreamAvoiding("l1", ["gateway"], ["ai"])`, true},
		{"agrees with pathAvoiding when kinds are empty",
			ot, `g.nodes.all(x, g.nodes.all(c, (c in g.upstreamAvoiding(x.id, ["human_step"], [])) == g.pathAvoiding(c.id, x.id, "human_step")))`, true},
		{"agrees with pathAvoiding on the gateway model",
			paths, `g.nodes.all(x, g.nodes.all(c, (c in g.upstreamAvoiding(x.id, ["gateway"], [])) == g.pathAvoiding(c.id, x.id, "gateway")))`, true},
		// The function-aware form (ADR-088 Amendments, B2b): declared functions decide; no functions declared credits by kind.
		{"functions: no functions declared credits by kind, as the kind form",
			paths, `g.upstreamAvoiding("l1", ["gateway"], ["ai"], ["policy"]) == g.upstreamAvoiding("l1", ["gateway"], ["ai"])`, true},
		{"functions: a gateway of another kind is walked through when it declares none",
			paths, `g.upstreamAvoiding("l2", ["gateway"], ["ai"], ["policy"]).map(c, c.id) == ["ap", "gapi", "l2"]`, true},
		{"functions: a gateway that declares every needed function blocks whatever its kind",
			fnPaths, `g.upstreamAvoiding("l1", ["gateway"], ["ai"], ["observability", "policy"]).map(c, c.id) == ["gfull", "l1"]`, true},
		{"functions: a gateway of the credited kind whose functions lack one is walked through",
			fnPaths, `g.upstreamAvoiding("l2", ["gateway"], ["ai"], ["observability", "policy"]).map(c, c.id) == ["ag", "g1", "g2", "g3", "g4", "l2"]`, true},
		{"functions: the walk is exact past three gateways in series",
			fnPaths, `g.upstreamAvoiding("l2", ["gateway"], ["ai"], ["observability"]).map(c, c.id) == ["g4", "l2"]`, true},
		{"functions: a crediting start is only its own source",
			fnPaths, `g.upstreamAvoiding("gfull", ["gateway"], [], ["policy"]).map(c, c.id) == ["gfull"]`, true},
		{"functions: empty kinds credit any gateway that declares none",
			paths, `g.upstreamAvoiding("l3", ["gateway"], [], ["policy"]) == g.upstreamAvoiding("l3", ["gateway"], [])`, true},
		{"functions: cached walk answers the same and differs from the attr form's cache",
			fnPaths, `g.upstreamAvoiding("l2", ["gateway"], ["ai"], ["observability"]) == g.upstreamAvoiding("l2", ["gateway"], ["ai"], ["observability"]) && g.upstreamAvoiding("l2", ["gateway"], ["ai"]).size() == 2`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := evalExpr(t, ScopeGraph, tc.expr, tc.a, Policy{}, "")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUpstreamAvoidingArguments(t *testing.T) {
	t.Parallel()
	_, err := stringList(types.NewDynamicList(types.DefaultTypeAdapter, []any{"gateway", 1}))
	require.Error(t, err, "a list with a non-string element")
	_, err = stringList(types.String("api|waf"))
	require.Error(t, err, "the specs' pipe notation is a list, not a string")
	got, err := stringList(types.NewDynamicList(types.DefaultTypeAdapter, []any{"api", "waf"}))
	require.NoError(t, err)
	assert.Equal(t, []string{"api", "waf"}, got)

	g := buildGraph(gatewayPathModel(), Policy{}, nil)
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"))), "arity")
	assert.True(t, types.IsError(graphUpstreamAvoiding(types.String("g"), types.String("l1"), types.NewStringList(types.DefaultTypeAdapter, nil), types.NewStringList(types.DefaultTypeAdapter, nil))), "receiver")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.Int(1), types.NewStringList(types.DefaultTypeAdapter, nil), types.NewStringList(types.DefaultTypeAdapter, nil))), "id")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), types.String("gateway"), types.NewStringList(types.DefaultTypeAdapter, nil))), "types")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), types.NewStringList(types.DefaultTypeAdapter, []string{"gateway"}), types.String("ai"))), "kinds")
	ok := graphUpstreamAvoiding(g, types.String("l1"), types.NewStringList(types.DefaultTypeAdapter, []string{"gateway"}), types.NewStringList(types.DefaultTypeAdapter, []string{"ai"}))
	require.False(t, types.IsError(ok))
	assert.Equal(t, types.Int(3), ok.(traits.Lister).Size())
	none := types.NewStringList(types.DefaultTypeAdapter, nil)
	agents := types.NewStringList(types.DefaultTypeAdapter, []string{"agent"})
	// Four arguments after the receiver are the function-aware form (Reconcile A, 2026-10-02): this call was an arity
	// error before the overload existed; it is now valid, and the form's own argument errors are pinned instead.
	assert.False(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), none, none, agents)), "the function-aware form")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), none, none, none)), "empty needFunctions")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), none, none, types.String("policy"))), "needFunctions not a list")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), none, none, agents, types.String("content_safety"), agents)), "arity 6")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), none, none, agents, types.String(""))), "an empty blocking attribute")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), none, none, agents, types.Int(1))), "a blocking attribute that is not a string")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), none, none, none, types.String("content_safety"))), "empty attrTypes")
	assert.True(t, types.IsError(graphUpstreamAvoiding(g, types.String("l1"), none, none, types.String("agent"), types.String("content_safety"))), "attrTypes not a list")
}

// The attr form of upstreamAvoiding also blocks every node of the given types whose boolean attribute is true
// (ADR-088 Amendments, AGT-003): A (no content safety) → B (content safety) → tool, and C (no content safety) → tool
// beside it; a tool that carries the attribute is not of the given types and does not block.
func TestUpstreamAvoidingBlockingAttr(t *testing.T) {
	t.Parallel()
	a := model.Empty("arch_attr_block", "tenant_t", "attr block")
	n := func(id, typ string, attrs model.Attrs) model.Node {
		return model.Node{ID: id, Type: typ, Name: "N " + id, Layer: "ai", Source: "design", Attrs: attrs}
	}
	a.Nodes = []model.Node{
		n("a", "agent", model.Attrs{"content_safety": false}),
		n("b", "agent", model.Attrs{"content_safety": true}),
		n("c", "agent", model.Attrs{}),
		n("gw", "gateway", model.Attrs{"kind": "ai"}),
		n("t", "tool", model.Attrs{}),
		n("t2", "tool", model.Attrs{"content_safety": true}),
		n("t3", "tool", model.Attrs{}),
	}
	e := func(id, from, to string) model.Edge {
		return model.Edge{ID: id, From: from, To: to, Kind: "calls", Auth: "managed_identity", Encryption: "tls", Attrs: model.Attrs{}}
	}
	a.Edges = []model.Edge{e("x1", "a", "b"), e("x2", "b", "t"), e("x3", "c", "gw"), e("x4", "gw", "t"), e("x5", "a", "t2"), e("x6", "t2", "t3")}
	tests := []struct{ name, expr string }{
		{"without the attr the walk passes the safe agent", `g.upstreamAvoiding("t", ["gateway"], []).map(x, x.id) == ["a", "b", "gw", "t"]`},
		{"the attr blocks the safe agent; it is a source but not walked through", `g.upstreamAvoiding("t", ["gateway"], [], ["agent"], "content_safety").map(x, x.id) == ["b", "gw", "t"]`},
		{"a blocked start is only its own source", `g.upstreamAvoiding("b", [], [], ["agent"], "content_safety").map(x, x.id) == ["b"]`},
		{"a false or missing attribute does not block", `g.upstreamAvoiding("gw", [], [], ["agent"], "content_safety").map(x, x.id) == ["c", "gw"]`},
		{"a node of another type with the attribute does not block", `g.upstreamAvoiding("t3", [], [], ["agent"], "content_safety").map(x, x.id) == ["a", "t2", "t3"]`},
		{"the attr form is cached apart from the plain form",
			`size(g.upstreamAvoiding("t", ["gateway"], [])) == 4 && size(g.upstreamAvoiding("t", ["gateway"], [], ["agent"], "content_safety")) == 3`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := evalExpr(t, ScopeGraph, tc.expr, a, Policy{}, "")
			require.NoError(t, err)
			assert.Equal(t, true, got)
		})
	}
}
