package rules

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Schema 1.2 projection (ADR-093 M1, docs/18 WS-M): every framework attribute is readable through
// attr(), the workflow group kind is visible to inZone and g.groups (with its bounds), and the edge
// attributes are readable on every edge a helper returns, the flows inside a workflow included.
// No rule reads them yet (M3 adds packs/fw.yaml).
func schema12Model(t *testing.T) *model.Architecture {
	t.Helper()
	a := model.Empty("arch_12", "t", "schema 1.2")
	a.Groups = []model.Group{
		{ID: "g_wf", Kind: "workflow", Name: "Workflow", NodeIDs: []string{"sup", "worker", "note"},
			Attrs: model.Attrs{"max_iterations": 0.0, "checkpointing": "memory"}},
		{ID: "g_wf2", Kind: "workflow", Name: "Bounded", NodeIDs: []string{"exec"}, Attrs: model.Attrs{}},
	}
	a.Nodes = []model.Node{
		{ID: "srv", Type: "app", Name: "Server", Layer: "app", Attrs: model.Attrs{"exposure": "public", "protocols": []any{"mcp", "a2a"}, "integrity": "none"}},
		{ID: "sup", Type: "agent", Name: "Supervisor", Layer: "ai", Attrs: model.Attrs{"framework": "langgraph", "framework_version": "1.0.3",
			"kind": "orchestrator", "orchestration": "supervisor", "max_iterations": 0.0, "max_duration_s": 0.0, "hosted_on": "srv",
			"guardrails":        []any{map[string]any{"stage": "input", "kind": "llm"}, map[string]any{"stage": "output", "kind": "llm", "blocking": true}},
			"definition_source": "repository", "config_imports_code": true}},
		{ID: "worker", Type: "agent", Name: "Worker", Layer: "ai", Attrs: model.Attrs{"framework": "google_adk", "kind": "llm", "hosted_on": "srv"}},
		{ID: "exec", Type: "agent", Name: "Executor", Layer: "ai", Attrs: model.Attrs{"framework": "ms_agent_framework"}},
		{ID: "mem", Type: "agent_memory", Name: "Checkpoints", Layer: "data", Attrs: model.Attrs{"write_path": "every_step", "validated": false,
			"scope": "tenant", "retention_days": 0.0, "encryption": "none", "deserialization": "pickle", "hosted_on": "db"}},
		{ID: "db", Type: "datastore", Name: "DB", Layer: "data", Attrs: model.Attrs{"engine": "postgres", "data_class": "pii", "region": "ch", "encryption_key": "none"}},
		{ID: "code", Type: "tool", Name: "Code", Layer: "app", Attrs: model.Attrs{"origin": "first_party", "scopes": []any{"run"},
			"capabilities": []any{"executes_code"}, "sandbox": "model_hosted", "egress_policy": "disabled"}},
		{ID: "mcp", Type: "mcp_server", Name: "MCP", Layer: "app", Attrs: model.Attrs{"origin": "third_party", "scopes": []any{"r"},
			"transport": "websocket", "invoked_from": "provider", "sampling": "auto"}},
		{ID: "reg", Type: "agent_registry", Name: "Foundry", Layer: "identity", Attrs: model.Attrs{"kind": "foundry", "verification": "unknown"}},
		{ID: "note", Type: "note", Name: "Note", Layer: "app", Attrs: model.Attrs{"text": "the supervisor loops"}},
	}
	a.Edges = []model.Edge{
		{ID: "d1", From: "sup", To: "worker", Kind: "delegates", Auth: "none", Encryption: "none",
			Attrs: model.Attrs{"mode": "handoff", "routing": "llm_choice", "bidirectional": true, "context_forwarded": "full_history"}},
		{ID: "f1", From: "sup", To: "worker", Kind: "flows", Auth: "none", Encryption: "none",
			Attrs: model.Attrs{"flow_group": "fan_out", "condition_name": "needs_research"}},
		{ID: "c1", From: "worker", To: "mcp", Kind: "calls", Protocol: "mcp_http", Auth: "api_key", Encryption: "tls", Attrs: model.Attrs{"target_from_content": true}},
		{ID: "w1", From: "sup", To: "mem", Kind: "writes", Auth: "none", Encryption: "none", Attrs: model.Attrs{}},
	}
	require.NoError(t, model.Validate(a))
	return a
}

func TestSchema12Projection(t *testing.T) {
	t.Parallel()
	a := schema12Model(t)
	for _, tc := range []struct {
		name    string
		scope   string
		element string
		expr    string
		want    any
	}{
		// Agent attributes (FS-01 to FS-04, FS-14, FS-15, FS-21).
		{"framework and version", ScopeNode, "sup", `attr(n, "framework", "") + "@" + attr(n, "framework_version", "")`, "langgraph@1.0.3"},
		{"kind and orchestration", ScopeNode, "sup", `attr(n, "kind", "llm") == "orchestrator" && attr(n, "orchestration", "") == "supervisor"`, true},
		{"declared zero bound tells unbounded from undeclared", ScopeNode, "sup", `attr(n, "max_iterations", -1) == 0 && attr(n, "max_tool_calls", -1) == -1`, true},
		{"guardrails are a list of objects", ScopeNode, "sup", `attr(n, "guardrails", []).all(x, x.kind == "llm")`, true},
		{"guardrail members", ScopeNode, "sup", `attr(n, "guardrails", []).filter(x, has(x.blocking) && x.blocking).map(x, x.stage)`, []any{"output"}},
		{"definition loading", ScopeNode, "sup", `attr(n, "definition_source", "local") == "repository" && attr(n, "config_imports_code", false)`, true},
		{"agents hosted on one app", ScopeNode, "srv", `g.nodes("agent").filter(x, attr(x, "hosted_on", "") == n.id).map(x, x.id)`, []any{"sup", "worker"}},
		{"host bound through cel.bind", ScopeNode, "worker", `cel.bind(h, g.nodes("app").filter(x, x.id == attr(n, "hosted_on", "")), size(h) == 1 && "a2a" in attr(h[0], "protocols", []))`, true},
		// Memory, store, tool, MCP server, registry (FS-08 to FS-13, FS-16, FS-17, FS-18, FS-24).
		{"memory facts", ScopeNode, "mem", `attr(n, "scope", "") == "tenant" && attr(n, "retention_days", -1) == 0 && attr(n, "encryption", "") == "none" && attr(n, "deserialization", "") == "pickle"`, true},
		{"memory store", ScopeNode, "mem", `g.nodes("datastore").exists(d, d.id == attr(n, "hosted_on", "") && attr(d, "encryption_key", "") == "none")`, true},
		{"tool sandbox and egress", ScopeNode, "code", `attr(n, "sandbox", "") == "model_hosted" && attr(n, "egress_policy", "undeclared") in ["disabled", "default_deny_allowlist"]`, true},
		{"MCP transport, caller and sampling", ScopeNode, "mcp", `attr(n, "transport", "") == "websocket" && attr(n, "invoked_from", "client") == "provider" && attr(n, "sampling", "") == "auto"`, true},
		{"registry kind", ScopeNode, "reg", `attr(n, "kind", "")`, "foundry"},
		{"hosted runtime protocols and integrity", ScopeNode, "srv", `size(attr(n, "protocols", [])) == 2 && attr(n, "integrity", "") == "none"`, true},
		// Edge attributes (FS-05, FS-07, FS-22), on the edge and inside the flows a helper returns.
		{"delegation attributes", ScopeEdge, "d1", `attr(e, "mode", "") == "handoff" && attr(e, "routing", "") == "llm_choice" && attr(e, "bidirectional", false) && attr(e, "context_forwarded", "") == "full_history"`, true},
		{"flow group", ScopeEdge, "f1", `attr(e, "flow_group", "single") + ":" + attr(e, "condition_name", "")`, "fan_out:needs_research"},
		{"flows out of the supervisor", ScopeNode, "sup", `g.out(n.id, "flows").map(x, attr(x, "flow_group", "single"))`, []any{"fan_out"}},
		{"delegations into the worker", ScopeNode, "worker", `g.in(n.id, "delegates").exists(x, attr(x, "context_forwarded", "") == "full_history")`, true},
		{"graph edges of a kind", ScopeGraph, "", `g.edges("delegates").all(x, attr(x, "mode", "") in ["as_tool", "handoff"])`, true},
		{"computed target", ScopeEdge, "c1", `attr(e, "target_from_content", false) && e.auth == "api_key"`, true},
		// The workflow group kind (FS-06).
		{"workflow membership", ScopeNode, "worker", `n.inZone("workflow")`, true},
		{"not in a workflow", ScopeNode, "mem", `n.inZone("workflow")`, false},
		// A workflow is no boundary: it stays out of n.groups and n.group_ids (the packs compare those
		// to decide that an edge crosses a boundary) and is read through n.workflow_ids instead.
		{"workflow ids", ScopeNode, "sup", `n.workflow_ids`, []any{"g_wf"}},
		{"a workflow is not a group kind of the node", ScopeNode, "sup", `"workflow" in n.groups || "g_wf" in n.group_ids`, false},
		{"no workflow ids outside a workflow", ScopeNode, "mem", `size(n.workflow_ids)`, int64(0)},
		{"edge ends share no boundary through a workflow", ScopeEdge, "d1", `size(e.from.group_ids) + size(e.to.group_ids)`, int64(0)},
		{"graph groups", ScopeGraph, "", `g.groups.filter(x, x.kind == "workflow").map(x, x.id)`, []any{"g_wf", "g_wf2"}},
		{"workflow bounds", ScopeGraph, "", `g.groups.filter(x, x.kind == "workflow" && attr(x, "max_iterations", -1) == 0).map(x, x.id)`, []any{"g_wf"}},
		{"workflow checkpointing", ScopeGraph, "", `g.groups.exists(x, attr(x, "checkpointing", "") == "memory")`, true},
		{"a node's workflow", ScopeNode, "exec", `g.groups.exists(w, w.kind == "workflow" && n.id in w.node_ids && attr(w, "max_iterations", -1) == -1)`, true},
		{"notes stay out of a group's members", ScopeGraph, "", `g.groups.exists(x, "note" in x.node_ids)`, false},
		{"group members in model order", ScopeGraph, "", `g.groups[0].node_ids`, []any{"sup", "worker"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := evalExpr(t, tc.scope, tc.expr, a, Policy{}, tc.element)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestSchema12ProjectionOfAModelWithoutTheVocabulary: a model that declares none of it reads the
// defaults, never an error, and has no groups.
func TestSchema12ProjectionOfAModelWithoutTheVocabulary(t *testing.T) {
	t.Parallel()
	m := testModel()
	for _, tc := range []struct {
		expr string
		want any
	}{
		{`g.nodes("agent").all(x, attr(x, "framework", "") == "" && attr(x, "max_iterations", -1) == -1 && size(attr(x, "guardrails", [])) == 0)`, true},
		{`g.edges.all(x, attr(x, "mode", "") == "" && attr(x, "flow_group", "single") == "single")`, true},
		{`g.groups.all(x, x.kind != "workflow")`, true},
	} {
		got, err := evalExpr(t, ScopeGraph, tc.expr, m, Policy{}, "")
		require.NoError(t, err, tc.expr)
		assert.Equal(t, tc.want, got, tc.expr)
	}
}

// boundaryRules are the shipped rules whose condition reads "the two ends share no group id" (or a
// group kind) as crossing a boundary: drawing a workflow group must never move one of them.
var boundaryRules = []string{"DLG-003", "WIS-011", "ATA-001", "STR-002", "TLS-001", "SEG-", "NET-", "C4-"}

func isBoundaryRule(id string) bool {
	return slices.ContainsFunc(boundaryRules, func(p string) bool { return id == p || (p[len(p)-1] == '-' && len(id) > len(p) && id[:len(p)] == p) })
}

// withWorkflow returns a copy of a with one workflow group per members list (ids of assessed nodes).
func withWorkflow(t *testing.T, a *model.Architecture, members ...[]string) *model.Architecture {
	t.Helper()
	b := cloneArch(t, a)
	for i, ids := range members {
		if len(ids) == 0 {
			continue
		}
		b.Groups = append(b.Groups, model.Group{ID: "g_wf_test_" + string(rune('a'+i)), Kind: model.GroupKindWorkflow,
			Name: "Workflow", NodeIDs: slices.Clone(ids), Attrs: model.Attrs{}})
	}
	require.NoError(t, model.Validate(b))
	return b
}

func idsOf(a *model.Architecture, keep func(model.Node) bool) []string {
	var out []string
	for _, n := range model.AssessedNodes(a) {
		if keep(n) {
			out = append(out, n.ID)
		}
	}
	return out
}

// TestWorkflowGroupsNeverMoveFindings (review of M1): a workflow group lists the executors of one
// workflow; it is not a security boundary. Over every golden model, drawing workflow groups (all
// agents in one, every agent in its own, every assessed node in one) neither adds nor removes a
// finding, the boundary-crossing rules (DLG-003, WIS-011, ATA-*, STR-002, TLS-001, SEG-*, NET-*,
// C4-*) included.
func TestWorkflowGroupsNeverMoveFindings(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	files, err := filepath.Glob(repoPath("golden-set", "models", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	isAgent := func(n model.Node) bool { return n.Type == "agent" }
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, f)
			p := policyFromAttrs(a)
			want, err := eng.Evaluate(context.Background(), a, p)
			require.NoError(t, err)
			agents := idsOf(a, isAgent)
			each := make([][]string, 0, len(agents))
			for _, id := range agents {
				each = append(each, []string{id})
			}
			for _, tc := range []struct {
				name    string
				members [][]string
			}{
				{"all agents in one workflow", [][]string{agents}},
				{"every agent in its own workflow", each},
				{"every node in one workflow", [][]string{idsOf(a, func(model.Node) bool { return true })}},
			} {
				got, err := eng.Evaluate(context.Background(), withWorkflow(t, a, tc.members...), p)
				require.NoError(t, err, tc.name)
				assert.Equal(t, findingsByRule(want), findingsByRule(got), tc.name)
			}
		})
	}
}

// TestWorkflowGroupIsNoBoundary reproduces the review cases: agents in two trust boundaries with a
// delegation between them, and a third agent outside both. A workflow group around the delegating
// pair hides none of the boundary findings, and a workflow group alone creates none.
func TestWorkflowGroupIsNoBoundary(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	base := model.Empty("arch_wf", "t", "workflow is no boundary")
	agent := func(id string) model.Node {
		return model.Node{ID: id, Type: "agent", Name: "Agent " + id, Layer: "ai", Attrs: model.Attrs{
			"autonomy": "autonomous", "purpose": "p", "owner": "o", "identity": "shared"}}
	}
	base.Nodes = []model.Node{agent("a"), agent("b"), agent("c"),
		{ID: "tool", Type: "tool", Name: "Tool", Layer: "app", Attrs: model.Attrs{"origin": "third_party", "scopes": []any{"*"}}}}
	base.Edges = []model.Edge{
		{ID: "d_ab", From: "a", To: "b", Kind: "delegates", Auth: "obo", Encryption: "tls", Attrs: model.Attrs{"token_binding": "none"}},
		{ID: "d_bc", From: "b", To: "c", Kind: "delegates", Auth: "obo", Encryption: "tls", Attrs: model.Attrs{"token_binding": "none"}},
		{ID: "e_tool", From: "a", To: "tool", Kind: "calls", Auth: "none", Encryption: "tls", Attrs: model.Attrs{}},
	}
	require.NoError(t, model.Validate(base))
	bounded := cloneArch(t, base)
	bounded.Groups = []model.Group{
		{ID: "tb1", Kind: "trust_boundary", Name: "TB1", NodeIDs: []string{"a"}, Attrs: model.Attrs{}},
		{ID: "tb2", Kind: "trust_boundary", Name: "TB2", NodeIDs: []string{"b"}, Attrs: model.Attrs{}},
	}
	require.NoError(t, model.Validate(bounded))
	for _, tc := range []struct {
		name string
		a    *model.Architecture
	}{
		{"trust boundaries", bounded},
		{"no groups", base},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want, err := eng.Evaluate(context.Background(), tc.a, Policy{})
			require.NoError(t, err)
			for _, members := range [][]string{{"a", "b"}, {"b", "c"}, {"a", "b", "c", "tool"}, {"a"}} {
				got, err := eng.Evaluate(context.Background(), withWorkflow(t, tc.a, members), Policy{})
				require.NoError(t, err)
				assert.Equal(t, boundaryFindings(want), boundaryFindings(got), "workflow %v", members)
				assert.Equal(t, findingsByRule(want), findingsByRule(got), "workflow %v", members)
			}
		})
	}
	// The case is meaningful: the trust boundaries alone raise boundary findings on the delegation.
	bf, err := eng.Evaluate(context.Background(), bounded, Policy{})
	require.NoError(t, err)
	assert.NotEmpty(t, boundaryFindings(bf), "the trust-boundary model raises at least one boundary-crossing finding")
}

func boundaryFindings(fs []model.Finding) map[string][]string {
	out := map[string][]string{}
	for rule, ids := range findingsByRule(fs) {
		if isBoundaryRule(rule) {
			out[rule] = ids
		}
	}
	return out
}

func cloneArch(t *testing.T, a *model.Architecture) *model.Architecture {
	t.Helper()
	b, err := a.Clone()
	require.NoError(t, err)
	return b
}
