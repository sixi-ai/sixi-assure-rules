package model

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Schema 1.2 (ADR-093 M1, docs/18 WS-M, docs/research/07-agentic-frameworks/00-synthesis.md §2): the
// framework vocabulary. Every addition is optional; the server checks what JSON Schema cannot say
// (hosted_on names a node, the delegation and flow attributes sit on their edge kinds, the workflow
// bounds on a workflow group).

// frameworks12 is a small valid 1.2 model using every new construct once.
func frameworks12() map[string]any {
	return map[string]any{
		"schema_version": CurrentSchemaVersion, "id": "arch_12", "tenant_id": "t", "name": "1.2", "version": 1,
		"attrs": map[string]any{},
		"groups": []any{
			map[string]any{"id": "g_wf", "kind": "workflow", "name": "Claims workflow", "node_ids": []any{"n_sup", "n_worker"},
				"attrs": map[string]any{"max_iterations": 100, "checkpointing": "store"}},
			map[string]any{"id": "g_zone", "kind": "zone", "name": "Cloud", "node_ids": []any{"n_app"}},
		},
		"nodes": []any{
			map[string]any{"id": "n_app", "type": "app", "name": "LangGraph Server", "layer": "app", "zone": "g_zone", "attrs": map[string]any{
				"exposure": "public", "authn": []any{"oidc"}, "protocols": []any{"http_api", "mcp", "a2a"}, "integrity": "pinned"}},
			map[string]any{"id": "n_sup", "type": "agent", "name": "Supervisor", "layer": "ai", "attrs": map[string]any{
				"autonomy": "semi", "purpose": "route claims", "owner": "o",
				"framework": "langgraph", "framework_version": "1.0.3", "kind": "orchestrator", "orchestration": "supervisor",
				"max_iterations": 25, "max_tool_calls": 0, "max_duration_s": 300,
				"guardrails": []any{
					map[string]any{"stage": "input", "kind": "code", "blocking": true, "scope": "runner"},
					map[string]any{"stage": "tool_output", "kind": "llm"},
				},
				"definition_source": "local", "config_imports_code": false, "config_env_access": false, "hosted_on": "n_app"}},
			map[string]any{"id": "n_worker", "type": "agent", "name": "Worker", "layer": "ai", "attrs": map[string]any{
				"framework": "google_adk", "kind": "llm", "hosted_on": "n_app"}},
			map[string]any{"id": "n_mem", "type": "agent_memory", "name": "Checkpoints", "layer": "data", "attrs": map[string]any{
				"write_path": "every_step", "validated": false, "scope": "tenant", "retention_days": 0,
				"encryption": "none", "deserialization": "pickle", "hosted_on": "n_db"}},
			map[string]any{"id": "n_db", "type": "datastore", "name": "Postgres", "layer": "data", "attrs": map[string]any{
				"engine": "postgres", "data_class": "pii", "region": "ch", "encryption_key": "none"}},
			map[string]any{"id": "n_code", "type": "tool", "name": "Code executor", "layer": "app", "attrs": map[string]any{
				"origin": "first_party", "scopes": []any{"run"}, "capabilities": []any{"executes_code"},
				"sandbox": "wasm", "egress_policy": "disabled", "egress_allowlist": []any{"pypi.org"}}},
			map[string]any{"id": "n_mcp", "type": "mcp_server", "name": "Hosted MCP", "layer": "app", "attrs": map[string]any{
				"origin": "third_party", "scopes": []any{"read"}, "transport": "websocket", "invoked_from": "provider", "sampling": "gated"}},
			map[string]any{"id": "n_reg", "type": "agent_registry", "name": "Foundry", "layer": "identity", "attrs": map[string]any{
				"kind": "foundry", "verification": "unknown"}},
			map[string]any{"id": "n_api", "type": "api", "name": "Partner API", "layer": "app", "attrs": map[string]any{"exposure": "public"}},
		},
		"edges": []any{
			map[string]any{"id": "e_del", "from": "n_sup", "to": "n_worker", "kind": "delegates", "auth": "none", "encryption": "none",
				"attrs": map[string]any{"mode": "handoff", "routing": "llm_choice", "bidirectional": true, "context_forwarded": "full_history"}},
			map[string]any{"id": "e_flow", "from": "n_sup", "to": "n_worker", "kind": "flows", "auth": "none", "encryption": "none",
				"attrs": map[string]any{"flow_group": "switch_case", "condition_name": "is_large_claim"}},
			map[string]any{"id": "e_http", "from": "n_worker", "to": "n_api", "kind": "calls", "protocol": "https", "auth": "api_key", "encryption": "tls",
				"attrs": map[string]any{"target_from_content": true}},
			map[string]any{"id": "e_mem", "from": "n_sup", "to": "n_mem", "kind": "writes", "auth": "none", "encryption": "none", "attrs": map[string]any{}},
		},
		"findings": []any{}, "evidence": []any{},
	}
}

func TestSchema12ModelValidates(t *testing.T) {
	t.Parallel()
	a, err := ValidateJSON(marshal(t, frameworks12()))
	require.NoError(t, err)
	assert.Equal(t, "1.2", a.SchemaVersion)
	sup := a.Node("n_sup")
	require.NotNil(t, sup)
	assert.Equal(t, "langgraph", sup.Attrs["framework"])
	assert.Equal(t, "orchestrator", sup.Attrs["kind"])
	assert.Len(t, sup.Attrs["guardrails"], 2)
	assert.Equal(t, GroupKindWorkflow, a.Group("g_wf").Kind)

	// The vocabulary is part of the designed model: the hash covers it.
	h1, err := Hash(a)
	require.NoError(t, err)
	b, err := a.Clone()
	require.NoError(t, err)
	b.Edges[0].Attrs["context_forwarded"] = "last_message"
	h2, err := Hash(b)
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2)

	// A Go value carrying the vocabulary validates too.
	require.NoError(t, Validate(a))
}

func TestSchema12Rejects(t *testing.T) {
	t.Parallel()
	nodeAttrs := func(m map[string]any, id string) map[string]any {
		for _, n := range m["nodes"].([]any) {
			if n.(map[string]any)["id"] == id {
				return n.(map[string]any)["attrs"].(map[string]any)
			}
		}
		t.Fatalf("no node %s", id)
		return nil
	}
	edge := func(m map[string]any, id string) map[string]any {
		for _, e := range m["edges"].([]any) {
			if e.(map[string]any)["id"] == id {
				return e.(map[string]any)
			}
		}
		t.Fatalf("no edge %s", id)
		return nil
	}
	group := func(m map[string]any, id string) map[string]any {
		for _, g := range m["groups"].([]any) {
			if g.(map[string]any)["id"] == id {
				return g.(map[string]any)
			}
		}
		t.Fatalf("no group %s", id)
		return nil
	}
	for _, tc := range []struct {
		name   string
		mutate func(m map[string]any)
		path   string
		msg    string
	}{
		// SD-2 groundwork: an agent's or a memory's host is a node of the model.
		{"agent hosted on nothing", func(m map[string]any) { nodeAttrs(m, "n_sup")["hosted_on"] = "n_gone" }, "/nodes/1/attrs/hosted_on", "names no node of this model"},
		{"agent hosted on itself", func(m map[string]any) { nodeAttrs(m, "n_sup")["hosted_on"] = "n_sup" }, "/nodes/1/attrs/hosted_on", "not hosted on itself"},
		{"memory hosted on nothing", func(m map[string]any) { nodeAttrs(m, "n_mem")["hosted_on"] = "free text host" }, "/nodes/3/attrs/hosted_on", "names no node of this model"},
		{"agent hosted on a note", func(m map[string]any) {
			m["nodes"] = append(m["nodes"].([]any), map[string]any{"id": "n_note", "type": "note", "name": "Note", "layer": "app", "attrs": map[string]any{"text": "t"}})
			nodeAttrs(m, "n_sup")["hosted_on"] = "n_note"
		}, "/nodes/1/attrs/hosted_on", "a note hosts nothing"},
		// SD-1: the delegation attributes belong to delegates edges, the flow-group ones to flows edges.
		{"mode on a calls edge", func(m map[string]any) { edge(m, "e_http")["attrs"].(map[string]any)["mode"] = "as_tool" }, "/edges/2/attrs/mode", "set only on a delegates edge"},
		{"context on a writes edge", func(m map[string]any) { edge(m, "e_mem")["attrs"].(map[string]any)["context_forwarded"] = "none" }, "/edges/3/attrs/context_forwarded", "set only on a delegates edge"},
		{"bidirectional false is a statement too", func(m map[string]any) { edge(m, "e_flow")["attrs"].(map[string]any)["bidirectional"] = false }, "/edges/1/attrs/bidirectional", "set only on a delegates edge"},
		{"flow group on a delegates edge", func(m map[string]any) { edge(m, "e_del")["attrs"].(map[string]any)["flow_group"] = "fan_out" }, "/edges/0/attrs/flow_group", "set only on a flows edge"},
		{"workflow bound on a zone", func(m map[string]any) {
			group(m, "g_zone")["attrs"] = map[string]any{"max_iterations": 3}
		}, "/groups/1/attrs/max_iterations", "set only on a workflow group"},
		{"checkpointing on a zone", func(m map[string]any) {
			group(m, "g_zone")["attrs"] = map[string]any{"checkpointing": "memory"}
		}, "/groups/1/attrs/checkpointing", "set only on a workflow group"},
		// Enums and shapes.
		{"unknown framework", func(m map[string]any) { nodeAttrs(m, "n_sup")["framework"] = "autogen" }, "/nodes/1/attrs/framework", ""},
		{"unknown orchestration", func(m map[string]any) { nodeAttrs(m, "n_sup")["orchestration"] = "anarchy" }, "/nodes/1/attrs/orchestration", ""},
		{"negative loop bound", func(m map[string]any) { nodeAttrs(m, "n_sup")["max_iterations"] = -1 }, "/nodes/1/attrs/max_iterations", ""},
		{"guardrail without kind", func(m map[string]any) {
			nodeAttrs(m, "n_sup")["guardrails"] = []any{map[string]any{"stage": "input"}}
		}, "/nodes/1/attrs/guardrails/0", ""},
		{"guardrail unknown stage", func(m map[string]any) {
			nodeAttrs(m, "n_sup")["guardrails"] = []any{map[string]any{"stage": "everywhere", "kind": "code"}}
		}, "/nodes/1/attrs/guardrails/0/stage", ""},
		{"unknown hosted protocol", func(m map[string]any) { nodeAttrs(m, "n_app")["protocols"] = []any{"gopher"} }, "/nodes/0/attrs/protocols/0", ""},
		{"unknown deserialisation", func(m map[string]any) { nodeAttrs(m, "n_mem")["deserialization"] = "yaml" }, "/nodes/3/attrs/deserialization", ""},
		{"unknown flow group", func(m map[string]any) { edge(m, "e_flow")["attrs"].(map[string]any)["flow_group"] = "broadcast" }, "/edges/1/attrs/flow_group", ""},
		// FS-23: sas is a 1.2 value since the shared-secret rules name it (Reconcile A, 2026-10-02; ADR-093-M1 §4):
		// TestSchema12Accepts takes it now, and a spelling outside the enum is still refused.
		{"an auth spelling outside the enum", func(m map[string]any) { edge(m, "e_http")["auth"] = "shared_access_signature" }, "/edges/2/auth", ""},
		// x-attr-values: the 1.2 values are per type.
		{"wasm sandbox on an MCP server", func(m map[string]any) { nodeAttrs(m, "n_mcp")["sandbox"] = "wasm" }, "/nodes/6/attrs/sandbox", "a mcp_server accepts"},
		{"vm sandbox on an agent", func(m map[string]any) { nodeAttrs(m, "n_sup")["sandbox"] = "vm" }, "/nodes/1/attrs/sandbox", "a agent accepts"},
		{"disabled egress on an agent", func(m map[string]any) { nodeAttrs(m, "n_sup")["egress_policy"] = "disabled" }, "/nodes/1/attrs/egress_policy", "a agent accepts"},
		{"agent kind on a gateway", func(m map[string]any) {
			m["nodes"] = append(m["nodes"].([]any), map[string]any{"id": "n_gw", "type": "gateway", "name": "GW", "layer": "platform", "attrs": map[string]any{"kind": "orchestrator"}})
		}, "/nodes/9/attrs/kind", "a gateway accepts"},
		{"foundry kind on a gateway", func(m map[string]any) {
			m["nodes"] = append(m["nodes"].([]any), map[string]any{"id": "n_gw", "type": "gateway", "name": "GW", "layer": "platform", "attrs": map[string]any{"kind": "foundry"}})
		}, "/nodes/9/attrs/kind", "a gateway accepts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := frameworks12()
			tc.mutate(m)
			_, err := ValidateJSON(marshal(t, m))
			var ve *ValidationError
			require.True(t, errors.As(err, &ve), "%v", err)
			paths := make([]string, 0, len(ve.Problems))
			found := false
			for _, p := range ve.Problems {
				paths = append(paths, p.Path)
				if p.Path == tc.path {
					found = true
					if tc.msg != "" {
						assert.Contains(t, p.Message, tc.msg)
					}
				}
			}
			assert.True(t, found, "want a problem at %s, got %v", tc.path, paths)
			assert.NotContains(t, err.Error(), "free text host", "a hosted_on value is never echoed")
		})
	}
}

// TestSchema12Accepts: what 1.2 keeps valid that a stricter reading might refuse.
func TestSchema12Accepts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(m map[string]any)
	}{
		{"an agent-to-agent calls edge stays valid (the convention is delegates, docs/02 §10)", func(m map[string]any) {
			m["edges"] = append(m["edges"].([]any), map[string]any{"id": "e_call", "from": "n_sup", "to": "n_worker", "kind": "calls", "auth": "none", "encryption": "none", "attrs": map[string]any{}})
		}},
		{"an empty delegation attribute on a calls edge counts as unset", func(m map[string]any) {
			for _, e := range m["edges"].([]any) {
				if e.(map[string]any)["id"] == "e_http" {
					e.(map[string]any)["attrs"].(map[string]any)["mode"] = ""
				}
			}
		}},
		{"an empty hosted_on on an agent is undeclared", func(m map[string]any) {
			m["nodes"].([]any)[1].(map[string]any)["attrs"].(map[string]any)["hosted_on"] = ""
		}},
		{"a tool keeps the 1.1 reading of hosted_on (a declaration, not checked)", func(m map[string]any) {
			m["nodes"].([]any)[5].(map[string]any)["attrs"].(map[string]any)["hosted_on"] = "edge-box-7"
		}},
		{"a workflow group without bounds", func(m map[string]any) {
			m["groups"].([]any)[0].(map[string]any)["attrs"] = map[string]any{}
		}},
		{"an agent kind no 1.2 profile lists is read, not refused (tolerant reading)", func(m map[string]any) {
			m["nodes"].([]any)[2].(map[string]any)["attrs"].(map[string]any)["kind"] = "waf"
		}},
		// FS-23, restored once every shared-secret rule names it (ADR-093-M1 §4; rules TestSASReadsAsAnAPIKey).
		{"a shared access signature (auth sas)", func(m map[string]any) {
			for _, e := range m["edges"].([]any) {
				if e.(map[string]any)["id"] == "e_http" {
					e.(map[string]any)["auth"] = "sas"
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := frameworks12()
			tc.mutate(m)
			_, err := ValidateJSON(marshal(t, m))
			require.NoError(t, err)
		})
	}
}

func TestScopedAttrKindsComeFromTheSchema(t *testing.T) {
	t.Parallel()
	edges := EdgeAttrKinds()
	for _, k := range []string{"mode", "routing", "bidirectional", "context_forwarded"} {
		assert.Equal(t, []string{"delegates"}, edges[k], k)
	}
	assert.Equal(t, []string{"flows"}, edges["flow_group"])
	assert.Equal(t, []string{"flows"}, edges["condition_name"])
	assert.NotContains(t, edges, "target_from_content", "a computed target is a fact of any call")
	assert.NotContains(t, edges, "audience")
	groups := GroupAttrKinds()
	assert.Equal(t, map[string][]string{"max_iterations": {"workflow"}, "checkpointing": {"workflow"}}, groups)
	edges["mode"][0] = "changed"
	assert.Equal(t, "delegates", EdgeAttrKinds()["mode"][0], "a copy is returned")
}

// TestSchema12UpgradeOnRead (review of M1): a model valid at 1.1 is never refused once 1.2 is
// current (ADR-040 §1). A free-text hosted_on on an agent or agent_memory (the 1.1 flat attribute
// set accepted it) is removed by the 1.1 → 1.2 step with an x_migrated_from note, and an attribute a
// rewrite removes takes its provenance entry (ADR-086) with it, on a stored 1.1 document and on a
// current one (the tolerant reading) alike.
func TestSchema12UpgradeOnRead(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		raw      string
		node     string
		gone     string // the attribute that is removed
		migrated string // the x_migrated_from note it leaves
		provKept []string
	}{
		{"1.1 agent with a free-text host",
			`{"schema_version":"1.1","id":"arch","tenant_id":"t","name":"m","version":1,"attrs":{},"groups":[],"findings":[],"evidence":[],"edges":[],` +
				`"nodes":[{"id":"a","type":"agent","name":"A","layer":"ai","attrs":{"hosted_on":"aks-prod-cluster"}},` +
				`{"id":"m","type":"agent_memory","name":"M","layer":"data","attrs":{"hosted_on":"redis"}}]}`,
			"a", "hosted_on", "hosted_on=aks-prod-cluster", nil},
		{"1.1 agent_memory with a free-text host",
			`{"schema_version":"1.1","id":"arch","tenant_id":"t","name":"m","version":1,"attrs":{},"groups":[],"findings":[],"evidence":[],"edges":[],` +
				`"nodes":[{"id":"a","type":"agent","name":"A","layer":"ai","attrs":{"hosted_on":"aks-prod-cluster"}},` +
				`{"id":"m","type":"agent_memory","name":"M","layer":"data","attrs":{"hosted_on":"redis"}}]}`,
			"m", "hosted_on", "hosted_on=redis", nil},
		{"1.1 agent kind with a provenance entry",
			`{"schema_version":"1.1","id":"arch","tenant_id":"t","name":"m","version":1,"attrs":{},"groups":[],"findings":[],"evidence":[],"edges":[],` +
				`"nodes":[{"id":"a","type":"agent","name":"A","layer":"ai","attrs":{"kind":"api","owner":"o"}}],` +
				`"provenance":{"/nodes/a/attrs/kind":{"kind":"declared"},"/nodes/a/attrs/owner":{"kind":"declared"}}}`,
			"a", "kind", "kind=api", []string{"/nodes/a/attrs/owner"}},
		{"1.1 agent host with a provenance entry",
			`{"schema_version":"1.1","id":"arch","tenant_id":"t","name":"m","version":1,"attrs":{},"groups":[],"findings":[],"evidence":[],"edges":[],` +
				`"nodes":[{"id":"a","type":"agent","name":"A","layer":"ai","attrs":{"hosted_on":"vm-7"}}],` +
				`"provenance":{"/nodes/a/attrs/hosted_on":{"kind":"imported"},"/nodes/a":{"kind":"declared"}}}`,
			"a", "hosted_on", "hosted_on=vm-7", []string{"/nodes/a"}},
		{"current agent kind with a provenance entry (tolerant reading)",
			`{"schema_version":"` + CurrentSchemaVersion + `","id":"arch","tenant_id":"t","name":"m","version":1,"attrs":{},"groups":[],"findings":[],"evidence":[],"edges":[],` +
				`"nodes":[{"id":"a","type":"agent","name":"A","layer":"ai","attrs":{"kind":"api"}}],` +
				`"provenance":{"/nodes/a/attrs/kind":{"kind":"declared"}}}`,
			"a", "kind", "kind=api", nil},
		{"current tool egress boolean with a provenance entry (tolerant reading)",
			`{"schema_version":"` + CurrentSchemaVersion + `","id":"arch","tenant_id":"t","name":"m","version":1,"attrs":{},"groups":[],"findings":[],"evidence":[],"edges":[],` +
				`"nodes":[{"id":"a","type":"tool","name":"T","layer":"app","attrs":{"origin":"first_party","scopes":["r"],"egress_policy":true}}],` +
				`"provenance":{"/nodes/a/attrs/egress_policy":{"kind":"declared"},"/nodes/a/attrs/origin":{"kind":"declared"}}}`,
			"a", "egress_policy", "egress_policy=true", []string{"/nodes/a/attrs/origin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := ValidateJSON([]byte(tc.raw))
			require.NoError(t, err)
			assert.Equal(t, CurrentSchemaVersion, a.SchemaVersion)
			n := a.Node(tc.node)
			require.NotNil(t, n)
			assert.NotContains(t, n.Attrs, tc.gone)
			assert.Contains(t, n.Attrs[MigratedFromAttr], tc.migrated)
			kept := make([]string, 0, len(a.Provenance))
			for k := range a.Provenance {
				kept = append(kept, k)
			}
			assert.ElementsMatch(t, tc.provKept, kept, "only the removed attribute's provenance entry goes")
			// The upgraded model saves and patches: Validate and a patch round-trip accept it.
			require.NoError(t, Validate(a))
			_, err = Apply(a, []PatchOp{{Op: "replace", Path: "/name", Value: []byte(`"renamed"`)}}, false)
			require.NoError(t, err)
		})
	}
}

// TestNormalizeLegacyShapesDropsProvenance: the Go-value form of the tolerant reading (an importer or a
// pattern that builds an Architecture) drops the provenance entry of an attribute it removes.
func TestNormalizeLegacyShapesDropsProvenance(t *testing.T) {
	t.Parallel()
	a := Empty("arch", "t", "m")
	a.Nodes = []Node{{ID: "a.1", Type: "agent", Name: "A", Layer: "ai", Attrs: Attrs{"kind": "waf", "owner": "o"}}}
	a.Provenance = Provenance{
		"/nodes/a.1/attrs/kind":  {Kind: ProvenanceDeclared},
		"/nodes/a.1/attrs/owner": {Kind: ProvenanceDeclared},
	}
	require.NoError(t, Validate(a))
	assert.NotContains(t, a.Nodes[0].Attrs, "kind")
	assert.Equal(t, "kind=waf", a.Nodes[0].Attrs[MigratedFromAttr])
	assert.Len(t, a.Provenance, 1)
	assert.Contains(t, a.Provenance, "/nodes/a.1/attrs/owner")
}

// TestRemovingAHost: the patch the web's removeNodeOps builds (the hosted_on references cleared,
// then the host removed) applies; removing the host alone leaves a dangling hosted_on and is refused.
func TestRemovingAHost(t *testing.T) {
	t.Parallel()
	a, err := ValidateJSON(marshal(t, frameworks12()))
	require.NoError(t, err)
	_, err = Apply(a, []PatchOp{{Op: "remove", Path: "/groups/g_zone/node_ids/0"}, {Op: "remove", Path: "/nodes/n_app"}}, false)
	require.Error(t, err, "a host removed under its agents leaves dangling references")
	assert.Contains(t, err.Error(), "names no node of this model")
	out, err := Apply(a, []PatchOp{
		{Op: "remove", Path: "/nodes/n_sup/attrs/hosted_on"},
		{Op: "remove", Path: "/nodes/n_worker/attrs/hosted_on"},
		{Op: "remove", Path: "/groups/g_zone/node_ids/0"},
		{Op: "remove", Path: "/nodes/n_app"},
	}, false)
	require.NoError(t, err)
	assert.Nil(t, out.Node("n_app"))
}
