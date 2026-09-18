package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	modelschema "github.com/sixi-ai/sixi-assure-rules/schema"
)

func loadGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "golden-set", "models", name))
	require.NoError(t, err)
	return b
}

func TestGoldenModelValidates(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(filepath.Join("..", "golden-set", "models"))
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			a, err := ValidateJSON(loadGolden(t, e.Name()))
			require.NoError(t, err)
			assert.NotEmpty(t, a.Nodes)
			h, err := Hash(a)
			require.NoError(t, err)
			assert.Len(t, h, 64)
		})
	}
}

func TestEnumsMatchSchema(t *testing.T) {
	t.Parallel()
	var doc struct {
		Defs map[string]struct {
			Enum []string `json:"enum"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(modelschema.ModelSchema, &doc))
	cases := map[string][]string{
		"nodeType": NodeTypes, "layer": Layers, "source": Sources, "edgeKind": EdgeKinds, "edgeAuth": EdgeAuths,
		"edgeEncryption": Encryptions, "dataClass": DataClasses, "severity": Severities, "findingStatus": FindingStatuses,
		"groupKind": GroupKinds, "regime": Regimes, "integrity": Integrities,
	}
	for def, want := range cases {
		assert.Equal(t, want, doc.Defs[def].Enum, def)
	}
	var caps struct {
		Defs struct {
			Capabilities struct {
				Items struct {
					Enum []string `json:"enum"`
				} `json:"items"`
			} `json:"capabilities"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(modelschema.ModelSchema, &caps))
	assert.Equal(t, Capabilities, caps.Defs.Capabilities.Items.Enum, "capabilities")
	var scopes struct {
		Defs struct {
			EvaluationScope struct {
				Items struct {
					Enum []string `json:"enum"`
				} `json:"items"`
			} `json:"evaluationScope"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(modelschema.ModelSchema, &scopes))
	assert.Equal(t, EvaluationScopes, scopes.Defs.EvaluationScope.Items.Enum, "evaluationScope")
	var ev struct {
		Defs struct {
			EvidenceRef struct {
				Properties struct {
					Type struct {
						Enum []string `json:"enum"`
					} `json:"type"`
				} `json:"properties"`
			} `json:"evidenceRef"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(modelschema.ModelSchema, &ev))
	assert.Equal(t, EvidenceTypes, ev.Defs.EvidenceRef.Properties.Type.Enum)
}

func TestValidationRejects(t *testing.T) {
	t.Parallel()
	base := func() map[string]any {
		var m map[string]any
		require.NoError(t, json.Unmarshal(loadGolden(t, "rag-chatbot-bad.json"), &m))
		return m
	}
	tests := []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{"unknown node type", func(m map[string]any) { m["nodes"].([]any)[0].(map[string]any)["type"] = "toaster" }, "/nodes/0/type"},
		{"unknown attr", func(m map[string]any) {
			m["nodes"].([]any)[0].(map[string]any)["attrs"].(map[string]any)["colour"] = "red"
		}, "/nodes/0/attrs"},
		{"x_ attr allowed but must be scalar", func(m map[string]any) {
			m["nodes"].([]any)[0].(map[string]any)["attrs"].(map[string]any)["x_note"] = []any{1}
		}, "/nodes/0/attrs/x_note"},
		{"bad enum value", func(m map[string]any) { m["edges"].([]any)[0].(map[string]any)["auth"] = "magic" }, "/edges/0/auth"},
		{"dangling edge", func(m map[string]any) { m["edges"].([]any)[0].(map[string]any)["to"] = "n_missing" }, "/edges/0/to"},
		{"self loop", func(m map[string]any) {
			e := m["edges"].([]any)[0].(map[string]any)
			e["to"] = e["from"]
		}, "self-loop"},
		{"duplicate id", func(m map[string]any) { m["edges"].([]any)[1].(map[string]any)["id"] = "e_user_web" }, "duplicate id"},
		{"two zones", func(m map[string]any) {
			m["groups"].([]any)[0].(map[string]any)["node_ids"] = []any{"n_user", "n_web"}
		}, "already belongs to zone"},
		{"unknown region", func(m map[string]any) {
			m["nodes"].([]any)[5].(map[string]any)["attrs"].(map[string]any)["region"] = "moonbase"
		}, "unknown region"},
		{"unknown root field", func(m map[string]any) { m["extra"] = 1 }, "/"},
		{"finding referencing unknown id", func(m map[string]any) {
			m["findings"] = []any{map[string]any{"id": "f1", "rule_id": "ZT-001", "pack": "zt", "severity": "high", "status": "open", "ids": []any{"nope"}, "message": "m"}}
		}, "/findings/0/ids/0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := base()
			tt.mutate(m)
			b, _ := json.Marshal(m)
			_, err := ValidateJSON(b)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestSelfLoopDelegationAllowed(t *testing.T) {
	t.Parallel()
	a := Empty("arch_x", "t1", "x")
	a.Nodes = append(a.Nodes, Node{ID: "ag", Type: "agent", Name: "A", Layer: "ai", Attrs: Attrs{"identity": "agent_id"}})
	a.Edges = append(a.Edges, Edge{ID: "e1", From: "ag", To: "ag", Kind: "delegates", Auth: "obo", Encryption: "tls"})
	require.NoError(t, Validate(a))
	a.Edges[0].Auth = "api_key"
	require.Error(t, Validate(a))
}

func TestHashDeterministicAndIgnoresFindings(t *testing.T) {
	t.Parallel()
	a, err := ValidateJSON(loadGolden(t, "rag-chatbot-bad.json"))
	require.NoError(t, err)
	h1, _ := Hash(a)
	b, _ := a.Clone()
	b.Findings = append(b.Findings, Finding{ID: "f1", RuleID: "ZT-001", Pack: "zt", Severity: "high", Status: "open", IDs: []string{"e_agent_sql"}, Message: "m"})
	h2, _ := Hash(b)
	assert.Equal(t, h1, h2)
	b.Nodes[0].Name = "renamed"
	h3, _ := Hash(b)
	assert.NotEqual(t, h1, h3)
}

func TestApplyIDAddressedPatch(t *testing.T) {
	t.Parallel()
	a, err := ValidateJSON(loadGolden(t, "rag-chatbot-bad.json"))
	require.NoError(t, err)

	ops := []PatchOp{
		{Op: "replace", Path: "/edges/e_agent_sql/auth", Value: json.RawMessage(`"managed_identity"`)},
		{Op: "add", Path: "/nodes/-", Value: json.RawMessage(`{"id":"n_gw","type":"gateway","name":"AI gateway","layer":"platform","attrs":{"kind":"ai","logging":true}}`)},
		{Op: "replace", Path: "/edges/e_agent_llm/to", Value: json.RawMessage(`"n_gw"`)},
		{Op: "add", Path: "/edges/-", Value: json.RawMessage(`{"id":"e_gw_llm","from":"n_gw","to":"n_llm","kind":"calls","auth":"managed_identity","encryption":"tls"}`)},
		{Op: "replace", Path: "/nodes/n_agent/attrs/identity", Value: json.RawMessage(`"agent_id"`)},
		{Op: "add", Path: "/groups/g_cloud/node_ids/-", Value: json.RawMessage(`"n_gw"`)},
	}
	out, err := Apply(a, ops, false)
	require.NoError(t, err)
	assert.Equal(t, "managed_identity", out.Edge("e_agent_sql").Auth)
	assert.Equal(t, "n_gw", out.Edge("e_agent_llm").To)
	assert.Equal(t, "agent_id", out.Node("n_agent").Attrs.String("identity", ""))
	require.NotNil(t, out.Node("n_gw"))
	// input untouched
	assert.Equal(t, "connection_string", a.Edge("e_agent_sql").Auth)

	// Removing a node requires removing its group membership and edges in the same patch.
	_, err = Apply(a, []PatchOp{{Op: "remove", Path: "/nodes/n_kv"}}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/groups/1/node_ids")
	out, err = Apply(a, []PatchOp{
		{Op: "remove", Path: "/groups/g_cloud/node_ids/6"},
		{Op: "remove", Path: "/nodes/n_kv"},
	}, false)
	require.NoError(t, err)
	assert.Nil(t, out.Node("n_kv"))
	_, err = Apply(a, []PatchOp{{Op: "remove", Path: "/nodes/n_llm"}}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown node")
}

func TestApplyRejections(t *testing.T) {
	t.Parallel()
	a, err := ValidateJSON(loadGolden(t, "rag-chatbot-bad.json"))
	require.NoError(t, err)
	tests := []struct {
		name string
		ops  []PatchOp
		want string
	}{
		{"unknown id", []PatchOp{{Op: "replace", Path: "/edges/nope/auth", Value: json.RawMessage(`"tls"`)}}, `no edge with id "nope"`},
		{"findings are server-owned", []PatchOp{{Op: "add", Path: "/findings/-", Value: json.RawMessage(`{}`)}}, "managed by the server"},
		{"evidence is server-owned", []PatchOp{{Op: "remove", Path: "/evidence"}}, "managed by the server"},
		{"id immutable", []PatchOp{{Op: "replace", Path: "/id", Value: json.RawMessage(`"x"`)}}, "immutable"},
		{"version immutable", []PatchOp{{Op: "replace", Path: "/version", Value: json.RawMessage(`99`)}}, "immutable"},
		{"invalid value", []PatchOp{{Op: "replace", Path: "/edges/e_agent_sql/auth", Value: json.RawMessage(`"magic"`)}}, "/edges/4/auth"},
		{"test op mismatch", []PatchOp{{Op: "test", Path: "/name", Value: json.RawMessage(`"other"`)}}, "test"},
		{"empty", nil, "empty patch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Apply(a, tt.ops, false)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestObservedNodesReadOnly(t *testing.T) {
	t.Parallel()
	a := Empty("arch_x", "t1", "x")
	a.Nodes = append(a.Nodes, Node{ID: "obs", Type: "app", Name: "Observed", Layer: "app", Source: SourceObserved, Attrs: Attrs{}})
	require.NoError(t, Validate(a))
	_, err := Apply(a, []PatchOp{{Op: "replace", Path: "/nodes/obs/name", Value: json.RawMessage(`"x"`)}}, false)
	require.Error(t, err)
	_, err = Apply(a, []PatchOp{{Op: "remove", Path: "/nodes/obs"}}, false)
	require.Error(t, err)
	// Other edits are fine.
	_, err = Apply(a, []PatchOp{{Op: "replace", Path: "/name", Value: json.RawMessage(`"renamed"`)}}, false)
	require.NoError(t, err)
}

func TestRequiredAttrs(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"identity", "autonomy", "purpose", "owner"}, RequiredAttrs("agent"))
	assert.Equal(t, []string{"origin", "scopes"}, RequiredAttrs("mcp_server"))
	assert.Equal(t, []string{"exposure"}, RequiredAttrs("api"))
	assert.Empty(t, RequiredAttrs("queue"))
}

func TestAttrsHelpers(t *testing.T) {
	t.Parallel()
	at := Attrs{"s": "v", "b": true, "n": float64(7)}
	assert.Equal(t, "v", at.String("s", "d"))
	assert.Equal(t, "d", at.String("missing", "d"))
	assert.True(t, at.Bool("b", false))
	assert.Equal(t, 7, at.Int("n", 0))
	assert.Equal(t, 3, at.Int("missing", 3))
}
