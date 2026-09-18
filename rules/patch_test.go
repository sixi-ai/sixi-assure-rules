package rules

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

func TestPatchForPlaceholders(t *testing.T) {
	t.Parallel()
	c := mustInline(t, `
pack: tst
version: 0.1.0
rules:
  - id: TST-001
    title: T
    scope: edge
    severity: high
    condition: 'e.id == "e5"'
    message: "m"
    clauses: [A:B]
    patch_template:
      - { op: add, path: "/nodes/-", value: { id: "{{new:hs}}", type: human_step, name: "Approval for {{e.to.name}}", layer: human, attrs: { role: ops, x_count: "{{attr(g,'x_count',0)}}", x_flag: "{{e.from.type == 'agent'}}" } } }
      - { op: replace, path: "/edges/{{e.id}}/to", value: "{{new:hs}}" }
      - { op: add, path: "/edges/-", value: { id: "{{new:e}}", from: "{{new:hs}}", to: "{{e.to.id}}", kind: "{{e.kind}}", auth: managed_identity, encryption: tls, attrs: { consequence: high, x_arch: "{{g.id}}", x_src: "{{e.from.id}}" } } }
      - { op: test, path: "/name", value: "{{g.name}}" }
`)
	r, _ := c.Rule("TST-001")
	eng := New(c, nil)
	a := testModel()
	b, err := eng.Bind(a, Policy{}, ScopeEdge, "e5")
	require.NoError(t, err)
	ops, err := PatchFor(context.Background(), r, b)
	require.NoError(t, err)
	require.Len(t, ops, 4)

	var node map[string]any
	require.NoError(t, json.Unmarshal(ops[0].Value, &node))
	hsID := node["id"].(string)
	assert.Regexp(t, regexp.MustCompile(`^n_hs_[a-z2-7]{6}$`), hsID)
	assert.Equal(t, "Approval for N db", node["name"])
	attrs := node["attrs"].(map[string]any)
	assert.Equal(t, float64(3), attrs["x_count"], "whole-string placeholder keeps the native type")
	assert.Equal(t, true, attrs["x_flag"])

	assert.Equal(t, "/edges/e5/to", ops[1].Path)
	assert.Equal(t, `"`+hsID+`"`, string(ops[1].Value), "same tag → same fresh id within one rendering")

	var edge map[string]any
	require.NoError(t, json.Unmarshal(ops[2].Value, &edge))
	assert.Regexp(t, regexp.MustCompile(`^n_e_[a-z2-7]{6}$`), edge["id"])
	assert.NotEqual(t, hsID, edge["id"])
	assert.Equal(t, hsID, edge["from"])
	assert.Equal(t, "db", edge["to"])
	assert.Equal(t, "writes", edge["kind"])
	assert.Equal(t, map[string]any{"consequence": "high", "x_arch": "arch_t", "x_src": "ag"}, edge["attrs"])
	assert.Equal(t, `"helpers"`, string(ops[3].Value))

	// A second rendering gets different fresh ids; the model applies cleanly and the rule is resolved.
	ops2, err := PatchFor(context.Background(), r, b)
	require.NoError(t, err)
	var node2 map[string]any
	require.NoError(t, json.Unmarshal(ops2[0].Value, &node2))
	assert.NotEqual(t, hsID, node2["id"])

	next, err := model.Apply(a, ops, false)
	require.NoError(t, err)
	assert.Len(t, next.Nodes, len(a.Nodes)+1)
	assert.Equal(t, hsID, next.Edge("e5").To)
}

func TestPatchForErrors(t *testing.T) {
	t.Parallel()
	c := mustInline(t, minimalPack)
	r, _ := c.Rule("TST-001")
	eng := New(c, nil)
	_, err := PatchFor(context.Background(), &Rule{ID: "X"}, nil)
	assert.ErrorIs(t, err, ErrNoPatch)
	_, err = PatchFor(context.Background(), r, nil)
	require.Error(t, err)
	_, err = eng.Bind(testModel(), Policy{}, ScopeNode, "ghost")
	require.Error(t, err)
	_, err = eng.Bind(testModel(), Policy{}, ScopeEdge, "ghost")
	require.Error(t, err)
	_, err = eng.Bind(testModel(), Policy{}, ScopeGraph, "other")
	require.Error(t, err)
	_, err = eng.Bind(testModel(), Policy{}, "cluster", "x")
	require.Error(t, err)
	b, err := eng.Bind(testModel(), Policy{}, ScopeGraph, "arch_t")
	require.NoError(t, err)
	assert.NotNil(t, b.Vars["g"])
}

func TestPatchForFinding(t *testing.T) {
	t.Parallel()
	c := mustInline(t, minimalPack+`
  - id: TST-002
    title: No patch
    scope: graph
    severity: low
    condition: 'true'
    message: m
    clauses: [A:B]
`)
	eng := New(c, nil)
	a := testModel()
	ops, ok, err := eng.PatchForFinding(context.Background(), a, model.Finding{RuleID: "TST-001", IDs: []string{"ag"}}, Policy{})
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, ops, 1)
	assert.Equal(t, "/nodes/ag/attrs/identity", ops[0].Path)
	assert.Equal(t, `"agent_id"`, string(ops[0].Value))

	_, ok, err = eng.PatchForFinding(context.Background(), a, model.Finding{RuleID: "TST-002", IDs: []string{"arch_t"}}, Policy{})
	require.NoError(t, err)
	assert.False(t, ok, "rule without patch template")

	_, _, err = eng.PatchForFinding(context.Background(), a, model.Finding{RuleID: "NOPE-001", IDs: []string{"ag"}}, Policy{})
	require.Error(t, err)
	_, _, err = eng.PatchForFinding(context.Background(), a, model.Finding{RuleID: "TST-001", IDs: []string{"ghost"}}, Policy{})
	require.Error(t, err)
	_, _, err = eng.PatchForFinding(context.Background(), a, model.Finding{RuleID: "TST-001", IDs: []string{"ag", "web"}}, Policy{})
	require.Error(t, err)
	_, _, err = eng.PatchForFinding(context.Background(), nil, model.Finding{RuleID: "TST-001", IDs: []string{"ag"}}, Policy{})
	require.Error(t, err)
	_, _, err = New(nil, nil).PatchForFinding(context.Background(), a, model.Finding{RuleID: "TST-001", IDs: []string{"ag"}}, Policy{})
	require.Error(t, err)
}

// TestGoldenPatchesResolveFindings renders the shipped patches of AI-001, ZT-001 and AI-003 on the
// golden bad twin, applies them with model.Apply and checks the finding disappears on re-evaluation.
func TestGoldenPatchesResolveFindings(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	if err != nil {
		t.Skipf("rules packs not loadable yet: %v", err)
	}
	for _, id := range []string{"AI-001", "ZT-001", "AI-003"} {
		if _, ok := c.Rule(id); !ok {
			t.Skipf("rule %s not in packs yet", id)
		}
	}
	eng := New(c, nil)
	base := loadModel(t, repoPath("golden-set", "models", "rag-chatbot-bad.json"))
	p := policyFromAttrs(base)

	// AI-003 needs a high-consequence agent action; the bad twin has none, so add one.
	withAction, err := base.Clone()
	require.NoError(t, err)
	withAction.Edges = append(withAction.Edges, model.Edge{ID: "e_agent_write", From: "n_agent", To: "n_sql", Kind: "writes",
		Auth: "managed_identity", Encryption: "tls", Attrs: model.Attrs{"consequence": "high"}})
	require.NoError(t, model.Validate(withAction))

	tests := []struct {
		rule string
		elem string
		arch *model.Architecture
		ops  int
	}{
		{"AI-001", "e_agent_llm", base, 3},
		{"ZT-001", "e_agent_sql", base, 1},
		{"AI-003", "e_agent_write", withAction, 3},
	}
	for _, tc := range tests {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			before, err := eng.Evaluate(context.Background(), tc.arch, p)
			require.NoError(t, err)
			var finding *model.Finding
			for i := range before {
				if before[i].RuleID == tc.rule && before[i].IDs[0] == tc.elem {
					finding = &before[i]
				}
			}
			require.NotNil(t, finding, "%s must fire on %s before the patch", tc.rule, tc.elem)
			require.True(t, finding.HasPatch)

			ops, ok, err := eng.PatchForFinding(context.Background(), tc.arch, *finding, p)
			require.NoError(t, err)
			require.True(t, ok)
			assert.Len(t, ops, tc.ops)
			next, err := model.Apply(tc.arch, ops, false)
			require.NoError(t, err, "rendered patch must apply cleanly")

			after, err := eng.Evaluate(context.Background(), next, p)
			require.NoError(t, err)
			for _, f := range after {
				assert.False(t, f.RuleID == tc.rule && f.IDs[0] == tc.elem, "%s still reported on %s after its own patch", tc.rule, tc.elem)
			}
			if tc.rule == "AI-003" {
				// The inserted approval step sits between agent and datastore; neither hop reports AI-003.
				_, still := findingsByRule(after)["AI-003"]
				assert.False(t, still, "AI-003 must be clean on both hops (endpoints count in pathThrough)")
			}
			if tc.rule == "AI-001" {
				_, still := findingsByRule(after)["AI-001"]
				assert.False(t, still)
			}
		})
	}
}

func TestRenderValueListsAndNesting(t *testing.T) {
	t.Parallel()
	c := mustInline(t, `
pack: tst
version: 0.1.0
rules:
  - id: TST-001
    title: T
    scope: edge
    severity: low
    condition: 'true'
    message: m
    clauses: [A:B]
    patch_template:
      - { op: add, path: "/x", value: { list: ["{{e.kind}}", "lit", { deep: "{{e.from.id}}-{{e.to.id}}" }], n: 1, b: true } }
`)
	r, _ := c.Rule("TST-001")
	b, err := New(c, nil).Bind(testModel(), Policy{}, ScopeEdge, "e5")
	require.NoError(t, err)
	ops, err := PatchFor(context.Background(), r, b)
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, json.Unmarshal(ops[0].Value, &v))
	assert.Equal(t, map[string]any{"list": []any{"writes", "lit", map[string]any{"deep": "ag-db"}}, "n": float64(1), "b": true}, v)
}
