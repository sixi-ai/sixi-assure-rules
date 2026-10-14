package rules

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

func TestTypeGuards(t *testing.T) {
	t.Parallel()
	envs, err := newEnvs()
	require.NoError(t, err)
	for _, tc := range []struct {
		name, scope, cond string
		want              map[string][]string // path joined with "." → values
	}{
		{"node equals", ScopeNode, `n.type == "agent" && attr(n, "x", false)`, map[string][]string{"type": {"agent"}}},
		{"node in list", ScopeNode, `attr(n, "x", false) && n.type in ["edge_device","edge_gateway"]`, map[string][]string{"type": {"edge_device", "edge_gateway"}}},
		{"nested conjunction", ScopeNode, `(n.type == "api" && n.name != "") && true`, map[string][]string{"type": {"api"}}},
		{"edge kind and endpoint", ScopeEdge, `e.kind in ["writes","executes"] && e.to.type == "secret_store" && e.from.type != "human_step"`,
			map[string][]string{"kind": {"executes", "writes"}, "to.type": {"secret_store"}}},
		{"disjunction is not a guard", ScopeNode, `n.type == "agent" || n.type == "api"`, nil},
		{"negation is not a guard", ScopeNode, `!(n.type == "agent")`, nil},
		{"inequality is not a guard", ScopeNode, `n.type != "agent"`, nil},
		{"computed list is not a guard", ScopeNode, `n.type in g.nodes("agent").map(a, a.type)`, nil},
		{"attribute is not a guard", ScopeNode, `n.layer == "app"`, nil},
		{"attrs path is not a guard", ScopeNode, `n.attrs.type == "x"`, nil},
		{"graph scope has none", ScopeGraph, `g.has("agent")`, nil},
		{"non-string literal is not a guard", ScopeNode, `n.type in ["agent", 1]`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, a, err := envs.compileAst(tc.scope, tc.cond, 0)
			require.NoError(t, err)
			got := map[string][]string{}
			for _, g := range typeGuards(tc.scope, a.NativeRep().Expr()) {
				var vs []string
				for v := range g.values {
					vs = append(vs, v)
				}
				slices.Sort(vs)
				got[strings.Join(g.path, ".")] = vs
			}
			if tc.want == nil {
				tc.want = map[string][]string{}
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExcludes(t *testing.T) {
	t.Parallel()
	g := []typeGuard{{path: []string{"to", "type"}, values: map[string]bool{"secret_store": true}}}
	assert.True(t, excludes(g, map[string]any{"to": map[string]any{"type": "api"}}))
	assert.False(t, excludes(g, map[string]any{"to": map[string]any{"type": "secret_store"}}))
	assert.False(t, excludes(g, map[string]any{"to": map[string]any{}}), "an absent field is left to CEL")
	assert.False(t, excludes(g, map[string]any{"to": "n1"}), "a field that is not a map is left to CEL")
	assert.False(t, excludes(nil, map[string]any{}))
}

// TestTypeGuardsChangeNoFinding evaluates every shipped pack over the perf model, every golden model and every
// fixture twice — with the guards the packs compile to and with none — and requires the same findings.
func TestTypeGuardsChangeNoFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates every model twice")
	}
	guarded := perfCatalog(t)
	plain := perfCatalog(t)
	n := 0
	for _, r := range plain.Rules() {
		if len(r.guards) > 0 {
			n++
		}
		r.guards = nil
	}
	require.Greater(t, n, 100, "most shipped conditions start with a type test")
	table, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	gEng, pEng := New(guarded, table), New(plain, table)
	paths, err := filepath.Glob(repoPath("golden-set", "models", "*.json"))
	require.NoError(t, err)
	fx, err := filepath.Glob(repoPath("packs", "fixtures", "*.json"))
	require.NoError(t, err)
	models := map[string]*model.Architecture{"perf-500": perfModel(t)}
	for _, p := range append(paths, fx...) {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		if !strings.Contains(string(b), `"nodes"`) {
			continue // a knowledge-facts fixture, not a model
		}
		models[filepath.Base(p)] = loadModel(t, p)
	}
	require.Greater(t, len(models), 100)
	for name, a := range models {
		pol := policyFromAttrs(a)
		want, wantErr := pEng.Evaluate(context.Background(), a, pol)
		got, gotErr := gEng.Evaluate(context.Background(), a, pol)
		assert.Equal(t, wantErr == nil, gotErr == nil, name)
		assert.Equal(t, want, got, name)
	}
}
