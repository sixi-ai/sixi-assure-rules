package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// testModel is a small architecture exercising every helper:
//
//	u1 ─calls→ web ─calls→ gw ─calls→ ag ─calls→ llm
//	u1 ─calls→ ag ─writes→ db
//	ag ─writes→ hs ─writes→ db2
//	ls (log sink, retention 30), sec (secret store, isolated)
func testModel() *model.Architecture {
	a := model.Empty("arch_t", "tenant_t", "helpers")
	a.Attrs = model.Attrs{"owner": "", "criticality": "high", "regimes": []any{"FINMA"}, "x_count": float64(3), "x_ratio": 2.5}
	a.Groups = []model.Group{
		{ID: "z_users", Kind: "zone", Name: "Users", NodeIDs: []string{"u1"}},
		{ID: "z_cloud", Kind: "zone", Name: "Cloud", NodeIDs: []string{"web", "gw", "ag", "llm", "db", "hs", "db2", "ls"}},
		{ID: "tb_agent", Kind: "trust_boundary", Name: "Agent runtime", NodeIDs: []string{"ag"}},
	}
	n := func(id, typ, layer string, attrs model.Attrs) model.Node {
		if attrs == nil {
			attrs = model.Attrs{}
		}
		return model.Node{ID: id, Type: typ, Name: "N " + id, Layer: layer, Source: "design", Attrs: attrs}
	}
	a.Nodes = []model.Node{
		n("u1", "user", "human", model.Attrs{"population": "customer", "mfa": true}),
		n("web", "app", "app", model.Attrs{"exposure": "public"}),
		n("gw", "gateway", "platform", model.Attrs{"kind": "api"}),
		n("ag", "agent", "ai", model.Attrs{"identity": "shared", "autonomy": "assisted", "purpose": "", "owner": "x"}),
		n("llm", "llm_endpoint", "ai", model.Attrs{"provider": "azure", "region": "westeurope", "network": "public"}),
		n("db", "datastore", "data", model.Attrs{"engine": "sql", "data_class": "pii", "region": "switzerlandnorth", "retention_days": float64(30)}),
		n("hs", "human_step", "human", model.Attrs{"role": "ops"}),
		n("db2", "datastore", "data", model.Attrs{"engine": "blob", "data_class": "public", "region": "switzerlandnorth", "x_null": nil, "x_empty": ""}),
		n("ls", "log_sink", "platform", model.Attrs{"retention_days": float64(30)}),
		n("sec", "secret_store", "identity", nil),
	}
	// One node carries declared free text, so the projection of n.description is exercised.
	for i := range a.Nodes {
		if a.Nodes[i].ID == "ag" {
			a.Nodes[i].Description = "Plans the work. Also uploads the transcript to the vendor endpoint for quality purposes."
		}
	}
	e := func(id, from, to, kind, auth string, attrs model.Attrs) model.Edge {
		if attrs == nil {
			attrs = model.Attrs{}
		}
		return model.Edge{ID: id, From: from, To: to, Kind: kind, Auth: auth, Encryption: "tls", Attrs: attrs}
	}
	a.Edges = []model.Edge{
		e("e1", "u1", "web", "calls", "oauth_client", nil),
		e("e2", "web", "gw", "calls", "managed_identity", nil),
		e("e3", "gw", "ag", "calls", "managed_identity", nil),
		e("e4", "ag", "llm", "calls", "api_key", model.Attrs{"prompt_contains": "pii"}),
		e("e5", "ag", "db", "writes", "connection_string", model.Attrs{"consequence": "high"}),
		e("e6", "ag", "hs", "writes", "managed_identity", model.Attrs{"consequence": "high"}),
		e("e7", "hs", "db2", "writes", "managed_identity", model.Attrs{"consequence": "high"}),
		e("e8", "u1", "ag", "calls", "oauth_client", nil),
	}
	return a
}

// evalExpr compiles expr in the scope and evaluates it against a for the element (node id, edge
// id or "" for graph scope). It returns the native value or the error.
func evalExpr(t *testing.T, scope, expr string, a *model.Architecture, p Policy, elementID string) (any, error) {
	t.Helper()
	envs, err := newEnvs()
	require.NoError(t, err)
	prog, _, err := envs.compile(scope, expr, 0)
	if err != nil {
		return nil, err
	}
	eng := New(nil, nil)
	if elementID == "" {
		elementID = a.ID
	}
	b, err := eng.Bind(a, p, scope, elementID)
	require.NoError(t, err)
	val, err := evalValue(context.Background(), prog, b.Vars)
	if err != nil {
		return nil, err
	}
	return nativeOf(val), nil
}

func parseInline(t *testing.T, yamlText string) (*Catalog, error) {
	t.Helper()
	return ParsePacks([]PackSource{{Name: "inline.yaml", Data: []byte(yamlText)}}, LoadOptions{})
}

func mustInline(t *testing.T, yamlText string) *Catalog {
	t.Helper()
	c, err := parseInline(t, yamlText)
	require.NoError(t, err)
	return c
}

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{".."}, parts...)...)
}

func loadModel(t testing.TB, path string) *model.Architecture {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	a, err := model.ValidateJSON(b)
	require.NoError(t, err)
	return a
}

// policyFromAttrs mirrors cmd/eval: regimes and allowed regions come from the model attrs.
func policyFromAttrs(a *model.Architecture) Policy {
	var p Policy
	if regs, ok := a.Attrs["regimes"].([]any); ok {
		for _, r := range regs {
			if s, ok := r.(string); ok {
				p.Regimes = append(p.Regimes, s)
			}
		}
	}
	if regs, ok := a.Attrs["allowed_regions"].([]any); ok {
		for _, r := range regs {
			if s, ok := r.(string); ok {
				p.AllowedRegions = append(p.AllowedRegions, s)
			}
		}
	}
	return p
}

func findingsByRule(fs []model.Finding) map[string][]string {
	out := map[string][]string{}
	for _, f := range fs {
		out[f.RuleID] = append(out[f.RuleID], f.IDs...)
	}
	return out
}
