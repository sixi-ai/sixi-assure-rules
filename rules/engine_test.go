package rules

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

func TestEvaluateScopesAndOrdering(t *testing.T) {
	t.Parallel()
	c := mustInline(t, `
pack: tst
version: 0.1.0
regimes: [FINMA]
rules:
  - id: TST-001
    title: Shared secret to datastore
    scope: edge
    severity: high
    condition: 'e.to.type == "datastore" && e.auth in ["password","connection_string","api_key"]'
    message: "{{e.from.name}} -> {{e.to.name}}"
    clauses: [MCSB:v1:IM-1]
    remediation: "Use managed identity."
    patch_template:
      - { op: replace, path: "/edges/{{e.id}}/auth", value: managed_identity }
  - id: TST-002
    title: Agent identity
    scope: node
    severity: medium
    condition: 'n.type == "agent" && attr(n,"identity","none") == "shared"'
    message: "{{n.name}}"
    clauses: [MSFT:EntraAgentID]
  - id: TST-003
    title: Owner missing
    scope: graph
    severity: medium
    condition: 'attr(g,"owner","") == ""'
    message: "no owner"
    clauses: [FINMA:08/2024:Governance]
  - id: TST-004
    title: Never fires
    scope: graph
    severity: critical
    condition: 'g.has("evaluation") && regime("DORA")'
    message: "x"
    clauses: [DORA:2022/2554:Art24]
  - id: TST-005
    title: Public app
    scope: node
    severity: medium
    condition: 'attr(n,"exposure","") == "public"'
    message: "{{n.id}}"
    clauses: [MCSB:v1:NS-6]
`)
	eng := New(c, nil)
	a := testModel()
	fs, err := eng.Evaluate(context.Background(), a, Policy{Regimes: []string{"FINMA"}})
	require.NoError(t, err)
	keys := make([]string, 0, len(fs))
	for _, f := range fs {
		keys = append(keys, f.Severity+" "+f.RuleID+" "+strings.Join(f.IDs, ","))
	}
	assert.Equal(t, []string{"high TST-001 e5", "medium TST-002 ag", "medium TST-003 arch_t", "medium TST-005 web"}, keys)
	f := fs[0]
	assert.Equal(t, "tst", f.Pack)
	assert.Equal(t, model.StatusOpen, f.Status)
	assert.Equal(t, "Shared secret to datastore", f.Title)
	assert.Equal(t, "N ag -> N db", f.Message)
	assert.Equal(t, []string{"MCSB:v1:IM-1"}, f.Clauses)
	assert.Equal(t, "Use managed identity.", f.Remediation)
	assert.True(t, f.HasPatch)
	assert.False(t, fs[1].HasPatch)
	assert.Empty(t, f.ID, "finding ids are assigned by the store")

	// Pack applicability: disjoint regimes → nothing; empty regimes → everything.
	fs, err = eng.Evaluate(context.Background(), a, Policy{Regimes: []string{"DORA"}})
	require.NoError(t, err)
	assert.Empty(t, fs)
	fs, err = eng.Evaluate(context.Background(), a, Policy{})
	require.NoError(t, err)
	assert.Len(t, fs, 4)
}

func TestEvaluateDeterministic(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	if err != nil {
		t.Skipf("rules packs not loadable yet: %v", err)
	}
	eng := New(c, nil)
	a := loadModel(t, repoPath("golden-set", "models", "rag-chatbot-bad.json"))
	p := policyFromAttrs(a)
	first, err := eng.Evaluate(context.Background(), a, p)
	require.NoError(t, err)
	require.NotEmpty(t, first)
	for i := 0; i < 5; i++ {
		again, err := eng.Evaluate(context.Background(), a, p)
		require.NoError(t, err)
		assert.Equal(t, first, again, "run %d", i)
	}
	// Shuffling input order must not change the (sorted) output.
	b, err := a.Clone()
	require.NoError(t, err)
	for i, j := 0, len(b.Nodes)-1; i < j; i, j = i+1, j-1 {
		b.Nodes[i], b.Nodes[j] = b.Nodes[j], b.Nodes[i]
	}
	for i, j := 0, len(b.Edges)-1; i < j; i, j = i+1, j-1 {
		b.Edges[i], b.Edges[j] = b.Edges[j], b.Edges[i]
	}
	shuffled, err := eng.Evaluate(context.Background(), b, p)
	require.NoError(t, err)
	assert.Equal(t, first, shuffled)
}

func TestEvaluateNilAndEmptyCatalog(t *testing.T) {
	t.Parallel()
	eng := New(nil, nil)
	_, err := eng.Evaluate(context.Background(), nil, Policy{})
	require.Error(t, err)
	fs, err := eng.Evaluate(context.Background(), testModel(), Policy{})
	require.NoError(t, err)
	assert.Equal(t, []model.Finding{}, fs)
	var _ Evaluator = eng
	var _ Evaluator = Noop{}
}

func TestEvaluateErrorsCarryRuleAndElement(t *testing.T) {
	t.Parallel()
	c := mustInline(t, `
pack: tst
version: 0.1.0
rules:
  - id: TST-001
    title: T
    scope: node
    severity: low
    condition: 'n.type == "agent" && n.attrs.identity == "shared" && n.attrs.nope == 1'
    message: "x"
    clauses: [A:B]
  - id: TST-002
    title: T
    scope: node
    severity: low
    condition: 'n.type == "user"'
    message: "{{n.attrs.pim}}"
    clauses: [A:B]
`)
	eng := New(c, nil)
	fs, err := eng.Evaluate(context.Background(), testModel(), Policy{})
	require.Error(t, err)
	var re *RuleError
	require.True(t, errors.As(err, &re))
	assert.Contains(t, err.Error(), "rule TST-001 on ag")
	assert.Contains(t, err.Error(), "rule TST-002 on u1")
	assert.Contains(t, err.Error(), "no such key")
	assert.Empty(t, fs)
}

func TestCostLimitStopsPathologicalCondition(t *testing.T) {
	t.Parallel()
	pathological := "pack: tst\nversion: 0.1.0\nrules:\n  - id: TST-001\n    title: T\n    scope: graph\n    severity: low\n" +
		`    condition: 'g.nodes("app").all(a, g.nodes("app").all(b, g.nodes("app").all(c, a.id != "" && b.id != "" && c.id != "")))'` +
		"\n    message: x\n    clauses: [A:B]\n"
	c, err := ParsePacks([]PackSource{{Name: "p.yaml", Data: []byte(pathological)}}, LoadOptions{CostLimit: 5_000})
	require.NoError(t, err)
	a := model.Empty("arch_big", "t", "big")
	for i := 0; i < 60; i++ {
		a.Nodes = append(a.Nodes, model.Node{ID: fmt.Sprintf("n%d", i), Type: "app", Name: "a", Layer: "app", Source: "design", Attrs: model.Attrs{"exposure": "internal"}})
	}
	eng := New(c, nil)
	_, err = eng.Evaluate(context.Background(), a, Policy{})
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "cost")
	assert.Contains(t, err.Error(), "TST-001")

	// The same condition passes under the default limit on a small model.
	c2 := mustInline(t, pathological)
	fs, err := New(c2, nil).Evaluate(context.Background(), testModel(), Policy{})
	require.NoError(t, err)
	assert.Len(t, fs, 1)
}

func TestRuleTimeout(t *testing.T) {
	t.Parallel()
	pathological := "pack: tst\nversion: 0.1.0\nrules:\n  - id: TST-001\n    title: T\n    scope: node\n    severity: low\n" +
		`    condition: 'g.nodes("app").all(a, g.nodes("app").all(b, g.nodes("app").all(c, a.id != "" && b.id != "" && c.id != "")))'` +
		"\n    message: x\n    clauses: [A:B]\n"
	c, err := ParsePacks([]PackSource{{Name: "p.yaml", Data: []byte(pathological)}}, LoadOptions{CostLimit: 1 << 40})
	require.NoError(t, err)
	a := model.Empty("arch_big", "t", "big")
	for i := 0; i < 120; i++ {
		a.Nodes = append(a.Nodes, model.Node{ID: fmt.Sprintf("n%d", i), Type: "app", Name: "a", Layer: "app", Source: "design", Attrs: model.Attrs{}})
	}
	eng := New(c, nil, WithRuleTimeout(30*time.Millisecond))
	start := time.Now()
	_, err = eng.Evaluate(context.Background(), a, Policy{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), err.Error())
	assert.Less(t, time.Since(start), 5*time.Second)

	// A cancelled parent context is honoured too.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = New(c, nil).Evaluate(ctx, a, Policy{})
	require.Error(t, err)
}

// TestPackFixtures runs every loaded rule's positive and negative fixture (skips rules whose
// fixtures the pack author has not written yet).
func TestPackFixtures(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	if err != nil {
		t.Skipf("rules packs not loadable yet: %v", err)
	}
	table, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	eng := New(c, table)
	for _, r := range c.Rules() {
		t.Run(r.ID, func(t *testing.T) {
			t.Parallel()
			for _, fx := range []struct {
				path string
				want bool
			}{{r.Fixtures.Positive, true}, {r.Fixtures.Negative, false}} {
				if fx.path == "" {
					t.Skip("fixture not declared")
				}
				if _, err := os.Stat(fx.path); err != nil {
					t.Skipf("fixture %s not written yet", filepath.Base(fx.path))
				}
				a := loadModel(t, fx.path)
				policy := policyFromAttrs(a)
				facts, err := LoadFixtureFacts(r.Fixtures.KB)
				require.NoError(t, err)
				policy.Knowledge = facts
				fs, err := eng.Evaluate(context.Background(), a, policy)
				require.NoError(t, err, filepath.Base(fx.path))
				_, fired := findingsByRule(fs)[r.ID]
				assert.Equal(t, fx.want, fired, "%s: rule %s fired=%v", filepath.Base(fx.path), r.ID, fired)
			}
		})
	}
}

// syntheticPack builds n rules across scopes that exercise the graph helpers (perf tests).
func syntheticPack(n int) string {
	var b strings.Builder
	b.WriteString("pack: syn\nversion: 0.1.0\nrules:\n")
	conds := []struct{ scope, cond string }{
		{"edge", `e.from.type in ["agent","app"] && e.to.type == "llm_endpoint" && !g.pathThrough(e.from.id, e.to.id, "gateway")`},
		{"node", `n.type == "agent" && attr(n,"identity","none") in ["none","shared"] && g.in(n.id,"calls").exists(x, x.from.type == "user")`},
		{"edge", `e.kind in ["reads","writes"] && e.to.type == "datastore" && e.auth in ["password","connection_string","api_key"]`},
		{"graph", `(g.has("agent") || g.has("llm_endpoint")) && !g.has("log_sink")`},
		{"node", `n.type == "datastore" && attr(n,"data_class","") in ["pii","cid"] && !(attr(n,"region","") in tenant.allowed_regions)`},
		{"edge", `e.from.type == "user" && e.to.type in ["app","api"] && attr(e.to,"exposure","") == "public" && !g.pathThrough(e.from.id, e.to.id, "gateway")`},
		{"node", `n.type == "log_sink" && attr(n,"retention_days",0) < required("retention_days")`},
		{"edge", `e.from.layer == "edge" && e.to.type == "datastore" && !g.pathThrough(e.from.id,e.to.id,"broker") && !g.pathThrough(e.from.id,e.to.id,"dmz")`},
		{"node", `n.inZone("zone") && n.type == "app" && attr(n,"exposure","") == "public" && g.reachable(n.id, "n_1")`},
		{"edge", `e.encryption == "none" && regime("FINMA")`},
	}
	for i := 0; i < n; i++ {
		c := conds[i%len(conds)]
		fmt.Fprintf(&b, "  - id: SYN-%03d\n    title: Synthetic %d\n    scope: %s\n    severity: medium\n    condition: '%s'\n    message: \"synthetic {{g.id}}\"\n    clauses: [SYN:doc:%d]\n", i+1, i+1, c.scope, c.cond, i)
	}
	return b.String()
}

func perfCatalog(t testing.TB) *Catalog {
	t.Helper()
	sources := []PackSource{{Name: "syn.yaml", Data: []byte(syntheticPack(42))}}
	dir := repoPath("packs")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		sources = append(sources, PackSource{Name: e.Name(), Data: b, BaseDir: dir})
	}
	c, err := ParsePacks(sources, LoadOptions{})
	require.NoError(t, err)
	return c
}

func perfModel(t testing.TB) *model.Architecture {
	t.Helper()
	b, err := os.ReadFile(repoPath("golden-set", "perf", "perf-500.json"))
	require.NoError(t, err)
	a, err := model.ValidateJSON(b)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(a.Nodes), 500)
	require.GreaterOrEqual(t, len(a.Edges), 800)
	return a
}

func TestPerf500NodesUnderOneSecond(t *testing.T) {
	if testing.Short() {
		t.Skip("perf test skipped in -short mode")
	}
	c := perfCatalog(t)
	a := perfModel(t)
	eng := New(c, nil)
	p := policyFromAttrs(a)
	_, err := eng.Evaluate(context.Background(), a, p) // warm-up (page cache, allocator)
	require.NoError(t, err)
	start := time.Now()
	fs, err := eng.Evaluate(context.Background(), a, p)
	elapsed := time.Since(start)
	require.NoError(t, err)
	t.Logf("perf-500: %d rules, %d findings in %s", len(c.Rules()), len(fs), elapsed)
	budget := time.Second
	if raceEnabled {
		budget = 4 * time.Second // the race detector slows CEL evaluation ~5×; docs/09 budget applies to non-instrumented builds
	}
	assert.Less(t, elapsed, budget)
}

func BenchmarkEvaluatePerf500(b *testing.B) {
	c := perfCatalog(b)
	a := perfModel(b)
	eng := New(c, nil)
	p := policyFromAttrs(a)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.Evaluate(context.Background(), a, p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvaluateBadTwin(b *testing.B) {
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	if err != nil {
		b.Skip(err)
	}
	a := loadModel(b, repoPath("golden-set", "models", "rag-chatbot-bad.json"))
	eng := New(c, nil)
	p := policyFromAttrs(a)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.Evaluate(context.Background(), a, p); err != nil {
			b.Fatal(err)
		}
	}
}

// The `kb` variable exposes knowledge facts to the rules: absent facts read as unavailable and
// empty, present facts as maps a condition can look names and urls up in.
func TestKnowledgeFactsReachRulesAsKB(t *testing.T) {
	t.Parallel()
	pack := `pack: kbt
version: 0.1.0
rules:
  - id: KBT-001
    title: Deprecated service in use
    scope: node
    severity: high
    condition: 'kb.available && attr(n, "provider_service", "").lowerAscii() in kb.deprecated'
    message: "{{n.name}} uses a deprecated service"
    clauses: [MCSB:v1:IM-1]
    fixtures: { positive: none.json, negative: none.json }
  - id: KBT-002
    title: Document superseded
    scope: node
    severity: low
    condition: 'attr(n, "external_ref", "") in kb.freshness && kb.freshness[attr(n, "external_ref", "")] in ["superseded", "unreachable"]'
    message: "{{n.name}} cites a superseded document"
    clauses: [MCSB:v1:IM-1]
    fixtures: { positive: none.json, negative: none.json }
`
	c, err := ParsePacks([]PackSource{{Name: "kbt.yaml", Data: []byte(pack)}}, LoadOptions{CostLimit: DefaultCostLimit})
	require.NoError(t, err)
	table, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	eng := New(c, table)
	a := loadModel(t, repoPath("golden-set", "models", "rag-chatbot.json"))
	a.Node("n_llm").Attrs["provider_service"] = "Azure OpenAI on your data"
	a.Node("n_web").Attrs["external_ref"] = "https://learn.microsoft.com/old"
	fs, err := eng.Evaluate(context.Background(), a, Policy{})
	require.NoError(t, err)
	assert.Empty(t, findingsByRule(fs)["KBT-001"], "no facts → silent")
	facts := &KnowledgeFacts{Deprecated: map[string]string{"azure openai on your data": "azure ai foundry agent service"}, Freshness: map[string]string{"https://learn.microsoft.com/old": "superseded"}}
	fs, err = eng.Evaluate(context.Background(), a, Policy{Knowledge: facts})
	require.NoError(t, err)
	assert.Len(t, findingsByRule(fs)["KBT-001"], 1)
	assert.Len(t, findingsByRule(fs)["KBT-002"], 1)
}
