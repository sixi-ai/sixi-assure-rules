package rules

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	// The budget is the CPU time the evaluation spends (the evaluation is single-threaded), measured on its own locked
	// thread, so a loaded machine (other test binaries, other agents) does not move it; the best of three runs is
	// kept, as a benchmark would. Without a per-thread CPU clock the wall time is measured instead.
	var (
		fs      []model.Finding
		elapsed time.Duration
		clock   = "cpu"
	)
	for i := range 3 {
		var runErr error
		start := time.Now()
		cpu, ok := threadCPUTime(func() { fs, runErr = eng.Evaluate(context.Background(), a, p) })
		wall := time.Since(start)
		require.NoError(t, runErr)
		if !ok {
			cpu, clock = wall, "wall"
		}
		if i == 0 || cpu < elapsed {
			elapsed = cpu
		}
	}
	t.Logf("perf-500: %d rules, %d findings in %s (%s time, best of 3)", len(c.Rules()), len(fs), elapsed, clock)
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

// ---- coverage (ADR-088 §4, docs/03 "requires and not_checked") -----------------------------------------------------

const coveragePack = `
pack: cov
version: 0.1.0
rules:
  - id: COV-001
    title: No requires decides every element of its scope
    scope: node
    severity: low
    condition: 'n.type == "datastore" && attr(n, "backup", false)'
    message: m
    clauses: [TST:cov:1]
  - id: COV-002
    title: Undeclared criticality
    scope: node
    severity: low
    condition: 'n.type == "datastore" && attr(n, "criticality", "") == "critical" && !attr(n, "backup", false)'
    requires: [n.attrs.criticality]
    domain: 'n.type == "datastore"'
    message: m
    clauses: [TST:cov:2]
  - id: COV-003
    title: Fires, so decided
    scope: node
    severity: low
    condition: 'n.type == "agent" && attr(n, "identity", "none") in ["none","shared"]'
    requires: [n.attrs.identity]
    domain: 'n.type == "agent"'
    message: m
    clauses: [TST:cov:3]
  - id: COV-004
    title: A declared fact decides without the undeclared one
    scope: node
    severity: low
    condition: 'n.type == "datastore" && attr(n, "data_class", "") == "pii" && attr(n, "criticality", "") == "critical"'
    requires: [n.attrs.data_class, n.attrs.criticality]
    domain: 'n.type == "datastore"'
    message: m
    clauses: [TST:cov:4]
  - id: COV-005
    title: Edge attribute declared
    scope: edge
    severity: low
    condition: 'e.to.type == "llm_endpoint" && attr(e, "prompt_contains", "") == "secrets"'
    requires: [e.attrs.prompt_contains]
    domain: 'e.to.type == "llm_endpoint"'
    message: m
    clauses: [TST:cov:5]
  - id: COV-006
    title: Endpoint attribute
    scope: edge
    severity: low
    condition: 'e.from.type == "user" && attr(e.to, "exposure", "") == "internal"'
    requires: [e.to.attrs.exposure]
    domain: 'e.from.type == "user"'
    message: m
    clauses: [TST:cov:6]
  - id: COV-007
    title: Edge field
    scope: edge
    severity: low
    condition: 'e.to.type == "datastore" && e.auth == "password"'
    requires: [e.auth]
    domain: 'e.to.type == "datastore"'
    message: m
    clauses: [TST:cov:7]
  - id: COV-008
    title: Architecture attribute
    scope: graph
    severity: low
    condition: 'attr(g, "ai_act_tier", "") == "high_risk"'
    requires: [g.attrs.ai_act_tier]
    message: m
    clauses: [TST:cov:8]
  - id: COV-009
    title: Knowledge facts
    scope: graph
    severity: low
    condition: 'kb.available && "gpt-4" in kb.deprecated'
    requires: [kb]
    message: m
    clauses: [TST:cov:9]
  - id: COV-010
    title: Node field
    scope: node
    severity: low
    condition: 'n.type == "app" && n.zone == "dmz"'
    requires: [n.zone]
    domain: 'n.type == "app"'
    message: m
    clauses: [TST:cov:10]
  - id: COV-011
    title: Domain outside the enabled regimes
    scope: node
    severity: low
    condition: 'regime("DORA") && n.type == "agent" && attr(n, "kill_switch", "") == ""'
    requires: [n.attrs.kill_switch]
    domain: 'regime("DORA") && n.type == "agent"'
    message: m
    clauses: [TST:cov:11]
  - id: COV-012
    title: A list attribute fed to size()
    scope: node
    severity: low
    condition: 'n.type == "human_step" && size(attr(n, "approval_for", [])) > 0'
    requires: [n.attrs.approval_for]
    domain: 'n.type == "human_step"'
    message: m
    clauses: [TST:cov:12]
`

func TestEvaluateCoverage(t *testing.T) {
	t.Parallel()
	c := mustInline(t, coveragePack)
	eng := New(c, nil)
	type expect struct {
		decided    int
		notChecked []string
	}
	base := map[string]expect{
		"COV-001": {decided: 10},                                   // every node of the scope; nothing required
		"COV-002": {decided: 0, notChecked: []string{"db", "db2"}}, // both stores leave criticality undeclared
		"COV-003": {decided: 1},                                    // fired on the agent
		"COV-004": {decided: 1, notChecked: []string{"db"}},        // db2 is public: decided whatever its criticality
		"COV-005": {decided: 1},                                    // prompt_contains declared on e4
		"COV-006": {decided: 1, notChecked: []string{"e8"}},        // the agent declares no exposure
		"COV-007": {decided: 2},                                    // connection_string and managed_identity are declarations
		"COV-008": {decided: 0, notChecked: []string{"arch_t"}},    // no AI Act tier
		"COV-009": {decided: 0, notChecked: []string{"arch_t"}},    // no knowledge facts
		"COV-010": {decided: 0, notChecked: []string{"web"}},       // no zone on the app
		"COV-011": {decided: 0},                                    // DORA is not enabled: an empty domain
		"COV-012": {decided: 0, notChecked: []string{"hs"}},        // no approval_for list
	}
	with := func(changes map[string]expect) map[string]expect {
		out := map[string]expect{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range changes {
			out[k] = v
		}
		return out
	}
	tests := []struct {
		name   string
		mutate func(a *model.Architecture, p *Policy)
		want   map[string]expect
	}{
		{"as drawn", nil, base},
		{"an edge auth of unknown is undeclared", func(a *model.Architecture, _ *Policy) {
			a.Edges[6].Auth = "unknown" // e7 hs → db2
		}, with(map[string]expect{"COV-007": {decided: 1, notChecked: []string{"e7"}}})},
		{"facts declared", func(a *model.Architecture, p *Policy) {
			a.Nodes[5].Attrs["criticality"] = "critical" // db, no backup: COV-002 fires
			a.Nodes[7].Attrs["criticality"] = "low"      // db2
			a.Nodes[1].Zone = "dmz"                      // web: COV-010 fires
			a.Nodes[2].Attrs["exposure"] = "internal"    // a gateway as edge target is outside COV-006's question; harmless
			a.Nodes[3].Attrs["exposure"] = "internal"    // ag: COV-006 fires on e8
			a.Nodes[6].Attrs["approval_for"] = []any{}   // an empty list is a declaration
			a.Attrs["ai_act_tier"] = "limited"
			p.Knowledge = &KnowledgeFacts{Deprecated: map[string]string{"gpt-4": "gpt-5"}}
		}, with(map[string]expect{
			"COV-002": {decided: 2}, "COV-004": {decided: 2}, "COV-006": {decided: 2}, "COV-008": {decided: 1},
			"COV-009": {decided: 1}, "COV-010": {decided: 1}, "COV-012": {decided: 1},
		})},
		{"blank and unknown strings are undeclared", func(a *model.Architecture, _ *Policy) {
			a.Nodes[3].Attrs["identity"] = "unknown" // ag: no longer fires, and cannot be decided
			a.Attrs["ai_act_tier"] = "  "
		}, with(map[string]expect{"COV-003": {decided: 0, notChecked: []string{"ag"}}})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := testModel()
			p := Policy{Regimes: []string{"FINMA"}}
			if tc.mutate != nil {
				tc.mutate(a, &p)
			}
			fs, cov, err := eng.EvaluateCoverage(context.Background(), a, p)
			require.NoError(t, err)
			plain, err := eng.Evaluate(context.Background(), a, p)
			require.NoError(t, err)
			assert.Equal(t, plain, fs, "coverage never changes a finding")
			require.Len(t, cov.Decided, len(tc.want), "every rule that ran is reported")
			for id, w := range tc.want {
				assert.Equal(t, w.decided, cov.Decided[id], "%s decided", id)
				assert.Equal(t, w.notChecked, cov.NotChecked[id], "%s not checked", id)
				assert.True(t, cov.Ran(id), id)
			}
			for id := range cov.NotChecked {
				assert.Contains(t, tc.want, id)
				assert.NotEmpty(t, cov.NotChecked[id], "a rule without not-checked elements is absent")
			}
			// The second pass copies before it writes: the model's own values are untouched.
			again, cov2, err := eng.EvaluateCoverage(context.Background(), a, p)
			require.NoError(t, err)
			assert.Equal(t, fs, again)
			assert.Equal(t, cov, cov2)
		})
	}
}

func TestEvaluateCoverageEdgeCases(t *testing.T) {
	t.Parallel()
	_, cov, err := New(nil, nil).EvaluateCoverage(context.Background(), testModel(), Policy{})
	require.NoError(t, err)
	assert.Empty(t, cov.Decided)
	_, _, err = New(mustInline(t, coveragePack), nil).EvaluateCoverage(context.Background(), nil, Policy{})
	require.Error(t, err)
	var nilCov *Coverage
	assert.False(t, nilCov.Ran("COV-001"))

	// A pack that does not apply runs no rule; a rule that fails to evaluate is not reported as run.
	c := mustInline(t, strings.Replace(coveragePack, "version: 0.1.0\n", "version: 0.1.0\nregimes: [DORA]\n", 1)+`
  - id: COV-099
    title: Fails at run time
    scope: graph
    severity: low
    condition: 'attr(g, "x_count", 0) / 0 > 1'
    message: m
    clauses: [TST:cov:99]
`)
	_, cov, err = New(c, nil).EvaluateCoverage(context.Background(), testModel(), Policy{Regimes: []string{"FINMA"}})
	require.NoError(t, err)
	assert.Empty(t, cov.Decided, "the pack's regimes are not enabled")
	_, cov, err = New(c, nil).EvaluateCoverage(context.Background(), testModel(), Policy{Regimes: []string{"DORA"}})
	require.Error(t, err)
	assert.False(t, cov.Ran("COV-099"))
	assert.True(t, cov.Ran("COV-001"))
}

// removeFact deletes one required fact of an element (a structural field becomes "unknown" or blank, the knowledge
// facts are dropped), as a fixture author would by leaving it out.
// removeIdentityFact clears one member of the identity entity the node runs as (a requires path n.identity.<member>).
func removeIdentityFact(t *testing.T, a *model.Architecture, n *model.Node, member string) {
	t.Helper()
	id, _ := n.Attrs["identity_id"].(string)
	for i := range a.Identities {
		ident := &a.Identities[i]
		if ident.ID != id {
			continue
		}
		switch member {
		case "name":
			ident.Name = ""
		case "kind":
			ident.Kind = ""
		case "ref":
			ident.Ref = ""
		case "issuer":
			ident.Issuer = ""
		case "credential_type":
			ident.CredentialType = ""
		case "credential_ttl":
			ident.CredentialTTL = nil
		case "rotation_days":
			ident.RotationDays = nil
		case "sponsor":
			ident.Sponsor = ""
		case "owner":
			ident.Owner = ""
		case "blueprint":
			ident.Blueprint = ""
		case "registry":
			ident.Registry = ""
		case "federation":
			ident.Federation = ""
		case "trust_domain":
			ident.TrustDomain = ""
		default:
			require.Failf(t, "unknown identity member", member)
		}
		return
	}
	// A node that names no identity entity already leaves every identity fact undeclared.
}

func removeFact(t *testing.T, a *model.Architecture, p *Policy, elementID string, rp requiredPath) {
	t.Helper()
	node := func(id string) *model.Node {
		for i := range a.Nodes {
			if a.Nodes[i].ID == id {
				return &a.Nodes[i]
			}
		}
		require.Failf(t, "node not found", id)
		return nil
	}
	edge := func(id string) *model.Edge {
		for i := range a.Edges {
			if a.Edges[i].ID == id {
				return &a.Edges[i]
			}
		}
		require.Failf(t, "edge not found", id)
		return nil
	}
	switch rp.root {
	case "kb":
		p.Knowledge = nil
	case "g":
		delete(a.Attrs, rp.field)
	case "e":
		e := edge(elementID)
		switch {
		case rp.attr:
			delete(e.Attrs, rp.field)
		case rp.field == "auth":
			e.Auth = "unknown"
		case rp.field == "encryption":
			e.Encryption = "unknown"
		case rp.field == "data_class":
			e.DataClass = ""
		case rp.field == "protocol":
			e.Protocol = ""
		case rp.field == "label":
			e.Label = ""
		}
	default:
		id := elementID
		if rp.root != "n" {
			e := edge(elementID)
			id = e.From
			if rp.root == "e.to" {
				id = e.To
			}
		}
		n := node(id)
		switch {
		case rp.identity:
			removeIdentityFact(t, a, n, rp.field)
		case rp.attr:
			delete(n.Attrs, rp.field)
		case rp.field == "zone":
			n.Zone = ""
		case rp.field == "layer":
			n.Layer = ""
		}
	}
}

func fixtureInput(t *testing.T, r *Rule, path string) (*model.Architecture, Policy) {
	t.Helper()
	a := loadModel(t, path)
	p := policyFromAttrs(a)
	facts, err := LoadFixtureFacts(r.Fixtures.KB)
	require.NoError(t, err)
	p.Knowledge = facts
	return a, p
}

// The shipped rules against their own fixtures: a finding lies in the rule's domain; the positive fixture with every
// required fact of the firing element removed yields the finding or not_checked, never a silent decision; every
// domain element of the negative fixture with its facts declared is decided; and the domain is not empty on both.
func TestCoverageOnShippedFixtures(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	table, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	eng := New(c, table)
	ctx := context.Background()
	inDomain := func(t *testing.T, r *Rule, a *model.Architecture, p Policy, id string) bool {
		t.Helper()
		if r.domain == nil {
			return true
		}
		b, err := eng.Bind(a, p, r.Scope, id)
		require.NoError(t, err)
		in, err := evalBool(ctx, r.domain, b.Vars)
		require.NoError(t, err)
		return in
	}
	for _, r := range c.Rules() {
		if len(r.Requires) == 0 {
			continue
		}
		t.Run(r.ID, func(t *testing.T) {
			t.Parallel()
			domainSeen := 0
			pos, pp := fixtureInput(t, r, r.Fixtures.Positive)
			fs, _, err := eng.EvaluateCoverage(ctx, pos, pp)
			require.NoError(t, err)
			fired := findingsByRule(fs)[r.ID]
			require.NotEmpty(t, fired, "positive fixture")
			for _, id := range fired {
				require.True(t, inDomain(t, r, pos, pp, id), "%s fires on %s outside its domain %q", r.ID, id, r.Domain)
				domainSeen++
				stripped, sp := fixtureInput(t, r, r.Fixtures.Positive)
				for _, rp := range r.required {
					removeFact(t, stripped, &sp, id, rp)
				}
				fs2, cov, err := eng.EvaluateCoverage(ctx, stripped, sp)
				require.NoError(t, err)
				still := slices.Contains(findingsByRule(fs2)[r.ID], id)
				notChecked := slices.Contains(cov.NotChecked[r.ID], id)
				assert.True(t, still || notChecked, "%s on %s without %v: neither a finding nor not_checked", r.ID, id, r.Requires)
			}

			neg, np := fixtureInput(t, r, r.Fixtures.Negative)
			_, cov, err := eng.EvaluateCoverage(ctx, neg, np)
			require.NoError(t, err)
			b := func(id string) map[string]any {
				bind, err := eng.Bind(neg, np, r.Scope, id)
				require.NoError(t, err)
				return bind.Vars
			}
			ids := []string{neg.ID}
			switch r.Scope {
			case ScopeNode:
				ids = ids[:0]
				for _, n := range model.AssessedNodes(neg) {
					ids = append(ids, n.ID)
				}
			case ScopeEdge:
				ids = ids[:0]
				for _, e := range neg.Edges {
					ids = append(ids, e.ID)
				}
			}
			for _, id := range ids {
				if !inDomain(t, r, neg, np, id) {
					continue
				}
				domainSeen++
				if len(undeclaredPaths(r.required, b(id))) == 0 {
					assert.NotContains(t, cov.NotChecked[r.ID], id, "%s: %s declares every required fact", r.ID, id)
				}
			}
			assert.GreaterOrEqual(t, domainSeen, 2, "%s: the fixtures exercise the domain", r.ID)
		})
	}
}

// The merge gate of docs/18 A6: a negative fixture with a required fact removed yields not_checked — unless another
// declared fact still decides the element, which the coverage pass recognises instead of reporting it unchecked.
func TestNegativeFixtureWithoutRequiredFact(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	table, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	eng := New(c, table)
	tests := []struct {
		rule, element string
		remove        []string // required paths removed from the element
		notChecked    bool
	}{
		{"ZT-001", "e1", []string{"e.auth"}, true},
		{"ZT-002", "n_agent", nil, true}, // identity: "unknown" below
		{"OT-004", "e_write", []string{"e.from.zone"}, true},
		{"DRF-001", "n_llm", []string{"kb"}, true},
		{"ATA-003", "e1", []string{"e.attrs.prompt_contains"}, true},
		{"MR-001", "n_guard", []string{"n.attrs.safety_function", "n.attrs.conformity_route"}, true},
		// Decided all the same: the store declares a backup, the model a conformity route, the evaluation both scopes.
		{"DATA-005", "n_db", []string{"n.attrs.criticality"}, false},
		{"MR-001", "n_guard", []string{"n.attrs.safety_function"}, false},
		{"AI-015", "n_eval", []string{"g.attrs.ai_act_tier"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.rule+" "+strings.Join(tc.remove, "+"), func(t *testing.T) {
			t.Parallel()
			r, ok := c.Rule(tc.rule)
			require.True(t, ok)
			a, p := fixtureInput(t, r, r.Fixtures.Negative)
			_, cov, err := eng.EvaluateCoverage(context.Background(), a, p)
			require.NoError(t, err)
			require.NotContains(t, cov.NotChecked[tc.rule], tc.element, "as written the negative fixture is decided")
			require.Positive(t, cov.Decided[tc.rule])

			if tc.rule == "ZT-002" {
				for i := range a.Nodes {
					if a.Nodes[i].ID == tc.element {
						a.Nodes[i].Attrs["identity"] = "unknown"
					}
				}
			}
			for _, raw := range tc.remove {
				rp, err := parseRequired(r.Scope, raw)
				if err != nil { // a fact the rule does not require (conformity_route): remove it as a node attribute
					rp = requiredPath{raw: raw, root: "n", attr: true, field: strings.TrimPrefix(raw, "n.attrs.")}
				}
				removeFact(t, a, &p, tc.element, rp)
			}
			fs, cov, err := eng.EvaluateCoverage(context.Background(), a, p)
			require.NoError(t, err)
			assert.NotContains(t, findingsByRule(fs)[tc.rule], tc.element, "still no finding")
			assert.Equal(t, tc.notChecked, slices.Contains(cov.NotChecked[tc.rule], tc.element))
		})
	}
}
