package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const minimalPack = `
pack: tst
version: 0.1.0
regimes: [FINMA]
rules:
  - id: TST-001
    title: Agent without identity
    scope: node
    severity: high
    condition: 'n.type == "agent" && attr(n,"identity","none") in ["none","shared"]'
    message: "Agent {{n.name}} has identity {{attr(n,'identity','none')}}."
    clauses: [MSFT:EntraAgentID]
    remediation: "Assign an agent identity."
    patch_template:
      - { op: replace, path: "/nodes/{{n.id}}/attrs/identity", value: agent_id }
    tags: [identity]
`

func TestParsePackMinimal(t *testing.T) {
	t.Parallel()
	c := mustInline(t, minimalPack)
	require.Len(t, c.Packs(), 1)
	p := c.Packs()[0]
	assert.Equal(t, "tst", p.Pack)
	assert.Equal(t, "0.1.0", p.Version)
	assert.Equal(t, []string{"FINMA"}, p.Regimes)
	r, ok := c.Rule("TST-001")
	require.True(t, ok)
	assert.Equal(t, "tst", r.Pack)
	assert.Equal(t, ScopeNode, r.Scope)
	assert.True(t, r.HasPatch())
	assert.Equal(t, []string{"identity"}, r.Tags)
	assert.Len(t, c.Rules(), 1)
	_, ok = c.Rule("NOPE-001")
	assert.False(t, ok)
}

func TestPackValidationErrors(t *testing.T) {
	t.Parallel()
	rule := func(id, scope, sev, cond, msg, clauses, extra string) string {
		return "pack: tst\nversion: 0.1.0\nregimes: [FINMA]\nrules:\n" +
			"  - id: " + id + "\n    title: T\n    scope: " + scope + "\n    severity: " + sev + "\n" +
			"    condition: '" + cond + "'\n    message: \"" + msg + "\"\n    clauses: " + clauses + "\n" + extra
	}
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"bad id", rule("zt-1", "node", "high", "true", "m", "[A:B]", ""), `id "zt-1" must match`},
		{"bad scope", rule("ZT-001", "cluster", "high", "true", "m", "[A:B]", ""), `scope "cluster" must be one of node|edge|graph`},
		{"bad severity", rule("ZT-001", "node", "urgent", "true", "m", "[A:B]", ""), `severity "urgent" must be one of`},
		{"bad CEL", rule("ZT-001", "node", "high", "n.type ==", "m", "[A:B]", ""), "condition: ERROR"},
		{"unknown helper", rule("ZT-001", "node", "high", "g.nope()", "m", "[A:B]", ""), "undeclared reference"},
		{"wrong scope variable", rule("ZT-001", "node", "high", "e.kind == \"x\"", "m", "[A:B]", ""), "undeclared reference to 'e'"},
		{"non-bool condition", rule("ZT-001", "node", "high", "n.name + \"x\"", "m", "[A:B]", ""), "must evaluate to bool"},
		{"empty clauses", rule("ZT-001", "node", "high", "true", "m", "[]", ""), "clauses must not be empty"},
		{"clause without regime", rule("ZT-001", "node", "high", "true", "m", "[Art12]", ""), "REGIME:DOC"},
		{"bad message placeholder", rule("ZT-001", "node", "high", "true", "{{n.nope(}}", "[A:B]", ""), "message: placeholder"},
		{"new: in message", rule("ZT-001", "node", "high", "true", "{{new:x}}", "[A:B]", ""), "only valid in patch templates"},
		{"bad override CEL", rule("ZT-001", "node", "high", "true", "m", "[A:B]", "    severity_override:\n      - { when: 'n.x ==', severity: low }\n"), "severity_override[0]"},
		{"bad override severity", rule("ZT-001", "node", "high", "true", "m", "[A:B]", "    severity_override:\n      - { when: 'true', severity: loud }\n"), `severity "loud" invalid`},
		{"bad patch op", rule("ZT-001", "node", "high", "true", "m", "[A:B]", "    patch_template:\n      - { op: zap, path: /x, value: 1 }\n"), `unknown op "zap"`},
		{"patch path without slash", rule("ZT-001", "node", "high", "true", "m", "[A:B]", "    patch_template:\n      - { op: add, path: x, value: 1 }\n"), "path must start with"},
		{"patch missing value", rule("ZT-001", "node", "high", "true", "m", "[A:B]", "    patch_template:\n      - { op: add, path: /x }\n"), "add requires value"},
		{"patch move without from", rule("ZT-001", "node", "high", "true", "m", "[A:B]", "    patch_template:\n      - { op: move, path: /x }\n"), "move requires from"},
		{"patch unknown key", rule("ZT-001", "node", "high", "true", "m", "[A:B]", "    patch_template:\n      - { op: add, path: /x, value: 1, extra: 2 }\n"), `unknown key "extra"`},
		{"bad patch placeholder", rule("ZT-001", "node", "high", "true", "m", "[A:B]", "    patch_template:\n      - { op: add, path: \"/nodes/{{n.nope(}}\", value: 1 }\n"), "patch_template[0]: placeholder"},
		{"unknown rule key", rule("ZT-001", "node", "high", "true", "m", "[A:B]", "    bogus: 1\n"), `unknown field "bogus"`},
		{"missing title", "pack: tst\nversion: 0.1.0\nrules:\n  - id: ZT-001\n    scope: node\n    severity: high\n    condition: 'true'\n    message: m\n    clauses: [A:B]\n", "title is required"},
		{"missing condition", "pack: tst\nversion: 0.1.0\nrules:\n  - id: ZT-001\n    title: T\n    scope: node\n    severity: high\n    message: m\n    clauses: [A:B]\n", "condition is required"},
		{"bad pack name", strings.Replace(minimalPack, "pack: tst", "pack: ZT", 1), `pack name "ZT" invalid`},
		{"missing version", strings.Replace(minimalPack, "version: 0.1.0", "version: ''", 1), "version is required"},
		{"no rules", "pack: tst\nversion: 0.1.0\nrules: []\n", "pack has no rules"},
		{"not yaml", "pack: [", ""},
		{"duplicate id within pack", minimalPack + strings.TrimPrefix(strings.SplitN(minimalPack, "rules:\n", 2)[1], ""), "duplicate id within pack"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseInline(t, tc.yaml)
			require.Error(t, err)
			if tc.want != "" {
				assert.Contains(t, err.Error(), tc.want)
			}
		})
	}
}

func TestDuplicateRuleIDAcrossPacks(t *testing.T) {
	t.Parallel()
	other := strings.Replace(minimalPack, "pack: tst", "pack: other", 1)
	_, err := ParsePacks([]PackSource{{Name: "a.yaml", Data: []byte(minimalPack)}, {Name: "b.yaml", Data: []byte(other)}}, LoadOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate rule id TST-001")

	_, err = ParsePacks([]PackSource{{Name: "a.yaml", Data: []byte(minimalPack)}, {Name: "b.yaml", Data: []byte(strings.Replace(minimalPack, "TST-001", "TST-002", 1))}}, LoadOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `duplicate pack name "tst"`)
}

func TestLoadDirFixturesAndNonYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	withFixtures := minimalPack + "    fixtures: { positive: fixtures/TST-001.pos.json, negative: fixtures/TST-001.neg.json }\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tst.yaml"), []byte(withFixtures), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "TODO.md"), []byte("ignored"), 0o600))

	_, err := LoadDir(dir)
	require.Error(t, err, "fixtures missing")
	assert.Contains(t, err.Error(), "fixtures.positive: fixtures/TST-001.pos.json not found")
	assert.Contains(t, err.Error(), "fixtures.negative")

	c, err := LoadDirWith(dir, LoadOptions{})
	require.NoError(t, err, "lenient load ignores fixtures")
	r, _ := c.Rule("TST-001")
	assert.Equal(t, filepath.Join(dir, "fixtures", "TST-001.pos.json"), r.Fixtures.Positive)

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "fixtures"), 0o750))
	for _, f := range []string{"TST-001.pos.json", "TST-001.neg.json"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "fixtures", f), []byte("{}"), 0o600))
	}
	c, err = LoadDir(dir)
	require.NoError(t, err)
	assert.Len(t, c.Rules(), 1)

	_, err = LoadDir(filepath.Join(dir, "missing"))
	require.Error(t, err)

	noFixtureField := minimalPack
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tst.yaml"), []byte(noFixtureField), 0o600))
	_, err = LoadDir(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fixtures.positive is required")
}

func TestPackAppliesTo(t *testing.T) {
	t.Parallel()
	p := &Pack{Regimes: []string{"MCSB", "NIST", "FINMA"}}
	tests := []struct {
		name    string
		regimes []string
		want    bool
	}{
		{"no regimes enabled → applies", nil, true},
		{"intersects", []string{"AIACT", "FINMA"}, true},
		{"disjoint", []string{"AIACT", "DORA"}, false},
		{"alias match", []string{"finma"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, p.AppliesTo(tc.regimes))
		})
	}
	assert.True(t, (&Pack{}).AppliesTo([]string{"DORA"}), "pack without regimes applies to every tenant")
}

func TestMessageTemplating(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 2500)
	c := mustInline(t, `
pack: tst
version: 0.1.0
rules:
  - id: TST-001
    title: T
    scope: edge
    severity: low
    condition: 'e.id == "e4"'
    message: "{{e.from.name}} -> {{e.to.name}} via {{e.auth}}; consequence={{attr(e,'consequence','n/a')}}; n={{attr(g,'x_count',0)}}; ok={{e.from.type == 'agent'}}; list={{g.nodes('user').map(u, u.id)}}"
    clauses: [A:B]
  - id: TST-002
    title: T
    scope: graph
    severity: low
    condition: 'true'
    message: "line one\nline two\r\n\ttabbed `+long+` end"
    clauses: [A:B]
  - id: TST-003
    title: T
    scope: node
    severity: low
    condition: 'n.id == "u1"'
    message: "no placeholders"
    clauses: [A:B]
`)
	eng := New(c, nil)
	fs, err := eng.Evaluate(context.Background(), testModel(), Policy{})
	require.NoError(t, err)
	by := map[string]string{}
	for _, f := range fs {
		by[f.RuleID] = f.Message
	}
	assert.Equal(t, `N ag -> N llm via api_key; consequence=n/a; n=3; ok=true; list=["u1"]`, by["TST-001"])
	assert.Equal(t, "no placeholders", by["TST-003"])
	assert.NotContains(t, by["TST-002"], "\n")
	assert.NotContains(t, by["TST-002"], "\t")
	assert.True(t, strings.HasPrefix(by["TST-002"], "line one line two  tabbed"), by["TST-002"][:40])
	assert.LessOrEqual(t, len([]rune(by["TST-002"])), maxMessageLen)
	assert.True(t, strings.HasSuffix(by["TST-002"], "…"))
}

func TestSeverityOverrideFirstMatchWins(t *testing.T) {
	t.Parallel()
	c := mustInline(t, `
pack: tst
version: 0.1.0
rules:
  - id: TST-006
    title: Transport encryption
    scope: edge
    severity: high
    condition: 'e.encryption in ["none","unknown"]'
    severity_override:
      - { when: 'e.encryption == "unknown"', severity: medium }
      - { when: 'e.encryption == "unknown" && e.kind == "calls"', severity: low }
      - { when: 'e.kind == "flows"', severity: critical }
    message: "{{e.id}} {{e.encryption}}"
    clauses: [ISO:27001:A.8.24]
`)
	a := testModel()
	a.Edges[0].Encryption = "unknown" // e1 calls
	a.Edges[1].Encryption = "none"    // e2 calls
	a.Edges[2].Encryption = "unknown" // e3
	a.Edges[2].Kind = "flows"
	eng := New(c, nil)
	fs, err := eng.Evaluate(context.Background(), a, Policy{})
	require.NoError(t, err)
	got := map[string]string{}
	for _, f := range fs {
		got[f.IDs[0]] = f.Severity
	}
	assert.Equal(t, map[string]string{"e1": "medium", "e2": "high", "e3": "medium"}, got, "first matching override wins; no match keeps base severity")
	assert.Equal(t, "e2", fs[0].IDs[0], "sorted by severity rank first")
}

func TestLoadDirWithoutPackFilesFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("no packs here"), 0o600))
	_, err := LoadDir(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no pack files")
}

// requires and domain (ADR-088 §4): paths on the scope variable, the architecture or the knowledge facts, checked
// against the model schema at load; a node or edge rule that requires facts names its domain.
func TestRequiresAndDomainValidation(t *testing.T) {
	t.Parallel()
	rule := func(scope, cond, extra string) string {
		return "pack: tst\nversion: 0.1.0\nregimes: [FINMA]\nrules:\n  - id: TST-001\n    title: T\n    scope: " + scope +
			"\n    severity: high\n    condition: '" + cond + "'\n    message: m\n    clauses: [A:B]\n" + extra
	}
	nodeCond := `n.type == "agent" && attr(n, "autonomy", "") == "autonomous"`
	edgeCond := `e.to.type == "datastore" && e.auth == "api_key"`
	tests := []struct {
		name     string
		yaml     string
		want     string // "" → loads
		requires []string
		domain   string
	}{
		{"node attribute", rule("node", nodeCond, "    requires: [n.attrs.autonomy]\n    domain: 'n.type == \"agent\"'\n"), "", []string{"n.attrs.autonomy"}, `n.type == "agent"`},
		{"node field and architecture attribute", rule("node", nodeCond, "    requires: [n.zone, g.attrs.ai_act_tier]\n    domain: 'true'\n"), "", []string{"n.zone", "g.attrs.ai_act_tier"}, "true"},
		{"edge field, endpoint attribute and edge attribute", rule("edge", edgeCond, "    requires: [e.auth, e.to.attrs.data_class, e.attrs.prompt_contains, e.from.layer]\n    domain: 'e.to.type == \"datastore\"'\n"), "", []string{"e.auth", "e.to.attrs.data_class", "e.attrs.prompt_contains", "e.from.layer"}, `e.to.type == "datastore"`},
		{"extension attribute", rule("node", nodeCond, "    requires: [n.attrs.x_vendor_tier]\n    domain: 'true'\n"), "", []string{"n.attrs.x_vendor_tier"}, "true"},
		{"graph rule: knowledge facts, no domain", rule("graph", `attr(g, "owner", "") == ""`, "    requires: [kb, g.attrs.owner]\n"), "", []string{"kb", "g.attrs.owner"}, ""},
		{"no requires", rule("node", nodeCond, ""), "", nil, ""},
		// Schema 1.1 identity facts (docs/18 D2 review): the member of the identity entity the node runs as.
		{"identity fact on a node", rule("node", nodeCond, "    requires: [n.attrs.identity_id, n.identity.sponsor]\n    domain: 'n.type == \"agent\"'\n"), "", []string{"n.attrs.identity_id", "n.identity.sponsor"}, `n.type == "agent"`},
		{"identity facts on edge endpoints", rule("edge", edgeCond, "    requires: [e.from.identity.federation, e.to.identity.ref]\n    domain: 'true'\n"), "", []string{"e.from.identity.federation", "e.to.identity.ref"}, "true"},
		{"identity id is the node attribute", rule("node", nodeCond, "    requires: [n.identity.id]\n    domain: 'true'\n"), "an identity fact is one of", nil, ""},
		{"identity member the schema does not declare", rule("node", nodeCond, "    requires: [n.identity.migrated]\n    domain: 'true'\n"), "an identity fact is one of", nil, ""},
		{"the edge itself has no identity", rule("edge", edgeCond, "    requires: [e.identity.issuer]\n    domain: 'true'\n"), "an edge field is one of", nil, ""},
		{"attribute the schema does not declare", rule("node", nodeCond, "    requires: [n.attrs.autonomie]\n    domain: 'true'\n"), `no attribute "autonomie"`, nil, ""},
		{"edge attribute on a node path", rule("node", nodeCond, "    requires: [n.attrs.consequence]\n    domain: 'true'\n"), `no attribute "consequence"`, nil, ""},
		{"node attribute on the edge", rule("edge", edgeCond, "    requires: [e.attrs.data_class]\n    domain: 'true'\n"), `no attribute "data_class"`, nil, ""},
		{"architecture attribute the schema does not declare", rule("node", nodeCond, "    requires: [g.attrs.autonomy]\n    domain: 'true'\n"), `no attribute "autonomy"`, nil, ""},
		{"edge root in a node rule", rule("node", nodeCond, "    requires: [e.auth]\n    domain: 'true'\n"), "a path starts with n, g", nil, ""},
		{"node root in an edge rule", rule("edge", edgeCond, "    requires: [n.attrs.identity]\n    domain: 'true'\n"), "a path starts with e.from, e.to, e, g", nil, ""},
		{"unknown edge field", rule("edge", edgeCond, "    requires: [e.kind]\n    domain: 'true'\n"), "an edge field is one of", nil, ""},
		{"unknown node field", rule("node", nodeCond, "    requires: [n.name]\n    domain: 'true'\n"), "a node field is one of", nil, ""},
		{"architecture field", rule("graph", "true", "    requires: [g.name]\n"), "g.attrs.<name>", nil, ""},
		{"not an attribute name", rule("node", nodeCond, "    requires: [n.attrs.Bad-Name]\n    domain: 'true'\n"), "is not an attribute name", nil, ""},
		{"duplicate path", rule("node", nodeCond, "    requires: [n.attrs.autonomy, n.attrs.autonomy]\n    domain: 'true'\n"), "duplicate path", nil, ""},
		{"requires without domain on a node rule", rule("node", nodeCond, "    requires: [n.attrs.autonomy]\n"), "domain is required with requires on a node rule", nil, ""},
		{"requires without domain on an edge rule", rule("edge", edgeCond, "    requires: [e.auth]\n"), "domain is required with requires on a edge rule", nil, ""},
		{"domain without requires", rule("node", nodeCond, "    domain: 'n.type == \"agent\"'\n"), "domain without requires", nil, ""},
		{"domain that is not CEL", rule("node", nodeCond, "    requires: [n.attrs.autonomy]\n    domain: 'n.type =='\n"), "domain: ERROR", nil, ""},
		{"domain that is not bool", rule("node", nodeCond, "    requires: [n.attrs.autonomy]\n    domain: '\"agent\"'\n"), "domain must evaluate to bool", nil, ""},
		{"domain with the wrong scope variable", rule("node", nodeCond, "    requires: [n.attrs.autonomy]\n    domain: 'e.kind == \"calls\"'\n"), "undeclared reference to 'e'", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := parseInline(t, tc.yaml)
			if tc.want != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.want)
				return
			}
			require.NoError(t, err)
			r, ok := c.Rule("TST-001")
			require.True(t, ok)
			assert.Equal(t, tc.requires, r.Requires)
			assert.Equal(t, tc.domain, r.Domain)
		})
	}
}

// The shipped packs (docs/03 "requires and not_checked"): every requires path parses, a node or edge rule that
// requires facts names its domain, and the rules A6 left alone stay without: the packs outside the A6 list. Wave 3
// (docs/18 B1, ADR-088 §4) gave the all-paths AI-003 and NET-003 the facts they read (consequence, exposure), so the
// count moved from 34 to 36 and the net pack joined; AI-001 stays without one: types and gateway kinds decide it.
func TestShippedRequires(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	// docs/18 E1-E5 review: the regulatory mappers' rules read defaulted facts too (DOR-001, FIN-002, FIN-003,
	// AIA-002, CHE-002, CHE-004, CRA-004), so they declare them and the fin and aia packs join; AIA-001 and NIS-004
	// read only types, structure and an attribute whose absence is the finding, and take none.
	annotated := map[string]bool{"zt": true, "data": true, "res": true, "tpr": true, "gov": true, "gxp": true, "mr": true,
		"ot": true, "drift": true, "imp": true, "a2a": true, "ai": true, "net": true, "fin": true, "aia": true,
		// docs/18 WS-I I2 (team 06): CHE-003 joins the log pack with a requires list.
		"log": true,
		// docs/18 C5 (ADR-086 §7): the prov pack's domain (imported elements while a sidecar is present) decides its
		// coverage; requires names n.layer, a fact every node declares, because a domain needs a requires list.
		"prov": true,
		// docs/18 D2 (ADR-047 §4): the mcp pack's schema 1.1 rules read declared MCP and agent facts.
		"mcp": true,
		// docs/18 B2b: STR-005 requires the gateway's declared functions (a gateway of the right kind that declares none
		// leaves the hop out of it not_checked).
		"c4": true}
	// docs/18 WS-I I2 (team 05): the evd, evl and irr packs declare the facts whose absence silences their rules.
	for _, pack := range []string{"evd", "evl", "irr"} {
		annotated[pack] = true
	}
	// docs/18 WS-I I2 (team 01): the scp pack's tier and regime rules declare the scope facts that silence them.
	annotated["scp"] = true
	// docs/18 WS-I I2 (swarm team 03, agentic runtime and supply chain): the arh, tsc, ing, hov, mem and blr packs declare
	// the facts whose absence silences their rules.
	for _, pack := range []string{"arh", "tsc", "ing", "hov", "mem", "blr"} {
		annotated[pack] = true
	}
	// docs/18 WS-I I2 (swarm team 04, gateways, network and data): the new rag pack declares the facts whose absence
	// silences RAG-001 and RAG-003.
	annotated["rag"] = true
	// docs/18 WS-I I2 (swarm team 02): the new lpv pack declares the scope and role facts that silence its rules.
	annotated["lpv"] = true
	// docs/18 WS-I I2 (swarm team 07): the new aei pack; AEI-002 declares the agent's autonomy, whose absence silences it.
	annotated["aei"] = true
	// docs/18 WS-M M3 (ADR-093): the fw pack declares the schema 1.2 facts whose absence silences its rules.
	annotated["fw"] = true
	withRequires := 0
	for _, r := range c.Rules() {
		if len(r.Requires) == 0 {
			assert.Empty(t, r.Domain, r.ID)
			continue
		}
		withRequires++
		assert.True(t, annotated[r.Pack], "%s: pack %s is not annotated in A6", r.ID, r.Pack)
		assert.Len(t, r.required, len(r.Requires), r.ID)
		if r.Scope != ScopeGraph {
			assert.NotEmpty(t, r.Domain, "%s: a %s rule that requires facts names its domain", r.ID, r.Scope)
		}
	}
	r, ok := c.Rule("AI-001")
	require.True(t, ok)
	// B2b (docs/18 WS-B, ADR-088 Amendments): the path rules read the gateway's declared functions, so a hop out of a
	// gateway of the right kind that declares none is not_checked (facts_missing) instead of silently satisfied.
	assert.Equal(t, []string{"e.from.attrs.functions"}, r.Requires, "AI-001 reads the declared functions of the gateway it leaves (B2b)")
	for id, want := range map[string][]string{"AI-003": {"e.attrs.consequence"}, "NET-003": {"e.to.attrs.exposure", "e.from.attrs.functions"},
		"STR-005": {"e.from.attrs.functions"}} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Equal(t, want, r.Requires, "%s: the fact the all-paths rule reads (ADR-088 §4)", id)
	}
	for id, want := range map[string][]string{"DOR-001": {"n.attrs.criticality"}, "FIN-002": {"n.attrs.data_class"},
		"FIN-003": {"n.attrs.materiality"}, "AIA-002": {"g.attrs.ai_act_tier"}, "CHE-002": {"n.attrs.autonomy"},
		"CHE-004": {"n.attrs.exposure"}, "CRA-004": {"e.auth"}} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Equal(t, want, r.Requires, "%s: the fact whose absence silences the mapper rule (ADR-088 §4)", id)
	}
	for _, id := range []string{"AIA-001", "NIS-004"} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Empty(t, r.Requires, "%s reads no defaulted fact that could silence it", id)
	}
	// docs/18 WS-I I2 (team 06, the regulatory mappers' still-specified rules): each declares the fact whose absence
	// silences it, and the domain it decides (a graph rule's domain narrows the architectures it speaks for). DOR-004
	// reads the dependency edge and requires the consumer's criticality (review fix: it decided every node before);
	// CHE-001 decides only components every reaching store of which declares its class (review fix).
	for _, tc := range []struct {
		id       string
		requires []string
		domain   string
	}{
		{"AIA-003", []string{"g.attrs.ai_act_tier"}, `regime("AIACT") && g.has("agent")`},
		{"FIN-001", []string{"g.attrs.materiality", "n.attrs.materiality"}, `regime("FINMA") && n.type in ["agent", "llm_endpoint"]`},
		{"DOR-002", []string{"n.attrs.criticality", "n.attrs.provider"}, `regime("DORA") && n.type in ["llm_endpoint", "saas"]`},
		{"DOR-003", []string{"n.attrs.criticality"}, `regime("DORA") && n.type in ["llm_endpoint", "saas"]`},
		{"CRA-003", []string{"n.attrs.cra_scope"}, `regime("CRA") && n.type == "product"`},
		{"CRA-005", []string{"n.attrs.c4_parent"}, `regime("CRA") && n.type in ["agent", "tool", "mcp_server", "app", "api"] && g.nodes("product").exists(p, attr(p, "cra_scope", false))`},
		{"CRA-006", []string{"n.attrs.cra_scope"}, `regime("CRA") && n.type == "product"`},
		{"NIS-001", []string{"g.attrs.decisions"}, `regime("NIS2")`},
		{"NIS-003", []string{"g.attrs.incident_reporting"}, `regime("NIS2")`},
		{"CHE-001", []string{"g.attrs.decisions"}, `regime("FADP") && n.type in ["agent", "llm_endpoint"] && g.nodes("datastore").exists(s, s.id in g.dataSources(n.id, "data")) && g.nodes("datastore").all(s, !(s.id in g.dataSources(n.id, "data")) || attr(s, "data_class", "") != "")`},
		{"DOR-004", []string{"e.from.attrs.criticality"}, `regime("DORA") && e.kind in ["calls", "reads", "writes", "publishes", "subscribes", "delegates"] && e.to.type in ["llm_endpoint", "saas"] && attr(e.to, "criticality", "") == ""`},
		{"CHE-003", []string{"n.attrs.retention_days"}, `(regime("CH-CO") || regime("FINMA")) && n.type == "datastore" && g.in(n.id, "writes").exists(w, w.from.type in ["agent", "tool", "mcp_server"])`},
	} {
		r, ok := c.Rule(tc.id)
		require.True(t, ok, tc.id)
		assert.Equal(t, tc.requires, r.Requires, "%s: the fact whose absence silences the mapper rule (ADR-088 §4)", tc.id)
		assert.Equal(t, tc.domain, r.Domain, "%s: the domain the mapper rule decides", tc.id)
	}
	// docs/18 WS-I I2 (team 09, the sector packs): OT-009, OT-010, OT-011, MR-005, MR-006, MR-008 and GXP-005 to GXP-008
	// declare the fact whose absence silences them; OT-008 and MR-007 fire on an absent immutable and take none.
	for _, tc := range []struct {
		id       string
		requires []string
		domain   string
	}{
		{"OT-009", []string{"n.attrs.key_use", "n.attrs.network_exposure"}, `n.type == "secret_store"`},
		{"OT-010", []string{"n.zone"}, `n.type == "human_step"`},
		{"OT-011", []string{"e.from.attrs.command_validation", "e.from.layer"}, `e.kind in ["writes","executes"] && e.to.type == "edge_device"`},
		{"MR-005", []string{"n.attrs.safety_function"}, `regime("MR") && n.type == "edge_model"`},
		{"MR-006", []string{"n.attrs.safety_function", "n.attrs.self_evolving"}, `regime("MR") && n.type in ["edge_model","edge_gateway"]`},
		{"MR-008", []string{"n.attrs.safety_function", "n.attrs.self_evolving", "g.attrs.ai_act_tier"}, `regime("MR") && regime("AIACT") && n.type in ["edge_model","edge_device","edge_gateway"]`},
		{"GXP-005", []string{"n.attrs.data_class", "n.attrs.retention_days"}, `(regime("FDA") || regime("EU-GMP")) && n.type == "datastore"`},
		{"GXP-006", []string{"e.to.attrs.data_class"}, `e.kind in ["writes","executes"] && e.to.type == "datastore" && (regime("FDA") || regime("EU-GMP"))`},
		{"GXP-007", []string{"n.attrs.approval_for"}, `n.type == "human_step" && (regime("FDA") || regime("EU-GMP"))`},
		{"GXP-008", []string{"e.to.attrs.data_class"}, `e.kind in ["writes","executes"] && e.to.type == "datastore" && (regime("FDA") || regime("EU-GMP"))`},
	} {
		r, ok := c.Rule(tc.id)
		require.True(t, ok, tc.id)
		assert.Equal(t, tc.requires, r.Requires, "%s: the fact whose absence silences the sector rule (ADR-088 §4)", tc.id)
		assert.Equal(t, tc.domain, r.Domain, "%s: the domain the sector rule decides", tc.id)
	}
	for _, id := range []string{"OT-008", "MR-007"} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Empty(t, r.Requires, "%s fires on the absent immutable it would otherwise require", id)
	}
	// docs/18 WS-I I2 (team 05, logging, evidence and resilience): a fact on another element (the purpose or
	// immutability of the sinks an agent reaches, the data class of every store) cannot be a requires path, so LOG-006,
	// LOG-007, LOG-009, EVL-001, EVL-002, RES-006, IRR-001, IRR-002, IRR-004 and IRR-005 (IRR-001's GDPR twin, split
	// out 2026-10-02) take none and their agents list the silence as a not-checked row.
	for _, tc := range []struct {
		id       string
		requires []string
		domain   string
	}{
		{"LOG-008", []string{"n.attrs.region"}, `n.type == "log_sink"`},
		{"EVD-001", []string{"n.attrs.purpose", "n.attrs.immutable"}, `n.type == "log_sink"`},
		{"EVD-003", []string{"e.auth"}, `e.kind in ["writes", "publishes"] && e.to.type == "log_sink"`},
		{"EVD-004", []string{"g.attrs.ai_act_tier"}, ``},
		{"EVL-003", []string{"g.attrs.ai_act_tier", "n.attrs.evaluates"}, `n.type == "evaluation"`},
		{"EVL-004", []string{"n.attrs.evaluates", "g.attrs.ai_act_tier"}, `n.type == "evaluation"`},
		{"RES-004", []string{"n.attrs.criticality", "n.attrs.geo_redundant"}, `n.type in ["agent","llm_endpoint","datastore","app","api","saas","queue","vector_index","secret_store","identity_provider","log_sink"]`},
		{"RES-005", []string{"n.attrs.criticality", "n.attrs.rto_min", "n.attrs.rpo_min"}, `n.type in ["agent","llm_endpoint","datastore","app","api","saas","queue","vector_index","secret_store","identity_provider","log_sink"]`},
		{"RES-007", []string{"n.attrs.purpose"}, `n.type == "log_sink"`},
		{"IRR-003", []string{"g.attrs.ai_act_tier"}, ``},
		{"DRF-005", []string{"kb", "n.attrs.spec_version"}, `n.type == "mcp_server"`},
		{"DRF-006", []string{"kb", "n.attrs.retention_statement"}, `n.type == "llm_endpoint"`},
		{"DRF-007", []string{"kb"}, ``},
		{"DRF-008", []string{"kb"}, `n.description != ""`},
	} {
		r, ok := c.Rule(tc.id)
		require.True(t, ok, tc.id)
		assert.Equal(t, tc.requires, r.Requires, "%s: the fact whose absence silences the team 05 rule (ADR-088 §4)", tc.id)
		assert.Equal(t, tc.domain, r.Domain, "%s: the domain the team 05 rule decides", tc.id)
	}
	for _, id := range []string{"LOG-006", "LOG-007", "LOG-009", "EVL-001", "EVL-002", "RES-006", "IRR-001", "IRR-002", "IRR-004", "IRR-005"} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Empty(t, r.Requires, "%s reads no defaulted fact of its own element that could silence it", id)
	}
	// 36 before the regulatory mappers' rules gained requires (seven of them, docs/18 E1-E5 review); +11 for the
	// team-06 rules above (docs/18 WS-I I2).
	// +7 for docs/18 B2b and E6: AI-001 and STR-005 gain requires (gateway functions), TPR-001 (the register status of
	// a managed service), and the new AGW-003, APX-004, SEG-005 and WIS-006 declare theirs.
	// +10 for the team-09 sector rules above (docs/18 WS-I I2).
	// +21 for docs/18 D2 (ADR-047 §4): the mcp pack's eight rules, ten zt rules (AID-001, AID-002, AID-010, AID-011,
	// WIS-004, WIS-010, WIS-011, DLG-001, DLG-003, DLG-010), ATA-006 and ATA-011, and SEG-010 read declared 1.1 facts.
	// (21, not 20, since the D2 review split the delegation rule: the spec's DLG-001 and ADR-047's DLG-010.)
	// +14 for the team-05 rules above (docs/18 WS-I I2).
	// +2: docs/18 C5 (ADR-086 §7) PRV-005 and PRV-006 name n.layer so that their prov domain decides their coverage.
	// +1: the team-06 review fix recasts DOR-004 at edge scope with requires: [e.from.attrs.criticality] (it took none).
	// docs/18 WS-I I2 (team 03, agentic runtime and supply chain): each rule declares the fact whose absence silences it.
	// A fact on another element (the capabilities of a reached tool, the origin of a source, the consequence of a step's
	// out-edge) cannot be a requires path, so ING-001, ING-003, ING-004, HOV-002 and MEM-003 take none and their agents
	// list the silence as a not-checked row.
	team03Agent := `n.type == "agent"`
	for _, tc := range []struct {
		id       string
		requires []string
		domain   string
	}{
		{"ARH-003", []string{"n.attrs.autonomy"}, team03Agent},
		{"ARH-004", []string{"n.attrs.autonomy", "n.attrs.rate_limit"}, team03Agent},
		{"TSC-002", []string{"n.attrs.origin"}, `n.type in ["tool","mcp_server"]`},
		{"TSC-003", []string{"n.attrs.origin", "n.attrs.capabilities"}, `n.type in ["tool","mcp_server"]`},
		{"TSC-004", []string{"n.attrs.verification"}, `n.type == "agent_registry" && g.inEdges(n.id, "").exists(x, x.from.type == "agent")`},
		{"MCP-004", []string{"n.attrs.auth_mode", "n.attrs.resource_metadata"}, `n.type == "mcp_server"`},
		{"ING-002", []string{"n.attrs.exposure"}, `n.type in ["app","api"]`},
		{"HOV-001", []string{"n.attrs.approval_identity"}, `n.type == "human_step" && g.nodes("agent").exists(a, g.reachable(a.id, n.id))`},
		{"HOV-004", []string{"n.attrs.autonomy"}, team03Agent},
		{"MEM-002", []string{"n.attrs.scope"}, `n.type == "agent_memory"`},
		{"MEM-004", []string{"n.attrs.write_path"}, `n.type == "agent_memory" && g.inEdges(n.id, "writes").exists(w, w.from.type == "agent")`},
		{"MEM-005", []string{"e.attrs.guarded"}, `e.kind == "writes" && e.from.type == "agent" && e.to.type == "agent_memory"`},
		{"BLR-001", []string{"n.attrs.autonomy"}, team03Agent},
		{"BLR-002", []string{"n.attrs.autonomy"}, team03Agent},
		{"BLR-003", []string{"n.attrs.autonomy"}, team03Agent},
		{"BLR-004", []string{"n.attrs.autonomy"}, team03Agent},
	} {
		r, ok := c.Rule(tc.id)
		require.True(t, ok, tc.id)
		assert.Equal(t, tc.requires, r.Requires, "%s: the fact whose absence silences the team 03 rule (ADR-088 §4)", tc.id)
		assert.Equal(t, tc.domain, r.Domain, "%s: the domain the team 03 rule decides", tc.id)
	}
	for _, id := range []string{"ING-001", "ING-003", "ING-004", "HOV-002", "MEM-003"} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Empty(t, r.Requires, "%s reads no defaulted fact of its own element that could silence it", id)
	}
	// +16 for the team-03 rules above (docs/18 WS-I I2).
	team03Requires := 16
	// docs/18 WS-I I2 (team 01, intake and model): the rules that read a defaulted scope or provenance fact declare it.
	// The CMP rules and IMP-002 to IMP-005 report the absence or the marker they read and take none; PRV-003 and PRV-004
	// read n.source and n.description, which cannot be requires paths (the provenance-auditor lists those silences).
	for _, tc := range []struct {
		id       string
		requires []string
		domain   string
	}{
		{"SCP-002", []string{"g.attrs.ai_act_tier"}, ``},
		{"SCP-003", []string{"g.attrs.ai_act_tier", "g.attrs.regimes"}, ``},
		{"SCP-004", []string{"g.attrs.regimes"}, ``},
		{"SCP-005", []string{"g.attrs.regimes"}, ``},
		{"PRV-001", []string{"g.attrs.x_import_source"}, `n.type in ["gateway", "human_step", "data_diode", "dmz", "broker", "identity_provider", "secret_store", "log_sink", "evaluation"]`},
		{"PRV-002", []string{"g.attrs.x_import_source"}, ``},
		{"IMP-006", []string{"g.attrs.x_import_unmapped"}, `attr(g, "x_import_source", "") != ""`},
		{"STR-010", []string{"e.from.attrs.c4_level"}, `attr(e.from, "c4_parent", "") != ""`},
		{"STR-011", []string{"g.attrs.decisions"}, ``},
	} {
		r, ok := c.Rule(tc.id)
		require.True(t, ok, tc.id)
		assert.Equal(t, tc.requires, r.Requires, "%s: the fact whose absence silences the team 01 rule (ADR-088 §4)", tc.id)
		assert.Equal(t, tc.domain, r.Domain, "%s: the domain the team 01 rule decides", tc.id)
	}
	for _, id := range []string{"SCP-001", "CMP-001", "CMP-002", "CMP-003", "CMP-004", "CMP-005", "IMP-002", "IMP-003", "IMP-004", "IMP-005", "PRV-003", "PRV-004", "STR-009", "STR-012"} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Empty(t, r.Requires, "%s: its finding is the absence or the marker it reads", id)
	}
	team01Requires := 9
	// docs/18 WS-I I2 (swarm team 02, identity and zero trust): the zt and a2a additions and the new lpv pack declare the
	// facts whose absence silences them (lpv is annotated above). WIS-003 is graph scope and reports an absent rotation
	// (its finding), ATA-004 reads only fields; both take none.
	for _, tc := range []struct {
		id       string
		requires []string
		domain   string
	}{
		{"AID-003", []string{"n.attrs.identity"}, `n.type == "agent" && g.has("identity_provider")`},
		{"AID-004", []string{"n.attrs.identity"}, `n.type == "agent"`},
		{"WIS-001", []string{"n.attrs.network_exposure"}, `n.type == "secret_store"`},
		{"WIS-002", []string{"n.attrs.secrets_in"}, `n.type in ["app","api"] && g.has("secret_store")`},
		{"DLG-002", []string{"e.attrs.audience", "e.to.attrs.identity_id"}, `e.kind == "delegates" && e.from.type == "agent" && e.to.type == "agent" && e.auth in ["obo","token_exchange","jwt_assertion"]`},
		{"DLG-004", []string{"n.attrs.write_capable", "n.attrs.capabilities"}, `n.type in ["tool","mcp_server"]`},
		{"LPV-001", []string{"n.attrs.tool_scopes"}, `n.type == "agent" && g.out(n.id, "").exists(x, x.to.type in ["tool","mcp_server"])`},
		{"LPV-002", []string{"e.from.attrs.tool_scopes", "e.to.attrs.scopes"}, `e.from.type == "agent" && e.to.type in ["tool","mcp_server"]`},
		{"LPV-003", []string{"e.attrs.scopes", "e.to.attrs.scopes"}, `e.from.type == "agent" && e.to.type in ["tool","mcp_server"]`},
		{"LPV-004", []string{"n.attrs.rbac_scope"}, `n.type in ["agent","tool","mcp_server"]`},
		{"HAC-001", []string{"n.attrs.exposure", "n.attrs.authn"}, `n.type in ["app","api"]`},
		{"HAC-002", []string{"e.to.attrs.exposure", "e.attrs.token_lifetime"}, `e.from.type in ["user","external_party"] && e.to.type in ["app","api","agent"] && e.auth in ["oauth_client","jwt_assertion"]`},
		{"HAC-003", []string{"n.attrs.exposure"}, `n.type in ["app","api"] && g.has("identity_provider")`},
		{"HAC-004", []string{"e.to.attrs.inbound_auth"}, `e.from.type in ["user","external_party"] && e.to.type == "agent"`},
		{"ATA-005", []string{"n.attrs.inbound_auth", "n.attrs.security_schemes"}, `n.type in ["agent","external_agent"] && g.in(n.id, "").exists(x, x.protocol.lowerAscii() == "a2a" && size(x.from.group_ids) + size(n.group_ids) > 0 && !x.from.group_ids.exists(gid, gid in n.group_ids))`},
		{"ATA-007", []string{"e.to.attrs.card_url"}, `e.protocol.lowerAscii() == "a2a" && size(e.from.group_ids) + size(e.to.group_ids) > 0 && !e.from.group_ids.exists(gid, gid in e.to.group_ids) && e.to.type in ["agent","external_agent"]`},
	} {
		r, ok := c.Rule(tc.id)
		require.True(t, ok, tc.id)
		assert.Equal(t, tc.requires, r.Requires, "%s: the fact whose absence silences the team 02 rule (ADR-088 §4)", tc.id)
		assert.Equal(t, tc.domain, r.Domain, "%s: the domain the team 02 rule decides", tc.id)
	}
	for _, id := range []string{"WIS-003", "ATA-004"} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Empty(t, r.Requires, "%s: reads no defaulted fact that could silence it", id)
	}
	team02Requires := 16
	// docs/18 WS-I I2 (swarm team 04, gateways, network and data): the AGW, APX, SEG, TLS, DCR and RAG rules declare the
	// facts whose absence silences them (gateway functions and cache, exposure, zones, capabilities, protocol, region,
	// key use, class, the read hop's auth). The path and type rules (AGW-002, APX-003, SEG-002, SEG-003, TLS-001,
	// TLS-002, RAG-002, RAG-004) read types, layers, groups and attributes whose absence is the finding, and take none.
	for _, tc := range []struct {
		id       string
		requires []string
		domain   string
	}{
		{"AGW-004", []string{"n.attrs.functions"}, `n.type == "gateway"`},
		{"AGW-005", []string{"e.from.attrs.semantic_cache", "e.attrs.prompt_contains"}, `e.from.type == "gateway" && e.to.type == "llm_endpoint"`},
		{"APX-001", []string{"e.to.attrs.exposure", "e.from.attrs.functions"}, `e.kind == "calls" && e.to.type in ["app","api"]`},
		{"APX-002", []string{"n.attrs.network_exposure"}, `n.type == "secret_store"`},
		{"SEG-001", []string{"e.from.zone", "e.to.zone"}, `e.kind in ["writes","executes","publishes","flows"]`},
		{"SEG-004", []string{"n.attrs.capabilities"}, `n.type in ["mcp_server","tool"]`},
		{"TLS-003", []string{"e.protocol"}, `true`},
		{"DCR-001", []string{"n.attrs.region"}, `n.type in ["llm_endpoint","vector_index"]`},
		{"DCR-002", []string{"n.attrs.key_use", "n.attrs.region"}, `n.type == "secret_store"`},
		{"DCR-003", []string{"e.to.attrs.data_class"}, `e.kind in ["writes","flows","publishes"] && e.to.type in ["datastore","vector_index"]`},
		{"RAG-001", []string{"e.auth"}, `e.kind == "reads" && e.to.type == "vector_index"`},
		{"RAG-003", []string{"n.attrs.data_class"}, `n.type == "vector_index"`},
	} {
		r, ok := c.Rule(tc.id)
		require.True(t, ok, tc.id)
		assert.Equal(t, tc.requires, r.Requires, "%s: the fact whose absence silences the team 04 rule (ADR-088 §4)", tc.id)
		assert.Equal(t, tc.domain, r.Domain, "%s: the domain the team 04 rule decides", tc.id)
	}
	for _, id := range []string{"AGW-002", "APX-003", "SEG-002", "SEG-003", "TLS-001", "TLS-002", "RAG-002", "RAG-004"} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Empty(t, r.Requires, "%s: reads types, layers, groups or an attribute whose absence is the finding", id)
	}
	team04Requires := 12
	// docs/18 WS-I I2 (swarm team 07): AEI-002 requires the agent's autonomy on agents with a tool hop; AEI-001 reads
	// types, the call structure and other nodes' scopes, and takes none.
	for _, tc := range []struct {
		id       string
		requires []string
		domain   string
	}{
		{"AEI-002", []string{"n.attrs.autonomy"}, `n.type == "agent" && g.out(n.id, "").exists(x, x.to.type in ["tool", "mcp_server"])`},
	} {
		r, ok := c.Rule(tc.id)
		require.True(t, ok, tc.id)
		assert.Equal(t, tc.requires, r.Requires, "%s: the fact whose absence silences the team 07 rule (ADR-088 §4)", tc.id)
		assert.Equal(t, tc.domain, r.Domain, "%s: the domain the team 07 rule decides", tc.id)
	}
	r, ok = c.Rule("AEI-001")
	require.True(t, ok)
	assert.Empty(t, r.Requires, "AEI-001 reads no defaulted fact that could silence it")
	team07Requires := 1
	// docs/18 WS-M M3 (ADR-093, packs/fw.yaml): eight FW rules declare the schema 1.2 fact whose absence silences
	// them. FW-006, FW-010, FW-012 and FW-013 report an explicit value or an edge the design draws, and FW-008 reads an
	// undeclared egress policy on a code-executing tool as the gap (the synthesis's reading): they take none.
	fwMemory := `n.type == "agent_memory"`
	fwHost := `n.type in ["app", "api"] && g.nodes("agent").exists(a, attr(a, "hosted_on", "") == n.id)`
	for _, tc := range []struct {
		id       string
		requires []string
		domain   string
	}{
		{"FW-001", []string{"n.attrs.deserialization"}, fwMemory},
		{"FW-002", []string{"n.attrs.retention_days"}, fwMemory},
		{"FW-003", []string{"n.attrs.encryption"}, fwMemory},
		{"FW-004", []string{"n.attrs.scope"}, `n.type == "agent_memory" && g.inEdges(n.id, "writes").exists(w, w.from.type == "agent")`},
		{"FW-005", []string{"n.attrs.max_iterations"}, `n.type == "agent" && attr(n, "autonomy", "") != "assisted"`},
		{"FW-007", []string{"e.attrs.context_forwarded"}, "e.kind == \"delegates\" && e.from.type == \"agent\" &&\n(e.to.type == \"external_agent\" ||\n (size(e.from.group_ids) + size(e.to.group_ids) > 0 && !e.from.group_ids.exists(gid, gid in e.to.group_ids)))"},
		{"FW-009", []string{"n.attrs.authn"}, fwHost},
		{"FW-011", []string{"n.attrs.integrity"}, fwHost},
	} {
		r, ok := c.Rule(tc.id)
		require.True(t, ok, tc.id)
		assert.Equal(t, tc.requires, r.Requires, "%s: the schema 1.2 fact whose absence silences the FW rule (ADR-088 §4)", tc.id)
		assert.Equal(t, tc.domain, r.Domain, "%s: the domain the FW rule decides", tc.id)
	}
	for _, id := range []string{"FW-006", "FW-008", "FW-010", "FW-012", "FW-013"} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		assert.Empty(t, r.Requires, "%s: reports an explicit value, a drawn edge or (FW-008) an undeclared egress policy", id)
	}
	fwRequires := 8
	assert.Equal(t, 43+11+7+10+21+14+2+1+team03Requires+team01Requires+team02Requires+team04Requires+team07Requires+fwRequires, withRequires, "rules with a requires list (docs/03 \"requires and not_checked\")")

	// The per-pack table is complete (Reconcile A, 2026-10-02): every loaded pack has a row, 0 for a pack whose rules
	// read no defaulted fact (cmp: the absence is the finding), and the counts are read from the loaded catalog, so a
	// pack added or a requires list changed fails here with the pack named, not only in the total above.
	perPack := map[string]int{"a2a": 6, "aei": 1, "agt": 0, "ai": 9, "aia": 2, "arh": 2, "blr": 4, "c4": 3, "cmp": 0,
		"data": 11, "drift": 8, "evd": 3, "evl": 2, "fin": 3, "fw": 8, "gov": 9, "gxp": 6, "hov": 2, "imp": 1, "ing": 1,
		"irr": 1, "log": 2, "lpv": 4, "mcp": 9, "mem": 3, "mr": 5, "net": 9, "ot": 5, "prov": 4, "rag": 2, "res": 5,
		"scp": 4, "tpr": 6, "tsc": 3, "zt": 28}
	got := map[string]int{}
	for _, p := range c.Packs() {
		got[p.Pack] = 0
		for _, r := range p.Rules {
			if len(r.Requires) > 0 {
				got[p.Pack]++
			}
		}
	}
	assert.Equal(t, perPack, got, "rules with a requires list, per pack")
	total := 0
	for _, n := range perPack {
		total += n
	}
	assert.Equal(t, total, withRequires, "the per-pack table adds up to the catalog's count")
	for pack, n := range got {
		if n > 0 {
			assert.True(t, annotated[pack], "pack %s has rules with requires and is annotated above", pack)
		}
	}
}
