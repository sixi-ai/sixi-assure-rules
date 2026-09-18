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
