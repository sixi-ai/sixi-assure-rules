package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Content hashes of rule packs (ADR-042 §4, docs/18 A2): what an export pins as "findings are as
// of rule pack <hash>" and what GET /rules/packs publishes.

var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// hashPack is the base pack of the hash tests: two rules, so rule order can be varied.
const hashPack = `
pack: tst
version: 0.1.0
regimes: [FINMA]
rules:
  - id: TST-001
    title: Agent without identity
    scope: node
    severity: high
    condition: 'n.type == "agent" && attr(n,"identity","none") in ["none","shared"]'
    message: "Agent {{n.name}} has no identity."
    clauses: [MSFT:EntraAgentID]
    remediation: "Assign an agent identity."
    patch_template:
      - { op: replace, path: "/nodes/{{n.id}}/attrs/identity", value: agent_id }
    tags: [identity]
  - id: TST-002
    title: Datastore without encryption
    scope: node
    severity: medium
    condition: 'n.type == "datastore" && !attr(n,"encryption",false)'
    message: "Datastore {{n.name}} is not encrypted."
    clauses: [FINMA:2023/1:Rz53]
`

// packHashOf parses one inline pack and returns its hash.
func packHashOf(t *testing.T, yamlText string) string {
	t.Helper()
	c := mustInline(t, yamlText)
	require.Len(t, c.Packs(), 1)
	h := c.Packs()[0].Hash()
	require.Regexp(t, hexHash, h)
	return h
}

func TestPackHashIgnoresLayoutButNotContent(t *testing.T) {
	t.Parallel()
	base := packHashOf(t, hashPack)
	tests := []struct {
		name string
		edit func(string) string
		same bool
	}{
		{"comments and blank lines", func(s string) string {
			return "# a comment\n\n" + strings.Replace(s, "rules:\n", "rules: # the rules\n", 1)
		}, true},
		{"top-level key order", func(s string) string {
			return strings.Replace(s, "pack: tst\nversion: 0.1.0\n", "version: 0.1.0\npack: tst\n", 1)
		}, true},
		{"rule key order", func(s string) string {
			return strings.Replace(s, "    title: Agent without identity\n    scope: node\n", "    scope: node\n    title: Agent without identity\n", 1)
		}, true},
		{"rule order", func(s string) string {
			i := strings.Index(s, "  - id: TST-002")
			j := strings.Index(s, "  - id: TST-001")
			return s[:j] + s[i:] + s[j:i]
		}, true},
		{"flow and block style", func(s string) string {
			return strings.Replace(s, "clauses: [MSFT:EntraAgentID]", "clauses:\n      - MSFT:EntraAgentID", 1)
		}, true},
		{"fixtures are test inputs", func(s string) string {
			return strings.Replace(s, "    tags: [identity]\n", "    tags: [identity]\n    fixtures: { positive: a.json, negative: b.json }\n", 1)
		}, true},
		{"condition", func(s string) string { return strings.Replace(s, `"shared"]`, `"shared","none"]`, 1) }, false},
		{"severity", func(s string) string { return strings.Replace(s, "severity: medium", "severity: low", 1) }, false},
		{"clauses", func(s string) string { return strings.Replace(s, "[FINMA:2023/1:Rz53]", "[FINMA:2023/1:Rz54]", 1) }, false},
		{"remediation", func(s string) string { return strings.Replace(s, "Assign an agent identity.", "Assign one.", 1) }, false},
		{"patch template", func(s string) string { return strings.Replace(s, "value: agent_id", "value: managed_identity", 1) }, false},
		{"message", func(s string) string { return strings.Replace(s, "is not encrypted.", "lacks encryption.", 1) }, false},
		{"version", func(s string) string { return strings.Replace(s, "version: 0.1.0", "version: 0.1.1", 1) }, false},
		{"regimes", func(s string) string { return strings.Replace(s, "regimes: [FINMA]", "regimes: [FINMA, DORA]", 1) }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := packHashOf(t, tc.edit(hashPack))
			if tc.same {
				assert.Equal(t, base, got, "layout must not move the hash")
			} else {
				assert.NotEqual(t, base, got, "content must move the hash")
			}
		})
	}
}

// TestCanonicalPackCoversRequires: a rule's `requires` list (docs/18 A6) is part of what the rule
// decides, so it is part of the hash wherever a pack declares it; the canonical form is read from
// the document, not from the fields this build knows.
func TestCanonicalPackCoversRequires(t *testing.T) {
	t.Parallel()
	without, err := CanonicalPack([]byte(hashPack))
	require.NoError(t, err)
	with, err := CanonicalPack([]byte(strings.Replace(hashPack, "    tags: [identity]\n", "    tags: [identity]\n    requires: [n.attrs.identity]\n", 1)))
	require.NoError(t, err)
	assert.NotEqual(t, without, with)
	assert.Contains(t, string(with), `"requires":["n.attrs.identity"]`)
	assert.NotContains(t, string(without), "fixtures")
	assert.True(t, strings.Index(string(with), `"TST-001"`) < strings.Index(string(with), `"TST-002"`), "rules sorted by id")

	_, err = CanonicalPack([]byte("pack: [unclosed"))
	assert.Error(t, err)
}

func TestCombinedHash(t *testing.T) {
	t.Parallel()
	other := strings.ReplaceAll(strings.ReplaceAll(hashPack, "pack: tst", "pack: abc"), "TST-", "ABC-")
	c, err := ParsePacks([]PackSource{{Name: "tst.yaml", Data: []byte(hashPack)}, {Name: "abc.yaml", Data: []byte(other)}}, LoadOptions{})
	require.NoError(t, err)
	packs := c.Packs()
	require.Len(t, packs, 2)

	sum := sha256.Sum256([]byte(fmt.Sprintf("abc %s\ntst %s\n", packs[0].Hash(), packs[1].Hash())))
	want := hex.EncodeToString(sum[:])
	assert.Equal(t, want, c.Hash(), "one line per pack, sorted by pack id")
	assert.Equal(t, want, CombinedHash([]*Pack{packs[1], packs[0]}), "input order does not matter")
	assert.Equal(t, 2, packs[0].RuleCount())

	changed, err := ParsePacks([]PackSource{{Name: "tst.yaml", Data: []byte(strings.Replace(hashPack, "severity: medium", "severity: low", 1))},
		{Name: "abc.yaml", Data: []byte(other)}}, LoadOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, c.Hash(), changed.Hash(), "a change in one pack moves the combined hash")

	var nilCatalog *Catalog
	assert.Empty(t, nilCatalog.Hash())
	var nilPack *Pack
	assert.Empty(t, nilPack.Hash())
	assert.Zero(t, nilPack.RuleCount())
	assert.Empty(t, (&Pack{Pack: "built"}).Hash(), "a pack that was not parsed from a source has no content hash")
}

// TestShippedPacksHash loads rules/packs twice: every pack carries a content hash and the combined
// hash is a pure function of the files (no value is pinned: the packs change with every release).
func TestShippedPacksHash(t *testing.T) {
	t.Parallel()
	first, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	second, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, first.Packs())
	seen := map[string]bool{}
	for _, p := range first.Packs() {
		assert.Regexp(t, hexHash, p.Hash(), p.Pack)
		assert.False(t, seen[p.Hash()], "two packs with one hash: %s", p.Pack)
		seen[p.Hash()] = true
		assert.Positive(t, p.RuleCount(), p.Pack)
	}
	assert.Regexp(t, hexHash, first.Hash())
	assert.Equal(t, first.Hash(), second.Hash())
	assert.Equal(t, CombinedHash(first.Packs()), first.Hash())
}
