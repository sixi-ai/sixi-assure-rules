package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalCauses covers the one rule of minimalPack (testhelpers_test.go).
const minimalCauses = `
causes:
  - id: identity
    title: Identity, not shared secrets
    sentence: Every caller proves who it is with its own identity, and secrets live in a secret store.
    rules: [TST-001]
`

// writeCausesDir lays out packsDir/tst.yaml plus, when causes != "", the causes file next to it,
// and returns the packs directory to load.
func writeCausesDir(t *testing.T, pack, causes string) string {
	t.Helper()
	root := t.TempDir()
	packs := filepath.Join(root, "packs")
	require.NoError(t, os.MkdirAll(packs, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(packs, "tst.yaml"), []byte(pack), 0o600))
	if causes != "" {
		require.NoError(t, os.WriteFile(filepath.Join(root, CausesFileName), []byte(causes), 0o600))
	}
	return packs
}

// TestRepositoryCausesCoverEveryRule is the gate that keeps the taxonomy complete: a new rule
// without a cause fails this test (and every LoadDir of rules/packs).
func TestRepositoryCausesCoverEveryRule(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)

	causes := c.Causes()
	require.NotEmpty(t, causes, "causes.yaml must be loaded with the packs")

	listed := map[string]string{}
	for _, cause := range causes {
		assert.NotEmpty(t, cause.Rules, "%s: a cause without rules", cause.ID)
		assert.LessOrEqual(t, len(cause.Title), causeTitleMax, "%s: title too long", cause.ID)
		assert.LessOrEqual(t, len(cause.Sentence), causeSentenceMax, "%s: sentence too long", cause.ID)
		for _, id := range cause.Rules {
			assert.Empty(t, listed[id], "%s: rule %s also belongs to %s", cause.ID, id, listed[id])
			listed[id] = cause.ID
		}
	}

	for _, r := range c.Rules() {
		cause, ok := c.CauseOf(r.ID)
		require.True(t, ok, "%s (pack %s) has no cause in causes.yaml", r.ID, r.Pack)
		assert.Equal(t, listed[r.ID], cause.ID, "%s: CauseOf disagrees with the file", r.ID)
	}
	assert.Len(t, listed, len(c.Rules()), "causes.yaml lists a rule that is not in any pack")
}

// TestLoadCausesValidation: every way a hand-authored taxonomy can be wrong.
func TestLoadCausesValidation(t *testing.T) {
	t.Parallel()
	cause := func(id, title, sentence, rules string) string {
		return "  - id: " + id + "\n    title: " + title + "\n    sentence: " + sentence + "\n    rules: " + rules + "\n"
	}
	ok := cause("command-path", "Command path", "Nothing an AI component does reaches a machine without a human approval.", "[OT-001]")

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"valid", "causes:\n" + ok, ""},
		{"duplicate id", "causes:\n" + ok + cause("command-path", "Command path two", "A second sentence about the same invariant.", "[OT-002]"), "duplicate id"},
		{"rule listed twice", "causes:\n" + ok + cause("records", "Records and retention", "What happened is written to a sink nobody can edit.", "[OT-001]"), "already listed under cause command-path"},
		{"malformed id", "causes:\n" + cause("Command_Path", "Command path", "Nothing reaches a machine without a human approval.", "[OT-001]"), `id "Command_Path" must match`},
		{"empty id", "causes:\n" + cause("''", "Command path", "Nothing reaches a machine without a human approval.", "[OT-001]"), "causes[0]"},
		{"missing title", "causes:\n" + cause("command-path", "''", "Nothing reaches a machine without a human approval.", "[OT-001]"), "title is required"},
		{"title too long", "causes:\n" + cause("command-path", "The command path from an agent to a machine", "Nothing reaches a machine without approval.", "[OT-001]"), "title is 43 characters, at most 32"},
		{"missing sentence", "causes:\n" + cause("command-path", "Command path", "''", "[OT-001]"), "sentence is required"},
		{"sentence too long", "causes:\n" + cause("command-path", "Command path", strings.Repeat("a ", 101), "[OT-001]"), "at most 200"},
		{"wording in sentence", "causes:\n" + cause("command-path", "Command path", "The design is compliant when no AI component reaches a machine.", "[OT-001]"), `sentence says "compliant"`},
		{"wording in title", "causes:\n" + cause("command-path", "Certified command path", "Nothing reaches a machine without a human approval.", "[OT-001]"), `title says "Certified"`},
		{"no rules", "causes:\n" + cause("command-path", "Command path", "Nothing reaches a machine without a human approval.", "[]"), "lists no rules"},
		{"malformed rule id", "causes:\n" + cause("command-path", "Command path", "Nothing reaches a machine without a human approval.", "[ot-1]"), `rule id "ot-1" must match`},
		{"no causes", "causes: []\n", "no causes found"},
		{"unknown field", "causes:\n" + ok + "    colour: red\n", `unknown field "colour"`},
		{"not yaml", "causes: [", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), CausesFileName)
			require.NoError(t, os.WriteFile(path, []byte(tc.yaml), 0o600))
			causes, err := LoadCauses(path)
			if tc.want == "" && tc.name == "valid" {
				require.NoError(t, err)
				require.Len(t, causes, 1)
				assert.Equal(t, "command-path", causes[0].ID)
				assert.Equal(t, []string{"OT-001"}, causes[0].Rules)
				return
			}
			require.Error(t, err)
			if tc.want != "" {
				assert.Contains(t, err.Error(), tc.want)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, err := LoadCauses(filepath.Join(t.TempDir(), CausesFileName))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "causes:")
	})
}

// TestLoadDirCausesCoverage: with a causes file present, the catalog and the taxonomy must match.
func TestLoadDirCausesCoverage(t *testing.T) {
	t.Parallel()
	twoRulePack := minimalPack + strings.Replace(
		strings.SplitN(minimalPack, "rules:\n", 2)[1], "TST-001", "TST-002", 1)

	tests := []struct {
		name   string
		pack   string
		causes string
		want   string
	}{
		{"covered", minimalPack, minimalCauses, ""},
		{"rule without a cause", twoRulePack, minimalCauses, "no cause for TST-002"},
		{"cause names an unknown rule", minimalPack,
			strings.Replace(minimalCauses, "[TST-001]", "[TST-001, ZZZ-999]", 1), "unknown rule ZZZ-999"},
		{"invalid causes file", minimalPack, "causes:\n  - id: X\n    title: T\n    sentence: S\n    rules: [TST-001]\n", `id "X" must match`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := LoadDirWith(writeCausesDir(t, tc.pack, tc.causes), LoadOptions{})
			if tc.want != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.want)
				return
			}
			require.NoError(t, err)
			require.Len(t, c.Causes(), 1)
			assert.Equal(t, "identity", c.Causes()[0].ID)
		})
	}
}

// TestCauseOf covers a known rule, an unknown rule and a catalog loaded without any causes file.
func TestCauseOf(t *testing.T) {
	t.Parallel()
	withCauses, err := LoadDirWith(writeCausesDir(t, minimalPack, minimalCauses), LoadOptions{})
	require.NoError(t, err)
	without, err := LoadDirWith(writeCausesDir(t, minimalPack, ""), LoadOptions{})
	require.NoError(t, err)

	tests := []struct {
		name    string
		catalog *Catalog
		ruleID  string
		want    string
	}{
		{"known rule", withCauses, "TST-001", "identity"},
		{"unknown rule", withCauses, "NOPE-001", ""},
		{"no causes file", without, "TST-001", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cause, ok := tc.catalog.CauseOf(tc.ruleID)
			if tc.want == "" {
				assert.False(t, ok)
				assert.Equal(t, Cause{}, cause)
				return
			}
			require.True(t, ok)
			assert.Equal(t, tc.want, cause.ID)
			assert.Equal(t, "Identity, not shared secrets", cause.Title)
			assert.Equal(t, []string{"TST-001"}, cause.Rules)
		})
	}

	assert.Nil(t, without.Causes(), "a packs directory without causes.yaml loads with no causes")

	// The catalog hands out copies: a caller cannot rewrite the taxonomy through them.
	cause, ok := withCauses.CauseOf("TST-001")
	require.True(t, ok)
	cause.Rules[0] = "MUTATED"
	again, _ := withCauses.CauseOf("TST-001")
	assert.Equal(t, []string{"TST-001"}, again.Rules)
	withCauses.Causes()[0].Rules[0] = "MUTATED"
	assert.Equal(t, []string{"TST-001"}, withCauses.Causes()[0].Rules)
}
