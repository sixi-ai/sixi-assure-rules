package rules

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adr/proposals/ADR-093-C2-imported-scopes-undeclared.md: the importers write scopes: [] where the schema requires the
// attribute and the source declares nothing, so on an element whose provenance is imported an empty list is not a
// declaration (engine importedPlaceholder): LPV-002 and LPV-003 report the hop not_checked. The same model without the
// provenance entry (a designed tool with scopes: []) is decided, as before.
func TestImportedEmptyScopesAreNotChecked(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	tests := []struct {
		fixture, rule, element string
	}{
		{"LPV-002.imported.neg.json", "LPV-002", "e1"},
		{"LPV-003.imported.neg.json", "LPV-003", "e1"},
	}
	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, filepath.Join(repoPath("packs"), "fixtures", tc.fixture))
			require.True(t, a.HasProvenance(), "the fixture carries the import's provenance")
			fs, cov, err := eng.EvaluateCoverage(context.Background(), a, policyFromAttrs(a))
			require.NoError(t, err)
			assert.Empty(t, findingsByRule(fs)[tc.rule], "an undeclared list raises nothing")
			assert.Contains(t, cov.NotChecked[tc.rule], tc.element, "imported scopes: [] is undeclared")

			designed := loadModel(t, filepath.Join(repoPath("packs"), "fixtures", tc.fixture))
			designed.Provenance = nil
			require.False(t, designed.HasProvenance())
			fs, cov, err = eng.EvaluateCoverage(context.Background(), designed, policyFromAttrs(designed))
			require.NoError(t, err)
			assert.Empty(t, findingsByRule(fs)[tc.rule])
			assert.NotContains(t, cov.NotChecked[tc.rule], tc.element, "a designed scopes: [] is a declaration")
		})
	}
}
