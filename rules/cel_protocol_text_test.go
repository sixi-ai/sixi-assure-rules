package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// upgradedNarrowed is the synthetic 1.0 migration fixture (model/migrate golden pair
// narrowed-values), read the way every entry path reads it: upgraded to the current version.
func upgradedNarrowed(t *testing.T) *model.Architecture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "model", "migrate", "testdata", "pairs", "narrowed-values.1.0.json"))
	require.NoError(t, err)
	a, err := model.ValidateJSON(raw)
	require.NoError(t, err)
	require.Equal(t, model.CurrentSchemaVersion, a.SchemaVersion)
	return a
}

// TestProtocolTextProjection: schema 1.1 maps a 1.0 free-text protocol to the enum, and the rules
// projection keeps what the author wrote readable as e.protocol_text (from x_migrated_from), so a
// name match is not lost to "other".
func TestProtocolTextProjection(t *testing.T) {
	t.Parallel()
	a := upgradedNarrowed(t)
	for _, tc := range []struct {
		edge, expr string
		want       any
	}{
		{"e_app_siem", `e.protocol`, "other"},
		{"e_app_siem", `e.protocol_text`, "ftp"},
		{"e_app_agent", `e.protocol_text`, "http"},
		{"e_agent_pub", `e.protocol + "/" + e.protocol_text`, "https/wss"},
		{"e_plc_ops", `e.protocol_text.lowerAscii()`, "mqtts"},
	} {
		t.Run(tc.edge+" "+tc.expr, func(t *testing.T) {
			t.Parallel()
			got, err := evalExpr(t, ScopeEdge, tc.expr, a, Policy{}, tc.edge)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	// An edge the migration did not touch reads its enum value; an empty protocol stays empty.
	m := testModel()
	for _, e := range m.Edges {
		got, err := evalExpr(t, ScopeEdge, `e.protocol_text == e.protocol`, m, Policy{}, e.ID)
		require.NoError(t, err)
		assert.Equal(t, true, got, e.ID)
	}
}

// TestDeprecatedFreeTextProtocolSurvivesTheUpgrade is the DRF-004 shape over an upgraded 1.0 model
// whose free-text protocol the knowledge base marks deprecated: matching e.protocol_text keeps the
// finding; matching the enum alone (what DRF-004 reads until D2 points it at protocol_text) loses
// it, because "ftp" is now "other".
func TestDeprecatedFreeTextProtocolSurvivesTheUpgrade(t *testing.T) {
	t.Parallel()
	c := mustInline(t, `
pack: tst
version: 0.1.0
rules:
  - id: TST-101
    title: Relationship names a deprecated protocol (protocol_text)
    scope: edge
    severity: low
    condition: 'kb.available && e.protocol_text != "" && e.protocol_text.lowerAscii() in kb.deprecated'
    message: "{{e.from.name}} -> {{e.to.name}} over {{e.protocol_text}} (replaced by {{kb.deprecated[e.protocol_text.lowerAscii()]}})"
    clauses: [A:B]
  - id: TST-102
    title: Relationship names a deprecated protocol (enum only)
    scope: edge
    severity: low
    condition: 'kb.available && e.protocol != "" && e.protocol.lowerAscii() in kb.deprecated'
    message: "{{e.from.name}} -> {{e.to.name}}"
    clauses: [A:B]
`)
	facts := &KnowledgeFacts{Deprecated: map[string]string{"ftp": "sftp"}}
	fs, err := New(c, nil).Evaluate(context.Background(), upgradedNarrowed(t), Policy{Knowledge: facts})
	require.NoError(t, err)
	byRule := map[string][]model.Finding{}
	for _, f := range fs {
		byRule[f.RuleID] = append(byRule[f.RuleID], f)
	}
	require.Len(t, byRule["TST-101"], 1)
	assert.Equal(t, []string{"e_app_siem"}, byRule["TST-101"][0].IDs)
	assert.Contains(t, byRule["TST-101"][0].Message, "over ftp (replaced by sftp)")
	assert.Empty(t, byRule["TST-102"], "the enum alone no longer names ftp")
}
