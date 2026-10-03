package rules

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// withNotes returns a copy of a with one note per tone, the first placed in the first group (and
// its zone, when that group is a zone). The last one carries the import marker IMP-001 reads, so
// the test proves a text box from draw.io can no longer raise it (ADR-081 §2).
func withNotes(t *testing.T, a *model.Architecture) *model.Architecture {
	t.Helper()
	b, err := a.Clone()
	require.NoError(t, err)
	for i, tone := range model.NoteTones {
		n := model.Node{ID: fmt.Sprintf("n_note_%d", i), Type: model.NodeTypeNote, Name: "Note " + tone, Layer: "app",
			Source: model.SourceDesign, Description: "uploads the transcript to the vendor endpoint",
			Attrs: model.Attrs{"text": "Decided 2026-09-12: stay in one region. Owner? PII? public?", "tone": tone}}
		if i == len(model.NoteTones)-1 {
			n.Attrs["x_unmapped_style"] = "text;html=1"
		}
		if i == 0 && len(b.Groups) > 0 {
			g := &b.Groups[0]
			g.NodeIDs = append(g.NodeIDs, n.ID)
			if g.Kind == "zone" {
				n.Zone = g.ID
			}
		}
		b.Nodes = append(b.Nodes, n)
	}
	require.NoError(t, model.Validate(b), "the model with notes must stay valid")
	return b
}

// TestNotesNeverChangeFindings evaluates every golden fixture with and without notes: the findings
// are identical, so no pack sees a note (ADR-081 §2, docs/17 DP-3).
func TestNotesNeverChangeFindings(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	files, err := filepath.Glob(repoPath("golden-set", "models", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, f)
			p := policyFromAttrs(a)
			want, err := eng.Evaluate(context.Background(), a, p)
			require.NoError(t, err)
			got, err := eng.Evaluate(context.Background(), withNotes(t, a), p)
			require.NoError(t, err)
			assert.Equal(t, want, got)
			for _, fd := range got {
				for _, id := range fd.IDs {
					assert.False(t, strings.HasPrefix(id, "n_note_"), "%s names a note", fd.RuleID)
				}
			}
		})
	}
}

// TestGraphNeverHoldsNotes pins the exclusion point: the CEL node set, the by-type index and the
// id lookup all skip notes, while every other node keeps its `n` projection.
func TestGraphNeverHoldsNotes(t *testing.T) {
	t.Parallel()
	a := withNotes(t, testModel())
	g := buildGraph(a, Policy{}, nil)
	assert.Len(t, g.nodes, len(testModel().Nodes))
	assert.Empty(t, g.nodesByType[model.NodeTypeNote])
	_, ok := g.nodeByID["n_note_0"]
	assert.False(t, ok)
	v, err := evalExpr(t, ScopeGraph, `g.nodes.exists(x, x.type == "note") || g.has("note") || size(g.nodes("note")) > 0`, a, Policy{}, "")
	require.NoError(t, err)
	assert.Equal(t, false, v)
	eng := New(nil, nil)
	_, err = eng.Bind(a, Policy{}, ScopeNode, "n_note_0")
	require.Error(t, err, "a note is never a rule subject")
}
