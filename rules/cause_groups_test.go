package rules

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// groupTaxonomy is a three-cause stand-in for causes.yaml, in file order: the ordering tests
// need the taxonomy position as a tiebreak, not the real 18 causes.
func groupTaxonomy() []Cause {
	return []Cause{
		{ID: "command-path", Title: "Command path", Rules: []string{"OT-001", "OT-002"},
			Sentence: "Nothing an AI component does reaches a machine without a human approval."},
		{ID: "records-retention", Title: "Records and retention", Rules: []string{"LOG-001", "LOG-002"},
			Sentence: "What the system did is written to a sink nobody can edit."},
		{ID: "identity", Title: "Identity, not shared secrets", Rules: []string{"ZT-001", "ZT-002"},
			Sentence: "Every caller proves who it is with its own identity."},
	}
}

// causeCatalog builds a catalog that knows only the rule ids of the taxonomy: GroupByCause reads
// the cause of a rule, never the rule body, so a pack is not needed here.
func causeCatalog(t *testing.T, causes []Cause) *Catalog {
	t.Helper()
	c := &Catalog{byID: map[string]*Rule{}}
	for _, cause := range causes {
		for _, id := range cause.Rules {
			c.byID[id] = &Rule{ID: id}
		}
	}
	require.NoError(t, c.setCauses(CausesFileName, causes))
	return c
}

// finding is a compact literal for the grouping tests: id, rule, severity, status, element.
func finding(id, ruleID, severity, status, element string) model.Finding {
	f := model.Finding{ID: id, RuleID: ruleID, Severity: severity, Status: status, Message: "m"}
	if element != "" {
		f.IDs = []string{element}
	}
	return f
}

func TestGroupByCauseOrdering(t *testing.T) {
	t.Parallel()
	type want struct {
		id    string
		title string
		worst string
		count int
	}
	tests := []struct {
		name     string
		catalog  func(t *testing.T) *Catalog
		findings []model.Finding
		want     []want
	}{
		{
			name:    "worst severity leads, then the number of findings",
			catalog: func(t *testing.T) *Catalog { return causeCatalog(t, groupTaxonomy()) },
			findings: []model.Finding{
				finding("f1", "ZT-001", "high", model.StatusOpen, "n_a"),
				finding("f2", "ZT-002", "high", model.StatusOpen, "n_b"),
				finding("f3", "ZT-002", "medium", model.StatusOpen, "n_c"),
				finding("f4", "LOG-001", "high", model.StatusOpen, "n_d"),
				finding("f5", "OT-001", "critical", model.StatusOpen, "n_e"),
			},
			want: []want{
				{id: "command-path", title: "Command path", worst: "critical", count: 1},
				{id: "identity", title: "Identity, not shared secrets", worst: "high", count: 3},
				{id: "records-retention", title: "Records and retention", worst: "high", count: 1},
			},
		},
		{
			name:    "equal severity and count fall back to the taxonomy order",
			catalog: func(t *testing.T) *Catalog { return causeCatalog(t, groupTaxonomy()) },
			findings: []model.Finding{
				finding("f1", "ZT-001", "high", model.StatusOpen, "n_a"),
				finding("f2", "LOG-001", "high", model.StatusOpen, "n_b"),
				finding("f3", "OT-001", "high", model.StatusOpen, "n_c"),
			},
			want: []want{
				{id: "command-path", title: "Command path", worst: "high", count: 1},
				{id: "records-retention", title: "Records and retention", worst: "high", count: 1},
				{id: "identity", title: "Identity, not shared secrets", worst: "high", count: 1},
			},
		},
		{
			name:    "only open findings are grouped",
			catalog: func(t *testing.T) *Catalog { return causeCatalog(t, groupTaxonomy()) },
			findings: []model.Finding{
				finding("f1", "OT-001", "critical", model.StatusAccepted, "n_a"),
				finding("f2", "OT-002", "critical", model.StatusFixed, "n_b"),
				finding("f3", "LOG-001", "low", model.StatusFalsePositive, "n_c"),
				finding("f4", "ZT-001", "medium", model.StatusOpen, "n_d"),
			},
			want: []want{{id: "identity", title: "Identity, not shared secrets", worst: "medium", count: 1}},
		},
		{
			name:    "nothing open, no groups",
			catalog: func(t *testing.T) *Catalog { return causeCatalog(t, groupTaxonomy()) },
			findings: []model.Finding{
				finding("f1", "OT-001", "critical", model.StatusAccepted, "n_a"),
			},
		},
		{
			name:     "no catalog, no groups",
			catalog:  func(*testing.T) *Catalog { return nil },
			findings: []model.Finding{finding("f1", "OT-001", "critical", model.StatusOpen, "n_a")},
		},
		{
			name:    "a catalog without a causes file groups everything under Other findings",
			catalog: func(t *testing.T) *Catalog { return mustInline(t, minimalPack) },
			findings: []model.Finding{
				finding("f1", "TST-001", "high", model.StatusOpen, "n_a"),
				finding("f2", "TST-001", "critical", model.StatusOpen, "n_b"),
			},
			want: []want{{id: "", title: "Other findings", worst: "critical", count: 2}},
		},
		{
			name:    "findings without a cause trail the caused ones, whatever their severity",
			catalog: func(t *testing.T) *Catalog { return causeCatalog(t, groupTaxonomy()) },
			findings: []model.Finding{
				finding("f1", "XXX-001", "critical", model.StatusOpen, "n_a"),
				finding("f2", "ZT-001", "low", model.StatusOpen, "n_b"),
			},
			want: []want{
				{id: "identity", title: "Identity, not shared secrets", worst: "low", count: 1},
				{id: "", title: "Other findings", worst: "critical", count: 1},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			groups := GroupByCause(tc.catalog(t), tc.findings)
			require.Len(t, groups, len(tc.want))
			for i, w := range tc.want {
				assert.Equal(t, w.id, groups[i].Cause.ID, "group %d", i)
				assert.Equal(t, w.title, groups[i].Cause.Title, "group %d", i)
				assert.Equal(t, w.worst, groups[i].Worst, "group %d", i)
				assert.Len(t, groups[i].Findings, w.count, "group %d", i)
				assert.Equal(t, groups[i].Findings[0].Severity, groups[i].Worst, "Worst is the first finding's severity")
			}
		})
	}
}

// TestCauseGroupContents covers what one group carries: the findings most severe first, the
// distinct elements in first-seen order, and the fix the group is headlined with.
func TestCauseGroupContents(t *testing.T) {
	t.Parallel()
	catalog := causeCatalog(t, groupTaxonomy())

	t.Run("findings sort by severity, rule and first element", func(t *testing.T) {
		t.Parallel()
		fs := []model.Finding{
			{ID: "f4", RuleID: "ZT-002", Severity: "high", Status: model.StatusOpen, IDs: []string{"n_b"}},
			{ID: "f3", RuleID: "ZT-002", Severity: "high", Status: model.StatusOpen, IDs: []string{"n_a"}},
			{ID: "f2", RuleID: "ZT-001", Severity: "high", Status: model.StatusOpen, IDs: []string{"n_z"}},
			{ID: "f1", RuleID: "ZT-002", Severity: "critical", Status: model.StatusOpen, IDs: []string{"n_c", "n_a"}},
			{ID: "f5", RuleID: "ZT-002", Severity: "high", Status: model.StatusOpen},
		}
		groups := GroupByCause(catalog, fs)
		require.Len(t, groups, 1)
		ids := make([]string, 0, len(groups[0].Findings))
		for _, f := range groups[0].Findings {
			ids = append(ids, f.ID)
		}
		assert.Equal(t, []string{"f1", "f2", "f5", "f3", "f4"}, ids)
		assert.Equal(t, "critical", groups[0].Worst)
		assert.Equal(t, []string{"n_c", "n_a", "n_z", "n_b"}, groups[0].Elements, "distinct, in first-seen order")
	})

	t.Run("the fix is the worst finding's remediation, patch templates listed beside it", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name          string
			findings      []model.Finding
			want          string
			wantPatchable []string
		}{
			{
				name: "the worst finding leads, whatever ships a patch template",
				findings: []model.Finding{
					{ID: "f1", RuleID: "ZT-001", Severity: "critical", Status: model.StatusOpen, Remediation: "redesign the zone"},
					{ID: "f2", RuleID: "ZT-002", Severity: "high", Status: model.StatusOpen, Remediation: "set identity=agent_id", HasPatch: true},
				},
				want: "redesign the zone", wantPatchable: []string{"ZT-002"},
			},
			{
				name: "a worst finding without a remediation falls back to the first stated one",
				findings: []model.Finding{
					{ID: "f1", RuleID: "ZT-001", Severity: "critical", Status: model.StatusOpen, HasPatch: true},
					{ID: "f2", RuleID: "ZT-002", Severity: "high", Status: model.StatusOpen, Remediation: "set identity=agent_id"},
				},
				want: "set identity=agent_id", wantPatchable: []string{"ZT-001"},
			},
			{
				name: "patchable rules are distinct and in finding order",
				findings: []model.Finding{
					{ID: "f3", RuleID: "ZT-002", Severity: "high", Status: model.StatusOpen, Remediation: "r", HasPatch: true},
					{ID: "f1", RuleID: "ZT-002", Severity: "critical", Status: model.StatusOpen, Remediation: "r", HasPatch: true},
					{ID: "f2", RuleID: "ZT-001", Severity: "critical", Status: model.StatusOpen, Remediation: "r", HasPatch: true},
					{ID: "f4", RuleID: "ZT-001", Severity: "low", Status: model.StatusOpen, Remediation: "r"},
				},
				want: "r", wantPatchable: []string{"ZT-001", "ZT-002"},
			},
			{
				name: "no patch template, nothing to offer",
				findings: []model.Finding{
					{ID: "f1", RuleID: "ZT-001", Severity: "critical", Status: model.StatusOpen, Remediation: "redesign the zone"},
				},
				want: "redesign the zone",
			},
			{
				name: "no remediation at all is empty, never invented",
				findings: []model.Finding{
					{ID: "f1", RuleID: "ZT-001", Severity: "critical", Status: model.StatusOpen},
				},
				want: "",
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				groups := GroupByCause(catalog, tc.findings)
				require.Len(t, groups, 1)
				assert.Equal(t, tc.want, groups[0].Fix)
				assert.Equal(t, tc.wantPatchable, groups[0].Patchable)
			})
		}
	})
}

// TestGroupByCauseGlassBoxBadTwin runs the grouping over the repository packs and the GlassBox bad
// twin, the model docs/03 §Causes is written against: its many findings come from a handful of
// shortcuts, and the command path is the one a reader must fix first.
func TestGroupByCauseGlassBoxBadTwin(t *testing.T) {
	t.Parallel()
	catalog, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	table, err := LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	a := loadModel(t, repoPath("golden-set", "models", "glassbox-ot-agent-bad.json"))
	findings, err := New(catalog, table).Evaluate(context.Background(), a, policyFromAttrs(a))
	require.NoError(t, err)

	open := 0
	for _, f := range findings {
		if f.Status == model.StatusOpen {
			open++
		}
	}
	require.Positive(t, open)

	groups := GroupByCause(catalog, findings)
	require.NotEmpty(t, groups)
	first := groups[0]
	assert.Equal(t, "command-path", first.Cause.ID, "the command path is what a reader fixes first")
	assert.Equal(t, "OT-001", first.Findings[0].RuleID, "the worst finding of the command path")
	assert.Equal(t, first.Findings[0].Remediation, first.Fix, "the fix is the worst finding's remediation")
	assert.NotEmpty(t, first.Fix)
	assert.Subset(t, first.Patchable, []string{"OT-002", "MR-002"}, "the rules of the group that ship a patch template")
	assert.NotContains(t, first.Patchable, "OT-001", "OT-001 has no patch template: the fix is a redesign")

	grouped := 0
	for _, g := range groups {
		grouped += len(g.Findings)
		assert.NotEmpty(t, g.Cause.ID, "every repository rule has a cause: no Other findings group")
		assert.NotEmpty(t, g.Cause.Sentence)
		assert.NotEmpty(t, g.Elements)
		t.Logf("%-22s %-8s %2d finding(s) %v patchable=%v fix=%q", g.Cause.Title, g.Worst, len(g.Findings), g.Elements, g.Patchable, g.Fix)
	}
	assert.Equal(t, open, grouped, "every open finding belongs to exactly one group")
	assert.LessOrEqual(t, len(groups), len(catalog.Causes()))
}
