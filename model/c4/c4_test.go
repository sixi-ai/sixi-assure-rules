package c4

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

var updateViews = flag.Bool("update", false, "rewrite testdata/views.json")

func fixtures(t *testing.T) map[string]*model.Architecture {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "golden-set", "models", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	out := map[string]*model.Architecture{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		a, err := model.ValidateJSON(raw)
		require.NoError(t, err, f)
		out[filepath.Base(f)] = a
	}
	return out
}

// TestRoundTripIsIdentity: canvas → C4 → canvas must be the identity on every fixture (prompt §5).
func TestRoundTripIsIdentity(t *testing.T) {
	for name, a := range fixtures(t) {
		before, err := model.Canonical(a)
		require.NoError(t, err)
		m := Project(a)
		require.Len(t, m.Elements, len(a.Nodes), name)
		require.Len(t, m.Relationships, len(a.Edges), name)
		require.Len(t, m.Boundaries, len(a.Groups), name)
		after, err := model.Canonical(m.Unproject())
		require.NoError(t, err)
		assert.Equal(t, string(before), string(after), name)
		for _, e := range m.Elements {
			assert.Contains(t, Levels, e.Level, "%s: %s", name, e.ID)
			assert.NotEmpty(t, e.Kind, "%s: %s", name, e.ID)
		}
		assert.Empty(t, m.Orphans(), name)
	}
}

func TestClassifyDerivesAndDeclaredWins(t *testing.T) {
	cases := map[string][2]string{
		"user": {LevelContext, KindPerson}, "external_party": {LevelContext, KindExternalSystem}, "product": {LevelContext, KindSoftwareSystem},
		"datastore": {LevelContainer, KindDataStore}, "queue": {LevelContainer, KindQueue}, "agent": {LevelContainer, KindAgent},
		"mcp_server": {LevelContainer, KindMCPServer}, "identity_provider": {LevelContainer, KindIdentity}, "gateway": {LevelContainer, KindGateway},
		"app": {LevelContainer, KindContainer},
	}
	for typ, want := range cases {
		level, kind, declared := Classify(&model.Node{Type: typ, Attrs: model.Attrs{}})
		assert.Equal(t, want[0], level, typ)
		assert.Equal(t, want[1], kind, typ)
		assert.False(t, declared)
	}
	level, kind, declared := Classify(&model.Node{Type: "app", Attrs: model.Attrs{"c4_level": "component", "c4_kind": "Component"}})
	assert.Equal(t, LevelComponent, level)
	assert.Equal(t, KindComponent, kind)
	assert.True(t, declared)
	level, kind, _ = Classify(&model.Node{Type: "app", Attrs: model.Attrs{"c4_kind": "SoftwareSystem"}})
	assert.Equal(t, LevelContext, level, "kind implies the level")
	assert.Equal(t, KindSoftwareSystem, kind)
}

// views is the golden projection of the RAG fixture, shared with the SPA (web/src/c4) so both
// derivations agree.
type views struct {
	Context   []string            `json:"context"`
	Container []string            `json:"container"`
	Component []string            `json:"component"`
	Kinds     map[string]string   `json:"kinds"`
	Crosses   map[string][]string `json:"crosses"`
}

func TestViewsGolden(t *testing.T) {
	a := fixtures(t)["rag-chatbot.json"]
	require.NotNil(t, a)
	// Declare a system with two children so the container and component views have a focus.
	a.Nodes[3].Attrs["c4_kind"] = KindSoftwareSystem // n_web → system
	for _, id := range []string{"n_agent", "n_aigw"} {
		n := a.Node(id)
		require.NotNil(t, n)
		n.Attrs["c4_parent"] = "n_web"
	}
	a.Node("n_eval").Attrs["c4_parent"] = "n_agent"
	a.Node("n_eval").Attrs["c4_level"] = LevelComponent
	m := Project(a)
	g := views{Kinds: map[string]string{}, Crosses: map[string][]string{}}
	for _, e := range m.ContextView().Elements {
		g.Context = append(g.Context, e.ID)
	}
	for _, e := range m.ContainerView("n_web").Elements {
		g.Container = append(g.Container, e.ID)
	}
	for _, e := range m.ComponentView("n_agent").Elements {
		g.Component = append(g.Component, e.ID)
	}
	for _, e := range m.Elements {
		g.Kinds[e.ID] = e.Level + "/" + e.Kind
	}
	for _, r := range m.Relationships {
		if len(r.Crosses) > 0 {
			g.Crosses[r.ID] = r.Crosses
		}
	}
	path := filepath.Join("testdata", "views.json")
	if *updateViews {
		b, _ := json.MarshalIndent(g, "", "  ")
		require.NoError(t, os.MkdirAll("testdata", 0o750))
		require.NoError(t, os.WriteFile(path, append(b, '\n'), 0o600))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	var expected views
	require.NoError(t, json.Unmarshal(want, &expected))
	assert.Equal(t, expected, g)

	assert.Contains(t, g.Context, "n_user")
	assert.Contains(t, g.Context, "n_web")
	assert.NotContains(t, g.Context, "n_sql", "containers are not context elements")
	assert.Contains(t, g.Container, "n_agent")
	assert.Contains(t, g.Container, "n_aigw")
	assert.Contains(t, g.Component, "n_eval")
	assert.NotEmpty(t, m.Systems())
	v, ok := m.Level(LevelContext, "")
	require.True(t, ok)
	assert.NotEmpty(t, v.Boundaries)
	_, ok = m.Level("nope", "")
	assert.False(t, ok)
	el, ok := m.ElementByName("Web App")
	if ok {
		assert.Equal(t, "n_web", el.ID)
	}
	assert.Len(t, m.Identities, 2, "the identity provider node and the auth kinds summary")
	assert.NotEmpty(t, m.Identities[1].AuthKinds)
}

func TestDiffAppliesToTarget(t *testing.T) {
	for name, a := range fixtures(t) {
		to, err := a.Clone()
		require.NoError(t, err)
		// mutate: drop one edge, change a node, add a node + edge + group, set a root attr
		if len(to.Edges) > 0 {
			to.Edges = to.Edges[1:]
		}
		to.Nodes[0].Description = "changed by the diff test"
		to.Nodes[0].Attrs["c4_kind"] = KindSoftwareSystem
		to.Nodes = append(to.Nodes, model.Node{ID: "n_diff_new", Type: "datastore", Name: "New store", Layer: "data", Attrs: model.Attrs{"c4_parent": to.Nodes[0].ID}})
		to.Edges = append(to.Edges, model.Edge{ID: "e_diff_new", From: to.Nodes[0].ID, To: "n_diff_new", Kind: "reads", Auth: "managed_identity", Encryption: "tls", Attrs: model.Attrs{}})
		to.Groups = append(to.Groups, model.Group{ID: "g_diff_new", Kind: "trust_boundary", Name: "New boundary", NodeIDs: []string{"n_diff_new"}, Attrs: model.Attrs{}})
		to.Attrs["decisions"] = []any{map[string]any{"id": "dec_1", "title": "Use managed identity", "status": "proposed"}}
		require.NoError(t, model.Validate(to), name)

		ops, err := Diff(a, to)
		require.NoError(t, err, name)
		require.NotEmpty(t, ops)
		got, err := model.Apply(a, ops, false)
		require.NoError(t, err, "%s: %v", name, ops)
		wantC, _ := model.Canonical(to)
		gotC, _ := model.Canonical(got)
		assert.Equal(t, string(wantC), string(gotC), name)

		none, err := Diff(a, a)
		require.NoError(t, err)
		assert.Empty(t, none, name)
	}
}

func TestOpsHelpersApply(t *testing.T) {
	a := fixtures(t)["rag-chatbot.json"]
	g := a.Groups[0]
	d := Decision{ID: "dec_mi", Title: "Prefer managed identity", Status: "proposed", Citations: []Citation{{Kind: "clause", ID: "MCSB:v1:IM-3"}, {Kind: "document", URL: "https://learn.microsoft.com/x", FetchedAt: "2026-09-11T00:00:00Z", Freshness: "fresh"}}}
	ops := make([]model.PatchOp, 0, 12)
	ops = append(ops,
		AddElement(model.Node{ID: "n_ops_new", Type: "tool", Name: "Ticket tool", Layer: "ai", Attrs: model.Attrs{}}),
		SetProperty("n_ops_new", "c4_kind", KindTool),
		SetParent("n_ops_new", "n_agent"),
		Annotate("n_ops_new", "creates tickets"),
		Move(&model.Node{ID: "n_ops_new"}, "", 10, 20),
		Move(&model.Node{ID: "n_ops_new"}, "l2", 30, 40),
		AddRelationship(model.Edge{ID: "e_ops_new", From: "n_agent", To: "n_ops_new", Kind: "calls", Auth: "obo", Encryption: "tls", Attrs: model.Attrs{}}),
		GroupIntoBoundary(g, "n_ops_new"),
	)
	ops = append(ops, AddDecision(a, d)...)
	got, err := model.Apply(a, ops, false)
	require.NoError(t, err)
	require.NoError(t, model.Validate(got))
	n := got.Node("n_ops_new")
	require.NotNil(t, n)
	assert.Equal(t, KindTool, n.Attrs.String("c4_kind", ""))
	assert.Equal(t, "n_agent", n.Attrs.String("c4_parent", ""))
	assert.Equal(t, "creates tickets", n.Description)
	assert.Equal(t, 30.0, n.Positions["l2"].X)
	assert.Contains(t, got.Group(g.ID).NodeIDs, "n_ops_new")
	m := Project(got)
	require.Len(t, m.Decisions, 1)
	assert.Equal(t, "Prefer managed identity", m.Decisions[0].Title)
	assert.Len(t, m.Decisions[0].Citations, 2)
	comp := m.ComponentView("n_agent")
	ids := make([]string, 0, len(comp.Elements))
	for _, e := range comp.Elements {
		ids = append(ids, e.ID)
	}
	assert.Contains(t, ids, "n_ops_new")
	// A second decision appends to the existing list.
	more, err := model.Apply(got, AddDecision(got, Decision{ID: "dec_2", Title: "Second", Status: "proposed"}), false)
	require.NoError(t, err)
	assert.Len(t, Project(more).Decisions, 2)
	// Removing a node still referenced by an edge or a boundary is refused by the invariants; the
	// assistant must remove the relationship and the membership first.
	_, err = model.Apply(got, []model.PatchOp{RemoveElement("n_ops_new")}, false)
	assert.Error(t, err)
	_, err = model.Apply(got, []model.PatchOp{RemoveRelationship("e_ops_new"), RemoveElement("n_ops_new")}, false)
	assert.Error(t, err)
	_, err = model.Apply(got, []model.PatchOp{RemoveRelationship("e_ops_new"), GroupIntoBoundary(model.Group{ID: g.ID, NodeIDs: g.NodeIDs}), RemoveElement("n_ops_new")}, false)
	assert.NoError(t, err)
}
