// Package c4 is the C4 projection of the typed graph model (docs/02): System Context, Container
// and Component views derived from nodes, edges and groups — never a second model (CLAUDE.md
// §1.1, ADR-032). Elements keep the node they were projected from, so Unproject is the identity
// and the round-trip tests hold for every fixture. Suggestions travel as RFC 6902 patch ops
// (Ops helpers below); nothing here writes to an architecture.
package c4

import (
	"sort"
	"strings"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Levels of the C4 model.
const (
	LevelContext   = "context"
	LevelContainer = "container"
	LevelComponent = "component"
	LevelCode      = "code"
)

// Levels lists the C4 levels in order.
var Levels = []string{LevelContext, LevelContainer, LevelComponent, LevelCode}

// Kinds of C4 elements (model.schema.json c4Kind).
const (
	KindPerson         = "Person"
	KindSoftwareSystem = "SoftwareSystem"
	KindExternalSystem = "ExternalSystem"
	KindContainer      = "Container"
	KindComponent      = "Component"
	KindDataStore      = "DataStore"
	KindQueue          = "Queue"
	KindAgent          = "Agent"
	KindTool           = "Tool"
	KindMCPServer      = "MCPServer"
	KindIdentity       = "Identity"
	KindGateway        = "Gateway"
)

// Element is one C4 element: the derived (or declared) level and kind plus the node itself.
type Element struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Level           string      `json:"level"`
	Kind            string      `json:"kind"`
	Type            string      `json:"type"`
	Provider        string      `json:"provider,omitempty"`
	ProviderService string      `json:"provider_service,omitempty"`
	Parent          string      `json:"parent,omitempty"`
	Boundaries      []string    `json:"boundaries,omitempty"`
	Description     string      `json:"description,omitempty"`
	Declared        bool        `json:"declared"` // level/kind set on the node rather than derived
	Node            *model.Node `json:"-"`
}

// Relationship is an edge with the C4 reading of its technology and authentication.
type Relationship struct {
	ID         string      `json:"id"`
	Src        string      `json:"src"`
	Dst        string      `json:"dst"`
	Kind       string      `json:"kind"`
	Technology string      `json:"technology,omitempty"`
	Auth       string      `json:"auth,omitempty"`
	Encryption string      `json:"encryption,omitempty"`
	DataClass  string      `json:"data_class,omitempty"`
	Label      string      `json:"label,omitempty"`
	Crosses    []string    `json:"crosses,omitempty"` // boundary ids the relationship leaves or enters
	Edge       *model.Edge `json:"-"`
}

// Boundary is a group read as a C4 boundary (zone, trust boundary, region, subscription, site).
type Boundary struct {
	ID      string       `json:"id"`
	Kind    string       `json:"kind"`
	Name    string       `json:"name"`
	Parent  string       `json:"parent,omitempty"`
	Members []string     `json:"members"`
	Group   *model.Group `json:"-"`
}

// Identity is what authenticates in the model: identity providers and every distinct auth kind
// the relationships use.
type Identity struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"` // node type (identity_provider) or "auth"
	AuthKinds []string `json:"auth_kinds,omitempty"`
}

// Decision mirrors model.schema.json `decision` (kept on architecture attrs).
type Decision struct {
	ID           string     `json:"id"`
	Title        string     `json:"title"`
	Status       string     `json:"status"`
	Context      string     `json:"context,omitempty"`
	Decision     string     `json:"decision,omitempty"`
	Consequences string     `json:"consequences,omitempty"`
	Citations    []Citation `json:"citations,omitempty"`
	ProposedBy   string     `json:"proposed_by,omitempty"`
	CreatedAt    string     `json:"created_at,omitempty"`
	DecidedAt    string     `json:"decided_at,omitempty"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	SupersededBy string     `json:"superseded_by,omitempty"`
}

// Citation mirrors model.schema.json `citation`.
type Citation struct {
	Kind      string `json:"kind"`
	ID        string `json:"id,omitempty"`
	URL       string `json:"url,omitempty"`
	Title     string `json:"title,omitempty"`
	FetchedAt string `json:"fetched_at,omitempty"`
	Freshness string `json:"freshness,omitempty"`
}

// Model is the projection of one architecture.
type Model struct {
	ArchID        string          `json:"arch_id"`
	Name          string          `json:"name"`
	Version       int             `json:"version"`
	Elements      []Element       `json:"elements"`
	Relationships []Relationship  `json:"relationships"`
	Boundaries    []Boundary      `json:"boundaries"`
	Identities    []Identity      `json:"identities"`
	Decisions     []Decision      `json:"decisions"`
	Findings      []model.Finding `json:"findings"`

	arch *model.Architecture
}

// Project derives the C4 model. It never mutates the architecture.
func Project(a *model.Architecture) *Model {
	m := &Model{ArchID: a.ID, Name: a.Name, Version: a.Version, Elements: []Element{}, Relationships: []Relationship{},
		Boundaries: []Boundary{}, Identities: []Identity{}, Decisions: []Decision{}, Findings: append([]model.Finding{}, a.Findings...), arch: a}
	membership := map[string][]string{} // node id → boundary ids (direct)
	for i := range a.Groups {
		g := &a.Groups[i]
		m.Boundaries = append(m.Boundaries, Boundary{ID: g.ID, Kind: g.Kind, Name: g.Name, Parent: g.Parent, Members: append([]string{}, g.NodeIDs...), Group: g})
		for _, nid := range g.NodeIDs {
			membership[nid] = append(membership[nid], g.ID)
		}
	}
	authKinds := map[string]bool{}
	for i := range a.Nodes {
		n := &a.Nodes[i]
		el := Element{ID: n.ID, Name: n.Name, Type: n.Type, Description: n.Description, Node: n}
		el.Level, el.Kind, el.Declared = Classify(n)
		el.Provider = n.Attrs.String("provider", "")
		el.ProviderService = n.Attrs.String("provider_service", "")
		el.Parent = n.Attrs.String("c4_parent", "")
		el.Boundaries = sortedCopy(membership[n.ID])
		m.Elements = append(m.Elements, el)
		if n.Type == "identity_provider" {
			m.Identities = append(m.Identities, Identity{ID: n.ID, Name: n.Name, Type: n.Type})
		}
	}
	for i := range a.Edges {
		e := &a.Edges[i]
		r := Relationship{ID: e.ID, Src: e.From, Dst: e.To, Kind: e.Kind, Technology: e.Protocol, Auth: e.Auth, Encryption: e.Encryption, DataClass: e.DataClass, Label: e.Label, Edge: e}
		r.Crosses = crosses(membership[e.From], membership[e.To])
		m.Relationships = append(m.Relationships, r)
		if e.Auth != "" && e.Auth != "none" && e.Auth != "unknown" {
			authKinds[e.Auth] = true
		}
	}
	if len(authKinds) > 0 {
		kinds := make([]string, 0, len(authKinds))
		for k := range authKinds {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		m.Identities = append(m.Identities, Identity{ID: "auth", Name: "relationship authentication", Type: "auth", AuthKinds: kinds})
	}
	if raw, ok := a.Attrs["decisions"].([]any); ok {
		for _, d := range raw {
			if dm, ok := d.(map[string]any); ok {
				m.Decisions = append(m.Decisions, decisionFrom(dm))
			}
		}
	}
	return m
}

// Unproject returns the architecture the model was projected from. The projection keeps every
// node, edge and group, so this is the identity — the round-trip tests assert it on every fixture.
func (m *Model) Unproject() *model.Architecture { return m.arch }

// Classify returns the C4 level and kind of a node: declared attrs win, otherwise the node type
// decides (users and external parties are context-level; everything deployable is a container;
// components are only ever declared).
func Classify(n *model.Node) (level, kind string, declared bool) {
	level = n.Attrs.String("c4_level", "")
	kind = n.Attrs.String("c4_kind", "")
	declared = level != "" || kind != ""
	if kind == "" {
		kind = kindOf(n.Type)
	}
	if level == "" {
		switch kind {
		case KindPerson, KindSoftwareSystem, KindExternalSystem:
			level = LevelContext
		case KindComponent:
			level = LevelComponent
		default:
			level = LevelContainer
		}
	}
	return level, kind, declared
}

func kindOf(nodeType string) string {
	switch nodeType {
	case "user", "human_step":
		return KindPerson
	case "product":
		return KindSoftwareSystem
	case "external_party", "saas":
		return KindExternalSystem
	case "datastore", "vector_index", "log_sink", "secret_store":
		return KindDataStore
	case "queue", "broker":
		return KindQueue
	case "agent":
		return KindAgent
	case "tool":
		return KindTool
	case "mcp_server":
		return KindMCPServer
	case "identity_provider":
		return KindIdentity
	case "gateway", "dmz", "edge_gateway", "data_diode":
		return KindGateway
	default:
		return KindContainer
	}
}

// View is one C4 diagram: the elements shown, the relationships among them and the boundaries
// that contain any of them.
type View struct {
	Level         string         `json:"level"`
	Focus         string         `json:"focus,omitempty"`
	Elements      []Element      `json:"elements"`
	Relationships []Relationship `json:"relationships"`
	Boundaries    []Boundary     `json:"boundaries"`
}

// ContextView: people and software systems (context-level elements). When the architecture has
// no declared systems, every container-level element that talks to a person or external system
// is shown too, so a flat model still reads as a context diagram.
func (m *Model) ContextView() View {
	keep := map[string]bool{}
	for _, e := range m.Elements {
		if e.Level == LevelContext {
			keep[e.ID] = true
		}
	}
	hasSystem := false
	for _, e := range m.Elements {
		if e.Kind == KindSoftwareSystem {
			hasSystem = true
			break
		}
	}
	if !hasSystem {
		for _, r := range m.Relationships {
			if keep[r.Src] != keep[r.Dst] {
				keep[r.Src], keep[r.Dst] = true, true
			}
		}
	}
	return m.view(LevelContext, "", keep)
}

// ContainerView of a system: its direct children (c4_parent == system), the system itself, and
// the elements those children talk to. With focus "" every non-component element is shown.
func (m *Model) ContainerView(focus string) View {
	if focus == "" {
		keep := map[string]bool{}
		for _, e := range m.Elements {
			if e.Level != LevelComponent {
				keep[e.ID] = true
			}
		}
		return m.view(LevelContainer, focus, keep)
	}
	return m.view(LevelContainer, focus, m.childrenAndNeighbours(focus))
}

// ComponentView of a container: its children (c4_parent == container), the container itself, and
// what those children talk to. With focus "" every component-level element is shown.
func (m *Model) ComponentView(focus string) View {
	if focus == "" {
		keep := map[string]bool{}
		for _, e := range m.Elements {
			if e.Level == LevelComponent {
				keep[e.ID] = true
			}
		}
		return m.view(LevelComponent, focus, keep)
	}
	return m.view(LevelComponent, focus, m.childrenAndNeighbours(focus))
}

// childrenAndNeighbours: the focus, its direct children and the other ends of the children's
// relationships (the focus's own relationships stay out — they belong to the level above).
func (m *Model) childrenAndNeighbours(focus string) map[string]bool {
	children := map[string]bool{}
	for _, e := range m.Elements {
		if e.Parent == focus {
			children[e.ID] = true
		}
	}
	keep := map[string]bool{focus: true}
	for id := range children {
		keep[id] = true
	}
	for _, r := range m.Relationships {
		if children[r.Src] {
			keep[r.Dst] = true
		}
		if children[r.Dst] {
			keep[r.Src] = true
		}
	}
	return keep
}

func (m *Model) view(level, focus string, keep map[string]bool) View {
	v := View{Level: level, Focus: focus, Elements: []Element{}, Relationships: []Relationship{}, Boundaries: []Boundary{}}
	for _, e := range m.Elements {
		if keep[e.ID] {
			v.Elements = append(v.Elements, e)
		}
	}
	for _, r := range m.Relationships {
		if keep[r.Src] && keep[r.Dst] {
			v.Relationships = append(v.Relationships, r)
		}
	}
	for _, b := range m.Boundaries {
		for _, mid := range b.Members {
			if keep[mid] {
				v.Boundaries = append(v.Boundaries, b)
				break
			}
		}
	}
	return v
}

// Level returns the view for a level ("context" needs no focus).
func (m *Model) Level(level, focus string) (View, bool) {
	switch level {
	case LevelContext:
		return m.ContextView(), true
	case LevelContainer:
		return m.ContainerView(focus), true
	case LevelComponent:
		return m.ComponentView(focus), true
	}
	return View{}, false
}

// Systems lists the software systems (candidates for a container view focus).
func (m *Model) Systems() []Element {
	var out []Element
	for _, e := range m.Elements {
		if e.Kind == KindSoftwareSystem {
			out = append(out, e)
		}
	}
	return out
}

// Orphans lists elements whose declared parent does not exist (C4 well-formedness).
func (m *Model) Orphans() []string {
	ids := map[string]bool{}
	for _, e := range m.Elements {
		ids[e.ID] = true
	}
	var out []string
	for _, e := range m.Elements {
		if e.Parent != "" && !ids[e.Parent] {
			out = append(out, e.ID)
		}
	}
	return out
}

func crosses(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	var out []string
	for _, x := range b {
		if !set[x] {
			out = append(out, x)
		}
	}
	setB := map[string]bool{}
	for _, x := range b {
		setB[x] = true
	}
	for _, x := range a {
		if !setB[x] {
			out = append(out, x)
		}
	}
	return sortedCopy(out)
}

func sortedCopy(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func decisionFrom(m map[string]any) Decision {
	str := func(k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	d := Decision{ID: str("id"), Title: str("title"), Status: str("status"), Context: str("context"), Decision: str("decision"), Consequences: str("consequences"),
		ProposedBy: str("proposed_by"), CreatedAt: str("created_at"), DecidedAt: str("decided_at"), DecidedBy: str("decided_by"), SupersededBy: str("superseded_by")}
	if cs, ok := m["citations"].([]any); ok {
		for _, c := range cs {
			if cm, ok := c.(map[string]any); ok {
				g := func(k string) string {
					v, _ := cm[k].(string)
					return v
				}
				d.Citations = append(d.Citations, Citation{Kind: g("kind"), ID: g("id"), URL: g("url"), Title: g("title"), FetchedAt: g("fetched_at"), Freshness: g("freshness")})
			}
		}
	}
	return d
}

// ElementByName resolves an element by id or (case-insensitive) name.
func (m *Model) ElementByName(ref string) (Element, bool) {
	for _, e := range m.Elements {
		if e.ID == ref {
			return e, true
		}
	}
	for _, e := range m.Elements {
		if strings.EqualFold(e.Name, ref) {
			return e, true
		}
	}
	return Element{}, false
}
