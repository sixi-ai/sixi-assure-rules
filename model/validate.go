package model

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/sixi-ai/sixi-assure-rules/model/migrate"
	modelschema "github.com/sixi-ai/sixi-assure-rules/schema"
	"github.com/sixi-ai/sixi-assure-rules/secretguard"
)

// ValidationError aggregates schema and invariant violations. Messages are safe to show to users
// (they contain JSON pointers and enum names, never free text from the model).
type ValidationError struct {
	Problems []Problem
}

// Problem is one violation.
type Problem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 0 {
		return "invalid model"
	}
	parts := make([]string, 0, len(e.Problems))
	for i, p := range e.Problems {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("… and %d more", len(e.Problems)-5))
			break
		}
		parts = append(parts, p.Path+": "+p.Message)
	}
	return "invalid model: " + strings.Join(parts, "; ")
}

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

func compiled() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(modelschema.ModelSchema))
		if err != nil {
			schemaErr = fmt.Errorf("parse model schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		if err := c.AddResource("model.schema.json", doc); err != nil {
			schemaErr = fmt.Errorf("add model schema: %w", err)
			return
		}
		schema, schemaErr = c.Compile("model.schema.json")
	})
	return schema, schemaErr
}

// ValidateJSON validates raw JSON against the schema and the invariants and returns the decoded
// architecture. It is the single entry point for untrusted model input (API, import, patches,
// A2A and MCP submissions, templates, the demo seed): the document is upgraded to the current
// schema version first (ADR-040 §1), so what is returned is always at CurrentSchemaVersion.
func ValidateJSON(raw []byte) (*Architecture, error) {
	s, err := compiled()
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, &ValidationError{Problems: []Problem{{Path: "/", Message: "malformed JSON"}}}
	}
	// The secret guard runs before anything else touches the document (ADR-041 §2): every string
	// leaf, every object key, including x_* extension values and patch operands after apply. This
	// is what makes every model write path — create, patch, import confirmation, rule fix, agent
	// and MCP proposals — covered by construction rather than per handler. The returned error
	// names the JSON pointer and the detector and never the value.
	if err := secretguard.CheckDocument(context.Background(), secretguard.SourceModel, doc); err != nil {
		return nil, err
	}
	if err := checkProvenanceKeys(context.Background(), doc); err != nil {
		return nil, err
	}
	// Upgrade on read (ADR-040 §1): an older document (no schema_version is 0.9) is migrated before
	// the schema, the invariants or the rules see it; a current one passes through untouched. A
	// version this build cannot read is refused, never guessed at.
	upgraded, from, _, err := migrate.Upgrade(raw)
	if err != nil {
		path := "/" + migrate.Field
		if errors.Is(err, migrate.ErrNotObject) {
			path = "/"
		}
		return nil, &ValidationError{Problems: []Problem{{Path: path, Message: err.Error()}}}
	}
	rewritten := from != CurrentSchemaVersion
	if rewritten {
		raw = upgraded
	} else {
		// Tolerant reading (ADR-040 §4, docs/02 §Versions): for two MINOR versions a document at
		// the current version may still carry the 1.0 shapes 1.1 replaced — a free-text protocol, a
		// single authn value — as importers, patterns and agent proposals wrote them. They are
		// mapped (migrate.Normalize) before the schema sees the document, so rules never do.
		if raw, rewritten, err = migrate.NormalizeJSON(raw); err != nil {
			return nil, fmt.Errorf("normalise model: %w", err)
		}
	}
	if rewritten {
		if doc, err = jsonschema.UnmarshalJSON(bytes.NewReader(raw)); err != nil {
			return nil, fmt.Errorf("re-read upgraded model: %w", err)
		}
		// A migration may move a value under another key; the guard sees what will be stored.
		if err := secretguard.CheckDocument(context.Background(), secretguard.SourceModel, doc); err != nil {
			return nil, err
		}
	}
	if err := s.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return nil, &ValidationError{Problems: flatten(ve)}
		}
		return nil, err
	}
	var a Architecture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, &ValidationError{Problems: []Problem{{Path: "/", Message: "cannot decode: " + err.Error()}}}
	}
	normalize(&a)
	if err := Invariants(&a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Validate normalises nil collections, marshals the architecture and runs ValidateJSON. A Go value
// is at the current schema version by construction (normalize writes it when a builder left it
// empty); one that names another version was decoded without the upgrade and is refused, so it can
// never be saved under a version its content does not follow.
func Validate(a *Architecture) error {
	normalize(a)
	if a.SchemaVersion != CurrentSchemaVersion {
		return &ValidationError{Problems: []Problem{{Path: "/" + migrate.Field, Message: "a decoded model is at schema version " +
			CurrentSchemaVersion + "; upgrade the document (model/migrate) before decoding it"}}}
	}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = ValidateJSON(b)
	return err
}

var printer = message.NewPrinter(language.English)

func flatten(ve *jsonschema.ValidationError) []Problem {
	var out []Problem
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			// RFC 6901: a token that holds "/" or "~" (a provenance key, ADR-086) is escaped, so the path is a pointer.
			toks := make([]string, len(e.InstanceLocation))
			for i, tok := range e.InstanceLocation {
				toks[i] = EscapePointerToken(tok)
			}
			out = append(out, Problem{Path: "/" + strings.Join(toks, "/"), Message: e.ErrorKind.LocalizedString(printer)})
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func normalize(a *Architecture) {
	if a.SchemaVersion == "" {
		a.SchemaVersion = CurrentSchemaVersion
	}
	normalizeLegacyShapes(a)
	if a.Attrs == nil {
		a.Attrs = Attrs{}
	}
	if a.Groups == nil {
		a.Groups = []Group{}
	}
	if a.Nodes == nil {
		a.Nodes = []Node{}
	}
	if a.Edges == nil {
		a.Edges = []Edge{}
	}
	if a.Findings == nil {
		a.Findings = []Finding{}
	}
	if a.Evidence == nil {
		a.Evidence = []EvidenceRef{}
	}
	for i := range a.Nodes {
		if a.Nodes[i].Source == "" {
			a.Nodes[i].Source = SourceDesign
		}
		if a.Nodes[i].Attrs == nil {
			a.Nodes[i].Attrs = Attrs{}
		}
	}
	for i := range a.Edges {
		if a.Edges[i].Attrs == nil {
			a.Edges[i].Attrs = Attrs{}
		}
	}
	for i := range a.Groups {
		if a.Groups[i].NodeIDs == nil {
			a.Groups[i].NodeIDs = []string{}
		}
	}
}

// normalizeLegacyShapes is the tolerant reading of migrate.Normalize for a Go value (an importer
// or a pattern that builds an Architecture and calls Validate): a free-text protocol is mapped to
// the enum with an x_migrated_from note where the spelling carried information, and a single
// string authn becomes a one-item list, and a narrowed attribute's 1.0 value is rewritten
// (migrate.NormalizeNodeAttrs). Validate checks the value it was given, so the mapping
// happens on that value, not only on the copy the schema sees.
func normalizeLegacyShapes(a *Architecture) {
	for i := range a.Edges {
		if !migrate.ValidProtocol(a.Edges[i].Protocol) {
			a.Edges[i].SetProtocolText(a.Edges[i].Protocol)
		}
	}
	for i := range a.Nodes {
		// The attributes 1.1 narrowed per node type (log_sink.purpose, agent.egress_policy,
		// mcp_server.exposure): a 1.0 value is rewritten with its x_migrated_from note, never refused.
		before := make([]string, 0, len(a.Nodes[i].Attrs))
		for k := range a.Nodes[i].Attrs {
			before = append(before, k)
		}
		migrate.NormalizeNodeAttrs(a.Nodes[i].Type, a.Nodes[i].Attrs)
		if s, ok := a.Nodes[i].Attrs["authn"].(string); ok {
			if s == "" {
				delete(a.Nodes[i].Attrs, "authn")
			} else {
				a.Nodes[i].Attrs["authn"] = []any{s}
			}
		}
		// A removed attribute takes its provenance entries with it (ADR-086), as migrate.Normalize does
		// on the document form, so the sidecar keeps resolving.
		for _, k := range migrate.RemovedKeys(before, a.Nodes[i].Attrs) {
			a.Provenance.dropUnder(ElementPointer("nodes", a.Nodes[i].ID) + "/attrs/" + EscapePointerToken(k))
		}
	}
}

// dropUnder removes the entry of key and every entry under it.
func (p Provenance) dropUnder(key string) {
	for k := range p {
		if k == key || strings.HasPrefix(k, key+"/") {
			delete(p, k)
		}
	}
}

// SetProtocolText sets e.Protocol from a protocol as free text names it (a 1.0 model, an importer
// reading a technology or a label): the 1.1 enum value (migrate.CanonicalProtocol), with
// "protocol=<text>" in x_migrated_from when the spelling carried more than case and separators, so
// ProtocolText (and the rules' e.protocol_text) still reads what was written. Blank text clears it.
func (e *Edge) SetProtocolText(text string) {
	v, noted := migrate.CanonicalProtocol(text)
	e.Protocol = v
	if noted && strings.TrimSpace(text) != "" {
		if e.Attrs == nil {
			e.Attrs = Attrs{}
		}
		addMigratedFrom(e.Attrs, "protocol="+text)
	}
}

// MigratedFromAttr is the extension attribute a migration or the tolerant reading leaves on an
// element it rewrote (ADR-040 §4): "<field>=<old value>" entries joined by "; ".
const MigratedFromAttr = migrate.MigratedFrom

// addMigratedFrom appends one "<field>=<old value>" entry to attrs.x_migrated_from (migrate.Rewrite's
// format), once, within the schema's 2 000-character bound.
func addMigratedFrom(attrs Attrs, entry string) {
	var entries []string
	if prev, ok := attrs[migrate.MigratedFrom].(string); ok && prev != "" {
		entries = strings.Split(prev, "; ")
	}
	if slices.Contains(entries, entry) {
		return
	}
	if joined := strings.Join(append(entries, entry), "; "); utf8.RuneCountInString(joined) <= 2000 {
		attrs[migrate.MigratedFrom] = joined
	}
}

// MigratedFromValue returns the old value a migration recorded for field in attrs.x_migrated_from
// ("<field>=<old value>" entries joined by "; "), and whether there is one. The first entry for
// the field wins.
func MigratedFromValue(attrs Attrs, field string) (string, bool) {
	notes, _ := attrs[migrate.MigratedFrom].(string)
	for _, entry := range strings.Split(notes, "; ") {
		if v, ok := strings.CutPrefix(entry, field+"="); ok {
			return v, true
		}
	}
	return "", false
}

// ProtocolText is the protocol as the model's author wrote it: the 1.0 free text a migration or the
// tolerant reading mapped to the enum (kept in x_migrated_from), else the enum value. The rules
// projection exposes it as e.protocol_text, so a rule that matches protocol names (DRF-004 against
// the knowledge base's deprecated list: ftp, smb1, tls1.0) still sees what "other" replaced.
func (e Edge) ProtocolText() string {
	if old, ok := MigratedFromValue(e.Attrs, "protocol"); ok && strings.TrimSpace(old) != "" {
		return old
	}
	return e.Protocol
}

// Invariants enforces docs/02 §4 on an already schema-valid architecture.
func Invariants(a *Architecture) error {
	var probs []Problem
	add := func(path, msg string) { probs = append(probs, Problem{Path: path, Message: msg}) }

	ids := map[string]string{}
	claim := func(id, what, path string) {
		if prev, dup := ids[id]; dup {
			add(path, fmt.Sprintf("duplicate id %q (already used by %s)", id, prev))
			return
		}
		ids[id] = what
	}
	nodeIdx := make(map[string]int, len(a.Nodes))
	for i, n := range a.Nodes {
		claim(n.ID, "node", fmt.Sprintf("/nodes/%d/id", i))
		nodeIdx[n.ID] = i
		if IsNote(n.Type) {
			noteInvariants(n, fmt.Sprintf("/nodes/%d/attrs", i), add)
		}
		for k, v := range n.Attrs {
			if k == "region" {
				if s, _ := v.(string); !ValidRegion(s) {
					add(fmt.Sprintf("/nodes/%d/attrs/region", i), fmt.Sprintf("unknown region %q", s))
				}
			}
		}
		attrValueInvariants(n, fmt.Sprintf("/nodes/%d/attrs", i), add)
	}
	// Identities (ADR-047 §1): ids share the namespace; a node's identity_id names one, and an
	// identity's registry names an agent_registry node.
	identityIDs := make(map[string]bool, len(a.Identities))
	for i, id := range a.Identities {
		claim(id.ID, "identity", fmt.Sprintf("/identities/%d/id", i))
		identityIDs[id.ID] = true
	}
	for i, id := range a.Identities {
		if id.Registry == "" {
			continue
		}
		ni, ok := nodeIdx[id.Registry]
		switch {
		case !ok:
			add(fmt.Sprintf("/identities/%d/registry", i), fmt.Sprintf("unknown node %q", id.Registry))
		case a.Nodes[ni].Type != "agent_registry":
			add(fmt.Sprintf("/identities/%d/registry", i), fmt.Sprintf("node %q is not an agent_registry", id.Registry))
		}
	}
	for i, n := range a.Nodes {
		if ref, ok := n.Attrs["identity_id"].(string); ok && ref != "" && !identityIDs[ref] {
			add(fmt.Sprintf("/nodes/%d/attrs/identity_id", i), fmt.Sprintf("unknown identity %q", ref))
		}
		hostedOnInvariant(a, n, nodeIdx, fmt.Sprintf("/nodes/%d/attrs/hosted_on", i), add)
	}
	for i, e := range a.Edges {
		claim(e.ID, "edge", fmt.Sprintf("/edges/%d/id", i))
		fi, okF := nodeIdx[e.From]
		ti, okT := nodeIdx[e.To]
		if !okF {
			add(fmt.Sprintf("/edges/%d/from", i), fmt.Sprintf("unknown node %q", e.From))
		}
		if !okT {
			add(fmt.Sprintf("/edges/%d/to", i), fmt.Sprintf("unknown node %q", e.To))
		}
		if okF && IsNote(a.Nodes[fi].Type) {
			add(fmt.Sprintf("/edges/%d/from", i), "a note has no flows")
		}
		if okT && IsNote(a.Nodes[ti].Type) {
			add(fmt.Sprintf("/edges/%d/to", i), "a note has no flows")
		}
		scopedAttrInvariants(e.Attrs, e.Kind, "edge", edgeAttrKinds(), fmt.Sprintf("/edges/%d/attrs", i), add)
		if okF && okT && e.From == e.To {
			n := a.Nodes[fi]
			if n.Type != "agent" || e.Kind != "delegates" || e.Auth != "obo" {
				add(fmt.Sprintf("/edges/%d", i), "self-loop not allowed (only agent→agent delegates with auth=obo)")
			}
		}
	}
	zoneOf := map[string]string{}
	for i, g := range a.Groups {
		claim(g.ID, "group", fmt.Sprintf("/groups/%d/id", i))
		for j, nid := range g.NodeIDs {
			if _, ok := nodeIdx[nid]; !ok {
				add(fmt.Sprintf("/groups/%d/node_ids/%d", i, j), fmt.Sprintf("unknown node %q", nid))
				continue
			}
			if g.Kind == "zone" {
				if prev, ok := zoneOf[nid]; ok && prev != g.ID {
					add(fmt.Sprintf("/groups/%d/node_ids/%d", i, j), fmt.Sprintf("node %q already belongs to zone %q", nid, prev))
				}
				zoneOf[nid] = g.ID
			}
		}
	}
	for i, g := range a.Groups {
		scopedAttrInvariants(g.Attrs, g.Kind, "group", groupAttrKinds(), fmt.Sprintf("/groups/%d/attrs", i), add)
		if g.Parent != "" {
			if a.Group(g.Parent) == nil {
				add(fmt.Sprintf("/groups/%d/parent", i), fmt.Sprintf("unknown group %q", g.Parent))
			} else if g.Parent == g.ID {
				add(fmt.Sprintf("/groups/%d/parent", i), "group cannot be its own parent")
			}
		}
	}
	for i, n := range a.Nodes {
		if n.Zone != "" {
			g := a.Group(n.Zone)
			switch {
			case g == nil:
				add(fmt.Sprintf("/nodes/%d/zone", i), fmt.Sprintf("unknown group %q", n.Zone))
			case g.Kind != "zone":
				add(fmt.Sprintf("/nodes/%d/zone", i), fmt.Sprintf("group %q is not a zone", n.Zone))
			case zoneOf[n.ID] != n.Zone:
				add(fmt.Sprintf("/nodes/%d/zone", i), fmt.Sprintf("zone %q does not list this node", n.Zone))
			}
		}
	}
	for i, f := range a.Findings {
		claim(f.ID, "finding", fmt.Sprintf("/findings/%d/id", i))
		for j, id := range f.IDs {
			if _, ok := ids[id]; !ok && id != a.ID {
				add(fmt.Sprintf("/findings/%d/ids/%d", i, j), fmt.Sprintf("unknown element %q", id))
			}
		}
	}
	// ADR-086 §2: every provenance key names a model element, member or attribute.
	probs = append(probs, provenanceProblems(a)...)
	if len(probs) > 0 {
		return &ValidationError{Problems: probs}
	}
	return nil
}

// noteInvariants: a note carries non-empty text of at most NoteTextMax runes and, when set, a known
// tone (ADR-081). The schema bounds the length and the enum; this also covers callers that build
// an Architecture in Go and check it with Invariants alone.
func noteInvariants(n Node, base string, add func(path, msg string)) {
	text, ok := n.Attrs["text"].(string)
	switch {
	case !ok || strings.TrimSpace(text) == "":
		add(base+"/text", "a note needs text")
	case utf8.RuneCountInString(text) > NoteTextMax:
		add(base+"/text", fmt.Sprintf("a note's text is at most %d characters", NoteTextMax))
	}
	if v, set := n.Attrs["tone"]; set {
		t, _ := v.(string)
		if !slices.Contains(NoteTones, t) {
			add(base+"/tone", "unknown tone (neutral, decision, question or warning)")
		}
	}
}

// attrValueInvariants enforces x-attr-values (schema 1.1): an attribute the flat nodeAttrs set shares
// between node types (gateway.kind and agent_registry.kind, the boolean egress_policy of an edge
// device and the enum of an agent) carries only the values its node's type accepts. The message
// names the accepted values, never the value given.
func attrValueInvariants(n Node, base string, add func(path, msg string)) {
	values := AttrValues(n.Type)
	if len(values) == 0 {
		return
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, set := n.Attrs[k]
		if !set || slices.Contains(values[k], v) {
			continue
		}
		names := make([]string, 0, len(values[k]))
		for _, x := range values[k] {
			if s := fmt.Sprint(x); s != "" {
				names = append(names, s)
			}
		}
		add(base+"/"+k, fmt.Sprintf("a %s accepts %s", n.Type, strings.Join(names, ", ")))
	}
}

// hostedOnTypes are the node types whose hosted_on names a node of the model (schema 1.2, ADR-093
// FS-14, SD-2): an agent names the app or runtime it runs in and an agent_memory the store it lives
// in, which is what lets the rules treat agents in one process as one principal. Other types keep
// the 1.1 reading (a declaration the rules compare with ids, TLS-002). A stored model is never
// refused for it: the 1.1 → 1.2 step removes a 1.1 free-text value that names no node, the node
// itself or a note (with x_migrated_from), so the invariant holds on every value written at 1.2.
var hostedOnTypes = migrate.HostedOnTypes()

// hostedOnInvariant: on an agent or agent_memory a declared hosted_on names another node of the
// model that is not a note. The message never repeats the value (hosted_on is free text up to 64
// characters, not an id pattern).
func hostedOnInvariant(a *Architecture, n Node, nodeIdx map[string]int, path string, add func(path, msg string)) {
	if !hostedOnTypes[n.Type] {
		return
	}
	ref, _ := n.Attrs["hosted_on"].(string)
	if ref == "" {
		return
	}
	ti, ok := nodeIdx[ref]
	switch {
	case !ok:
		add(path, "names no node of this model")
	case ref == n.ID:
		add(path, "a component is not hosted on itself")
	case IsNote(a.Nodes[ti].Type):
		add(path, "a note hosts nothing")
	}
}

// scopedAttrInvariants enforces x-edge-kinds and x-group-kinds (schema 1.2): an attribute annotated
// with the kinds it belongs to is set only on an element of one of them (the delegation attributes
// on a delegates edge, the flow-group attributes on a flows edge, the workflow bounds on a workflow
// group). An empty or null value counts as not set. The message names the kinds, never the value.
func scopedAttrInvariants(attrs Attrs, kind, element string, scoped map[string][]string, base string, add func(path, msg string)) {
	if len(attrs) == 0 || len(scoped) == 0 {
		return
	}
	keys := make([]string, 0, len(scoped))
	for k := range scoped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, set := attrs[k]
		if !set || v == nil || v == "" || slices.Contains(scoped[k], kind) {
			continue
		}
		add(base+"/"+k, fmt.Sprintf("set only on a %s %s", strings.Join(scoped[k], " or "), element))
	}
}

// EdgeAttrKinds returns the edge attributes the schema scopes to edge kinds (x-edge-kinds, schema
// 1.2): attribute → the kinds it may be set on. Importers and the panel use it to place a fact.
func EdgeAttrKinds() map[string][]string { return cloneScoped(edgeAttrKinds()) }

// GroupAttrKinds is EdgeAttrKinds for group attributes (x-group-kinds).
func GroupAttrKinds() map[string][]string { return cloneScoped(groupAttrKinds()) }

func cloneScoped(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = slices.Clone(v)
	}
	return out
}

var (
	scopedOnce sync.Once
	edgeScoped map[string][]string
	groupScope map[string][]string
)

func loadScopedAttrs() {
	scopedOnce.Do(func() {
		type prop map[string]struct {
			EdgeKinds  []string `json:"x-edge-kinds"`
			GroupKinds []string `json:"x-group-kinds"`
		}
		var doc struct {
			Defs struct {
				Edge struct {
					Properties struct {
						Attrs struct {
							Properties prop `json:"properties"`
						} `json:"attrs"`
					} `json:"properties"`
				} `json:"edge"`
				Group struct {
					Properties struct {
						Attrs struct {
							Properties prop `json:"properties"`
						} `json:"attrs"`
					} `json:"properties"`
				} `json:"group"`
			} `json:"$defs"`
		}
		edgeScoped, groupScope = map[string][]string{}, map[string][]string{}
		if err := json.Unmarshal(modelschema.ModelSchema, &doc); err != nil {
			return
		}
		for k, p := range doc.Defs.Edge.Properties.Attrs.Properties {
			if len(p.EdgeKinds) > 0 {
				edgeScoped[k] = p.EdgeKinds
			}
		}
		for k, p := range doc.Defs.Group.Properties.Attrs.Properties {
			if len(p.GroupKinds) > 0 {
				groupScope[k] = p.GroupKinds
			}
		}
	})
}

func edgeAttrKinds() map[string][]string {
	loadScopedAttrs()
	return edgeScoped
}

func groupAttrKinds() map[string][]string {
	loadScopedAttrs()
	return groupScope
}

// RequiredAttrs returns the inventory-required attribute names for a node type (schema x-required-attrs).
func RequiredAttrs(nodeType string) []string {
	return attrCatalog()[catalogKey(nodeType)].required
}

// RequiredAttrsOf returns the inventory-required attribute names for one node: RequiredAttrs without the attributes
// another declared attribute replaces (schema x-required-unless, schema 1.1). An agent that declares identity_id no
// longer needs the deprecated identity string.
func RequiredAttrsOf(n *Node) []string {
	if n == nil {
		return nil
	}
	p := attrCatalog()[catalogKey(n.Type)]
	if len(p.unless) == 0 {
		return p.required
	}
	out := make([]string, 0, len(p.required))
	for _, key := range p.required {
		replaced := false
		for _, alt := range p.unless[key] {
			if v, ok := n.Attrs[alt]; ok && v != nil && v != "" {
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, key)
		}
	}
	return out
}

// AttrValues returns the per-type values of the shared attributes a node type narrows (schema
// x-attr-values): attribute name → accepted values (strings, or booleans for a boolean attribute).
func AttrValues(nodeType string) map[string][]any {
	return attrCatalog()[catalogKey(nodeType)].values
}

type attrProfile struct {
	required []string
	values   map[string][]any
	// unless is x-required-unless: a required attribute → the attributes that replace it when declared.
	unless map[string][]string
}

var (
	catalogOnce sync.Once
	catalog     map[string]attrProfile
)

func attrCatalog() map[string]attrProfile {
	catalogOnce.Do(func() {
		var doc struct {
			Defs struct {
				Attrs map[string]struct {
					Required []string            `json:"x-required-attrs"`
					Values   map[string][]any    `json:"x-attr-values"`
					Unless   map[string][]string `json:"x-required-unless"`
				} `json:"attrs"`
			} `json:"$defs"`
		}
		catalog = map[string]attrProfile{}
		if err := json.Unmarshal(modelschema.ModelSchema, &doc); err == nil {
			for k, v := range doc.Defs.Attrs {
				catalog[k] = attrProfile{required: v.Required, values: v.Values, unless: v.Unless}
			}
		}
	})
	return catalog
}

func catalogKey(nodeType string) string {
	switch nodeType {
	case "edge_device", "edge_gateway":
		return "edge"
	case "api":
		return "app"
	}
	return nodeType
}
