package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/secretguard"
)

// Provenance sidecar (ADR-086, docs/02 §Provenance, schema 1.1). Every fact is a claim; the sidecar says where
// each one came from. It is a map on the model root, sibling of attrs and never inside any attrs, keyed by
// id-addressed JSON pointers as patches spell them (/nodes/<id>, /nodes/<id>/attrs/<key>, /edges/<id>/auth,
// RFC 6901-escaped). The most specific key wins; a key that resolves to nothing is an invariant error; a removed
// element's keys go with it.
//
// The sidecar is server-owned: a patch to /provenance is refused (patch.go), an accepted import writes `imported`
// entries (RecordImport), and an accepted patch resets every pointer it changed to `declared` with its actor
// (StampPatch). Rules never read it: the CEL projection carries only the precomputed `prov` variable (rules
// package), whose staleness is computed against a pinned clock, never stored.

// Provenance kinds (ADR-086 §3). `stale` is computed, never a kind.
const (
	// ProvenanceDeclared: typed by a person (canvas, diagram import, an accepted patch).
	ProvenanceDeclared = "declared"
	// ProvenanceImported: read from a source file or export by an accepted import.
	ProvenanceImported = "imported"
	// ProvenanceObserved: observed from an operated system. Reserved: no ingestion path while OBSERVED_OVERLAY is off.
	ProvenanceObserved = "observed"
)

// ProvenanceKinds lists the kinds, weakest first (the order the ledger weighs a fact by).
var ProvenanceKinds = []string{ProvenanceDeclared, ProvenanceImported, ProvenanceObserved}

// PreV11Import is the identifier the upgrade mapping gives a `source: declared` node that carries no external_ref:
// it was imported before the sidecar existed, from a source nobody recorded (ADR-086 §6).
const PreV11Import = "pre-1.1 import"

// ProvenanceEntry is one sidecar entry (ADR-086 §3). Actors are ids, never e-mail addresses; identifiers, versions
// and hashes name a source, never its content. The secret guard scans every key and value (validate.go).
type ProvenanceEntry struct {
	Kind string `json:"kind"`
	// Identifier names the source the fact was imported from (a file, an export, a registry), stable across
	// re-imports of the same source; for a declared fact from a diagram import, the diagram.
	Identifier string `json:"identifier,omitempty"`
	// Version or Hash pin the source as read (a hex SHA-256 of the file for a file import).
	Version string `json:"version,omitempty"`
	Hash    string `json:"hash,omitempty"`
	// ImportedBy and ImportedAt are written by the server when a person accepts the import.
	ImportedBy string     `json:"imported_by,omitempty"`
	ImportedAt *time.Time `json:"imported_at,omitempty"`
	// FetchedAt is when the source was produced or read; CadenceDays how often it is expected to be read again
	// (0: no cadence, the fact never goes stale by the clock).
	FetchedAt   *time.Time `json:"fetched_at,omitempty"`
	CadenceDays int        `json:"cadence_days,omitempty"`
	// SignatureVerified is true only when the server verified a signature over the source (no import source signs
	// its files yet). Absent means false.
	SignatureVerified bool `json:"signature_verified,omitempty"`
	// LastSeenImport is the version or hash of the latest import of Identifier that still carried the fact: a later
	// import of the identifier that no longer carries it leaves it behind, which is drift (ADR-086 §7).
	LastSeenImport string `json:"last_seen_import,omitempty"`
	// DeclaredBy and DeclaredAt name the person whose accepted change declared the fact.
	DeclaredBy string     `json:"declared_by,omitempty"`
	DeclaredAt *time.Time `json:"declared_at,omitempty"`
}

// Provenance is the sidecar: JSON pointer → entry.
type Provenance map[string]ProvenanceEntry

// provenanceRoots are the first pointer segments a key may start with: the id-addressed collections and the root
// attrs.
var provenanceRoots = map[string]bool{"nodes": true, "edges": true, "groups": true, "identities": true, "attrs": true}

// layoutFields are element members that place an element on the canvas. They are not facts: changing them never
// makes a fact declared, and a key may not name them.
var layoutFields = map[string]bool{"position": true, "positions": true, "size": true, "icon": true}

// serverOwnedFields are element members the server writes. A node's source is written from the sidecar (SyncSources);
// an element's id is its address.
var serverOwnedFields = map[string]bool{"source": true, "id": true}

// EscapePointerToken escapes one JSON pointer reference token (RFC 6901 §3).
func EscapePointerToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// ElementPointer is the id-addressed pointer of an element of a collection (nodes, edges, groups, identities).
func ElementPointer(collection, id string) string {
	return "/" + collection + "/" + EscapePointerToken(id)
}

// splitPointer splits an RFC 6901 pointer into unescaped tokens; ok is false when p does not start with "/".
func splitPointer(p string) ([]string, bool) {
	if p == "" || p[0] != '/' {
		return nil, false
	}
	toks := strings.Split(p[1:], "/")
	for i, t := range toks {
		toks[i] = unescape(t)
	}
	return toks, true
}

func joinPointer(toks []string) string {
	var b strings.Builder
	for _, t := range toks {
		b.WriteByte('/')
		b.WriteString(EscapePointerToken(t))
	}
	return b.String()
}

// under reports whether pointer p is q or lies below q at a token boundary.
func under(p, q string) bool {
	return p == q || strings.HasPrefix(p, q+"/")
}

// ---- resolution ----------------------------------------------------------------------------------------------

// pointerIndex resolves sidecar keys against one decoded document.
type pointerIndex struct {
	root  map[string]any
	byID  map[string]map[string]map[string]any // collection → id → element
	attrs map[string]any
}

func newPointerIndex(doc map[string]any) *pointerIndex {
	ix := &pointerIndex{root: doc, byID: map[string]map[string]map[string]any{}}
	ix.attrs, _ = doc["attrs"].(map[string]any)
	for coll := range provenanceRoots {
		if coll == "attrs" {
			continue
		}
		items, _ := doc[coll].([]any)
		m := make(map[string]map[string]any, len(items))
		for _, it := range items {
			if el, ok := it.(map[string]any); ok {
				if id, ok := el["id"].(string); ok {
					m[id] = el
				}
			}
		}
		ix.byID[coll] = m
	}
	return ix
}

func indexOf(a *Architecture) (*pointerIndex, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return newPointerIndex(doc), nil
}

// resolves reports whether a key names a value of the document: an element, a member of one (layout members
// excluded) or a value inside one, or a root attribute.
func (ix *pointerIndex) resolves(key string) bool {
	toks, ok := splitPointer(key)
	if !ok || len(toks) == 0 || !provenanceRoots[toks[0]] {
		return false
	}
	var cur any
	rest := toks[1:]
	if toks[0] == "attrs" {
		if len(rest) == 0 {
			return false
		}
		cur = ix.attrs
	} else {
		if len(rest) == 0 {
			return false
		}
		el, ok := ix.byID[toks[0]][rest[0]]
		if !ok {
			return false
		}
		rest = rest[1:]
		if len(rest) > 0 && (layoutFields[rest[0]] || serverOwnedFields[rest[0]]) {
			return false
		}
		cur = el
	}
	for _, t := range rest {
		switch v := cur.(type) {
		case map[string]any:
			nxt, ok := v[t]
			if !ok {
				return false
			}
			cur = nxt
		case []any:
			i, err := strconv.Atoi(t)
			if err != nil || i < 0 || i >= len(v) || strconv.Itoa(i) != t {
				return false
			}
			cur = v[i]
		default:
			return false
		}
	}
	return true
}

// provenanceProblems lists the keys that do not resolve (the invariant of ADR-086 §2), sorted.
func provenanceProblems(a *Architecture) []Problem {
	if len(a.Provenance) == 0 {
		return nil
	}
	ix, err := indexOf(a)
	if err != nil {
		return []Problem{{Path: "/provenance", Message: "cannot be read"}}
	}
	n := 0
	for k := range a.Provenance {
		if !ix.resolves(k) {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	// The key is model content: the problem counts the keys and never echoes one.
	return []Problem{{Path: "/provenance", Message: fmt.Sprintf("%d key(s) name no model element, member or attribute", n)}}
}

// checkProvenanceKeys runs the secret guard over each token of each sidecar key with an x_ prefix stripped
// (ADR-086 §5). The document walk scans a key whole and strips a leading x_ only, so a credential that follows an
// x_ inside a pointer (/nodes/n1/attrs/x_AKIA…) would pass it. The violation names /provenance, never the key.
func checkProvenanceKeys(ctx context.Context, doc any) error {
	root, _ := doc.(map[string]any)
	prov, _ := root["provenance"].(map[string]any)
	for k := range prov {
		toks, _ := splitPointer(k)
		for _, tok := range toks {
			text := strings.TrimPrefix(tok, "x_")
			if err := secretguard.CheckValue(ctx, secretguard.SourceModel, "/provenance", text); err != nil {
				return err
			}
		}
	}
	return nil
}

// pruneProvenanceDoc drops the sidecar keys a document no longer resolves (a patch removed the element or the
// attribute they name). It runs inside Apply before validation, so removing an imported element is a valid patch.
func pruneProvenanceDoc(doc []byte) ([]byte, error) {
	if !bytes.Contains(doc, []byte(`"provenance"`)) {
		return doc, nil // no sidecar: nothing to prune, no decode
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	prov, ok := root["provenance"].(map[string]any)
	if !ok || len(prov) == 0 {
		return doc, nil
	}
	ix := newPointerIndex(root)
	changed := false
	for k := range prov {
		if !ix.resolves(k) {
			delete(prov, k)
			changed = true
		}
	}
	if !changed {
		return doc, nil
	}
	if len(prov) == 0 {
		delete(root, "provenance")
	}
	return json.Marshal(root)
}

func sortedKeys(p Provenance) []string {
	keys := slices.Collect(maps.Keys(p))
	sort.Strings(keys)
	return keys
}

// ---- reading ---------------------------------------------------------------------------------------------------

// SourceToKind is the upgrade mapping of a node's source (ADR-086 §6): design → declared, declared → imported,
// observed → observed. An empty source is design.
func SourceToKind(source string) string {
	switch source {
	case SourceDeclared:
		return ProvenanceImported
	case SourceObserved:
		return ProvenanceObserved
	}
	return ProvenanceDeclared
}

// KindToSource is the inverse mapping: the node source written from the sidecar for two MINOR versions (ADR-040 §4).
func KindToSource(kind string) string {
	switch kind {
	case ProvenanceImported:
		return SourceDeclared
	case ProvenanceObserved:
		return SourceObserved
	}
	return SourceDesign
}

// weaker returns the weaker of two kinds (declared < imported < observed).
func weaker(x, y string) string {
	if slices.Index(ProvenanceKinds, x) <= slices.Index(ProvenanceKinds, y) {
		return x
	}
	return y
}

// upgradeEntry is the entry the upgrade mapping resolves for a node without one (ADR-086 §6). It is never written
// by reading: MaterializeProvenance writes it on the next save.
func upgradeEntry(n *Node) ProvenanceEntry {
	kind := SourceToKind(n.Source)
	e := ProvenanceEntry{Kind: kind}
	if kind == ProvenanceImported {
		e.Identifier = n.ExternalRef
		if e.Identifier == "" {
			e.Identifier = PreV11Import
		}
	}
	return e
}

// HasProvenance reports whether the model carries a stored sidecar (prov.available for the rules).
func (a *Architecture) HasProvenance() bool { return a != nil && len(a.Provenance) > 0 }

// storedEntry returns the stored entry of the most specific key at or above pointer.
func (a *Architecture) storedEntry(pointer string) (ProvenanceEntry, string, bool) {
	if len(a.Provenance) == 0 {
		return ProvenanceEntry{}, "", false
	}
	toks, ok := splitPointer(pointer)
	if !ok {
		return ProvenanceEntry{}, "", false
	}
	for n := len(toks); n > 0; n-- {
		k := joinPointer(toks[:n])
		if e, ok := a.Provenance[k]; ok {
			return e, k, true
		}
	}
	return ProvenanceEntry{}, "", false
}

// ProvenanceOf returns the entry that governs a pointer: the most specific stored key at or above it; else, upgrade
// on read (ADR-086 §6), the node's source mapped for a pointer under a node, the weaker of its endpoints for a
// pointer under an edge, and declared for anything else. Nothing is written.
func (a *Architecture) ProvenanceOf(pointer string) ProvenanceEntry {
	if a == nil {
		return ProvenanceEntry{Kind: ProvenanceDeclared}
	}
	if e, _, ok := a.storedEntry(pointer); ok {
		return e
	}
	toks, _ := splitPointer(pointer)
	if len(toks) >= 2 {
		switch toks[0] {
		case "nodes":
			if n := a.Node(toks[1]); n != nil {
				return upgradeEntry(n)
			}
		case "edges":
			if e := a.Edge(toks[1]); e != nil {
				from := a.ProvenanceOf(ElementPointer("nodes", e.From))
				to := a.ProvenanceOf(ElementPointer("nodes", e.To))
				if weaker(from.Kind, to.Kind) == from.Kind {
					return ProvenanceEntry{Kind: from.Kind, Identifier: from.Identifier}
				}
				return ProvenanceEntry{Kind: to.Kind, Identifier: to.Identifier}
			}
		}
	}
	return ProvenanceEntry{Kind: ProvenanceDeclared}
}

// KindOf is ProvenanceOf(pointer).Kind.
func (a *Architecture) KindOf(pointer string) string { return a.ProvenanceOf(pointer).Kind }

// Expired reports whether an imported entry is past its cadence at asOf: asOf − fetched_at > cadence_days. An entry
// without a cadence or a fetch date never expires by the clock.
func (e ProvenanceEntry) Expired(asOf time.Time) bool {
	if e.Kind != ProvenanceImported || e.CadenceDays <= 0 || e.FetchedAt == nil {
		return false
	}
	return asOf.Sub(*e.FetchedAt) > time.Duration(e.CadenceDays)*24*time.Hour
}

// LatestImport returns the version or hash of the latest import of an identifier the sidecar records: the
// last_seen_import of the identifier's most recently accepted entry (newerImport; the answer never depends on map
// order). "" when no entry records one.
func (a *Architecture) LatestImport(identifier string) string { return a.LatestImports()[identifier] }

// LatestImports is LatestImport for every identifier at once (one pass over the sidecar).
func (a *Architecture) LatestImports() map[string]string {
	best := map[string]ProvenanceEntry{}
	for _, e := range a.Provenance {
		if e.Kind == ProvenanceDeclared || e.Identifier == "" || e.LastSeenImport == "" {
			continue
		}
		if cur, ok := best[e.Identifier]; !ok || newerImport(e, cur) {
			best[e.Identifier] = e
		}
	}
	out := make(map[string]string, len(best))
	for id, e := range best {
		out[id] = e.LastSeenImport
	}
	return out
}

// newerImport orders imports by acceptance (imported_at), then by the source's own date, then by value: a source may
// date itself earlier than an import accepted before it, so the order in which people accepted them decides.
func newerImport(x, y ProvenanceEntry) bool {
	if c := cmpTime(x.ImportedAt, y.ImportedAt); c != 0 {
		return c > 0
	}
	if c := cmpTime(x.FetchedAt, y.FetchedAt); c != 0 {
		return c > 0
	}
	return x.LastSeenImport > y.LastSeenImport
}

func cmpTime(x, y *time.Time) int {
	switch {
	case x == nil && y == nil:
		return 0
	case x == nil:
		return -1
	case y == nil:
		return 1
	}
	return x.Compare(*y)
}

// Drifted reports whether a stored imported (or observed) entry was left behind by a later import of its identifier that no
// longer carries the fact (ADR-086 §7).
func (a *Architecture) Drifted(e ProvenanceEntry) bool { return DriftedAgainst(a.LatestImports(), e) }

// DriftedAgainst is Drifted with the identifiers' latest imports computed once (LatestImports).
func DriftedAgainst(latest map[string]string, e ProvenanceEntry) bool {
	if e.Kind == ProvenanceDeclared || e.Identifier == "" || e.LastSeenImport == "" {
		return false
	}
	l := latest[e.Identifier]
	return l != "" && l != e.LastSeenImport
}

// DriftedElements returns the pointers of the elements (nodes and edges) whose element-level stored entry drifted,
// sorted.
func (a *Architecture) DriftedElements(identifier string) []string {
	var out []string
	latest := a.LatestImports()
	for _, k := range sortedKeys(a.Provenance) {
		e := a.Provenance[k]
		if e.Identifier != identifier || !DriftedAgainst(latest, e) {
			continue
		}
		toks, _ := splitPointer(k)
		if len(toks) == 2 && (toks[0] == "nodes" || toks[0] == "edges") {
			out = append(out, k)
		}
	}
	return out
}

// ---- writing ---------------------------------------------------------------------------------------------------

func (a *Architecture) ensureProvenance() {
	if a.Provenance == nil {
		a.Provenance = Provenance{}
	}
}

// dropUnder removes every stored key strictly below pointer: the fact at pointer was rewritten as a whole.
func (a *Architecture) dropUnder(pointer string) {
	for k := range a.Provenance {
		if k != pointer && under(k, pointer) {
			delete(a.Provenance, k)
		}
	}
}

// MaterializeProvenance writes the upgrade mapping (ADR-086 §6) for every node without an element-level stored
// entry: the "next save materialises them" of the ADR. sources gives the source each node had before the change
// being saved (nil: the node's current source), so a patch can never raise a tier by editing `source`.
func (a *Architecture) MaterializeProvenance(sources map[string]string) {
	a.ensureProvenance()
	for i := range a.Nodes {
		n := &a.Nodes[i]
		if IsNote(n.Type) {
			continue
		}
		k := ElementPointer("nodes", n.ID)
		if _, ok := a.Provenance[k]; ok {
			continue
		}
		probe := *n
		if src, ok := sources[n.ID]; ok {
			probe.Source = src
		} else if sources != nil {
			// A node the change added: typed by the person who accepted it.
			probe.Source = SourceDesign
		}
		a.Provenance[k] = upgradeEntry(&probe)
	}
}

// SyncSources writes each node's source from its element-level entry (ADR-086 §6, ADR-040 §4: two MINOR versions
// carry both). A node without an element-level entry keeps its source.
func (a *Architecture) SyncSources() {
	for i := range a.Nodes {
		if e, ok := a.Provenance[ElementPointer("nodes", a.Nodes[i].ID)]; ok {
			a.Nodes[i].Source = KindToSource(e.Kind)
		}
	}
}

// ImportSource describes the source an import read (ADR-086 §3).
type ImportSource struct {
	// Kind is the kind the carried facts get: imported (the default), or observed for a fact the source itself
	// records as observed (a registry's observed tier, read only with OBSERVED_OVERLAY on), so an import never moves
	// a fact to another tier than the upgrade mapping of its source.
	Kind              string
	Identifier        string
	Version           string
	Hash              string
	FetchedAt         time.Time
	CadenceDays       int
	SignatureVerified bool
}

// MaxSourceClockSkew is how far past the server's clock a source may date itself in a preview: a file dated later
// is not believed (its date is dropped, and the fetch date becomes the acceptance time), so a future date can never
// keep an imported fact from going stale (ADR-086 §7).
const MaxSourceClockSkew = 5 * time.Minute

// provenanceNow is the clock a preview's source dates are bounded by (a variable for tests).
var provenanceNow = time.Now

// boundFetchedAt bounds a source's own date: never later than the acceptance at, and for a preview (zero at) never
// later than now plus MaxSourceClockSkew (nil: the date is not believed).
func boundFetchedAt(src, at time.Time) *time.Time {
	t := src.UTC().Truncate(time.Second)
	switch {
	case !at.IsZero() && t.After(at.UTC()):
		t = at.UTC()
	case at.IsZero() && t.After(provenanceNow().UTC().Add(MaxSourceClockSkew)):
		return nil
	}
	return &t
}

// RecordImport marks the pointers an import carries as imported from src (ADR-086 §4): every key below a carried
// pointer goes (the import rewrote the fact as a whole), and the entry names the identifier, the version or hash, the
// fetch date, the cadence and the actor who accepted the import. A preview passes no actor and a zero at: the server
// stamps both on acceptance (StampAccepted), and a source that states no fetch date is fetched when it is accepted.
// The source's own date is bounded by the acceptance (boundFetchedAt). LastSeenImport is the hash, else the version.
func (a *Architecture) RecordImport(src ImportSource, carried []string, actor string, at time.Time) {
	a.MergeImport(src, carried, carried, actor, at)
}

// MergeImport records an accepted import merged into an existing model (ADR-086 §4 and §7). Each carried element is
// imported from src as of this acceptance: its fetch date and last_seen_import are refreshed, whether or not the merge
// changed it. Below a carried element, the keys of the values the merge rewrote go (the import wrote them), and the
// keys of the values it left alone stay: an attribute an architect declared and the import does not own stays
// declared. RecordImport is MergeImport with every carried element rewritten as a whole.
func (a *Architecture) MergeImport(src ImportSource, carried, rewritten []string, actor string, at time.Time) {
	a.ensureProvenance()
	kind := src.Kind
	if kind == "" {
		kind = ProvenanceImported
	}
	var importedAt, fetchedAt *time.Time
	if !at.IsZero() {
		// Not truncated: two imports accepted within one second still order (newerImport).
		t := at.UTC()
		importedAt, fetchedAt = &t, &t
	}
	if !src.FetchedAt.IsZero() {
		if t := boundFetchedAt(src.FetchedAt, at); t != nil {
			fetchedAt = t
		}
	}
	seen := src.Hash
	if seen == "" {
		seen = src.Version
	}
	for _, p := range carried {
		for k := range a.Provenance {
			if k == p || !under(k, p) {
				continue
			}
			for _, r := range rewritten {
				if under(k, r) {
					delete(a.Provenance, k)
					break
				}
			}
		}
		a.Provenance[p] = ProvenanceEntry{Kind: kind, Identifier: src.Identifier, Version: src.Version, Hash: src.Hash,
			ImportedBy: actor, ImportedAt: cloneTime(importedAt), FetchedAt: cloneTime(fetchedAt), CadenceDays: src.CadenceDays,
			SignatureVerified: src.SignatureVerified, LastSeenImport: seen}
	}
	a.compactProvenance()
	a.SyncSources()
}

// PreviewImportSource returns the source a preview's imported (or observed) entries name: the identifier, version,
// hash, fetch date, cadence and signature state of the first such entry in key order. ok is false when the preview
// records no import. The server uses it to accept its own preview (a registry export it parsed), never a client's.
func (a *Architecture) PreviewImportSource() (ImportSource, bool) {
	for _, k := range sortedKeys(a.Provenance) {
		e := a.Provenance[k]
		if e.Kind == ProvenanceDeclared || e.Identifier == "" {
			continue
		}
		src := ImportSource{Identifier: e.Identifier, Version: e.Version, Hash: e.Hash, CadenceDays: e.CadenceDays,
			SignatureVerified: e.SignatureVerified}
		if e.FetchedAt != nil {
			src.FetchedAt = *e.FetchedAt
		}
		return src, true
	}
	return ImportSource{}, false
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

// RecordDeclared marks pointers as declared from a source a person drew (a diagram or DSL import): the identifier
// and hash name the file; the actor and date are stamped on acceptance.
func (a *Architecture) RecordDeclared(identifier, hash string, pointers []string) {
	a.ensureProvenance()
	for _, p := range pointers {
		a.dropUnder(p)
		a.Provenance[p] = ProvenanceEntry{Kind: ProvenanceDeclared, Identifier: identifier, Hash: hash}
	}
	a.SyncSources()
}

// ElementPointers returns the element-level pointers of every assessed node and every edge, in model order.
func (a *Architecture) ElementPointers() []string {
	out := make([]string, 0, len(a.Nodes)+len(a.Edges))
	for i := range a.Nodes {
		if !IsNote(a.Nodes[i].Type) {
			out = append(out, ElementPointer("nodes", a.Nodes[i].ID))
		}
	}
	for i := range a.Edges {
		out = append(out, ElementPointer("edges", a.Edges[i].ID))
	}
	return out
}

// StampAccepted is the server's stamp on a model a person accepts as a whole (a confirmed import: POST
// /architectures {model}). Imported entries are stamped with the accepting actor and time and never claim a
// verified signature (the server verified none); declared entries are stamped the same way, whatever the client named.
// Keys that do not resolve are dropped, the upgrade mapping is materialised when the model carries a sidecar, and the
// node sources are written from it. A model without a sidecar is left without one.
func (a *Architecture) StampAccepted(actor string, at time.Time) {
	if len(a.Provenance) == 0 {
		a.Provenance = nil
		return
	}
	at = at.UTC()
	a.pruneUnresolved()
	for k, e := range a.Provenance {
		switch e.Kind {
		case ProvenanceImported, ProvenanceObserved:
			if e.Identifier == "" {
				// Not written by an importer (the upgrade mapping, or a client): no stamp claims an import.
				break
			}
			e.ImportedBy, e.ImportedAt, e.SignatureVerified = actor, cloneTime(&at), false
			if e.FetchedAt == nil || e.FetchedAt.After(at) {
				// A source dated after its acceptance is fetched when it is accepted (boundFetchedAt).
				e.FetchedAt = cloneTime(&at)
			}
		case ProvenanceDeclared:
			// The person who accepts a model whole declares what it declares: a client never names another declarant.
			e.DeclaredBy, e.DeclaredAt = actor, cloneTime(&at)
		}
		a.Provenance[k] = e
	}
	a.MaterializeProvenance(nil)
	a.compactProvenance()
	a.SyncSources()
}

// DistrustProvenance is what the server does with provenance it did not write (ADR-086 §4: server-owned, never
// client-written; only an accepted import writes imported): a model a client posts without the seal of a preview the
// server produced. Every sidecar entry goes, and every node source above design is read as design, so the model
// resolves declared throughout and its creation names the accepting person. It returns how many entries and sources
// it dropped (counts for the log; never the values).
func (a *Architecture) DistrustProvenance() (entries, sources int) {
	entries = len(a.Provenance)
	a.Provenance = nil
	for i := range a.Nodes {
		if a.Nodes[i].Source != "" && a.Nodes[i].Source != SourceDesign {
			a.Nodes[i].Source = SourceDesign
			sources++
		}
	}
	return entries, sources
}

// HasObserved reports whether the model claims an observed fact: a sidecar entry of kind observed, or a node whose
// source is observed. No ingestion path writes one while OBSERVED_OVERLAY is off.
func (a *Architecture) HasObserved() bool {
	for _, e := range a.Provenance {
		if e.Kind == ProvenanceObserved {
			return true
		}
	}
	for i := range a.Nodes {
		if a.Nodes[i].Source == SourceObserved {
			return true
		}
	}
	return false
}

func (a *Architecture) pruneUnresolved() {
	if len(a.Provenance) == 0 {
		return
	}
	ix, err := indexOf(a)
	if err != nil {
		return
	}
	for k := range a.Provenance {
		if !ix.resolves(k) {
			delete(a.Provenance, k)
		}
	}
}

// StampPatch is the post-apply rewrite of an accepted patch (ADR-086 §4, docs/18 C1): every pointer whose value the
// change altered is reset to declared, naming the actor. prev is the model the patch was applied to and next the
// result (Apply keeps prev's sidecar, minus the keys of removed values). Changed pointers come from comparing the two
// models, so a patch is stamped the same whichever of the equivalent op sequences produced it; layout members never
// count. A model that carries no sidecar keeps none while every changed fact was declared already (the version
// history names the actor); a change to an imported or observed fact creates the sidecar, materialising the upgrade
// mapping of every other node first.
func StampPatch(prev, next *Architecture, actor string, at time.Time) {
	if prev == nil || next == nil {
		return
	}
	changed := ChangedPointers(prev, next)
	if len(next.Provenance) == 0 && !touchesNonDeclared(prev, next, changed) {
		next.Provenance = nil
		return
	}
	sources := make(map[string]string, len(prev.Nodes))
	for i := range prev.Nodes {
		sources[prev.Nodes[i].ID] = prev.Nodes[i].Source
	}
	// The sidecar as prev resolved it: pruned of what next no longer holds, then the upgrade mapping as prev's
	// sources say, so editing `source` never changes a kind.
	next.pruneUnresolved()
	next.MaterializeProvenance(sources)
	at = at.UTC().Truncate(time.Second)
	for _, p := range changed {
		next.dropUnder(p)
		next.Provenance[p] = ProvenanceEntry{Kind: ProvenanceDeclared, DeclaredBy: actor, DeclaredAt: cloneTime(&at)}
	}
	next.compactProvenance()
	next.SyncSources()
}

// ---- size ------------------------------------------------------------------------------------------------------

// MaxProvenanceKeys is the schema's maxProperties of /provenance (model.schema.json). It exceeds the number of
// element-level keys the collection limits allow (MaxProvenanceElements), so a sidecar folded to element level
// always fits: compactProvenance keeps every model within it, and no save is ever refused for a sidecar the user
// cannot patch.
const MaxProvenanceKeys = 50000

// MaxProvenanceElements is the most element-level keys a model can carry: nodes, edges, groups and identities at the
// schema's maxItems.
const MaxProvenanceElements = 5000 + 10000 + 500 + 1000

// provenanceKeyLimit is MaxProvenanceKeys (a variable so tests can exercise the fold).
var provenanceKeyLimit = MaxProvenanceKeys

// sameClaim reports whether two entries make the same claim: every field but the declaration date equal.
func sameClaim(x, y ProvenanceEntry) bool {
	x.DeclaredAt, y.DeclaredAt = nil, nil
	return reflect.DeepEqual(x, y)
}

// pointerDepth is the number of tokens of a key (cheap: no unescaping).
func pointerDepth(k string) int { return strings.Count(k, "/") }

// compactProvenance keeps the sidecar from growing with every patch (ADR-086 §2). First, a key that makes the same
// claim as the stored key governing it from above is redundant and goes; for a declared claim the governing entry's
// declared_at becomes the latest declaration it now covers. A person who edits one element many times therefore
// leaves one key, not one per attribute. Second, only while the sidecar still exceeds the schema's limit, every key
// below an element folds into the element's key, the weaker claim winning (a declared attribute under an imported
// element makes the element declared: understating where a fact came from is the safe direction); then root
// attribute keys go (they resolve declared). The result never exceeds MaxProvenanceElements keys.
func (a *Architecture) compactProvenance() {
	if len(a.Provenance) < 2 {
		return
	}
	keys := sortedKeys(a.Provenance)
	// Deepest first: a key folds into its parent before the parent is compared with its own.
	sort.SliceStable(keys, func(i, j int) bool { return pointerDepth(keys[i]) > pointerDepth(keys[j]) })
	for _, k := range keys {
		e, ok := a.Provenance[k]
		if !ok {
			continue
		}
		toks, _ := splitPointer(k)
		if len(toks) < 2 {
			continue
		}
		parent, pk, found := a.storedEntry(joinPointer(toks[:len(toks)-1]))
		if !found || !sameClaim(e, parent) {
			continue
		}
		if cmpTime(e.DeclaredAt, parent.DeclaredAt) > 0 {
			parent.DeclaredAt = cloneTime(e.DeclaredAt)
			a.Provenance[pk] = parent
		}
		delete(a.Provenance, k)
	}
	if len(a.Provenance) <= provenanceKeyLimit {
		return
	}
	for _, k := range keys {
		e, ok := a.Provenance[k]
		toks, _ := splitPointer(k)
		if !ok || len(toks) <= 2 || toks[0] == "attrs" {
			continue
		}
		el := joinPointer(toks[:2])
		cur := a.ProvenanceOf(el) // the stored element entry, else its upgrade mapping
		if e.Kind != cur.Kind && weaker(e.Kind, cur.Kind) == e.Kind {
			cur = e // the weaker claim wins
		}
		a.Provenance[el] = cur
		delete(a.Provenance, k)
	}
	if len(a.Provenance) <= provenanceKeyLimit {
		return
	}
	for k := range a.Provenance {
		if strings.HasPrefix(k, "/attrs/") {
			delete(a.Provenance, k)
		}
	}
}

// touchesNonDeclared reports whether a change on a model without a sidecar needs one: it alters a fact that resolves
// imported or observed, or it writes a node source the upgrade mapping would read as more than declared (a patch that
// sets `source: declared` on a node must not make it imported).
func touchesNonDeclared(prev, next *Architecture, changed []string) bool {
	for _, p := range changed {
		if prev.KindOf(p) != ProvenanceDeclared {
			return true
		}
	}
	for i := range next.Nodes {
		n := &next.Nodes[i]
		before := SourceDesign
		if p := prev.Node(n.ID); p != nil {
			before = p.Source
		}
		if SourceToKind(n.Source) != SourceToKind(before) {
			return true
		}
	}
	return false
}

// ChangedPointers lists the id-addressed pointers whose value differs between two models, sorted: an added element
// as a whole (/nodes/<id>), a changed member (/edges/<id>/auth), a changed attribute (/nodes/<id>/attrs/<key>) or
// root attribute (/attrs/<key>). Removed values are not listed (their keys are pruned); layout members, ids and the
// server-written node source never are.
func ChangedPointers(prev, next *Architecture) []string {
	var out []string
	out = append(out, diffAttrs("/attrs", prev.Attrs, next.Attrs)...)
	out = append(out, diffCollection("nodes", elementsByID(prev.Nodes, func(n Node) string { return n.ID }),
		elementsByID(next.Nodes, func(n Node) string { return n.ID }))...)
	out = append(out, diffCollection("edges", elementsByID(prev.Edges, func(e Edge) string { return e.ID }),
		elementsByID(next.Edges, func(e Edge) string { return e.ID }))...)
	out = append(out, diffCollection("groups", elementsByID(prev.Groups, func(g Group) string { return g.ID }),
		elementsByID(next.Groups, func(g Group) string { return g.ID }))...)
	out = append(out, diffCollection("identities", elementsByID(prev.Identities, func(i Identity) string { return i.ID }),
		elementsByID(next.Identities, func(i Identity) string { return i.ID }))...)
	sort.Strings(out)
	return out
}

func elementsByID[T any](items []T, id func(T) string) map[string]map[string]any {
	out := make(map[string]map[string]any, len(items))
	for _, it := range items {
		b, err := json.Marshal(it)
		if err != nil {
			continue
		}
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if dec.Decode(&m) == nil {
			out[id(it)] = m
		}
	}
	return out
}

func diffCollection(coll string, prev, next map[string]map[string]any) []string {
	var out []string
	for id, n := range next {
		base := ElementPointer(coll, id)
		p, ok := prev[id]
		if !ok {
			out = append(out, base)
			continue
		}
		fields := map[string]bool{}
		for k := range n {
			fields[k] = true
		}
		for k := range p {
			fields[k] = true
		}
		for k := range fields {
			if layoutFields[k] || serverOwnedFields[k] {
				continue
			}
			nv, inNext := n[k]
			if !inNext {
				continue // removed: its keys are pruned
			}
			if k == "attrs" {
				pa, _ := p[k].(map[string]any)
				na, _ := nv.(map[string]any)
				out = append(out, diffAttrMaps(base+"/attrs", pa, na)...)
				continue
			}
			if !reflect.DeepEqual(p[k], nv) {
				out = append(out, base+"/"+EscapePointerToken(k))
			}
		}
	}
	return out
}

func diffAttrs(base string, prev, next Attrs) []string {
	pm, nm := normalizeAttrs(prev), normalizeAttrs(next)
	return diffAttrMaps(base, pm, nm)
}

func normalizeAttrs(at Attrs) map[string]any {
	b, err := json.Marshal(at)
	if err != nil {
		return nil
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if dec.Decode(&m) != nil {
		return nil
	}
	return m
}

func diffAttrMaps(base string, prev, next map[string]any) []string {
	var out []string
	for k, nv := range next {
		if pv, ok := prev[k]; !ok || !reflect.DeepEqual(pv, nv) {
			out = append(out, base+"/"+EscapePointerToken(k))
		}
	}
	return out
}

// DriftRemovalOps is the import diff of ADR-086 §7 as a patch a person accepts or rejects (never applied by the
// server): for each drifted node of identifier, remove the edges touching it, its group memberships, then the node;
// then each drifted edge still present. nil when nothing drifted.
func (a *Architecture) DriftRemovalOps(identifier string) []PatchOp {
	drifted := a.DriftedElements(identifier)
	if len(drifted) == 0 {
		return nil
	}
	nodes := map[string]bool{}
	edges := map[string]bool{}
	for _, p := range drifted {
		toks, _ := splitPointer(p)
		if toks[0] == "nodes" {
			nodes[toks[1]] = true
		} else {
			edges[toks[1]] = true
		}
	}
	for i := range a.Edges {
		if nodes[a.Edges[i].From] || nodes[a.Edges[i].To] {
			edges[a.Edges[i].ID] = true
		}
	}
	var ops []PatchOp
	for i := range a.Edges {
		if edges[a.Edges[i].ID] {
			ops = append(ops, PatchOp{Op: "remove", Path: ElementPointer("edges", a.Edges[i].ID)})
		}
	}
	for _, g := range a.Groups {
		// Highest index first, so each removal leaves the earlier indexes in place.
		for j := len(g.NodeIDs) - 1; j >= 0; j-- {
			if nodes[g.NodeIDs[j]] {
				ops = append(ops, PatchOp{Op: "remove", Path: fmt.Sprintf("%s/node_ids/%d", ElementPointer("groups", g.ID), j)})
			}
		}
	}
	for i := range a.Nodes {
		if nodes[a.Nodes[i].ID] {
			// Its zone and group memberships were removed above; the node goes as a whole.
			ops = append(ops, PatchOp{Op: "remove", Path: ElementPointer("nodes", a.Nodes[i].ID)})
		}
	}
	return ops
}
