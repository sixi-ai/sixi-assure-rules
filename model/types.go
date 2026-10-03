// Package model defines the typed graph model (docs/02): Go types, schema validation,
// invariants, ID-addressed JSON Patch application and canonical hashing.
package model

import (
	"encoding/json"
	"time"
)

// Attrs are typed attributes; keys and value types are constrained by the JSON Schema.
type Attrs map[string]any

// Position is a canvas coordinate.
type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Size is a group box size.
type Size struct {
	W float64 `json:"w,omitempty"`
	H float64 `json:"h,omitempty"`
}

// Architecture is the model root.
//
// SchemaVersion is the schema the document follows (ADR-040 §1). A value in Go is always at
// CurrentSchemaVersion: raw JSON is upgraded by model/migrate before it is decoded (ValidateJSON,
// the store's read path), and normalize, Empty and Canonical write the current version where a Go
// builder left it empty.
//
// Provenance is the server-owned sidecar of ADR-086 (schema 1.1): JSON pointer → where the fact came from. It is
// absent on a model that never carried one, and rules never read it (provenance.go).
type Architecture struct {
	SchemaVersion string        `json:"schema_version,omitempty"`
	ID            string        `json:"id"`
	TenantID      string        `json:"tenant_id"`
	Name          string        `json:"name"`
	Version       int           `json:"version"`
	CreatedAt     *time.Time    `json:"created_at,omitempty"`
	UpdatedAt     *time.Time    `json:"updated_at,omitempty"`
	Attrs         Attrs         `json:"attrs"`
	Provenance    Provenance    `json:"provenance,omitempty"`
	Identities    []Identity    `json:"identities,omitempty"`
	Groups        []Group       `json:"groups"`
	Nodes         []Node        `json:"nodes"`
	Edges         []Edge        `json:"edges"`
	Findings      []Finding     `json:"findings"`
	Evidence      []EvidenceRef `json:"evidence"`
}

// Identity is a principal components run as (ADR-047 §1, schema 1.1): nodes reference one by
// attrs.identity_id. It holds claims about the identity, never a credential: CredentialTTL is a
// duration in seconds and Ref an identifier, and the secret guard inspects every string.
type Identity struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	Kind           string `json:"kind,omitempty"`
	Ref            string `json:"ref,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
	// CredentialTTL is the lifetime of one issued credential in seconds; nil when not declared.
	CredentialTTL *int64 `json:"credential_ttl,omitempty"`
	// RotationDays is the rotation period of a long-lived credential (ADR-047 §3b); nil when not declared.
	RotationDays *int64 `json:"rotation_days,omitempty"`
	Sponsor      string `json:"sponsor,omitempty"`
	Owner        string `json:"owner,omitempty"`
	Blueprint    string `json:"blueprint,omitempty"`
	// Registry is the id of the agent_registry node the identity is registered in.
	Registry    string `json:"registry,omitempty"`
	Federation  string `json:"federation,omitempty"`
	TrustDomain string `json:"trust_domain,omitempty"`
	Description string `json:"description,omitempty"`
	// Attrs holds x_ extension values only (x_migrated_from on an identity the 1.0 → 1.1 step created).
	Attrs Attrs `json:"attrs,omitempty"`
}

// Group is a zone, trust boundary, region, subscription, site, tenant or jurisdiction container.
type Group struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Name     string    `json:"name"`
	NodeIDs  []string  `json:"node_ids"`
	Parent   string    `json:"parent,omitempty"`
	Position *Position `json:"position,omitempty"`
	Size     *Size     `json:"size,omitempty"`
	Attrs    Attrs     `json:"attrs,omitempty"`
}

// Node is a typed component.
type Node struct {
	ID          string               `json:"id"`
	Type        string               `json:"type"`
	Name        string               `json:"name"`
	Layer       string               `json:"layer"`
	Zone        string               `json:"zone,omitempty"`
	Source      string               `json:"source,omitempty"`
	Position    *Position            `json:"position,omitempty"`
	Positions   map[string]*Position `json:"positions,omitempty"`
	Icon        string               `json:"icon,omitempty"`
	Description string               `json:"description,omitempty"`
	ExternalRef string               `json:"external_ref,omitempty"`
	Attrs       Attrs                `json:"attrs"`
}

// Edge is a typed relation between two nodes.
type Edge struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
	Label      string `json:"label,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Auth       string `json:"auth"`
	Encryption string `json:"encryption"`
	DataClass  string `json:"data_class,omitempty"`
	Attrs      Attrs  `json:"attrs"`
}

// Finding is a rule result persisted with its status.
type Finding struct {
	ID          string   `json:"id"`
	RuleID      string   `json:"rule_id"`
	Pack        string   `json:"pack"`
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	IDs         []string `json:"ids"`
	Title       string   `json:"title,omitempty"`
	Message     string   `json:"message"`
	Clauses     []string `json:"clauses,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	HasPatch    bool     `json:"has_patch,omitempty"`
	// Cause is the id of the design invariant the finding breaks (causes.yaml, docs/03
	// §Causes). It is a property of the loaded catalog, not of the stored model: the engine sets it
	// and read paths decorate stored findings with it. Empty when the rule has no cause mapped.
	Cause            string     `json:"cause,omitempty"`
	FirstSeenVersion int        `json:"first_seen_version,omitempty"`
	StatusReason     string     `json:"status_reason,omitempty"`
	StatusActor      string     `json:"status_actor,omitempty"`
	StatusAt         *time.Time `json:"status_at,omitempty"`
	// References are the rule's documentation references (a pack's `references:`, ADR-095): specifications that are
	// not law, cited by url and the day they were read. Like Cause they belong to the loaded catalog, not to the
	// stored model: the engine copies them and read paths decorate stored findings. They never carry a regulatory
	// statement (that is a clause id, CLAUDE.md §1.4). Empty for a rule that lists none.
	References []FindingReference `json:"references,omitempty"`
	// RemediationFramework is the rule's framework-native remediation for the agent framework the finding's elements
	// belong to (ADR-093 decision 9, docs/18 WS-M M4). Decorated on read against the architecture the finding is read
	// with (rules.Catalog.Decorate), never stored; Remediation stays the generic fallback.
	RemediationFramework *FindingRemediationFramework `json:"remediation_framework,omitempty"`
}

// FindingReference is one documentation reference of the rule behind a finding (ADR-095): kind "document", the
// document's title, its https url and the day (YYYY-MM-DD) the cited text was fetched.
type FindingReference struct {
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	FetchedAt string `json:"fetched_at"`
}

// FindingRemediationFramework is the framework-native remediation sentence of a finding: the framework value
// (schema 1.2 `agent.framework`), its display name, the sentence and the repository file at a commit it was read from.
type FindingRemediationFramework struct {
	Framework string `json:"framework"`
	Label     string `json:"label"`
	Text      string `json:"text"`
	Source    string `json:"source"`
}

// EvidenceRef points at an evidence event (docs/02 §6).
type EvidenceRef struct {
	ID    string    `json:"id"`
	Type  string    `json:"type"`
	TS    time.Time `json:"ts"`
	Hash  string    `json:"hash"`
	Actor string    `json:"actor,omitempty"`
}

// PatchOp is one RFC 6902 operation. Array segments under /nodes, /edges, /groups and
// /findings may name an element id instead of an index (resolved in Apply).
type PatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	From  string          `json:"from,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Patch is the envelope of docs/02 §5.
type Patch struct {
	PatchID    string    `json:"patch_id,omitempty"`
	ProposedBy string    `json:"proposed_by,omitempty"`
	Rationale  string    `json:"rationale,omitempty"`
	Clauses    []string  `json:"clauses,omitempty"`
	FindingID  string    `json:"finding_id,omitempty"`
	Ops        []PatchOp `json:"ops"`
	Status     string    `json:"status,omitempty"`
}

// Empty returns a valid empty architecture.
func Empty(id, tenantID, name string) *Architecture {
	return &Architecture{
		SchemaVersion: CurrentSchemaVersion,
		ID:            id,
		TenantID:      tenantID,
		Name:          name,
		Version:       0,
		Attrs:         Attrs{},
		Groups:        []Group{},
		Nodes:         []Node{},
		Edges:         []Edge{},
		Findings:      []Finding{},
		Evidence:      []EvidenceRef{},
	}
}

// Node returns the node with the given id, or nil.
func (a *Architecture) Node(id string) *Node {
	for i := range a.Nodes {
		if a.Nodes[i].ID == id {
			return &a.Nodes[i]
		}
	}
	return nil
}

// Identity returns the identity with the given id, or nil.
func (a *Architecture) Identity(id string) *Identity {
	for i := range a.Identities {
		if a.Identities[i].ID == id {
			return &a.Identities[i]
		}
	}
	return nil
}

// IdentityOf returns the identity a node runs as (attrs.identity_id), or nil.
func (a *Architecture) IdentityOf(n *Node) *Identity {
	if n == nil {
		return nil
	}
	id := n.Attrs.String("identity_id", "")
	if id == "" {
		return nil
	}
	return a.Identity(id)
}

// Edge returns the edge with the given id, or nil.
func (a *Architecture) Edge(id string) *Edge {
	for i := range a.Edges {
		if a.Edges[i].ID == id {
			return &a.Edges[i]
		}
	}
	return nil
}

// Group returns the group with the given id, or nil.
func (a *Architecture) Group(id string) *Group {
	for i := range a.Groups {
		if a.Groups[i].ID == id {
			return &a.Groups[i]
		}
	}
	return nil
}

// Finding returns the finding with the given id, or nil.
func (a *Architecture) Finding(id string) *Finding {
	for i := range a.Findings {
		if a.Findings[i].ID == id {
			return &a.Findings[i]
		}
	}
	return nil
}

// String returns a string attribute or def.
func (at Attrs) String(key, def string) string {
	if v, ok := at[key].(string); ok {
		return v
	}
	return def
}

// Bool returns a boolean attribute or def.
func (at Attrs) Bool(key string, def bool) bool {
	if v, ok := at[key].(bool); ok {
		return v
	}
	return def
}

// Int returns an integer attribute (JSON numbers decode as float64) or def.
func (at Attrs) Int(key string, def int) int {
	switch v := at[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
	}
	return def
}

// Clone deep-copies the architecture through JSON (models are small; simplicity wins).
func (a *Architecture) Clone() (*Architecture, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	var out Architecture
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
