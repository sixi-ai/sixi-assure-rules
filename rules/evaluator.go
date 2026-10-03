// Package rules evaluates deterministic rule packs (CEL) over the model (ADR-005, docs/03).
// Findings are produced only by rules; the LLM never creates findings (CLAUDE.md §1.2).
package rules

import (
	"context"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Policy carries tenant-level inputs to rules (allowed regions, enabled regimes, policy table).
type Policy struct {
	// AllowedRegions feeds `tenant.allowed_regions`; empty → policy table default.
	AllowedRegions []string
	// Regimes are the enabled regime codes (docs/04). Empty → every pack applies and regime(x) is false.
	Regimes []string
	// Requirements lets a tenant raise numeric requirements of the policy table (never lower):
	// required(code) = max(regime minimum or default, Requirements[code]). For a cap key read with
	// capped(code) the tenant's value replaces the default and may be lower, never above a regime
	// ceiling (PolicyTable.Cap).
	Requirements map[string]int
	// Knowledge carries the facts of the assistant's knowledge base for the drift rules (ADR-035):
	// nil → `kb.available` is false and every lookup is empty, so drift rules stay silent.
	Knowledge *KnowledgeFacts
	// AsOf pins the clock the `prov` variable computes import staleness against (ADR-086 §7): `assure verify` passes
	// the bundle's produced_at, so a re-evaluation reproduces the findings of the day. Zero → the time of evaluation.
	AsOf time.Time
}

// KnowledgeFacts is the rule-visible slice of the knowledge base (CEL variable `kb`). Keys are
// lower-cased canonical names or aliases; values are lower-cased replacement names. Freshness is
// keyed by document url (fresh | stale | superseded | unreachable). Facts are data the rules read;
// findings still come only from the rules that read them.
type KnowledgeFacts struct {
	Deprecated  map[string]string `json:"deprecated"`
	Freshness   map[string]string `json:"freshness"`
	GeneratedAt time.Time         `json:"generated_at"`
}

// Vars renders the facts as the `kb` activation variable.
func (k *KnowledgeFacts) Vars() map[string]any {
	dep := map[string]any{}
	fresh := map[string]any{}
	if k == nil {
		return map[string]any{"available": false, "deprecated": dep, "freshness": fresh}
	}
	for name, by := range k.Deprecated {
		dep[name] = by
	}
	for url, st := range k.Freshness {
		fresh[url] = st
	}
	return map[string]any{"available": true, "deprecated": dep, "freshness": fresh}
}

// ProvenanceVars renders the rule-visible slice of the provenance sidecar (ADR-086 §7) as the `prov` activation
// variable, built like `kb`: precomputed once per evaluation, with the clock pinned to asOf (zero → now).
//
//	prov.available            the model carries a stored sidecar; false → `elements` is empty and the prov rules are
//	                          silent, as drift is without kb
//	prov.as_of                the pinned clock (RFC 3339)
//	prov.elements[id]         per assessed node and per edge: kind (declared | imported | observed), stale (expired
//	                          or drifted), expired (now − fetched_at > cadence_days), drifted (a later import of the
//	                          identifier no longer carries it), fetched_at (RFC 3339, "" when unknown), identifier and
//	                          cadence_days
//
// The raw sidecar never reaches CEL: rules read only these computed facts, never actors or dates of acceptance.
func ProvenanceVars(a *model.Architecture, asOf time.Time) map[string]any {
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}
	elements := map[string]any{}
	out := map[string]any{"available": a.HasProvenance(), "as_of": asOf.UTC().Format(time.RFC3339), "elements": elements}
	if !a.HasProvenance() {
		return out
	}
	latest := a.LatestImports()
	add := func(id, pointer string) {
		e := a.ProvenanceOf(pointer)
		expired := e.Expired(asOf)
		drifted := model.DriftedAgainst(latest, e)
		fetched := ""
		if e.FetchedAt != nil {
			fetched = e.FetchedAt.UTC().Format(time.RFC3339)
		}
		elements[id] = map[string]any{"kind": e.Kind, "stale": expired || drifted, "expired": expired, "drifted": drifted,
			"fetched_at": fetched, "identifier": e.Identifier, "cadence_days": int64(e.CadenceDays)}
	}
	for _, n := range model.AssessedNodes(a) {
		add(n.ID, model.ElementPointer("nodes", n.ID))
	}
	for i := range a.Edges {
		add(a.Edges[i].ID, model.ElementPointer("edges", a.Edges[i].ID))
	}
	return out
}

// Evaluator computes findings for a model. Findings are produced only by rules; the LLM never
// creates findings (CLAUDE.md §1.2).
type Evaluator interface {
	Evaluate(ctx context.Context, a *model.Architecture, p Policy) ([]model.Finding, error)
}

// Noop returns no findings. Used when no packs are configured and in tests.
type Noop struct{}

// Evaluate implements Evaluator.
func (Noop) Evaluate(context.Context, *model.Architecture, Policy) ([]model.Finding, error) {
	return []model.Finding{}, nil
}

// Coverage says how far each rule that ran reached a decision (ADR-088 §4, docs/03 "requires and not_checked"). A
// rule decides an element when it fires on it, or when the element is in the rule's domain and the outcome does not
// depend on a required fact the model leaves undeclared. It is a by-product of evaluation and never changes a finding.
type Coverage struct {
	// Decided: rule id → elements the rule decided. Every rule of an applicable pack that ran appears, with 0 when
	// it decided nothing (an empty domain); a rule that failed to evaluate does not.
	Decided map[string]int `json:"decided"`
	// NotChecked: rule id → the domain elements the rule neither fired on nor could decide, sorted. A rule without
	// such elements is absent.
	NotChecked map[string][]string `json:"not_checked"`
}

// Ran reports whether the rule ran over the model (its pack applied and it evaluated without error).
func (c *Coverage) Ran(ruleID string) bool {
	if c == nil {
		return false
	}
	_, ok := c.Decided[ruleID]
	return ok
}

// CoverageEvaluator is implemented by evaluators that also report coverage (the Engine). Callers probe for it: the
// Noop evaluator does not.
type CoverageEvaluator interface {
	EvaluateCoverage(ctx context.Context, a *model.Architecture, p Policy) ([]model.Finding, Coverage, error)
}
