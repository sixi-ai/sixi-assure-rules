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
	// required(code) = max(regime minimum or default, Requirements[code]).
	Requirements map[string]int
	// Knowledge carries the facts of the assistant's knowledge base for the drift rules (ADR-035):
	// nil → `kb.available` is false and every lookup is empty, so drift rules stay silent.
	Knowledge *KnowledgeFacts
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
