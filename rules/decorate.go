package rules

import "github.com/sixi-ai/sixi-assure-rules/model"

// The read-time decoration of a finding (docs/03 §Causes, ADR-093 decision 9, ADR-095). The cause, the rule's
// documentation references and the framework-native remediation belong to the loaded catalog and to the architecture
// a finding is read against, not to the stored row: a finding persisted before a rule was mapped, or by an older
// build, is decorated on every read, so every body that carries a finding (the finding routes, an Architecture's
// `findings`, a patch, evaluate or draft result, the MCP `list_findings` tool) carries the same fields.

// ReferencesOf returns the documentation references of a rule as a finding carries them, nil when the rule lists none
// or is not loaded.
func (c *Catalog) ReferencesOf(ruleID string) []model.FindingReference {
	if c == nil {
		return nil
	}
	r, ok := c.Rule(ruleID)
	if !ok {
		return nil
	}
	return findingReferences(r.References)
}

func findingReferences(refs []Reference) []model.FindingReference {
	if len(refs) == 0 {
		return nil
	}
	out := make([]model.FindingReference, 0, len(refs))
	for _, ref := range refs {
		out = append(out, model.FindingReference{Kind: ref.Kind, Title: ref.Title, URL: ref.URL, FetchedAt: ref.FetchedAt})
	}
	return out
}

// RemediationFrameworkOf is the framework-native remediation of a finding read against architecture a, nil when the
// finding's elements settle no framework the rule has a sentence for (or a or the catalog is nil).
func (c *Catalog) RemediationFrameworkOf(a *model.Architecture, f model.Finding) *model.FindingRemediationFramework {
	if c == nil || a == nil {
		return nil
	}
	fr, ok := c.FrameworkRemediationFor(f.RuleID, a, f.IDs)
	if !ok {
		return nil
	}
	return &model.FindingRemediationFramework{Framework: fr.Framework, Label: FrameworkLabel(fr.Framework), Text: fr.Text, Source: fr.Source}
}

// Decorate fills in, on each finding, the fields that are the catalog's: the cause id (kept when already set), the
// rule's documentation references and, read against architecture a (nil: none), the framework-native remediation.
// It edits fs in place and returns it; a nil catalog leaves the findings as they are.
func (c *Catalog) Decorate(a *model.Architecture, fs []model.Finding) []model.Finding {
	if c == nil {
		return fs
	}
	for i := range fs {
		f := &fs[i]
		if f.Cause == "" {
			if cause, ok := c.CauseOf(f.RuleID); ok {
				f.Cause = cause.ID
			}
		}
		f.References = c.ReferencesOf(f.RuleID)
		f.RemediationFramework = c.RemediationFrameworkOf(a, *f)
	}
	return fs
}
