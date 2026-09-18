package rules

import (
	"sort"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Grouping findings by cause (docs/03 §Causes). A reader who opens a bad twin meets thirty-odd
// findings raised by a handful of shortcuts; the panel and the exports therefore lead with the few
// causes behind them ("Command path — 6 open findings … Fix: …") and keep the findings as the
// receipts underneath. The grouping is a pure projection of the taxonomy and the findings: it
// decides nothing (CLAUDE.md §1.2) and the web mirrors this ordering client-side, so every tie is
// broken here in a way a second implementation can reproduce.

// otherCauseTitle labels the trailing group for findings whose rule has no cause, which happens
// when a catalog was loaded without a causes file (synthetic packs in tests, an operator's
// RULES_DIR) or when a finding names a rule no loaded pack knows.
const otherCauseTitle = "Other findings"

// CauseGroup is the open findings behind one cause (docs/03 §Causes), the projection the panel and
// the exports lead with.
type CauseGroup struct {
	Cause Cause
	// Findings are the open findings of this cause, most severe first (see GroupByCause).
	Findings []model.Finding
	// Worst is the severity of Findings[0], the chip the group is shown with.
	Worst string
	// Elements are the distinct element ids across the findings, in first-seen order.
	Elements []string
	// Fix is the remediation of Findings[0] — the worst finding, the one a reader acts on first —
	// falling back to the first remediation stated in Findings order, else empty.
	Fix string
	// Patchable are the distinct rule ids of the group whose finding ships a patch template
	// (HasPatch), in Findings order: the one-click fixes the panel offers on top of Fix.
	Patchable []string
}

// GroupByCause groups the OPEN findings (status "open"; accepted, fixed and false-positive ones are
// left out) by the cause of their rule.
//
// Ordering, mirrored by the web:
//
//   - groups by worst severity (critical → info), then by number of findings (descending), then by
//     the order of the causes in the taxonomy (causes.yaml file order);
//   - the trailing group of findings without a cause (Cause{ID: "", Title: "Other findings"}) comes
//     last whatever its severity;
//   - findings inside a group by severity (critical → info), then rule id, then first element id
//     (findings without an element sort first), then finding id.
//
// The group's Fix is the worst finding's remediation; the rules that can be fixed with a patch
// template are listed separately in Patchable.
//
// A nil catalog yields no groups at all: without a taxonomy there is nothing to lead with, and the
// caller (panel, export) simply omits the section.
func GroupByCause(c *Catalog, findings []model.Finding) []CauseGroup {
	if c == nil {
		return nil
	}
	groups := map[string]*CauseGroup{}
	order := make([]string, 0, len(c.causes)+1)
	for _, f := range findings {
		if f.Status != model.StatusOpen {
			continue
		}
		cause, ok := c.CauseOf(f.RuleID)
		if !ok {
			cause = Cause{Title: otherCauseTitle}
		}
		g, seen := groups[cause.ID]
		if !seen {
			g = &CauseGroup{Cause: cause}
			groups[cause.ID] = g
			order = append(order, cause.ID)
		}
		g.Findings = append(g.Findings, f)
	}
	if len(groups) == 0 {
		return nil
	}

	// rank is the taxonomy position of a cause; the uncaused group sorts after every cause.
	rank := make(map[string]int, len(c.causes))
	for i, cause := range c.causes {
		rank[cause.ID] = i
	}
	out := make([]CauseGroup, 0, len(order))
	for _, id := range order {
		g := groups[id]
		sortFindingsBySeverity(g.Findings)
		g.Worst = g.Findings[0].Severity
		g.Elements = distinctElements(g.Findings)
		g.Fix = fixOf(g.Findings)
		g.Patchable = patchableRules(g.Findings)
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Cause.ID == "") != (b.Cause.ID == "") {
			return b.Cause.ID == "" // the uncaused group trails
		}
		if ra, rb := model.SeverityRank(a.Worst), model.SeverityRank(b.Worst); ra != rb {
			return ra < rb
		}
		if len(a.Findings) != len(b.Findings) {
			return len(a.Findings) > len(b.Findings)
		}
		return rank[a.Cause.ID] < rank[b.Cause.ID]
	})
	return out
}

// sortFindingsBySeverity orders the findings of one group the way the panel and the exports list
// them: most severe first, then by rule, then by the element the reader will look for.
func sortFindingsBySeverity(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := model.SeverityRank(a.Severity), model.SeverityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if ea, eb := firstElement(a), firstElement(b); ea != eb {
			return ea < eb
		}
		return a.ID < b.ID
	})
}

func firstElement(f model.Finding) string {
	if len(f.IDs) == 0 {
		return ""
	}
	return f.IDs[0]
}

// distinctElements lists the element ids the group touches, in the order the sorted findings name
// them, so the reader sees the worst finding's elements first.
func distinctElements(fs []model.Finding) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		for _, id := range f.IDs {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fixOf picks the one remediation the group is headlined with: the worst finding's, because that is
// what a reader acts on first. A worst finding whose rule states none falls back to the first
// remediation in the group. The text is the rule's, never generated here.
func fixOf(fs []model.Finding) string {
	for _, f := range fs {
		if f.Remediation != "" {
			return f.Remediation
		}
	}
	return ""
}

// patchableRules lists the rules of the group that ship a patch template, so the panel can offer a
// proposed patch beside the fix. A patch is still only ever a proposal a person accepts
// (CLAUDE.md §1.3).
func patchableRules(fs []model.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if !f.HasPatch || f.RuleID == "" || seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		out = append(out, f.RuleID)
	}
	return out
}
