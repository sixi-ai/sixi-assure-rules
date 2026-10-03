package verify

import (
	"encoding/json"
	"slices"
	"strings"
)

// AdvisorySchema is the rule-pack advisory list's schema (rules/README.md §Advisories).
const AdvisorySchema = "sixi-assure/rule-advisories/v1"

type advisoryFile struct {
	Schema     string     `json:"schema"`
	Updated    string     `json:"updated"`
	Signature  *string    `json:"signature"`
	Advisories []advisory `json:"advisories"`
}

type advisory struct {
	AdvisoryID    string   `json:"advisory_id"`
	Pack          string   `json:"pack"`
	PackVersion   string   `json:"pack_version"`
	PackHash      string   `json:"pack_hash"`
	AffectedRules []string `json:"affected_rules"`
	Nature        string   `json:"nature"`
	Published     string   `json:"published"`
	Summary       string   `json:"summary"`
	Replacement   *string  `json:"replacement_pack_version"`
}

// pinnedPack is a pack the input pins: from the loaded catalog when its combined hash is the
// report's, else from the report's own pack list.
type pinnedPack struct{ pack, version, hash string }

// checkAdvisories flags every advisory against a pack this input pins (ADVISORIES.md in the public
// repository): the verdict on the hashes is unchanged; an advisory says which findings to re-read.
func checkAdvisories(r *Report, raw []byte, from string, doc *reportDoc, lp *loadedPacks) {
	var f advisoryFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Schema != AdvisorySchema {
		r.add(SectionAdvisories, "advisory list", Fail, "%s is not a %s list", from, AdvisorySchema)
		return
	}
	if f.Signature == nil {
		r.add(SectionAdvisories, "advisory list", Info, "%s (updated %s) is unsigned: the list informs, it does not decide", from, oneLine(f.Updated))
	} else {
		r.add(SectionAdvisories, "advisory list", NotChecked, "%s carries a signature this verifier version does not check yet", from)
	}
	var pinned []pinnedPack
	switch {
	case lp != nil && doc != nil && doc.PackHash != "" && doc.PackHash == lp.cat.Hash():
		for _, p := range lp.cat.Packs() {
			pinned = append(pinned, pinnedPack{p.Pack, p.Version, p.Hash()})
		}
	case doc != nil:
		for _, p := range doc.RulePacks {
			pinned = append(pinned, pinnedPack{p.Pack, p.Version, p.Hash})
		}
	}
	if len(pinned) == 0 {
		r.add(SectionAdvisories, "advisories", NotChecked, "the pinned packs and versions are %s", NotPresent)
		return
	}
	fired := map[string]bool{}
	if doc != nil {
		for _, fd := range append(slices.Clone(doc.Findings), doc.AcceptedRisks...) {
			fired[fd.RuleID] = true
		}
	}
	hits := 0
	for _, a := range f.Advisories {
		for _, p := range pinned {
			sameVersion := a.PackVersion == p.version || (a.PackHash != "" && a.PackHash == p.hash)
			if a.Pack != p.pack || !sameVersion {
				continue
			}
			hit := AdvisoryHit{AdvisoryID: a.AdvisoryID, Pack: a.Pack, PackVersion: a.PackVersion, Nature: a.Nature, Summary: a.Summary,
				RulesWithFindings: []string{}, RulesSilent: []string{}}
			if a.Replacement != nil {
				hit.ReplacementPackVersion = *a.Replacement
			}
			for _, id := range a.AffectedRules {
				if fired[id] {
					hit.RulesWithFindings = append(hit.RulesWithFindings, id)
				} else {
					hit.RulesSilent = append(hit.RulesSilent, id)
				}
			}
			r.Advisories = append(r.Advisories, hit)
			hits++
			repl := "no replacement published yet"
			if hit.ReplacementPackVersion != "" {
				repl = "replaced by " + a.Pack + " " + hit.ReplacementPackVersion
			}
			r.add(SectionAdvisories, a.AdvisoryID, Flag, "%s %s (%s), %s; affected rules with findings here: %s; silent here: %s; re-read those findings",
				a.Pack, a.PackVersion, a.Nature, repl, orNoneList(hit.RulesWithFindings), orNoneList(hit.RulesSilent))
		}
	}
	if hits == 0 {
		r.add(SectionAdvisories, "advisories", Pass, "no advisory in %s names a pack version this input pins (%d checked)", from, len(f.Advisories))
	}
}

func orNoneList(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	return strings.Join(xs, ", ")
}
