package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// Causes group findings by the design invariant they break (docs/03 §Causes). A finding is a
// symptom — "this edge has no approval step" — while a cause is the one sentence a reader needs:
// "nothing an AI component does reaches a machine without a human approval". The taxonomy is
// authored by hand in causes.yaml and never inferred from tags at runtime, so it stays
// reviewable; loading fails when a rule has no cause or a cause names a rule that does not exist.

// Cause is one design invariant the rules evidence (causes.yaml, docs/03 §Causes).
type Cause struct {
	ID       string   `yaml:"id" json:"id"`
	Title    string   `yaml:"title" json:"title"`
	Sentence string   `yaml:"sentence" json:"sentence"`
	Rules    []string `yaml:"rules" json:"rules"`
}

// CausesFileName is the curated taxonomy next to the packs directory (causes.yaml for
// rules/packs). It is optional: a packs directory without it loads with no causes at all.
const CausesFileName = "causes.yaml"

const (
	causeTitleMax    = 32  // a grouping label in the dock and in exports
	causeSentenceMax = 200 // one sentence a reader takes in at a glance
)

var (
	causeIDRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	// causeWordingRe rejects the wording the product never uses (CLAUDE.md §1.5): it assesses,
	// evidences and proposes.
	causeWordingRe = regexp.MustCompile(`(?i)\b(?:compliant|compliance|certif\w*|guarantee\w*|confirm\w*|attest\w*|warrant\w*)\b`)
)

type causesFile struct {
	Causes []Cause `yaml:"causes"`
}

// LoadCauses reads and validates a causes file. It checks unique ids ([a-z0-9-], lower case), a
// non-empty title and sentence within their budgets, a rule listed at most once across all causes,
// and no wording violation in a title or a sentence. It does not know the catalog, so it cannot
// tell whether a listed rule exists: that check happens when the causes are attached to a catalog.
func LoadCauses(path string) ([]Cause, error) {
	raw, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-controlled configuration (RULES_DIR)
	if err != nil {
		return nil, fmt.Errorf("causes: %w", err)
	}
	return parseCauses(filepath.Base(path), raw)
}

func parseCauses(name string, data []byte) ([]Cause, error) {
	var cf causesFile
	if err := yaml.UnmarshalWithOptions(data, &cf, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("causes invalid: %s: %w", name, err)
	}
	var problems []error
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Errorf("%s: %s", name, fmt.Sprintf(format, args...)))
	}
	if len(cf.Causes) == 0 {
		fail("no causes found (remove the file or list the causes)")
	}
	seenID := map[string]bool{}
	seenRule := map[string]string{}
	out := make([]Cause, 0, len(cf.Causes))
	for i, c := range cf.Causes {
		where := c.ID
		if where == "" {
			where = fmt.Sprintf("causes[%d]", i)
		}
		if !causeIDRe.MatchString(c.ID) {
			fail("cause %s: id %q must match %s", where, c.ID, causeIDRe)
		} else if seenID[c.ID] {
			fail("cause %s: duplicate id", where)
		}
		seenID[c.ID] = true
		switch title := strings.TrimSpace(c.Title); {
		case title == "":
			fail("cause %s: title is required", where)
		case len(title) > causeTitleMax:
			fail("cause %s: title is %d characters, at most %d", where, len(title), causeTitleMax)
		}
		switch sentence := strings.TrimSpace(c.Sentence); {
		case sentence == "":
			fail("cause %s: sentence is required", where)
		case len(sentence) > causeSentenceMax:
			fail("cause %s: sentence is %d characters, at most %d", where, len(sentence), causeSentenceMax)
		}
		for _, f := range []struct{ field, text string }{{"title", c.Title}, {"sentence", c.Sentence}} {
			if m := causeWordingRe.FindString(f.text); m != "" {
				fail("cause %s: %s says %q — the product assesses, evidences and proposes (CLAUDE.md §1.5)", where, f.field, m)
			}
		}
		if len(c.Rules) == 0 {
			fail("cause %s: lists no rules", where)
		}
		for _, id := range c.Rules {
			switch {
			case !ruleIDRe.MatchString(id):
				fail("cause %s: rule id %q must match %s", where, id, ruleIDRe)
			case seenRule[id] != "":
				fail("cause %s: rule %s is already listed under cause %s (a rule has exactly one cause)", where, id, seenRule[id])
			default:
				seenRule[id] = c.ID
			}
		}
		out = append(out, Cause{ID: c.ID, Title: c.Title, Sentence: c.Sentence, Rules: slices.Clone(c.Rules)})
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("causes invalid: %w", errors.Join(problems...))
	}
	return out, nil
}

// Causes returns the loaded causes in file order, or nil when no causes file was present.
func (c *Catalog) Causes() []Cause {
	if len(c.causes) == 0 {
		return nil
	}
	out := make([]Cause, len(c.causes))
	for i, cause := range c.causes {
		out[i] = cloneCause(cause)
	}
	return out
}

// CauseOf returns the cause a rule belongs to. It reports false for an unknown rule and for every
// rule when no causes file was loaded.
func (c *Catalog) CauseOf(ruleID string) (Cause, bool) {
	cause, ok := c.causeByRule[ruleID]
	if !ok {
		return Cause{}, false
	}
	return cloneCause(cause), true
}

func cloneCause(c Cause) Cause {
	c.Rules = slices.Clone(c.Rules)
	return c
}

// causesPathFor is the causes file that governs a packs directory: rules/packs → causes.yaml.
func causesPathFor(packsDir string) string {
	return filepath.Join(packsDir, "..", CausesFileName)
}

// attachCausesFrom loads the causes file when it exists and binds it to the catalog. A missing
// file is not an error (packs loaded from a temp directory or an operator's RULES_DIR carry no
// curated taxonomy); a file that is present must cover the catalog exactly.
func (c *Catalog) attachCausesFrom(path string) error {
	st, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("causes: %w", err)
	case st.IsDir():
		return nil
	}
	causes, err := LoadCauses(path)
	if err != nil {
		return err
	}
	return c.setCauses(filepath.Base(path), causes)
}

// setCauses binds causes to the catalog after checking that they cover it exactly: every rule has
// a cause and every listed rule id exists.
func (c *Catalog) setCauses(name string, causes []Cause) error {
	byRule := make(map[string]Cause, len(c.byID))
	var unknown []string
	for _, cause := range causes {
		for _, id := range cause.Rules {
			if _, ok := c.byID[id]; !ok {
				unknown = append(unknown, id)
				continue
			}
			byRule[id] = cause
		}
	}
	var uncovered []string
	for id := range c.byID {
		if _, ok := byRule[id]; !ok {
			uncovered = append(uncovered, id)
		}
	}
	var problems []error
	if len(uncovered) > 0 {
		sort.Strings(uncovered)
		problems = append(problems, fmt.Errorf("%s: no cause for %s (every rule belongs to exactly one cause)", name, strings.Join(uncovered, ", ")))
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		problems = append(problems, fmt.Errorf("%s: unknown rule %s (not in any loaded pack)", name, strings.Join(unknown, ", ")))
	}
	if len(problems) > 0 {
		return fmt.Errorf("causes invalid: %w", errors.Join(problems...))
	}
	c.causes = causes
	c.causeByRule = byRule
	return nil
}
