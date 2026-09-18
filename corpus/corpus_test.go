package corpus_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sixi-ai/sixi-assure-rules/corpus"
	"github.com/sixi-ai/sixi-assure-rules/rules"
)

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{".."}, parts...)...)
}

// TestCorpusLoads is the gate on the redaction script: a malformed or duplicated record after a
// sync fails here, not in production.
func TestCorpusLoads(t *testing.T) {
	t.Parallel()
	if err := corpus.Err(); err != nil {
		t.Fatalf("corpus does not load: %v", err)
	}
	clauses := corpus.All()
	if len(clauses) < 100 {
		t.Fatalf("only %d clauses loaded", len(clauses))
	}
	for _, c := range clauses {
		switch {
		case c.Regime == "":
			t.Errorf("%s: no regime", c.ID)
		case c.Doc == "":
			t.Errorf("%s: no doc", c.ID)
		case c.Title == "" && c.Summary == "":
			t.Errorf("%s: neither title nor summary", c.ID)
		case !strings.HasPrefix(c.ID, c.Regime) && !strings.HasPrefix(c.ID, strings.SplitN(c.ID, ":", 2)[0]):
			t.Errorf("%s: id does not start with its regime %s", c.ID, c.Regime)
		}
		if _, ok := corpus.Disclaimer(c.Regime); !ok {
			t.Errorf("%s: regime %s has no disclaimer", c.ID, c.Regime)
		}
	}
}

// TestRedactedClausesCarryNoVerbatimText: every record the licence policy withholds text for must
// really be free of it. This is the check that keeps the published corpus lawful.
func TestRedactedClausesCarryNoVerbatimText(t *testing.T) {
	t.Parallel()
	redacted := 0
	for _, c := range corpus.All() {
		if c.Redacted == "" {
			continue
		}
		redacted++
		if c.Redacted != "licence" {
			t.Errorf("%s: unexpected redaction marker %q", c.ID, c.Redacted)
		}
		if c.Excerpt != "" {
			t.Errorf("%s: marked redacted but still carries a verbatim excerpt", c.ID)
		}
	}
	if redacted == 0 {
		t.Error("no redacted records at all — the licence policy was not applied")
	}
	t.Logf("%d of %d clauses carry references only (source licence does not permit the text)", redacted, len(corpus.All()))
}

// TestEveryClauseCitedByARuleExists: a finding must always be able to resolve its citation
// (CLAUDE.md §1.4 — unknown → say "no clause found", never invent).
func TestEveryClauseCitedByARuleExists(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat(repoPath("packs")); err != nil {
		t.Skip("packs not present")
	}
	catalog, err := rules.LoadDirWith(repoPath("packs"), rules.LoadOptions{})
	if err != nil {
		t.Fatalf("load packs: %v", err)
	}
	missing := map[string][]string{}
	cited := 0
	for _, r := range catalog.Rules() {
		for _, id := range r.Clauses {
			cited++
			if _, ok := corpus.Lookup(id); !ok {
				missing[id] = append(missing[id], r.ID)
			}
		}
	}
	for id, ruleIDs := range missing {
		t.Errorf("clause %s is cited by %s but is not in the corpus", id, strings.Join(ruleIDs, ", "))
	}
	t.Logf("%d clause citations across %d rules all resolve", cited, len(catalog.Rules()))
}
