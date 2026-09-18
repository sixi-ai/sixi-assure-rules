// Package corpus is the regulatory corpus: one record per clause, keyed by the citation id
// `REGIME:DOC:REF` that every finding carries. The records are embedded, so a binary built from
// this module can resolve a citation without any file on disk.
//
// A record holds our own paraphrase (`Summary`) and, only where the source licence permits
// redistribution, a short verbatim `Excerpt`. Records whose source does not permit it are marked
// `Redacted: "licence"` and carry references only — see NOTICE.md and scripts/redact_corpus.py.
// Nothing in this package asserts compliance: it resolves a citation to the instrument, the
// reference and the official URL, so a reader can check the text at the source.
package corpus

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

//go:embed regimes/*.json disclaimers.json
var files embed.FS

// Clause is one record of the corpus.
type Clause struct {
	ID        string   `json:"id"`        // stable citation, REGIME:DOC:REF
	Regime    string   `json:"regime"`    // regime code, a key of disclaimers.json
	Doc       string   `json:"doc"`       // instrument as cited in the UI and exports
	Ref       string   `json:"ref"`       // article, annex, section or control reference
	Title     string   `json:"title"`     // heading of the provision
	Summary   string   `json:"summary"`   // our paraphrase; never the source's wording
	Excerpt   string   `json:"excerpt"`   // short verbatim text, empty unless the licence permits it
	Version   string   `json:"version"`   // YYYY-MM-DD of the text version used
	Effective string   `json:"effective"` // YYYY-MM-DD the provision applies from, or ""
	AppliesTo []string `json:"applies_to"`
	SourceURL string   `json:"source_url"`
	Tags      []string `json:"tags"`
	Licence   string   `json:"licence"`
	Verified  bool     `json:"verified"`
	Note      string   `json:"note"`
	// Redacted is "licence" when the verbatim text of this clause is withheld here because its
	// source does not permit redistribution. The reference and our paraphrase remain.
	Redacted     string `json:"redacted,omitempty"`
	SupersededBy string `json:"superseded_by,omitempty"`
}

// Cite renders the human-readable citation of a clause: "Doc, Ref — Title".
func (c Clause) Cite() string {
	parts := []string{c.Doc}
	if c.Ref != "" && !strings.Contains(c.Doc, c.Ref) {
		parts = append(parts, c.Ref)
	}
	out := strings.Join(parts, ", ")
	if c.Title != "" {
		out += " — " + c.Title
	}
	return out
}

var (
	once        sync.Once
	byID        map[string]Clause
	all         []Clause
	disclaimers map[string]string
	loadErr     error
)

func load() {
	once.Do(func() {
		byID = map[string]Clause{}
		entries, err := fs.Glob(files, "regimes/*.json")
		if err != nil {
			loadErr = err
			return
		}
		sort.Strings(entries)
		for _, name := range entries {
			b, err := files.ReadFile(name)
			if err != nil {
				loadErr = fmt.Errorf("%s: %w", name, err)
				return
			}
			var records []Clause
			if err := json.Unmarshal(b, &records); err != nil {
				loadErr = fmt.Errorf("%s: %w", name, err)
				return
			}
			for _, r := range records {
				if r.ID == "" {
					loadErr = fmt.Errorf("%s: a record without an id", name)
					return
				}
				if prev, dup := byID[r.ID]; dup {
					loadErr = fmt.Errorf("duplicate clause id %s (%s and %s)", r.ID, prev.Doc, r.Doc)
					return
				}
				byID[r.ID] = r
				all = append(all, r)
			}
		}
		b, err := files.ReadFile("disclaimers.json")
		if err != nil {
			loadErr = err
			return
		}
		if err := json.Unmarshal(b, &disclaimers); err != nil {
			loadErr = fmt.Errorf("disclaimers.json: %w", err)
		}
	})
}

// Err reports a problem in the embedded corpus (malformed file, duplicate id). It is nil in a
// released build; the test suite is the gate.
func Err() error { load(); return loadErr }

// Lookup resolves a citation id such as "AIACT:REG:Art.12".
func Lookup(id string) (Clause, bool) {
	load()
	c, ok := byID[id]
	return c, ok
}

// All returns every clause, ordered by regime file and then by file order.
func All() []Clause {
	load()
	out := make([]Clause, len(all))
	copy(out, all)
	return out
}

// Disclaimer returns the one-sentence disclaimer shown with any statement about a regime.
// Sixi Assure assesses and evidences; it never certifies.
func Disclaimer(regime string) (string, bool) {
	load()
	d, ok := disclaimers[regime]
	return d, ok
}
