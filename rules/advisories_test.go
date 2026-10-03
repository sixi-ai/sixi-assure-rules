package rules

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The rule-pack advisory list (docs/03 §Defect disclosure, rules/README.md §Advisories, docs/18 WS-J J4).
// Production keeps rules/advisories.json empty until an advisory is published; rules/advisories.example.json
// is the fixture that exercises every field. Both are validated here against the documented schema, and
// every advisory must name a pack that exists in rules/packs and rules that exist in that pack — an advisory
// about a rule nobody ships is a typo, not a disclosure.

type advisoryFile struct {
	Schema     string         `json:"schema"`
	Updated    string         `json:"updated"`
	Signature  *string        `json:"signature"`
	Advisories []advisory     `json:"advisories"`
	Extra      map[string]any `json:"-"`
}

type advisory struct {
	AdvisoryID             string   `json:"advisory_id"`
	Pack                   string   `json:"pack"`
	PackVersion            string   `json:"pack_version"`
	AffectedRules          []string `json:"affected_rules"`
	Nature                 string   `json:"nature"`
	Published              string   `json:"published"`
	Summary                string   `json:"summary"`
	ReplacementPackVersion *string  `json:"replacement_pack_version"`
}

var (
	advisoryIDRe      = regexp.MustCompile(`^SAA-[0-9]{4}-[0-9]{3}$`)
	advisoryVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	advisoryNatures   = map[string]bool{"false_negative": true, "false_positive": true, "wrong_citation": true, "wrong_severity": true, "wrong_patch": true}
	// The summary assesses and evidences (CLAUDE.md §1.5); none of these may appear in a published sentence.
	advisoryForbidden = regexp.MustCompile(`(?i)\bcertif(y|ies|ied|ication)|\bguarantee|\bcompliant with\b|\bprov(e|es|en)\b`)
)

const advisorySchema = "sixi-assure/rule-advisories/v1"

func loadAdvisoryFile(t *testing.T, path string) advisoryFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	// Unknown top-level keys are a schema drift; decode strictly.
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var f advisoryFile
	require.NoError(t, dec.Decode(&f), "%s: not the documented schema", path)
	return f
}

func TestAdvisoryFilesMatchTheDocumentedSchema(t *testing.T) {
	t.Parallel()
	cat, err := LoadDir(repoPath("packs"))
	require.NoError(t, err)
	packs := map[string]*Pack{}
	for _, p := range cat.Packs() {
		packs[p.Pack] = p
	}

	tests := []struct {
		name    string
		path    string
		minSize int // the fixture must exercise the schema; production may be empty
	}{
		{"production list", repoPath("advisories.json"), 0},
		{"example fixture", repoPath("advisories.example.json"), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := loadAdvisoryFile(t, tc.path)
			assert.Equal(t, advisorySchema, f.Schema)
			updated, err := time.Parse("2006-01-02", f.Updated)
			require.NoError(t, err, "updated must be YYYY-MM-DD")
			if f.Signature != nil {
				assert.NotEmpty(t, *f.Signature, "signature is null until signing ships, or a non-empty signature")
			}
			require.NotNil(t, f.Advisories, "advisories must be a list, possibly empty")
			assert.GreaterOrEqual(t, len(f.Advisories), tc.minSize)

			seen := map[string]bool{}
			for i, a := range f.Advisories {
				t.Run(a.AdvisoryID, func(t *testing.T) {
					assert.Regexp(t, advisoryIDRe, a.AdvisoryID, "advisory_id is SAA-YYYY-NNN")
					assert.False(t, seen[a.AdvisoryID], "advisory_id reused")
					seen[a.AdvisoryID] = true

					p, ok := packs[a.Pack]
					require.True(t, ok, "pack %q is not a pack of rules/packs", a.Pack)
					assert.Regexp(t, advisoryVersionRe, a.PackVersion, "pack_version is MAJOR.MINOR.PATCH")

					require.NotEmpty(t, a.AffectedRules, "at least one affected rule")
					for _, id := range a.AffectedRules {
						assert.Regexp(t, ruleIDRe, id)
						r, ok := cat.Rule(id)
						require.True(t, ok, "affected rule %s does not exist", id)
						assert.Equal(t, p.Pack, r.Pack, "affected rule %s is not in pack %s", id, a.Pack)
					}

					assert.True(t, advisoryNatures[a.Nature], "nature %q is not one of the five", a.Nature)

					published, err := time.Parse("2006-01-02", a.Published)
					require.NoError(t, err, "published must be YYYY-MM-DD")
					assert.False(t, published.After(updated), "an advisory published after the file's updated date")

					assert.NotEmpty(t, strings.TrimSpace(a.Summary))
					assert.LessOrEqual(t, len([]rune(a.Summary)), 300, "summary is at most 300 characters")
					assert.NotRegexp(t, advisoryForbidden, a.Summary, "summary wording: assesses, evidences, proposes, records")

					if a.ReplacementPackVersion != nil {
						assert.Regexp(t, advisoryVersionRe, *a.ReplacementPackVersion)
						assert.NotEqual(t, a.PackVersion, *a.ReplacementPackVersion, "the replacement is a different version")
					}
					_ = i
				})
			}
		})
	}
}

// The example fixture must stay recognisable as a fixture: its summaries say so, so a reader who finds it
// synced by mistake is not misled, and the production file carries no "example" entry.
func TestAdvisoryExampleIsLabelledAndProductionIsNot(t *testing.T) {
	t.Parallel()
	example := loadAdvisoryFile(t, repoPath("advisories.example.json"))
	for _, a := range example.Advisories {
		assert.Contains(t, strings.ToLower(a.Summary), "example fixture", "%s: the fixture's summary names itself as one", a.AdvisoryID)
	}
	prod := loadAdvisoryFile(t, repoPath("advisories.json"))
	for _, a := range prod.Advisories {
		assert.NotContains(t, strings.ToLower(a.Summary), "example fixture", "%s: a fixture entry in the production list", a.AdvisoryID)
	}
}
