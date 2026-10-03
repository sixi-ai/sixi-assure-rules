// Package sarif renders rule findings as a SARIF 2.1.0 log — the format GitHub code scanning,
// Azure DevOps and most IDEs read — and as a short Markdown summary for a CI step summary or a
// pull-request comment.
//
// It is a projection, never a source: every result is a finding a rule created (CLAUDE.md §1.2),
// every clause id is one the rule cited (§1.4 — none is added, and one the caller cannot resolve
// is marked "no clause found", never described), and the wording assesses and evidences (§1.5).
//
// The package is standard library only, so the thin API client (cmd/assure) and the public
// rules repository (github.com/sixi-ai/sixi-assure-rules, synced by scripts/sync-public-rules.sh)
// can both use it without the rule engine's dependencies.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
)

const (
	// Version is the SARIF version this package writes.
	Version = "2.1.0"
	// SchemaURI is the published JSON schema of SARIF 2.1.0 (OASIS errata 01).
	SchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	// ToolName is driver.name. GitHub code scanning groups alerts by it.
	ToolName = "Sixi Assure"
	// InformationURI is driver.informationUri.
	InformationURI = "https://sixi.ai"
	// FingerprintKey names the partial fingerprint (versioned: a change of recipe is a new key).
	FingerprintKey = "sixiAssureFinding/v1"
)

// Finding is the input: one finding as a rule produced it. It is deliberately a plain struct so
// both the engine's model.Finding and the API's Finding schema map onto it without an import.
type Finding struct {
	RuleID      string
	Pack        string
	Severity    string // critical | high | medium | low | info
	Title       string
	Message     string
	Remediation string
	// Citations are the clause ids the rule cites, REGIME:DOC:REF. Passed through, never added to.
	Citations []string
	// ElementIDs are the model elements (nodes, edges, groups) the finding names.
	ElementIDs []string
	// Status is the reviewer's decision in the product (open, accepted, false_positive, fixed);
	// empty or "open" is undecided. A decided finding is written as a suppressed result.
	Status string
	// ArtifactURI overrides Options.ArtifactURI for this finding (a run over several models).
	ArtifactURI string
	// Line is the 1-based line of the model file the finding points at; 0 → 1. See LineOf.
	Line int
	// References are the rule's documentation references (ADR-095): documents that are not law, by url and the day
	// they were read. Written to result.properties.references and the rule's help, never as a clause.
	References []Reference
}

// Reference is one documentation reference of the rule behind a finding (the API's FindingReference).
type Reference struct {
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	FetchedAt string `json:"fetched_at"`
}

// Options are the run-level inputs.
type Options struct {
	// ToolVersion is driver.version (the CLI or engine version).
	ToolVersion string
	// ArtifactURI is the model file the findings are about, relative to the repository root and
	// with forward slashes, which is what code scanning maps onto a file in the pull request.
	ArtifactURI string
	// ClauseKnown, when set, resolves a clause id against the corpus. An id it rejects is
	// written as "<id> (no clause found)". Nil → ids are passed through unresolved.
	ClauseKnown func(id string) bool
}

// Log is a SARIF 2.1.0 log with the subset of properties this package writes.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one tool invocation.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool wraps the driver.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes Sixi Assure and the rules that produced results in this run.
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

// Rule is a reportingDescriptor.
type Rule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     Text           `json:"shortDescription"`
	FullDescription      *Text          `json:"fullDescription,omitempty"`
	Help                 *Help          `json:"help,omitempty"`
	DefaultConfiguration *Configuration `json:"defaultConfiguration,omitempty"`
	Properties           RuleProperties `json:"properties"`
}

// Text is a plain-text message string.
type Text struct {
	Text string `json:"text"`
}

// Help carries the remediation and the cited clause ids, as text and as Markdown.
type Help struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// Configuration is a rule's default level.
type Configuration struct {
	Level string `json:"level"`
}

// RuleProperties is the property bag of a rule. GitHub reads `tags` and `security-severity`.
type RuleProperties struct {
	Tags             []string `json:"tags"`
	Pack             string   `json:"pack,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Clauses          []string `json:"clauses,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

// Result is one finding.
type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Text              `json:"message"`
	Locations           []Location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Suppressions        []Suppression     `json:"suppressions,omitempty"`
	Properties          ResultProperties  `json:"properties"`
}

// ResultProperties is the property bag of a result.
type ResultProperties struct {
	Severity   string      `json:"severity,omitempty"`
	Pack       string      `json:"pack,omitempty"`
	Clauses    []string    `json:"clauses,omitempty"`
	Elements   []string    `json:"elements,omitempty"`
	References []Reference `json:"references,omitempty"`
}

// Location points at the model file and names the model elements.
type Location struct {
	PhysicalLocation PhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// PhysicalLocation is the model file.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

// ArtifactLocation is the model file's URI.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region is the line a result points at (code scanning needs one to annotate a diff).
type Region struct {
	StartLine int `json:"startLine"`
}

// LogicalLocation is a model element by id.
type LogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Suppression records a reviewer's decision taken in the product.
type Suppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

// Level maps a finding severity onto a SARIF level: critical and high → error, medium →
// warning, low, info and anything unrecognised → note.
func Level(severity string) string {
	switch norm(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the CVSS-like score GitHub uses to label an alert critical/high/medium/low.
func securitySeverity(severity string) string {
	switch norm(severity) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low":
		return "3.0"
	default:
		return ""
	}
}

// Fingerprint is stable across runs and model versions: the rule id and the sorted element ids,
// so reordering a model or rewording a message never re-opens an alert.
func Fingerprint(ruleID string, elementIDs []string) string {
	ids := cleanList(elementIDs)
	sort.Strings(ids)
	h := sha256.New()
	_, _ = io.WriteString(h, strings.TrimSpace(ruleID))
	for _, id := range ids {
		_, _ = io.WriteString(h, "\x00"+id)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Build renders findings as a SARIF log with one run. Rules are listed once each, sorted by id;
// results keep the order given.
func Build(findings []Finding, o Options) Log {
	// Rules sorted by id, first occurrence of each id wins for its descriptive fields.
	byID := map[string]Finding{}
	ids := []string{}
	for _, f := range findings {
		id := clean(f.RuleID)
		if _, ok := byID[id]; !ok {
			byID[id] = f
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	rules := make([]Rule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		index[id] = i
		rules = append(rules, buildRule(id, byID[id], o))
	}

	results := make([]Result, 0, len(findings))
	for _, f := range findings {
		results = append(results, buildResult(f, index[clean(f.RuleID)], o))
	}
	return Log{
		Schema:  SchemaURI,
		Version: Version,
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name: ToolName, Version: clean(o.ToolVersion), InformationURI: InformationURI, Rules: rules,
			}},
			Results: results,
		}},
	}
}

// Write encodes the log as indented JSON.
func (l Log) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(l)
}

func buildRule(id string, f Finding, o Options) Rule {
	title := clean(f.Title)
	if title == "" {
		title = id
	}
	cites := cleanList(f.Citations)
	var help, md strings.Builder
	if r := clean(f.Remediation); r != "" {
		help.WriteString("Remediation: " + r + "\n")
		md.WriteString("**Remediation:** " + mdEscape(r) + "\n\n")
	}
	if len(cites) > 0 {
		help.WriteString("Cites: " + strings.Join(citeLabels(cites, o.ClauseKnown), ", ") + "\n")
		md.WriteString("**Cites:** " + mdCites(cites, o.ClauseKnown) + "\n\n")
	} else {
		help.WriteString("Cites: no clause (the rule cites none)\n")
		md.WriteString("**Cites:** no clause (the rule cites none)\n\n")
	}
	if refs := cleanReferences(f.References); len(refs) > 0 {
		texts, mds := make([]string, 0, len(refs)), make([]string, 0, len(refs))
		for _, r := range refs {
			texts = append(texts, r.Title+" <"+r.URL+"> (fetched "+r.FetchedAt+")")
			mds = append(mds, mdEscape(r.Title)+" <"+r.URL+"> (fetched "+mdEscape(r.FetchedAt)+")")
		}
		help.WriteString("Documentation (not a clause): " + strings.Join(texts, "; ") + "\n")
		md.WriteString("**Documentation (not a clause):** " + strings.Join(mds, "; ") + "\n\n")
	}
	help.WriteString(disclaimer)
	md.WriteString(disclaimer)

	tags := []string{"security", "sixi-assure"}
	if p := clean(f.Pack); p != "" {
		tags = append(tags, "pack:"+p)
	}
	tags = append(tags, cites...)
	return Rule{
		ID:                   id,
		ShortDescription:     Text{Text: title},
		FullDescription:      &Text{Text: title},
		Help:                 &Help{Text: help.String(), Markdown: md.String()},
		DefaultConfiguration: &Configuration{Level: Level(f.Severity)},
		Properties: RuleProperties{
			Tags: tags, Pack: clean(f.Pack), Severity: norm(f.Severity), Clauses: cites,
			SecuritySeverity: securitySeverity(f.Severity),
		},
	}
}

func buildResult(f Finding, ruleIndex int, o Options) Result {
	ruleID := clean(f.RuleID)
	cites := cleanList(f.Citations)
	elements := cleanList(f.ElementIDs)

	msg := clean(f.Message)
	if msg == "" {
		msg = clean(f.Title)
	}
	if msg == "" {
		msg = ruleID
	}
	if len(cites) > 0 {
		msg += " Cites: " + strings.Join(citeLabels(cites, o.ClauseKnown), ", ") + "."
	} else {
		msg += " Cites: no clause."
	}

	uri := clean(f.ArtifactURI)
	if uri == "" {
		uri = clean(o.ArtifactURI)
	}
	line := f.Line
	if line < 1 {
		line = 1
	}
	loc := Location{PhysicalLocation: PhysicalLocation{
		ArtifactLocation: ArtifactLocation{URI: uri}, Region: Region{StartLine: line},
	}}
	for _, id := range elements {
		loc.LogicalLocations = append(loc.LogicalLocations, LogicalLocation{Name: id, Kind: "element"})
	}

	r := Result{
		RuleID: ruleID, RuleIndex: ruleIndex, Level: Level(f.Severity),
		Message:             Text{Text: sarifText(msg)},
		Locations:           []Location{loc},
		PartialFingerprints: map[string]string{FingerprintKey: Fingerprint(ruleID, elements)},
		Properties: ResultProperties{
			Severity: norm(f.Severity), Pack: clean(f.Pack), Clauses: cites, Elements: elements,
			References: cleanReferences(f.References),
		},
	}
	if s := norm(f.Status); s != "" && s != "open" {
		r.Suppressions = []Suppression{{
			Kind: "external", Status: "accepted",
			Justification: "decided in Sixi Assure by a reviewer: " + s,
		}}
	}
	return r
}

// sarifText escapes a result message for SARIF 2.1.0 §3.11.6: in a plain-text message "[" and
// "]" delimit embedded links ("[text](n)"), so model text could otherwise make a viewer render a
// link; a backslash escapes them and is itself escaped.
func sarifText(s string) string {
	return strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`).Replace(s)
}

// disclaimer closes every rule's help (CLAUDE.md §1.5).
const disclaimer = "Sixi Assure assesses the design against a deterministic rule and evidences the result; " +
	"it does not certify anything. Check each clause at its source."

// citeLabels renders clause ids; an id the resolver rejects says so instead of being described.
func citeLabels(ids []string, known func(string) bool) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if known != nil && !known(id) {
			out = append(out, id+" (no clause found)")
			continue
		}
		out = append(out, id)
	}
	return out
}

func mdCites(ids []string, known func(string) bool) string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if known != nil && !known(id) {
			out = append(out, "`"+mdCode(id)+"` (no clause found)")
			continue
		}
		out = append(out, "`"+mdCode(id)+"`")
	}
	return strings.Join(out, ", ")
}

// LineOf returns the 1-based line of the first place a model file declares the element id — a
// JSON `"id": "<id>"`, a YAML `id: <id>` or an XML `id="<id>"` — or 0 when it cannot tell.
func LineOf(content []byte, id string) int {
	id = strings.TrimSpace(id)
	if id == "" || len(content) == 0 {
		return 0
	}
	q := regexp.QuoteMeta(id)
	re, err := regexp.Compile(`(?m)(?:"id"\s*:\s*"` + q + `"|\bid\s*[:=]\s*["']?` + q + `["']?(?:\s|,|}|$))`)
	if err != nil {
		return 0
	}
	loc := re.FindIndex(content)
	if loc == nil {
		return 0
	}
	return 1 + strings.Count(string(content[:loc[0]]), "\n")
}

// FirstLine is LineOf over several ids: the first id found wins; 0 when none is.
func FirstLine(content []byte, ids []string) int {
	for _, id := range ids {
		if l := LineOf(content, id); l > 0 {
			return l
		}
	}
	return 0
}

// norm is a lower-cased, trimmed severity or status.
func norm(s string) string { return strings.ToLower(clean(s)) }

// clean keeps text single-line and printable: rule messages carry model content, which is
// untrusted and must not smuggle control characters into a log or an annotation.
func clean(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
}

// cleanList cleans, drops empties and de-duplicates, keeping the first order.
func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = clean(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// cleanReferences keeps the references a reader can follow: an https url and a title, each field trimmed; nil when
// none is left.
func cleanReferences(in []Reference) []Reference {
	var out []Reference
	for _, r := range in {
		r = Reference{Kind: clean(r.Kind), Title: clean(r.Title), URL: clean(r.URL), FetchedAt: clean(r.FetchedAt)}
		if r.Title == "" || !strings.HasPrefix(r.URL, "https://") {
			continue
		}
		if r.Kind == "" {
			r.Kind = "document"
		}
		out = append(out, r)
	}
	return out
}
