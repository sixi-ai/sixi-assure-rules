package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
)

// Status is the outcome of one check.
type Status string

// Statuses. A check that could not be made because its input is absent is NotChecked, never Pass.
const (
	Pass       Status = "pass"
	Fail       Status = "fail"
	NotChecked Status = "not_checked"
	// Flag marks something a reviewer must read that does not make a hash wrong: an advisory
	// against a pinned pack, a pack mismatch the caller allowed.
	Flag Status = "flag"
	Info Status = "info"
)

// Sections, in print order.
const (
	SectionInput           = "input"
	SectionManifest        = "manifest"
	SectionKeys            = "keys"
	SectionSignatures      = "signatures"
	SectionChain           = "chain"
	SectionAnchors         = "anchors"
	SectionReproducibility = "reproducibility"
	SectionAdvisories      = "advisories"
)

var sectionOrder = []string{SectionInput, SectionManifest, SectionKeys, SectionSignatures, SectionChain,
	SectionAnchors, SectionReproducibility, SectionReview, SectionAdvisories}

// NotPresent is the phrase every check uses when the input lacks what it needs.
const NotPresent = "not present in this input"

// Results.
const (
	ResultVerified   = "verified"
	ResultIncomplete = "verified_with_checks_not_made"
	ResultFailed     = "failed"
)

// DoesNotEstablish is the fixed block printed on every run (docs/18 §0, ADR-087 §6).
var DoesNotEstablish = []string{
	"that the model matches the operated system",
	"that the rules are complete or correct",
	"that a corpus paraphrase is the law",
	"that a key held by Sixi (custody vendor) was not misused by its custodian",
	"that a signature here is a qualified electronic signature or seal under ZertES or eIDAS: it is a cryptographic integrity control",
}

// Establishes is what a run without failures evidences, in one sentence.
const Establishes = "Within what this input carries, it evidences: integrity of the hashes, the signing key and its " +
	"validity window, the anchor times, and the reproducibility of the findings with the pinned rule packs."

// Check is one verified fact, or one that could not be verified.
type Check struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Detail  string `json:"detail"`
}

// KeyCustody is one signing key as the verifier read it, and the items it signed in this input.
type KeyCustody struct {
	KeyID     string     `json:"key_id"`
	Custody   string     `json:"custody"`
	Provider  string     `json:"provider,omitempty"`
	State     string     `json:"state,omitempty"`
	ValidFrom *time.Time `json:"valid_from,omitempty"`
	ValidTo   *time.Time `json:"valid_to,omitempty"`
	Signed    []string   `json:"signed,omitempty"`
	Note      string     `json:"note"`
}

// RuleElement is one rule result: a rule id and the element ids it names (sorted).
type RuleElement struct {
	RuleID   string   `json:"rule_id"`
	Elements []string `json:"elements"`
}

func (r RuleElement) String() string { return r.RuleID + " on " + strings.Join(r.Elements, ", ") }

// PackDiff is one pack whose hash or presence differs between the report and the loaded packs.
type PackDiff struct {
	Pack         string `json:"pack"`
	ReportHash   string `json:"report_hash,omitempty"`
	LoadedHash   string `json:"loaded_hash,omitempty"`
	ReportVer    string `json:"report_version,omitempty"`
	LoadedVer    string `json:"loaded_version,omitempty"`
	Disagreement string `json:"disagreement"`
}

// Reproduction is the rules re-run on the snapshot and compared with the report. Missing are
// results the rules produce that the report does not list; Extra are results the report lists that
// the rules do not produce.
type Reproduction struct {
	PacksFrom      string        `json:"packs_from"`
	PackHash       string        `json:"pack_hash"`
	ReportPackHash string        `json:"report_pack_hash,omitempty"`
	PackDiff       []PackDiff    `json:"pack_diff,omitempty"`
	PolicyFrom     string        `json:"policy_from"`
	Regimes        []string      `json:"regimes"`
	Ran            bool          `json:"ran"`
	Matched        []RuleElement `json:"matched"`
	Missing        []RuleElement `json:"missing"`
	Extra          []RuleElement `json:"extra"`
	Notes          []string      `json:"notes,omitempty"`
}

// AdvisoryHit is one advisory against a pack this input pins.
type AdvisoryHit struct {
	AdvisoryID             string   `json:"advisory_id"`
	Pack                   string   `json:"pack"`
	PackVersion            string   `json:"pack_version"`
	Nature                 string   `json:"nature"`
	ReplacementPackVersion string   `json:"replacement_pack_version,omitempty"`
	RulesWithFindings      []string `json:"rules_with_findings"`
	RulesSilent            []string `json:"rules_silent"`
	Summary                string   `json:"summary"`
}

// Report is the whole verification.
type Report struct {
	Tool             string        `json:"tool"`
	Version          string        `json:"verifier_version"`
	Input            string        `json:"input"`
	Kind             string        `json:"input_kind"`
	VerifiedAt       time.Time     `json:"verified_at"`
	Checks           []Check       `json:"checks"`
	Keys             []KeyCustody  `json:"keys,omitempty"`
	Unanchored       string        `json:"unanchored,omitempty"`
	Reproduction     *Reproduction `json:"reproduction,omitempty"`
	Advisories       []AdvisoryHit `json:"advisories,omitempty"`
	Failed           int           `json:"failed"`
	NotChecked       int           `json:"not_checked"`
	Flagged          int           `json:"flagged"`
	Result           string        `json:"result"`
	Establishes      string        `json:"establishes"`
	DoesNotEstablish []string      `json:"does_not_establish"`
}

// Input kinds.
const (
	KindReport    = "assurance_report"
	KindSpotCheck = "spot_check_receipt"
	KindChain     = "chain_export"
	KindBundleDir = "bundle_directory"
	KindBundleZip = "bundle_zip"
)

func (r *Report) add(section, name string, st Status, format string, a ...any) {
	r.Checks = append(r.Checks, Check{Section: section, Name: name, Status: st, Detail: fmt.Sprintf(format, a...)})
}

// finish counts the outcomes and sets the result.
func (r *Report) finish() {
	r.Failed, r.NotChecked, r.Flagged = 0, 0, 0
	for _, c := range r.Checks {
		switch c.Status {
		case Fail:
			r.Failed++
		case NotChecked:
			r.NotChecked++
		case Flag:
			r.Flagged++
		case Pass, Info:
		}
	}
	switch {
	case r.Failed > 0:
		r.Result = ResultFailed
	case r.NotChecked > 0:
		r.Result = ResultIncomplete
	default:
		r.Result = ResultVerified
	}
	r.Establishes = Establishes
	r.DoesNotEstablish = DoesNotEstablish
}

// OK reports a run without a failed check.
func (r *Report) OK() bool { return r.Failed == 0 }

// WriteJSON writes the report as one JSON document.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes the report for a person: one line per check, grouped by section, the result,
// and the fixed block of what verification does not establish. Every string read from the input is
// kept on one printable line (it may be read by a CI runner that parses its log).
func (r *Report) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s: %s (%s), %s, offline\n", r.Tool, r.Version, oneLine(r.Input), strings.ReplaceAll(r.Kind, "_", " "),
		r.VerifiedAt.UTC().Format(time.RFC3339))
	for _, sec := range sectionOrder {
		first := true
		for _, c := range r.Checks {
			if c.Section != sec {
				continue
			}
			if first {
				fmt.Fprintf(&b, "\n%s\n", sec)
				first = false
			}
			fmt.Fprintf(&b, "  %-11s %s: %s\n", label(c.Status), oneLine(c.Name), oneLine(c.Detail))
		}
	}
	if rep := r.Reproduction; rep != nil && rep.Ran {
		writeResults(&b, "missing from the report (the rules produce them)", rep.Missing)
		writeResults(&b, "in the report, not produced by the rules", rep.Extra)
	}
	switch r.Result {
	case ResultFailed:
		fmt.Fprintf(&b, "\nresult: verification FAILED: %d check(s) failed, %d not checked, %d flagged\n", r.Failed, r.NotChecked, r.Flagged)
	case ResultIncomplete:
		fmt.Fprintf(&b, "\nresult: no check failed; %d check(s) NOT made because their input is not present, %d flagged\n", r.NotChecked, r.Flagged)
	default:
		fmt.Fprintf(&b, "\nresult: every check passed, %d flagged\n", r.Flagged)
	}
	if r.Result != ResultFailed {
		b.WriteString("\n" + r.Establishes + "\n")
	}
	b.WriteString("\nWhat this verification does not establish:\n")
	for _, s := range r.DoesNotEstablish {
		fmt.Fprintf(&b, "  - %s;\n", s)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeResults(b *strings.Builder, title string, rs []RuleElement) {
	if len(rs) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s:\n", title)
	for _, r := range rs {
		fmt.Fprintf(b, "  %s\n", oneLine(r.String()))
	}
}

func label(s Status) string {
	switch s {
	case Fail:
		return "FAIL"
	case NotChecked:
		return "NOT CHECKED"
	case Flag:
		return "FLAG"
	case Pass:
		return "pass"
	default:
		return "info"
	}
}

// oneLine keeps input-derived text on one printable line: a newline or a control character in a
// file must never start a log line of its own.
func oneLine(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r' || r == '\u2028' || r == '\u2029' || r == '\u0085':
			return ' '
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, s))
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
