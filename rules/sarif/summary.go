package sarif

import (
	"fmt"
	"strings"
)

// DefaultSummaryRows caps the findings table so a step summary or a PR comment stays readable.
const DefaultSummaryRows = 20

// severityOrder lists severities most serious first; anything else counts as "unrated".
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// SummaryOptions shape the Markdown summary.
type SummaryOptions struct {
	// Heading is the level-2 heading; empty → "Sixi Assure design assessment".
	Heading string
	// Subject names what was assessed, e.g. the model file or the architecture id (shown as code).
	Subject string
	// MaxRows caps the table; 0 → DefaultSummaryRows.
	MaxRows int
	// Gate, when set, states the gate's decision.
	Gate *Gate
	// ClauseKnown resolves clause ids, as in Options. Nil → ids are shown unresolved.
	ClauseKnown func(id string) bool
}

// Gate is the pipeline's decision — never a statement about compliance.
type Gate struct {
	FailOn string
	Passed bool
}

// Summary renders findings as Markdown for $GITHUB_STEP_SUMMARY or a pull-request comment:
// counts per severity, then a table of the most serious open findings with their rule,
// severity, elements and the clause ids the rule cites. Findings a reviewer already decided are
// counted apart and left out of the table. Model text is escaped: it is untrusted and must not
// render as links, mentions or HTML.
func Summary(findings []Finding, o SummaryOptions) string {
	heading := clean(o.Heading)
	if heading == "" {
		heading = "Sixi Assure design assessment"
	}
	maxRows := o.MaxRows
	if maxRows <= 0 {
		maxRows = DefaultSummaryRows
	}

	open := make([]Finding, 0, len(findings))
	decided := 0
	counts := map[string]int{}
	for _, f := range findings {
		if s := norm(f.Status); s != "" && s != "open" {
			decided++
			continue
		}
		open = append(open, f)
		counts[severityKey(f.Severity)]++
	}
	sortBySeverity(open)

	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", mdEscape(heading))
	subject := ""
	if s := clean(o.Subject); s != "" {
		subject = " `" + mdCode(s) + "`"
	}
	fmt.Fprintf(&b, "Assessed%s against the deterministic rule packs: **%d open %s**", subject, len(open), plural(len(open), "finding", "findings"))
	if decided > 0 {
		fmt.Fprintf(&b, "; %d already decided by a reviewer", decided)
	}
	b.WriteString(".\n\n")

	if o.Gate != nil {
		failOn := mdEscape(norm(o.Gate.FailOn))
		if o.Gate.Passed {
			fmt.Fprintf(&b, "**Gate: passed** (fails on %s or above).\n\n", failOn)
		} else {
			fmt.Fprintf(&b, "**Gate: refused** at %s or above.\n\n", failOn)
		}
	}

	if len(open) > 0 {
		b.WriteString("| Severity | Count |\n|---|---:|\n")
		for _, s := range append(append([]string{}, severityOrder...), "unrated") {
			if counts[s] > 0 {
				fmt.Fprintf(&b, "| %s | %d |\n", s, counts[s])
			}
		}
		b.WriteString("\n")

		shown := open
		if len(shown) > maxRows {
			shown = shown[:maxRows]
		}
		fmt.Fprintf(&b, "### Top findings\n\n| Severity | Rule | Finding | Elements | Clauses |\n|---|---|---|---|---|\n")
		for _, f := range shown {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n",
				severityKey(f.Severity), mdCode(clean(f.RuleID)), cell(summaryTitle(f)), codeList(f.ElementIDs), clauseCell(f.Citations, o.ClauseKnown))
		}
		if rest := len(open) - len(shown); rest > 0 {
			fmt.Fprintf(&b, "\n…and %d more %s — see the SARIF results or the full report.\n", rest, plural(rest, "finding", "findings"))
		}
		b.WriteString("\n")
	} else {
		b.WriteString("The rule packs raised no open finding on this model.\n\n")
	}

	b.WriteString("_Sixi Assure assesses the design and evidences the result: every finding comes from a " +
		"deterministic rule and cites the clause ids that rule carries. It does not certify anything; " +
		"check each clause at its source._\n")
	return b.String()
}

func summaryTitle(f Finding) string {
	t := clean(f.Title)
	if t == "" {
		t = clean(f.Message)
	}
	if r := []rune(t); len(r) > 120 {
		t = strings.TrimSpace(string(r[:119])) + "…"
	}
	return t
}

func severityKey(s string) string {
	s = norm(s)
	for _, k := range severityOrder {
		if s == k {
			return s
		}
	}
	return "unrated"
}

func severityIndex(s string) int {
	k := severityKey(s)
	for i, v := range severityOrder {
		if v == k {
			return i
		}
	}
	return len(severityOrder)
}

// sortBySeverity is a stable sort: most serious first, then rule id.
func sortBySeverity(fs []Finding) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && less(fs[j], fs[j-1]); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func less(a, b Finding) bool {
	if x, y := severityIndex(a.Severity), severityIndex(b.Severity); x != y {
		return x < y
	}
	return clean(a.RuleID) < clean(b.RuleID)
}

func codeList(ids []string) string {
	ids = cleanList(ids)
	if len(ids) == 0 {
		return "—"
	}
	const maxIDs = 4
	out := make([]string, 0, maxIDs+1)
	for i, id := range ids {
		if i == maxIDs {
			out = append(out, fmt.Sprintf("+%d", len(ids)-maxIDs))
			break
		}
		out = append(out, "`"+mdCode(id)+"`")
	}
	return strings.Join(out, ", ")
}

func clauseCell(ids []string, known func(string) bool) string {
	ids = cleanList(ids)
	if len(ids) == 0 {
		return "no clause"
	}
	return mdCites(ids, known)
}

func cell(s string) string {
	if s == "" {
		return "—"
	}
	return mdEscape(s)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// mdEscape neutralises Markdown and HTML in untrusted text for a table cell: no links, images,
// emphasis, raw HTML, table breaks or @-mentions. Bare-URL autolinks (GFM "https://…" and
// "www.…") are broken with character references, which render as the same characters but no
// longer match the autolink patterns: a colon becomes "&#58;" and the dot after "www" "&#46;".
func mdEscape(s string) string {
	var b strings.Builder
	rs := []rune(clean(s))
	for i, r := range rs {
		switch r {
		case '\\', '`', '*', '_', '[', ']', '(', ')', '#', '|', '!', '~':
			b.WriteRune('\\')
			b.WriteRune(r)
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '&':
			b.WriteString("&amp;")
		case '@':
			b.WriteString("&#64;")
		case ':':
			b.WriteString("&#58;")
		case '.':
			if i >= 3 && strings.EqualFold(string(rs[i-3:i]), "www") {
				b.WriteString("&#46;")
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// MDCode makes untrusted text safe inside a single-backtick code span in a Markdown table cell
// or list: control characters and line breaks are removed first (a newline would end the span
// and let the rest render as Markdown), backticks are replaced and pipes escaped. Callers wrap
// the result in backticks themselves.
func MDCode(s string) string { return mdCode(s) }

// mdCode makes text safe inside a single-backtick code span in a table cell: backticks cannot be
// escaped there, so they are replaced, and a pipe would still split the cell.
func mdCode(s string) string {
	return strings.NewReplacer("`", "'", "|", "\\|").Replace(clean(s))
}
