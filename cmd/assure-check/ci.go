package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/sixi-ai/sixi-assure-rules/corpus"
	"github.com/sixi-ai/sixi-assure-rules/rules/sarif"
)

// stepSummaryEnv is where GitHub Actions reads the Markdown a step appends to its job summary.
const stepSummaryEnv = "GITHUB_STEP_SUMMARY"

// ciOutputs are the report files for a CI system: SARIF 2.1.0 for code scanning and a Markdown
// summary. Both are projections of the findings the rules produced; nothing is added to them.
type ciOutputs struct {
	sarifPath   string
	summaryPath string // "-" → stdout
	stepSummary bool
}

func (o ciOutputs) write(reports []fileReport, failOn string, code int, stdout, stderr io.Writer) error {
	if o.sarifPath == "" && o.summaryPath == "" && !o.stepSummary {
		return nil
	}
	in := sarifFindings(reports)
	if o.sarifPath != "" {
		var buf bytes.Buffer
		log := sarif.Build(in, sarif.Options{ToolVersion: toolVersion(), ClauseKnown: clauseKnown})
		if err := log.Write(&buf); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Clean(o.sarifPath), buf.Bytes(), 0o600); err != nil {
			return fmt.Errorf("cannot write -sarif: %w", err)
		}
	}
	if o.summaryPath == "" && !o.stepSummary {
		return nil
	}
	md := summary(reports, in, failOn, code)
	switch o.summaryPath {
	case "":
	case "-":
		fmt.Fprint(stdout, md)
	default:
		if err := os.WriteFile(filepath.Clean(o.summaryPath), []byte(md), 0o600); err != nil {
			return fmt.Errorf("cannot write -summary-md: %w", err)
		}
	}
	if o.stepSummary {
		path := os.Getenv(stepSummaryEnv)
		if path == "" {
			fmt.Fprintln(stderr, "assure-check: -step-summary: $"+stepSummaryEnv+" is not set (not a GitHub Actions step); no summary appended")
			return nil
		}
		f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 G703 -- runner-provided path by design
		if err != nil {
			return fmt.Errorf("cannot append to $%s: %w", stepSummaryEnv, err)
		}
		_, werr := io.WriteString(f, md+"\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fmt.Errorf("cannot append to $%s: %w", stepSummaryEnv, werr)
		}
	}
	return nil
}

// summary is the Markdown for a step summary or a PR comment. Files that failed validation are
// listed after it: they produced no finding, and the run fails on them.
func summary(reports []fileReport, in []sarif.Finding, failOn string, code int) string {
	o := sarif.SummaryOptions{ClauseKnown: clauseKnown}
	var valid, invalid []string
	for _, r := range reports {
		// A file name is untrusted too: a newline in it would end the code span and let the rest
		// render as Markdown in the job summary. MDCode strips control characters first.
		name := "`" + sarif.MDCode(artifactURI(r.File)) + "`"
		if r.OK {
			valid = append(valid, name)
		} else {
			invalid = append(invalid, name)
		}
	}
	if len(reports) == 1 {
		o.Subject = artifactURI(reports[0].File)
	}
	if failOn != "" && len(invalid) == 0 {
		o.Gate = &sarif.Gate{FailOn: failOn, Passed: code == 0}
	}
	md := sarif.Summary(in, o)
	if len(reports) > 1 && len(valid) > 0 {
		md += fmt.Sprintf("\nAssessed %d of %d model files: %s.\n", len(valid), len(reports), listUpTo(valid, 10))
	}
	if len(invalid) > 0 {
		md += fmt.Sprintf("\n**%d of %d model files failed validation** and were not assessed: %s.\n",
			len(invalid), len(reports), listUpTo(invalid, 10))
	}
	return md
}

// listUpTo joins at most n names and says how many more there are.
func listUpTo(names []string, n int) string {
	if len(names) <= n {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:n], ", "), len(names)-n)
}

// sarifFindings maps every valid file's findings onto the builder's input, each pointing at its
// own file and at the line that declares the first element it names.
func sarifFindings(reports []fileReport) []sarif.Finding {
	var out []sarif.Finding
	for _, r := range reports {
		uri := artifactURI(r.File)
		for _, f := range r.Findings {
			cites := make([]string, 0, len(f.Clauses))
			for _, c := range f.Clauses {
				cites = append(cites, c.ID)
			}
			out = append(out, sarif.Finding{
				RuleID: f.RuleID, Pack: f.Pack, Severity: f.Severity, Title: f.Title, Message: f.Message,
				Remediation: f.Remediation, Citations: cites, ElementIDs: f.IDs,
				ArtifactURI: uri, Line: sarif.FirstLine(r.raw, f.IDs),
			})
		}
	}
	return out
}

// clauseKnown resolves a citation against the embedded corpus; an unknown id is shown as
// "no clause found", never described.
func clauseKnown(id string) bool {
	_, ok := corpus.Lookup(id)
	return ok
}

// artifactURI is the model path as code scanning wants it: relative to the working directory
// (the repository root in a workflow) with forward slashes.
func artifactURI(path string) string {
	p := filepath.Clean(path)
	if filepath.IsAbs(p) {
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
				p = rel
			}
		}
	}
	return filepath.ToSlash(p)
}

// toolVersion is the module version when built from a tagged module, else "dev".
func toolVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
