// Command assure-check validates an architecture model against the typed-model schema and its
// invariants, then evaluates the deterministic rule packs and prints the findings with the clause
// each one cites.
//
//	go run ./cmd/assure-check examples/agentic-ai-on-azure-bad-twin.json
//	go run ./cmd/assure-check -validate-only model.json
//	go run ./cmd/assure-check -json model.json | jq '.[0].findings[0]'
//
// Findings come only from rules. The command never asserts compliance: it reports which rule
// fired, on which element, and which clause the rule cites, so a person can check the clause at
// its source.
//
// Exit status 1 when a file is invalid or a pack fails to load, or when a finding is at or above
// -fail-on (off by default).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/corpus"
	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/rules"
)

const checkTimeout = 2 * time.Minute

// severityRank orders the severities used by the packs (packs/*.yaml).
var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

type fileReport struct {
	File     string          `json:"file"`
	OK       bool            `json:"ok"`
	Problems []model.Problem `json:"problems,omitempty"`
	Nodes    int             `json:"nodes,omitempty"`
	Edges    int             `json:"edges,omitempty"`
	Groups   int             `json:"groups,omitempty"`
	Hash     string          `json:"hash,omitempty"`
	Findings []finding       `json:"findings,omitempty"`
}

type finding struct {
	RuleID      string   `json:"rule_id"`
	Pack        string   `json:"pack"`
	Severity    string   `json:"severity"`
	Cause       string   `json:"cause,omitempty"`
	IDs         []string `json:"ids"`
	Title       string   `json:"title,omitempty"`
	Message     string   `json:"message"`
	Clauses     []clause `json:"clauses,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type clause struct {
	ID        string `json:"id"`
	Cite      string `json:"cite,omitempty"`
	SourceURL string `json:"source_url,omitempty"`
	Known     bool   `json:"known"`
}

func main() {
	packsDir := flag.String("packs", "packs", "directory with the rule packs (*.yaml)")
	policyPath := flag.String("policy", "policy.yaml", "policy table")
	validateOnly := flag.Bool("validate-only", false, "validate the model, do not evaluate the rules")
	asJSON := flag.Bool("json", false, "machine-readable output")
	failOn := flag.String("fail-on", "", "exit 1 when a finding is at or above this severity (info|low|medium|high|critical)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: assure-check [flags] <model.json>…")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *failOn != "" {
		if _, ok := severityRank[*failOn]; !ok {
			fmt.Fprintf(os.Stderr, "assure-check: unknown severity %q\n", *failOn)
			os.Exit(2)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	var eng *rules.Engine
	if !*validateOnly {
		var err error
		eng, err = newEngine(*packsDir, *policyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "assure-check:", err)
			os.Exit(1)
		}
	}

	reports := make([]fileReport, 0, flag.NArg())
	for _, path := range flag.Args() {
		reports = append(reports, check(ctx, eng, path))
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	} else {
		for _, r := range reports {
			print(os.Stdout, r)
		}
	}
	os.Exit(exitCode(reports, *failOn))
}

func newEngine(packsDir, policyPath string) (*rules.Engine, error) {
	catalog, err := rules.LoadDir(packsDir)
	if err != nil {
		return nil, fmt.Errorf("packs: %w", err)
	}
	table, err := rules.LoadPolicyTable(policyPath)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	// The engine logs nothing here: the report on stdout is the whole output.
	return rules.New(catalog, table, rules.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))), nil
}

func check(ctx context.Context, eng *rules.Engine, path string) fileReport {
	rep := fileReport{File: path}
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied CLI argument by design
	if err != nil {
		rep.Problems = []model.Problem{{Path: "/", Message: err.Error()}}
		return rep
	}
	a, err := model.ValidateJSON(b)
	if err != nil {
		var ve *model.ValidationError
		if errors.As(err, &ve) {
			rep.Problems = ve.Problems
		} else {
			rep.Problems = []model.Problem{{Path: "/", Message: err.Error()}}
		}
		return rep
	}
	rep.OK = true
	rep.Nodes, rep.Edges, rep.Groups = len(a.Nodes), len(a.Edges), len(a.Groups)
	if h, err := model.Hash(a); err == nil && len(h) >= 12 {
		rep.Hash = h[:12]
	}
	if eng == nil {
		return rep
	}
	found, err := eng.Evaluate(ctx, a, policyFor(a))
	if err != nil {
		rep.Problems = append(rep.Problems, model.Problem{Path: "/", Message: "evaluate: " + err.Error()})
		rep.OK = false
		return rep
	}
	for _, f := range found {
		rep.Findings = append(rep.Findings, decorate(f))
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return strings.Join(a.IDs, ",") < strings.Join(b.IDs, ",")
	})
	return rep
}

// decorate resolves every clause id of a finding against the corpus. An id with no record is
// reported as unknown rather than described: we never invent a clause (CLAUDE.md §1.4).
func decorate(f model.Finding) finding {
	out := finding{
		RuleID: f.RuleID, Pack: f.Pack, Severity: f.Severity, Cause: f.Cause,
		IDs: f.IDs, Title: f.Title, Message: f.Message, Remediation: f.Remediation,
	}
	for _, id := range f.Clauses {
		c, ok := corpus.Lookup(id)
		if !ok {
			out.Clauses = append(out.Clauses, clause{ID: id, Known: false})
			continue
		}
		out.Clauses = append(out.Clauses, clause{ID: id, Cite: c.Cite(), SourceURL: c.SourceURL, Known: true})
	}
	return out
}

// policyFor derives the policy from the model's own attributes, as the product does for an
// organisation without overrides.
func policyFor(a *model.Architecture) rules.Policy {
	var p rules.Policy
	p.Regimes = stringsOf(a.Attrs["regimes"])
	p.AllowedRegions = stringsOf(a.Attrs["allowed_regions"])
	return p
}

func stringsOf(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func print(w io.Writer, r fileReport) {
	if !r.OK {
		fmt.Fprintf(w, "FAIL %s\n", r.File)
		for _, p := range r.Problems {
			fmt.Fprintf(w, "  %s: %s\n", p.Path, p.Message)
		}
		return
	}
	fmt.Fprintf(w, "OK   %s  nodes=%d edges=%d groups=%d hash=%s\n", r.File, r.Nodes, r.Edges, r.Groups, r.Hash)
	if r.Findings == nil {
		fmt.Fprintln(w, "     no findings")
		return
	}
	bySeverity := map[string]int{}
	for _, f := range r.Findings {
		bySeverity[f.Severity]++
	}
	fmt.Fprintf(w, "     %d findings (%s)\n\n", len(r.Findings), counts(bySeverity))
	for _, f := range r.Findings {
		fmt.Fprintf(w, "  [%-8s] %-8s %s\n", f.Severity, f.RuleID, strings.Join(f.IDs, ", "))
		fmt.Fprintf(w, "             %s\n", f.Message)
		for _, c := range f.Clauses {
			if c.Known {
				fmt.Fprintf(w, "             cites %s — %s\n", c.ID, c.Cite)
			} else {
				fmt.Fprintf(w, "             cites %s — no clause found in the corpus\n", c.ID)
			}
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "             fix:   %s\n", f.Remediation)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "Findings come only from rules; every regulatory statement cites a clause id you can check")
	fmt.Fprintln(w, "at its source. This assesses a design and evidences it; it does not certify anything.")
}

func counts(bySeverity map[string]int) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	var parts []string
	for _, s := range order {
		if n := bySeverity[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}

func exitCode(reports []fileReport, failOn string) int {
	for _, r := range reports {
		if !r.OK {
			return 1
		}
	}
	if failOn == "" {
		return 0
	}
	threshold := severityRank[failOn]
	for _, r := range reports {
		if slices.ContainsFunc(r.Findings, func(f finding) bool { return severityRank[f.Severity] >= threshold }) {
			return 1
		}
	}
	return 0
}
