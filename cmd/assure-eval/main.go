// Command assure-eval is the golden-set gate (docs/09 §2): it loads the rule packs (failing on
// validation errors), checks every rule's positive/negative fixture, evaluates every golden model
// with an expected file and reports TP/FP/FN, precision and recall per rule and per pack.
//
//	go run ./cmd/assure-eval -packs packs -policy ../policy.yaml \
//	    -models golden-set/models -expected golden-set/expected [-json] [-verbose]
//
// Exit status 1 when any fixture check fails or a pack with ≥ 1 expected finding has
// precision < 0.90 or recall < 0.85.
//
// Matching: a prediction matches an expectation when rule_id and the element id are equal. The
// engine reports one finding per element, so an expected entry listing several ids
// (`{"rule_id":"AI-005","ids":["n_agent","n_llm"]}`) is shorthand for one expected finding per id.
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
	"text/tabwriter"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/rules"
)

const (
	minPrecision = 0.90
	minRecall    = 0.85
	evalTimeout  = 2 * time.Minute
)

type expectedFinding struct {
	RuleID string   `json:"rule_id"`
	IDs    []string `json:"ids"`
}

type fixtureResult struct {
	RuleID string `json:"rule_id"`
	Kind   string `json:"kind"` // positive | negative
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

type modelResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // evaluated | no expected file | error
	Error  string `json:"error,omitempty"`
}

type counter struct {
	Rule      string   `json:"rule"`
	Pack      string   `json:"pack"`
	TP        int      `json:"tp"`
	FP        int      `json:"fp"`
	FN        int      `json:"fn"`
	Precision float64  `json:"precision"`
	Recall    float64  `json:"recall"`
	FPKeys    []string `json:"fp_keys,omitempty"`
	FNKeys    []string `json:"fn_keys,omitempty"`
}

type report struct {
	Packs    int             `json:"packs"`
	Rules    int             `json:"rules"`
	Fixtures []fixtureResult `json:"fixtures"`
	Models   []modelResult   `json:"models"`
	ByRule   []counter       `json:"by_rule"`
	ByPack   []counter       `json:"by_pack"`
	Failures []string        `json:"failures"`
	Pass     bool            `json:"pass"`
}

func main() {
	packsDir := flag.String("packs", "packs", "directory with rule packs (*.yaml)")
	policyPath := flag.String("policy", "../policy.yaml", "policy table")
	modelsDir := flag.String("models", "golden-set/models", "golden-set models")
	expectedDir := flag.String("expected", "golden-set/expected", "expected findings per model")
	asJSON := flag.Bool("json", false, "machine-readable output")
	verbose := flag.Bool("verbose", false, "list FP/FN keys per rule")
	flag.Parse()

	rep, err := run(*packsDir, *policyPath, *modelsDir, *expectedDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		os.Exit(1)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printReport(os.Stdout, rep, *verbose)
	}
	if !rep.Pass {
		os.Exit(1)
	}
}

func run(packsDir, policyPath, modelsDir, expectedDir string) (*report, error) {
	ctx, cancel := context.WithTimeout(context.Background(), evalTimeout)
	defer cancel()
	catalog, err := rules.LoadDir(packsDir)
	if err != nil {
		return nil, err
	}
	table, err := rules.LoadPolicyTable(policyPath)
	if err != nil {
		return nil, err
	}
	eng := rules.New(catalog, table, rules.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	rep := &report{Packs: len(catalog.Packs()), Rules: len(catalog.Rules()), Fixtures: []fixtureResult{}, Models: []modelResult{}, Failures: []string{}}
	known := map[string]string{} // rule id → pack
	for _, r := range catalog.Rules() {
		known[r.ID] = r.Pack
	}

	// 1. Fixtures.
	for _, r := range catalog.Rules() {
		for _, fx := range []struct {
			kind string
			path string
			want bool
		}{{"positive", r.Fixtures.Positive, true}, {"negative", r.Fixtures.Negative, false}} {
			res := fixtureResult{RuleID: r.ID, Kind: fx.kind, OK: true}
			if err := checkFixture(ctx, eng, r, fx.path, fx.want); err != nil {
				res.OK = false
				res.Error = err.Error()
				rep.Failures = append(rep.Failures, fmt.Sprintf("fixture %s (%s): %v", r.ID, fx.kind, err))
			}
			rep.Fixtures = append(rep.Fixtures, res)
		}
	}

	// 2. Golden set.
	byRule := map[string]*counter{}
	get := func(rule string) *counter {
		c, ok := byRule[rule]
		if !ok {
			pack := known[rule]
			if pack == "" {
				pack = packOfUnknown(rule)
			}
			c = &counter{Rule: rule, Pack: pack}
			byRule[rule] = c
		}
		return c
	}
	entries, err := os.ReadDir(modelsDir)
	if err != nil {
		return nil, fmt.Errorf("models dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		expPath := filepath.Join(expectedDir, name+".json")
		exp, err := readExpected(expPath)
		if errors.Is(err, os.ErrNotExist) {
			rep.Models = append(rep.Models, modelResult{Name: name, Status: "no expected file"})
			continue
		}
		if err != nil {
			rep.Models = append(rep.Models, modelResult{Name: name, Status: "error", Error: err.Error()})
			rep.Failures = append(rep.Failures, fmt.Sprintf("model %s: %v", name, err))
			continue
		}
		a, err := readModel(filepath.Join(modelsDir, e.Name()))
		if err != nil {
			rep.Models = append(rep.Models, modelResult{Name: name, Status: "error", Error: err.Error()})
			rep.Failures = append(rep.Failures, fmt.Sprintf("model %s: %v", name, err))
			continue
		}
		findings, err := eng.Evaluate(ctx, a, policyFor(a))
		if err != nil {
			rep.Models = append(rep.Models, modelResult{Name: name, Status: "error", Error: err.Error()})
			rep.Failures = append(rep.Failures, fmt.Sprintf("model %s: evaluate: %v", name, err))
			continue
		}
		rep.Models = append(rep.Models, modelResult{Name: name, Status: "evaluated"})
		expectedKeys := map[string]bool{}
		for _, x := range exp {
			for _, k := range keys(x.RuleID, x.IDs) {
				expectedKeys[k] = true
			}
		}
		predicted := map[string]bool{}
		for _, f := range findings {
			if _, ok := known[f.RuleID]; !ok {
				continue // a rule id outside every loaded pack is never counted as an FP
			}
			k := key(f.RuleID, f.IDs)
			predicted[k] = true
			c := get(f.RuleID)
			if expectedKeys[k] {
				c.TP++
			} else {
				c.FP++
				c.FPKeys = append(c.FPKeys, name+":"+k)
			}
		}
		for _, x := range exp {
			for _, k := range keys(x.RuleID, x.IDs) {
				if !predicted[k] {
					c := get(x.RuleID)
					c.FN++
					c.FNKeys = append(c.FNKeys, name+":"+k)
				}
			}
		}
	}
	// Rules with no expected and no predicted findings still appear (TP=FP=FN=0).
	for id := range known {
		get(id)
	}

	byPack := map[string]*counter{}
	for _, c := range byRule {
		c.Precision, c.Recall = ratios(c.TP, c.FP, c.FN)
		sort.Strings(c.FPKeys)
		sort.Strings(c.FNKeys)
		rep.ByRule = append(rep.ByRule, *c)
		p, ok := byPack[c.Pack]
		if !ok {
			p = &counter{Rule: "*", Pack: c.Pack}
			byPack[c.Pack] = p
		}
		p.TP += c.TP
		p.FP += c.FP
		p.FN += c.FN
	}
	sort.Slice(rep.ByRule, func(i, j int) bool { return rep.ByRule[i].Rule < rep.ByRule[j].Rule })
	for _, p := range byPack {
		p.Precision, p.Recall = ratios(p.TP, p.FP, p.FN)
		rep.ByPack = append(rep.ByPack, *p)
		if p.TP+p.FN+p.FP == 0 {
			continue // the pack neither expects nor raises a finding → thresholds do not apply
		}
		if p.Precision < minPrecision {
			rep.Failures = append(rep.Failures, fmt.Sprintf("pack %s: precision %.3f < %.2f", p.Pack, p.Precision, minPrecision))
		}
		if p.Recall < minRecall {
			rep.Failures = append(rep.Failures, fmt.Sprintf("pack %s: recall %.3f < %.2f", p.Pack, p.Recall, minRecall))
		}
	}
	sort.Slice(rep.ByPack, func(i, j int) bool { return rep.ByPack[i].Pack < rep.ByPack[j].Pack })
	sort.Strings(rep.Failures)
	rep.Pass = len(rep.Failures) == 0
	return rep, nil
}

func checkFixture(ctx context.Context, eng *rules.Engine, r *rules.Rule, path string, wantFire bool) error {
	ruleID := r.ID
	if path == "" {
		return errors.New("fixture not declared")
	}
	a, err := readModel(path)
	if err != nil {
		return err
	}
	policy := policyFor(a)
	// Drift rules read the knowledge facts the fixture declares (kb.available stays false otherwise).
	facts, err := rules.LoadFixtureFacts(r.Fixtures.KB)
	if err != nil {
		return fmt.Errorf("kb facts: %w", err)
	}
	policy.Knowledge = facts
	findings, err := eng.Evaluate(ctx, a, policy)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}
	fired := false
	for _, f := range findings {
		if f.RuleID == ruleID {
			fired = true
			break
		}
	}
	if fired != wantFire {
		return fmt.Errorf("%s: rule fired=%v, want %v", filepath.Base(path), fired, wantFire)
	}
	return nil
}

func readModel(path string) (*model.Architecture, error) {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- CLI-supplied repository paths
	if err != nil {
		return nil, err
	}
	a, err := model.ValidateJSON(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return a, nil
}

func readExpected(path string) ([]expectedFinding, error) {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- CLI-supplied repository paths
	if err != nil {
		return nil, err
	}
	var out []expectedFinding
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("expected file %s: %w", filepath.Base(path), err)
	}
	for i, x := range out {
		if x.RuleID == "" || len(x.IDs) == 0 {
			return nil, fmt.Errorf("expected file %s: entry %d needs rule_id and ids", filepath.Base(path), i)
		}
	}
	return out, nil
}

// policyFor derives the policy from the model attrs (regimes, allowed_regions), as the API does
// for a tenant without overrides.
func policyFor(a *model.Architecture) rules.Policy {
	var p rules.Policy
	if regs, ok := a.Attrs["regimes"].([]any); ok {
		for _, r := range regs {
			if s, ok := r.(string); ok {
				p.Regimes = append(p.Regimes, s)
			}
		}
	}
	if regs, ok := a.Attrs["allowed_regions"].([]any); ok {
		for _, r := range regs {
			if s, ok := r.(string); ok {
				p.AllowedRegions = append(p.AllowedRegions, s)
			}
		}
	}
	return p
}

// key identifies a predicted finding (rule + sorted ids; the engine emits exactly one id).
func key(ruleID string, ids []string) string {
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	return ruleID + ":" + strings.Join(sorted, ",")
}

// keys expands an expected entry into one key per id (see package comment).
func keys(ruleID string, ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, key(ruleID, []string{id}))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func packOfUnknown(rule string) string {
	if i := strings.Index(rule, "-"); i > 0 {
		return strings.ToLower(rule[:i]) + "?"
	}
	return "?"
}

func ratios(tp, fp, fn int) (precision, recall float64) {
	precision, recall = 1, 1
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	return precision, recall
}

func printReport(w io.Writer, rep *report, verbose bool) {
	failed := 0
	for _, f := range rep.Fixtures {
		if !f.OK {
			failed++
		}
	}
	_, _ = fmt.Fprintf(w, "packs: %d  rules: %d  fixtures checked: %d  fixture failures: %d\n", rep.Packs, rep.Rules, len(rep.Fixtures), failed)
	for _, m := range rep.Models {
		switch m.Status {
		case "evaluated":
			_, _ = fmt.Fprintf(w, "model %-28s evaluated\n", m.Name)
		case "no expected file":
			_, _ = fmt.Fprintf(w, "model %-28s no expected file\n", m.Name)
		default:
			_, _ = fmt.Fprintf(w, "model %-28s %s: %s\n", m.Name, m.Status, m.Error)
		}
	}
	_, _ = fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "rule\tpack\tTP\tFP\tFN\tprecision\trecall")
	for _, c := range rep.ByRule {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%.3f\t%.3f\n", c.Rule, c.Pack, c.TP, c.FP, c.FN, c.Precision, c.Recall)
		if verbose {
			for _, k := range c.FPKeys {
				_, _ = fmt.Fprintf(tw, "\t  FP %s\t\t\t\t\t\n", k)
			}
			for _, k := range c.FNKeys {
				_, _ = fmt.Fprintf(tw, "\t  FN %s\t\t\t\t\t\n", k)
			}
		}
	}
	_, _ = fmt.Fprintln(tw, "\t\t\t\t\t\t")
	_, _ = fmt.Fprintln(tw, "pack\t\tTP\tFP\tFN\tprecision\trecall")
	for _, p := range rep.ByPack {
		_, _ = fmt.Fprintf(tw, "%s\t\t%d\t%d\t%d\t%.3f\t%.3f\n", p.Pack, p.TP, p.FP, p.FN, p.Precision, p.Recall)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintln(w)
	for _, f := range rep.Failures {
		_, _ = fmt.Fprintln(w, "FAIL:", f)
	}
	if rep.Pass {
		_, _ = fmt.Fprintf(w, "PASS (precision ≥ %.2f, recall ≥ %.2f per pack; all fixtures ok)\n", minPrecision, minRecall)
	} else {
		_, _ = fmt.Fprintf(w, "FAIL (%d problem(s))\n", len(rep.Failures))
	}
}
