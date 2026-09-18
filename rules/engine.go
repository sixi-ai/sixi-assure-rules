package rules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// DefaultRuleTimeout bounds the wall-clock time one rule may spend over all elements of a model.
const DefaultRuleTimeout = 2 * time.Second

// maxMessageLen caps rendered finding messages (docs/02: messages are short, single-line).
const maxMessageLen = 2000

// Engine evaluates a Catalog against models. Safe for concurrent use (per-call state only).
type Engine struct {
	catalog     *Catalog
	table       *PolicyTable
	ruleTimeout time.Duration
	log         *slog.Logger
}

// Option configures the Engine.
type Option func(*Engine)

// WithRuleTimeout sets the per-rule evaluation timeout.
func WithRuleTimeout(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.ruleTimeout = d
		}
	}
}

// WithLogger sets the logger (structured, no model content).
func WithLogger(l *slog.Logger) Option {
	return func(e *Engine) {
		if l != nil {
			e.log = l
		}
	}
}

// New creates an engine over a catalog and policy table (nil → DefaultPolicyTable).
func New(catalog *Catalog, table *PolicyTable, opts ...Option) *Engine {
	if table == nil {
		table = DefaultPolicyTable()
	}
	e := &Engine{catalog: catalog, table: table, ruleTimeout: DefaultRuleTimeout, log: slog.Default()}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Catalog returns the loaded packs.
func (e *Engine) Catalog() *Catalog { return e.catalog }

// PolicyTable returns the policy table.
func (e *Engine) PolicyTable() *PolicyTable { return e.table }

// RuleError reports a failed rule evaluation (bad data, timeout, cost limit, panic).
type RuleError struct {
	RuleID    string
	ElementID string
	Err       error
}

func (e *RuleError) Error() string {
	return fmt.Sprintf("rule %s on %s: %v", e.RuleID, e.ElementID, e.Err)
}

func (e *RuleError) Unwrap() error { return e.Err }

// Evaluate implements Evaluator: node rules per node, edge rules per edge, graph rules once, for
// every pack applicable to the policy. Output is sorted by severity rank, rule id, ids and is
// deterministic for identical inputs. Finding ids are assigned by the store, not here.
func (e *Engine) Evaluate(ctx context.Context, a *model.Architecture, p Policy) ([]model.Finding, error) {
	if a == nil {
		return nil, errors.New("evaluate: nil architecture")
	}
	if e.catalog == nil {
		return []model.Finding{}, nil
	}
	g := buildGraph(a, p, e.table)
	tenant := e.tenantVars(p)
	kb := p.Knowledge.Vars()
	findings := []model.Finding{}
	var errs []error
	for _, pk := range e.catalog.Packs() {
		if !pk.AppliesTo(p.Regimes) {
			continue
		}
		for _, r := range pk.Rules {
			fs, err := e.runRule(ctx, r, g, tenant, kb)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			findings = append(findings, fs...)
		}
	}
	sortFindings(findings)
	if len(errs) > 0 {
		return findings, errors.Join(errs...)
	}
	return findings, nil
}

func (e *Engine) tenantVars(p Policy) map[string]any {
	regions := p.AllowedRegions
	if len(regions) == 0 {
		regions = e.table.AllowedRegionsDefault()
	}
	list := make([]any, 0, len(regions))
	for _, r := range regions {
		list = append(list, r)
	}
	return map[string]any{"allowed_regions": list}
}

// runRule evaluates one rule over all elements of its scope under a per-rule timeout.
func (e *Engine) runRule(ctx context.Context, r *Rule, g *graphVal, tenant, kb map[string]any) ([]model.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, e.ruleTimeout)
	defer cancel()
	var out []model.Finding
	eval := func(elementID string, vars map[string]any) error {
		vars["g"] = g
		vars["tenant"] = tenant
		vars["kb"] = kb
		hit, err := evalBool(ctx, r.prog, vars)
		if err != nil {
			return &RuleError{RuleID: r.ID, ElementID: elementID, Err: err}
		}
		if !hit {
			return nil
		}
		f, err := e.finding(ctx, r, elementID, vars)
		if err != nil {
			return err
		}
		out = append(out, f)
		return nil
	}
	switch r.Scope {
	case ScopeNode:
		for _, n := range g.nodes {
			nm := n.(map[string]any)
			if err := eval(nm["id"].(string), map[string]any{"n": nm}); err != nil {
				return nil, err
			}
		}
	case ScopeEdge:
		for _, ed := range g.edges {
			em := ed.(map[string]any)
			if err := eval(em["id"].(string), map[string]any{"e": em}); err != nil {
				return nil, err
			}
		}
	case ScopeGraph:
		if err := eval(g.id, map[string]any{}); err != nil {
			return nil, err
		}
	default:
		return nil, &RuleError{RuleID: r.ID, Err: fmt.Errorf("unknown scope %q", r.Scope)}
	}
	return out, nil
}

func (e *Engine) finding(ctx context.Context, r *Rule, elementID string, vars map[string]any) (model.Finding, error) {
	sev := r.Severity
	for i, prog := range r.overrides {
		hit, err := evalBool(ctx, prog, vars)
		if err != nil {
			return model.Finding{}, &RuleError{RuleID: r.ID, ElementID: elementID, Err: fmt.Errorf("severity_override[%d]: %w", i, err)}
		}
		if hit {
			sev = r.SeverityOverrides[i].Severity
			break
		}
	}
	msg, err := renderTemplate(ctx, r.msg, vars)
	if err != nil {
		return model.Finding{}, &RuleError{RuleID: r.ID, ElementID: elementID, Err: fmt.Errorf("message: %w", err)}
	}
	cause, _ := e.catalog.CauseOf(r.ID) // empty when the catalog ships no taxonomy (docs/03 §Causes)
	return model.Finding{
		RuleID: r.ID, Pack: r.Pack, Severity: sev, Status: model.StatusOpen, IDs: []string{elementID},
		Title: r.Title, Message: msg, Clauses: slices.Clone(r.Clauses), Remediation: r.Remediation, HasPatch: r.HasPatch(),
		Cause: cause.ID,
	}, nil
}

// evalValue evaluates a program, converting panics and context errors into errors.
func evalValue(ctx context.Context, prog cel.Program, vars map[string]any) (val ref.Val, err error) {
	if prog == nil {
		return nil, errors.New("program not compiled")
	}
	defer func() {
		if rec := recover(); rec != nil {
			val, err = nil, fmt.Errorf("panic during evaluation: %v", rec)
		}
	}()
	val, _, err = prog.ContextEval(ctx, vars)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ctxErr, err)
		}
		return nil, err
	}
	if types.IsError(val) {
		return nil, fmt.Errorf("%v", val)
	}
	return val, nil
}

func evalBool(ctx context.Context, prog cel.Program, vars map[string]any) (bool, error) {
	val, err := evalValue(ctx, prog, vars)
	if err != nil {
		return false, err
	}
	b, ok := val.(types.Bool)
	if !ok {
		return false, fmt.Errorf("condition returned %s, expected bool", val.Type().TypeName())
	}
	return bool(b), nil
}

// renderTemplate evaluates each placeholder in the rule context; the result is plain text,
// single-line and capped at maxMessageLen runes.
func renderTemplate(ctx context.Context, t *tmpl, vars map[string]any) (string, error) {
	if t == nil {
		return "", nil
	}
	var b strings.Builder
	for _, part := range t.parts {
		if part.prog == nil {
			b.WriteString(part.literal)
			continue
		}
		val, err := evalValue(ctx, part.prog, vars)
		if err != nil {
			return "", fmt.Errorf("{{%s}}: %w", part.expr, err)
		}
		b.WriteString(stringOf(val))
	}
	return sanitizeMessage(b.String()), nil
}

var newlineReplacer = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ")

func sanitizeMessage(s string) string {
	s = strings.TrimSpace(newlineReplacer.Replace(s))
	if utf8.RuneCountInString(s) > maxMessageLen {
		runes := []rune(s)
		s = string(runes[:maxMessageLen-1]) + "…"
	}
	return s
}

// sortFindings orders by severity rank, rule id, then ids.
func sortFindings(fs []model.Finding) {
	for i := range fs {
		slices.Sort(fs[i].IDs)
	}
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := model.SeverityRank(fs[i].Severity), model.SeverityRank(fs[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		return strings.Join(fs[i].IDs, ",") < strings.Join(fs[j].IDs, ",")
	})
}
