package rules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
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
	findings, _, err := e.evaluate(ctx, a, p, false)
	return findings, err
}

// EvaluateCoverage is Evaluate plus the coverage of every rule that ran (ADR-088 §4): how many elements each rule
// decided and which domain elements it could not decide because a required fact is undeclared. The findings are
// exactly Evaluate's: coverage is a second pass that never changes a finding, and its own failures only ever mark an
// element not checked.
func (e *Engine) EvaluateCoverage(ctx context.Context, a *model.Architecture, p Policy) ([]model.Finding, Coverage, error) {
	return e.evaluate(ctx, a, p, true)
}

func (e *Engine) evaluate(ctx context.Context, a *model.Architecture, p Policy, withCoverage bool) ([]model.Finding, Coverage, error) {
	cov := Coverage{Decided: map[string]int{}, NotChecked: map[string][]string{}}
	if a == nil {
		return nil, cov, errors.New("evaluate: nil architecture")
	}
	if e.catalog == nil {
		return []model.Finding{}, cov, nil
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
			if withCoverage {
				decided, notChecked := e.coverRule(ctx, r, g, tenant, kb, fs)
				cov.Decided[r.ID] = decided
				if len(notChecked) > 0 {
					cov.NotChecked[r.ID] = notChecked
				}
			}
		}
	}
	sortFindings(findings)
	if len(errs) > 0 {
		return findings, cov, errors.Join(errs...)
	}
	return findings, cov, nil
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
	err := forEachElement(r, g, func(elementID string, vars map[string]any) error {
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
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// forEachElement calls fn for every element of the rule's scope with a fresh activation holding the scope variable:
// each node (n), each edge (e), or the architecture once (graph scope, element id = the architecture id).
func forEachElement(r *Rule, g *graphVal, fn func(elementID string, vars map[string]any) error) error {
	switch r.Scope {
	case ScopeNode:
		for _, n := range g.nodes {
			nm := n.(map[string]any)
			if err := fn(nm["id"].(string), map[string]any{"n": nm}); err != nil {
				return err
			}
		}
	case ScopeEdge:
		for _, ed := range g.edges {
			em := ed.(map[string]any)
			if err := fn(em["id"].(string), map[string]any{"e": em}); err != nil {
				return err
			}
		}
	case ScopeGraph:
		return fn(g.id, map[string]any{})
	default:
		return &RuleError{RuleID: r.ID, Err: fmt.Errorf("unknown scope %q", r.Scope)}
	}
	return nil
}

// coverRule is the coverage pass of one rule that evaluated without error (ADR-088 §4, docs/03 "requires and
// not_checked"). Every element the rule fired on is decided. A rule without `requires` decides every element of its
// scope. Otherwise an element outside the domain is not counted; an element of the domain whose required facts are
// all declared is decided; one with an undeclared required fact is evaluated again with that fact unknown, and is
// decided only when the outcome is the same whatever the fact holds (CEL's `false && unknown` is false). Anything
// that fails here (a domain error, the timeout) marks the element not checked: coverage errs towards "not checked".
func (e *Engine) coverRule(ctx context.Context, r *Rule, g *graphVal, tenant, kb map[string]any, fired []model.Finding) (int, []string) {
	hits := make(map[string]bool, len(fired))
	for _, f := range fired {
		for _, id := range f.IDs {
			hits[id] = true
		}
	}
	decided := len(hits)
	if len(r.required) == 0 {
		_ = forEachElement(r, g, func(id string, _ map[string]any) error {
			if !hits[id] {
				decided++
			}
			return nil
		})
		return decided, nil
	}
	ctx, cancel := context.WithTimeout(ctx, e.ruleTimeout)
	defer cancel()
	var notChecked []string
	_ = forEachElement(r, g, func(id string, vars map[string]any) error {
		if hits[id] {
			return nil
		}
		vars["g"] = g
		vars["tenant"] = tenant
		vars["kb"] = kb
		switch in, failed := inDomain(ctx, r, vars); {
		case failed:
			notChecked = append(notChecked, id)
			return nil
		case !in:
			return nil
		}
		missing := undeclaredPaths(r.required, vars)
		if len(missing) == 0 || !dependsOn(ctx, r.prog, vars, missing) {
			decided++
			return nil
		}
		notChecked = append(notChecked, id)
		return nil
	})
	sort.Strings(notChecked)
	return decided, notChecked
}

// inDomain reports whether the element is in the rule's domain (always, without one). A domain that fails to evaluate
// reports failed: the caller counts the element not checked, never outside the domain.
func inDomain(ctx context.Context, r *Rule, vars map[string]any) (in, failed bool) {
	if r.domain == nil {
		return true, false
	}
	in, err := evalBool(ctx, r.domain, vars)
	return in, err != nil
}

// undeclaredPaths returns the required paths the element leaves undeclared: absent, null, blank or "unknown" (the
// schema's own word for an undeclared enum value). false, 0 and an empty list are declarations, except the importers'
// required placeholder `scopes: []` on an element whose provenance is imported (importedPlaceholder).
func undeclaredPaths(paths []requiredPath, vars map[string]any) []requiredPath {
	var out []requiredPath
	for _, p := range paths {
		if !pathDeclared(p, vars) {
			out = append(out, p)
		}
	}
	return out
}

func pathDeclared(p requiredPath, vars map[string]any) bool {
	switch p.root {
	case "kb":
		kb, _ := vars["kb"].(map[string]any)
		available, _ := kb["available"].(bool)
		return available
	case "g":
		g, _ := vars["g"].(*graphVal)
		if g == nil {
			return false
		}
		v, ok := g.attrs[p.field]
		return ok && valueDeclared(v)
	}
	obj := scopeMap(p.root, vars)
	if obj == nil {
		return false
	}
	if p.identity {
		// identityValue lists the declared members under attrs (an undeclared one is "" or 0 at the top level), so
		// a credential_ttl of 0 the architect wrote is a declaration and an absent one is not.
		ident, _ := obj["identity"].(map[string]any)
		declared, _ := ident["attrs"].(map[string]any)
		v, ok := declared[p.field]
		return ok && valueDeclared(v)
	}
	if p.attr {
		attrs, _ := obj["attrs"].(map[string]any)
		v, ok := attrs[p.field]
		if ok && importedPlaceholder(p.field, v, obj, vars) {
			return false
		}
		return ok && valueDeclared(v)
	}
	return valueDeclared(obj[p.field])
}

// placeholderLists are the list attributes the schema requires on a node type, so an importer whose source says
// nothing must still write them: `scopes` on tool and mcp_server (docs/13). Other lists an importer writes empty are
// declarations it read from the source (a tool whose MCP annotations rule out every capability has capabilities: []),
// so they stay declared.
var placeholderLists = map[string]bool{"scopes": true}

// importedPlaceholder reports a placeholder list (placeholderLists) left empty on an element whose provenance is
// imported (prov.elements[id].kind, ADR-086 §7): the importer wrote [] because the schema requires the attribute and
// its source declares nothing (the MCP server.json and agentic importers' `scopes: []`, docs/13), so the list is not
// the architect's declaration, and a rule that requires it reports the element not_checked (LPV-002, LPV-003;
// adr/proposals/ADR-093-C2-imported-scopes-undeclared.md). A designed or declared element's [] stays a declaration.
func importedPlaceholder(field string, v any, obj, vars map[string]any) bool {
	if !placeholderLists[field] {
		return false
	}
	if l, ok := v.([]any); !ok || len(l) != 0 {
		if s, ok := v.([]string); !ok || len(s) != 0 {
			return false
		}
	}
	g, _ := vars["g"].(*graphVal)
	if g == nil || g.prov == nil {
		return false
	}
	id, _ := obj["id"].(string)
	elements, _ := g.prov["elements"].(map[string]any)
	el, _ := elements[id].(map[string]any)
	kind, _ := el["kind"].(string)
	return kind == model.ProvenanceImported
}

func valueDeclared(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		s := strings.TrimSpace(x)
		return s != "" && !strings.EqualFold(s, "unknown")
	}
	return true
}

// scopeMap returns the node or edge map a path root names in the activation (n, e, e.from, e.to).
func scopeMap(root string, vars map[string]any) map[string]any {
	switch root {
	case "n", "e":
		m, _ := vars[root].(map[string]any)
		return m
	case "e.from", "e.to":
		e, _ := vars["e"].(map[string]any)
		m, _ := e[strings.TrimPrefix(root, "e.")].(map[string]any)
		return m
	}
	return nil
}

// dependsOn evaluates the condition again with the missing facts replaced by CEL unknowns and reports whether the
// outcome depends on them. A concrete result means the declared facts decide the element; an unknown, an error or
// (impossible for a condition that just evaluated false) true counts as depending on them.
func dependsOn(ctx context.Context, prog cel.Program, vars map[string]any, missing []requiredPath) bool {
	val, err := evalValue(ctx, prog, withUnknowns(vars, missing))
	if err != nil || types.IsUnknown(val) {
		return true
	}
	b, ok := val.(types.Bool)
	return !ok || bool(b)
}

// withUnknowns copies the activation with each missing fact set to a CEL unknown. Maps are copied before they are
// written, so the graph's shared node and edge values are never touched.
func withUnknowns(vars map[string]any, missing []requiredPath) map[string]any {
	sub := maps.Clone(vars)
	copied := map[string]bool{}
	mapAt := func(root string) map[string]any {
		var parent map[string]any
		key := root
		switch root {
		case "n", "e":
			parent = sub
		case "e.from", "e.to":
			parent, key = nil, strings.TrimPrefix(root, "e.")
		}
		if parent == nil {
			e, _ := sub["e"].(map[string]any)
			if !copied["e"] {
				e = maps.Clone(e)
				sub["e"], copied["e"] = e, true
			}
			parent = e
		}
		m, _ := parent[key].(map[string]any)
		if !copied[root] {
			m = maps.Clone(m)
			if m == nil {
				m = map[string]any{}
			}
			parent[key], copied[root] = m, true
		}
		return m
	}
	for i, p := range missing {
		unknown := types.NewUnknown(int64(-1-i), nil)
		switch p.root {
		case "kb":
			sub["kb"] = unknown
		case "g":
			g, _ := sub["g"].(*graphVal)
			if g == nil {
				continue
			}
			if !copied["g"] {
				cp := *g
				cp.attrs = maps.Clone(g.attrs)
				if cp.attrs == nil {
					cp.attrs = map[string]any{}
				}
				g = &cp
				sub["g"], copied["g"] = g, true
			}
			g.attrs[p.field] = unknown
		default:
			m := mapAt(p.root)
			if p.identity {
				// The identity value is shared by every node that runs as it: copy it (and its attrs) before the
				// member is set unknown at the top level and under attrs, so n.identity.issuer and
				// attr(n.identity, "issuer", "") both read the unknown.
				key := p.root + ".identity"
				ident, _ := m["identity"].(map[string]any)
				if !copied[key] {
					ident = maps.Clone(ident)
					if ident == nil {
						ident = map[string]any{}
					}
					declared, _ := ident["attrs"].(map[string]any)
					declared = maps.Clone(declared)
					if declared == nil {
						declared = map[string]any{}
					}
					ident["attrs"] = declared
					m["identity"], copied[key] = ident, true
				}
				ident[p.field] = unknown
				if declared, ok := ident["attrs"].(map[string]any); ok {
					declared[p.field] = unknown
				}
				continue
			}
			if !p.attr {
				m[p.field] = unknown
				continue
			}
			attrs, _ := m["attrs"].(map[string]any)
			if !copied[p.root+".attrs"] {
				attrs = maps.Clone(attrs)
				if attrs == nil {
					attrs = map[string]any{}
				}
				m["attrs"], copied[p.root+".attrs"] = attrs, true
			}
			attrs[p.field] = unknown
		}
	}
	return sub
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
		Cause: cause.ID, References: findingReferences(r.References),
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
