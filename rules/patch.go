package rules

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Binding is the evaluation context of one rule hit: the CEL variables (n / e / g / tenant) and
// the set of ids already present in the model (fresh ids must not collide).
type Binding struct {
	Vars     map[string]any
	existing map[string]bool
}

// ErrNoPatch is returned when a rule ships no patch template.
var ErrNoPatch = errors.New("rule has no patch template")

// PatchForFinding re-locates the element a finding points at and renders the rule's patch
// template in that context. ok is false when the rule has no patch template.
func (e *Engine) PatchForFinding(ctx context.Context, a *model.Architecture, f model.Finding, p Policy) (ops []model.PatchOp, ok bool, err error) {
	if a == nil {
		return nil, false, errors.New("nil architecture")
	}
	if e.catalog == nil {
		return nil, false, fmt.Errorf("unknown rule %q", f.RuleID)
	}
	r, found := e.catalog.Rule(f.RuleID)
	if !found {
		return nil, false, fmt.Errorf("unknown rule %q", f.RuleID)
	}
	if !r.HasPatch() {
		return nil, false, nil
	}
	if len(f.IDs) != 1 {
		return nil, false, fmt.Errorf("finding %s: expected exactly one element id, got %d", f.RuleID, len(f.IDs))
	}
	b, err := e.Bind(a, p, r.Scope, f.IDs[0])
	if err != nil {
		return nil, false, err
	}
	ops, err = PatchFor(ctx, r, b)
	if err != nil {
		return nil, false, err
	}
	return ops, true, nil
}

// Bind builds the rule context for an element of the given scope (node id, edge id or the
// architecture id for graph scope).
func (e *Engine) Bind(a *model.Architecture, p Policy, scope, elementID string) (*Binding, error) {
	g := buildGraph(a, p, e.table)
	vars := map[string]any{"g": g, "tenant": e.tenantVars(p), "kb": p.Knowledge.Vars()}
	switch scope {
	case ScopeNode:
		n, ok := g.nodeByID[elementID]
		if !ok {
			return nil, fmt.Errorf("node %q not found", elementID)
		}
		vars["n"] = n
	case ScopeEdge:
		ed, ok := g.edgeByID[elementID]
		if !ok {
			return nil, fmt.Errorf("edge %q not found", elementID)
		}
		vars["e"] = ed
	case ScopeGraph:
		if elementID != a.ID {
			return nil, fmt.Errorf("graph finding id %q does not match architecture %q", elementID, a.ID)
		}
	default:
		return nil, fmt.Errorf("unknown scope %q", scope)
	}
	existing := make(map[string]bool, len(a.Nodes)+len(a.Edges)+len(a.Groups))
	for i := range a.Nodes {
		existing[a.Nodes[i].ID] = true
	}
	for i := range a.Edges {
		existing[a.Edges[i].ID] = true
	}
	for i := range a.Groups {
		existing[a.Groups[i].ID] = true
	}
	return &Binding{Vars: vars, existing: existing}, nil
}

// PatchFor renders the rule's patch template in the binding: `{{new:<tag>}}` becomes a fresh id
// (stable per tag within one rendering), every other `{{…}}` is a CEL expression evaluated in the
// rule context (`{{e.id}}`, `{{e.to.id}}`, `{{n.id}}`, `{{g.id}}`, `{{e.kind}}` …). A string
// consisting of exactly one placeholder keeps the native type of the expression result.
func PatchFor(ctx context.Context, r *Rule, b *Binding) ([]model.PatchOp, error) {
	if r == nil || !r.HasPatch() {
		return nil, ErrNoPatch
	}
	if b == nil {
		return nil, errors.New("nil binding")
	}
	rd := &renderer{rule: r, binding: b, ctx: ctx, fresh: map[string]string{}}
	ops := make([]model.PatchOp, 0, len(r.PatchTemplate))
	for i, t := range r.PatchTemplate {
		path, err := rd.renderString(t.Path, true)
		if err != nil {
			return nil, fmt.Errorf("patch op %d path: %w", i, err)
		}
		from, err := rd.renderString(t.From, true)
		if err != nil {
			return nil, fmt.Errorf("patch op %d from: %w", i, err)
		}
		op := model.PatchOp{Op: t.Op, Path: path, From: from}
		if t.Value != nil {
			v, err := rd.renderValue(t.Value)
			if err != nil {
				return nil, fmt.Errorf("patch op %d value: %w", i, err)
			}
			raw, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("patch op %d value: %w", i, err)
			}
			op.Value = raw
		}
		ops = append(ops, op)
	}
	return ops, nil
}

type renderer struct {
	rule    *Rule
	binding *Binding
	ctx     context.Context
	fresh   map[string]string
}

func (rd *renderer) renderValue(v any) (any, error) {
	switch x := v.(type) {
	case string:
		if m := placeholderRe.FindStringSubmatchIndex(x); m != nil && m[0] == 0 && m[1] == len(x) {
			return rd.resolve(strings.TrimSpace(x[m[2]:m[3]]))
		}
		return rd.renderString(x, false)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			r, err := rd.renderValue(val)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			r, err := rd.renderValue(val)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	}
	return v, nil
}

// renderString substitutes every placeholder; in JSON-pointer position the value is escaped.
func (rd *renderer) renderString(s string, pointer bool) (string, error) {
	var err error
	out := placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
		if err != nil {
			return ""
		}
		expr := strings.TrimSpace(m[2 : len(m)-2])
		v, rerr := rd.resolve(expr)
		if rerr != nil {
			err = rerr
			return ""
		}
		str := fmt.Sprint(v)
		if pointer {
			str = strings.ReplaceAll(strings.ReplaceAll(str, "~", "~0"), "/", "~1")
		}
		return str
	})
	return out, err
}

func (rd *renderer) resolve(expr string) (any, error) {
	if m := newIDRe.FindStringSubmatch(expr); m != nil {
		return rd.freshID(m[1]), nil
	}
	prog, ok := rd.rule.patchExprs[expr]
	if !ok {
		return nil, fmt.Errorf("placeholder {{%s}} was not compiled for rule %s", expr, rd.rule.ID)
	}
	val, err := evalValue(rd.ctx, prog, rd.binding.Vars)
	if err != nil {
		return nil, fmt.Errorf("{{%s}}: %w", expr, err)
	}
	return nativeOf(val), nil
}

// freshID returns n_<tag>_<6 base32> not present in the model, stable per tag within a rendering.
func (rd *renderer) freshID(tag string) string {
	if id, ok := rd.fresh[tag]; ok {
		return id
	}
	for {
		id := "n_" + tag + "_" + randomSuffix()
		if !rd.binding.existing[id] {
			rd.binding.existing[id] = true
			rd.fresh[tag] = id
			return id
		}
	}
}

var base32Lower = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomSuffix() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return strings.ToLower(base32Lower.EncodeToString(b[:]))[:6]
}
