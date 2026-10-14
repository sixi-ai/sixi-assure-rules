package rules

import (
	"slices"

	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
)

// typeGuard is a leading type test of a rule condition, read from its checked AST when the pack loads: a top-level
// conjunct `n.type == "x"` or `n.type in ["x", "y"]` (node scope), or the same over `e.kind`, `e.from.type` or
// `e.to.type` (edge scope). An element whose field holds a string outside values cannot satisfy the condition —
// CEL's `false && x` is false whatever x evaluates to, an error included — so runRule skips it without evaluating
// the program. A field that is absent or not a string is left to CEL, so an element that errors today still errors
// (the one difference: a cost-limit error a conjunct before the guard would raise on a skipped element is not raised).
// Coverage (coverRule) still visits every element: the guards only spare the finding pass work it would discard.
type typeGuard struct {
	path   []string // the field path under the scope variable: ["type"], ["kind"], ["from", "type"], ["to", "type"]
	values map[string]bool
}

// guardPaths are the fields a guard may test, per scope: the ones every element carries as a string.
var guardPaths = map[string][][]string{
	ScopeNode: {{"type"}},
	ScopeEdge: {{"kind"}, {"from", "type"}, {"to", "type"}},
}

// typeGuards returns the guards of a condition compiled for scope: one per top-level conjunct of a supported form.
// Anything else (a disjunction, a negation, a computed list) yields no guard, and the element goes to CEL as before.
func typeGuards(scope string, e ast.Expr) []typeGuard {
	vars := map[string]string{ScopeNode: "n", ScopeEdge: "e"}
	v, ok := vars[scope]
	if !ok {
		return nil
	}
	var out []typeGuard
	for _, c := range conjuncts(e) {
		if g, ok := guardOf(scope, v, c); ok {
			out = append(out, g)
		}
	}
	return out
}

// conjuncts flattens the top-level `&&` tree of e.
func conjuncts(e ast.Expr) []ast.Expr {
	if e.Kind() != ast.CallKind || e.AsCall().FunctionName() != operators.LogicalAnd {
		return []ast.Expr{e}
	}
	var out []ast.Expr
	for _, a := range e.AsCall().Args() {
		out = append(out, conjuncts(a)...)
	}
	return out
}

func guardOf(scope, v string, c ast.Expr) (typeGuard, bool) {
	if c.Kind() != ast.CallKind {
		return typeGuard{}, false
	}
	call := c.AsCall()
	args := call.Args()
	if call.IsMemberFunction() || len(args) != 2 {
		return typeGuard{}, false
	}
	path, ok := fieldPath(v, args[0])
	if !ok || !guardable(scope, path) {
		return typeGuard{}, false
	}
	values := map[string]bool{}
	switch call.FunctionName() {
	case operators.Equals:
		s, ok := stringLiteral(args[1])
		if !ok {
			return typeGuard{}, false
		}
		values[s] = true
	case operators.In:
		if args[1].Kind() != ast.ListKind {
			return typeGuard{}, false
		}
		for _, el := range args[1].AsList().Elements() {
			s, ok := stringLiteral(el)
			if !ok {
				return typeGuard{}, false
			}
			values[s] = true
		}
	default:
		return typeGuard{}, false
	}
	return typeGuard{path: path, values: values}, true
}

// fieldPath reads `v.a.b` as ["a", "b"]; anything but plain field selection on the scope variable is not a path.
func fieldPath(v string, e ast.Expr) ([]string, bool) {
	var rev []string
	for e.Kind() == ast.SelectKind {
		s := e.AsSelect()
		if s.IsTestOnly() {
			return nil, false
		}
		rev = append(rev, s.FieldName())
		e = s.Operand()
	}
	if e.Kind() != ast.IdentKind || e.AsIdent() != v || len(rev) == 0 {
		return nil, false
	}
	path := make([]string, len(rev))
	for i, f := range rev {
		path[len(rev)-1-i] = f
	}
	return path, true
}

func guardable(scope string, path []string) bool {
	return slices.ContainsFunc(guardPaths[scope], func(p []string) bool { return slices.Equal(p, path) })
}

func stringLiteral(e ast.Expr) (string, bool) {
	if e.Kind() != ast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().(types.String)
	return string(s), ok
}

// excludes reports whether the element m (a node or edge value) certainly fails one of the guards: its field holds
// a string the guard does not list. An absent or non-string field never excludes.
func excludes(guards []typeGuard, m map[string]any) bool {
	for _, g := range guards {
		var cur any = m
		for _, f := range g.path {
			mm, ok := cur.(map[string]any)
			if !ok {
				cur = nil
				break
			}
			cur = mm[f]
		}
		if s, ok := cur.(string); ok && !g.values[s] {
			return true
		}
	}
	return false
}
