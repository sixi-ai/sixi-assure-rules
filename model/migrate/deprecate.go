package migrate

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// Deprecation is an enum value a schema version removed and the value that replaces it (ADR-040
// §4). A removed value stays readable for two MINOR versions after Since: the step that removes it
// calls Rewrite, which replaces it by its successor and leaves the old value in the element's
// attrs.x_migrated_from, which the UI surfaces once. Rules never see a removed value, because the
// rewrite happens before the model reaches them.
type Deprecation struct {
	// Scope is where the value lives: ScopeNodes, ScopeEdges, ScopeGroups or ScopeArchitecture.
	Scope string
	// Field is an element member ("type", "kind", "auth") or "attrs.<name>" for an attribute. In a
	// list-valued attribute (attrs.regimes) every matching item is rewritten and duplicates the
	// rewrite creates are dropped, so a uniqueItems list stays unique.
	Field string
	// Removed is the value that left the enum; Successor replaces it.
	Removed   string
	Successor string
	// Since is the schema version whose enum no longer lists Removed.
	Since string
}

// Scopes a Deprecation applies to.
const (
	ScopeArchitecture = "architecture"
	ScopeNodes        = "nodes"
	ScopeEdges        = "edges"
	ScopeGroups       = "groups"
)

// MigratedFrom is the extension attribute a rewrite leaves on the element it changed: one
// "<field>=<removed value>" note, several joined by "; ". It is an x_ extension, so rules ignore it
// (ADR-040 §5) and the schema accepts it on every element.
const MigratedFrom = "x_migrated_from"

// migratedFromMax is the extValue length bound of the schema.
const migratedFromMax = 2000

// Rewrite applies the deprecations to doc in place and returns how many values it rewrote. A Step
// calls it on the document it owns.
func Rewrite(doc map[string]any, ds ...Deprecation) (int, error) {
	n := 0
	for _, d := range ds {
		if d.Field == "" || d.Removed == "" || d.Successor == "" || d.Removed == d.Successor {
			return n, fmt.Errorf("migrate: deprecation of %q needs a field, a removed value and a different successor", d.Field)
		}
		var elems []map[string]any
		switch d.Scope {
		case ScopeArchitecture:
			elems = []map[string]any{doc}
		case ScopeNodes, ScopeEdges, ScopeGroups:
			list, _ := doc[d.Scope].([]any)
			for _, x := range list {
				if m, ok := x.(map[string]any); ok {
					elems = append(elems, m)
				}
			}
		default:
			return n, fmt.Errorf("migrate: unknown deprecation scope %q", d.Scope)
		}
		for _, el := range elems {
			n += rewriteElement(el, d)
		}
	}
	return n, nil
}

func rewriteElement(el map[string]any, d Deprecation) int {
	holder, key := el, d.Field
	if name, ok := strings.CutPrefix(d.Field, "attrs."); ok {
		attrs, _ := el["attrs"].(map[string]any)
		if attrs == nil {
			return 0
		}
		holder, key = attrs, name
	}
	changed := 0
	switch v := holder[key].(type) {
	case string:
		if v == d.Removed {
			holder[key] = d.Successor
			changed = 1
		}
	case []any:
		out := make([]any, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok && s == d.Removed {
				x = d.Successor
				changed++
			}
			if s, ok := x.(string); ok && slices.Contains(out, any(s)) {
				continue
			}
			out = append(out, x)
		}
		if changed > 0 {
			holder[key] = out
		}
	}
	if changed > 0 {
		note(el, d.Field+"="+d.Removed)
	}
	return changed
}

// note records one rewrite on the element; an entry already recorded is not repeated, and a note
// that would outgrow the schema's bound keeps the entries it has.
func note(el map[string]any, entry string) {
	attrs, _ := el["attrs"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
		el["attrs"] = attrs
	}
	noteAttrs(attrs, entry)
}

// noteAttrs is note on an element's attrs map.
func noteAttrs(attrs map[string]any, entry string) {
	var entries []string
	if prev, ok := attrs[MigratedFrom].(string); ok && prev != "" {
		entries = strings.Split(prev, "; ")
	}
	if slices.Contains(entries, entry) {
		return
	}
	joined := strings.Join(append(entries, entry), "; ")
	if utf8.RuneCountInString(joined) > migratedFromMax {
		return
	}
	attrs[MigratedFrom] = joined
}
