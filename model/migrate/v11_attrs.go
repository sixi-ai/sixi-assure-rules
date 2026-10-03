package migrate

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Narrowed attributes (ADR-040 §4, docs/02 §Versions 1.1). Schema 1.1 gives three attributes the
// flat nodeAttrs set already declared in 1.0 a per-type vocabulary (x-attr-values): a value 1.0
// accepted there is not a 1.1 value. MINOR changes are additive (ADR-040 §1), so the 1.0 → 1.1
// step and the tolerant reading (Normalize, for two MINOR versions) rewrite every such value, never
// refuse it, and leave the old value in x_migrated_from:
//
//   - log_sink.purpose was free text: an enum spelling (any case) is kept as the enum value; any
//     other text moves to the x_purpose extension attribute (rules never read it, the panel shows
//     it) and purpose is removed;
//   - agent.egress_policy was a boolean: it is removed. A boolean said a fail-closed allow-list
//     exists, which is not the 1.1 statement default_deny_allowlist about the agent's egress, so
//     nothing is inferred from it;
//   - mcp_server.exposure was internal, public or unknown: internal becomes private_network,
//     public stays, unknown is removed (an unset exposure is the 1.1 spelling of "not declared").
//
// Schema 1.2 (ADR-093) narrows two more the same way, and its step (v12.go) runs the same rewrite:
//
//   - agent.kind: llm or orchestrator; any other value of the flat kind set (a gateway or registry
//     kind, which no agent profile listed) is removed;
//   - tool.egress_policy: the agent's enum plus disabled; a boolean is removed, as on an agent.
//
// Rules read none of these on these node types, so findings do not move.

// narrowedAttrs is node type → attribute → the 1.1 values (the schema's x-attr-values without the
// empty value; TestNarrowedAttrsMatchTheSchema keeps them equal).
var narrowedAttrs = map[string]map[string][]string{
	"log_sink": {"purpose": {"operational", "security", "evidence"}},
	"agent": {
		"egress_policy": {"default_deny_allowlist", "default_allow", "undeclared"},
		// Schema 1.2 (ADR-093 FS-02): an agent is llm or orchestrator; the flat kind set also holds the
		// gateway and registry kinds, which no agent profile ever listed.
		"kind": {"llm", "orchestrator"},
	},
	"mcp_server": {"exposure": {"loopback", "private_network", "public"}},
	// Schema 1.2 (ADR-093 FS-09): a tool's egress_policy is the agent's enum plus disabled; the flat
	// set's boolean (an edge device's) was never in a tool profile.
	"tool": {"egress_policy": {"default_deny_allowlist", "default_allow", "undeclared", "disabled"}},
}

// mcpExposure maps the 1.0 exposure values an mcp_server could carry to 1.1 ("" removes it).
var mcpExposure = map[string]string{"internal": "private_network", "unknown": ""}

// PurposeExtension is the extension attribute a log_sink's free-text 1.0 purpose moves to.
const PurposeExtension = "x_purpose"

// NarrowedAttrs returns a copy of the node types and attributes 1.1 narrowed, with their 1.1 values
// (empty value excluded).
func NarrowedAttrs() map[string]map[string][]string {
	out := make(map[string]map[string][]string, len(narrowedAttrs))
	for t, attrs := range narrowedAttrs {
		out[t] = make(map[string][]string, len(attrs))
		for k, v := range attrs {
			out[t][k] = slices.Clone(v)
		}
	}
	return out
}

// needsNarrowing reports whether attrs of a node of nodeType carry a value 1.1 narrowed away.
func needsNarrowing(nodeType string, attrs map[string]any) bool {
	for k, allowed := range narrowedAttrs[nodeType] {
		v, set := attrs[k]
		if !set {
			continue
		}
		if s, ok := v.(string); ok && (s == "" || slices.Contains(allowed, s)) {
			continue
		}
		return true
	}
	return false
}

// NormalizeNodeAttrs rewrites the narrowed attributes of one node's attrs in place (the doc form
// and the Go form share it) and returns how many values it rewrote. Every rewrite leaves
// "<attr>=<old value>" in attrs.x_migrated_from. A value of a shape 1.0 never accepted either (a
// number for purpose, a string outside both vocabularies for exposure) is left for the validator.
func NormalizeNodeAttrs(nodeType string, attrs map[string]any) int {
	if attrs == nil || !needsNarrowing(nodeType, attrs) {
		return 0
	}
	n := 0
	switch nodeType {
	case "log_sink":
		n += narrowPurpose(attrs)
	case "agent":
		n += dropBoolean(attrs, "egress_policy")
		// Schema 1.2: a kind outside llm/orchestrator says nothing about the agent; it is removed.
		if old, ok := attrs["kind"].(string); ok && old != "" && !slices.Contains(narrowedAttrs["agent"]["kind"], old) {
			delete(attrs, "kind")
			noteAttrs(attrs, "kind="+old)
			n++
		}
	case "tool":
		n += dropBoolean(attrs, "egress_policy")
	case "mcp_server":
		if old, ok := attrs["exposure"].(string); ok {
			if v, known := mcpExposure[old]; known {
				if v == "" {
					delete(attrs, "exposure")
				} else {
					attrs["exposure"] = v
				}
				noteAttrs(attrs, "exposure="+old)
				n++
			}
		}
	}
	return n
}

// dropBoolean removes a boolean value of key (the edge device's egress_policy shape) and leaves
// "<key>=<value>" in x_migrated_from. A boolean said a fail-closed allow-list exists, which is not
// the enum's statement about an agent's or a tool's egress, so nothing is inferred from it.
func dropBoolean(attrs map[string]any, key string) int {
	b, ok := attrs[key].(bool)
	if !ok {
		return 0
	}
	delete(attrs, key)
	noteAttrs(attrs, key+"="+strconv.FormatBool(b))
	return 1
}

func narrowPurpose(attrs map[string]any) int {
	old, ok := attrs["purpose"].(string)
	if !ok {
		return 0
	}
	allowed := narrowedAttrs["log_sink"]["purpose"]
	if v := strings.ToLower(strings.TrimSpace(old)); slices.Contains(allowed, v) {
		attrs["purpose"] = v
		noteAttrs(attrs, "purpose="+old)
		return 1
	}
	delete(attrs, "purpose")
	if strings.TrimSpace(old) != "" {
		attrs[freeKey(attrs, PurposeExtension, old)] = old
	}
	noteAttrs(attrs, "purpose="+old)
	return 1
}

// freeKey returns base, or base_2, base_3 … : the first key that is unset or already holds value.
func freeKey(attrs map[string]any, base, value string) string {
	for i := 1; ; i++ {
		k := base
		if i > 1 {
			k = fmt.Sprintf("%s_%d", base, i)
		}
		if cur, set := attrs[k]; !set || cur == value {
			return k
		}
	}
}
