package migrate

import "strings"

// Schema 1.2 (ADR-093 M1, docs/18 WS-M): the agentic framework vocabulary. Every addition is an
// optional attribute, an enum value or the workflow group kind (docs/02 §8), so a 1.1 model is a
// 1.2 model once it says so: on every model whose values are inside the 1.2 type profiles the step
// changes schema_version and nothing else (the golden pairs check it).
//
// The step still rewrites three shapes 1.1 accepted, never refusing a stored model (ADR-040 §1;
// adr/proposals/ADR-093-M1-schema-12-narrowing-on-read.md records why this is a MINOR):
//
//   - the tolerant reading of the 1.0 shapes (a free-text protocol, a single authn value, the values
//     1.1 narrowed) is promised until 1.3 (ADR-040 §4). model.ValidateJSON applies it to a document
//     at the current version only, so a stored 1.1 document that still carries one is mapped here,
//     exactly as it was read while 1.1 was current;
//   - two attributes the flat attribute set shares get a per-type vocabulary in 1.2 (v11_attrs.go):
//     agent.kind (llm, orchestrator) and tool.egress_policy (the agent's enum plus disabled). A value
//     the flat set accepted there but no 1.1 type profile listed is removed with an x_migrated_from
//     note;
//   - hosted_on on an agent or agent_memory names a node of the model from 1.2 (SD-2 groundwork). 1.1
//     accepted free text there (the flat nodeAttrs set, up to 64 characters), so a value that names no
//     node, the node itself or a note is removed with "hosted_on=<value>" in x_migrated_from
//     (dropDanglingHosts). The invariant then holds on every value written at 1.2.
//
// A rewrite that removes a value also removes the provenance sidecar entries (ADR-086) that name
// it, so the sidecar keeps resolving (dropProvenance).

// v11to12 is the 1.1 → 1.2 step.
func v11to12(doc map[string]any) (map[string]any, error) {
	Normalize(doc)
	dropDanglingHosts(doc)
	doc[Field] = "1.2"
	return doc, nil
}

// hostedOnTypes are the node types whose hosted_on names a node of the model from schema 1.2.
var hostedOnTypes = map[string]bool{"agent": true, "agent_memory": true}

// HostedOnTypes returns the node types whose hosted_on must name another node of the model that is
// not a note (schema 1.2, ADR-093 FS-14). Other types keep the 1.1 reading, a declaration.
func HostedOnTypes() map[string]bool {
	out := make(map[string]bool, len(hostedOnTypes))
	for k, v := range hostedOnTypes {
		out[k] = v
	}
	return out
}

// noteType is model.NodeTypeNote (ADR-081); this package cannot import model.
const noteType = "note"

// dropDanglingHosts removes, on every agent and agent_memory, a hosted_on that names no node of the
// document, the node itself or a note, and leaves "hosted_on=<value>" in x_migrated_from. A value of
// another shape (not a string) is left for the validator. It returns how many values it removed.
func dropDanglingHosts(doc map[string]any) int {
	nodes := elements(doc, ScopeNodes)
	hosts := make(map[string]bool, len(nodes))
	for _, nd := range nodes {
		id, _ := nd["id"].(string)
		t, _ := nd["type"].(string)
		if id != "" && t != noteType {
			hosts[id] = true
		}
	}
	n := 0
	for _, nd := range nodes {
		t, _ := nd["type"].(string)
		if !hostedOnTypes[t] {
			continue
		}
		attrs, _ := nd["attrs"].(map[string]any)
		ref, ok := attrs["hosted_on"].(string)
		id, _ := nd["id"].(string)
		if !ok || ref == "" || (ref != id && hosts[ref]) {
			continue
		}
		delete(attrs, "hosted_on")
		noteAttrs(attrs, "hosted_on="+ref)
		dropProvenance(doc, ScopeNodes, id, "attrs", "hosted_on")
		n++
	}
	return n
}

// dropProvenance removes the provenance sidecar entries (ADR-086, schema 1.1) of a value a rewrite
// removed: the key that names it and every key under it. The tokens are the unescaped pointer
// tokens (collection, element id, member …); an emptied sidecar is removed, as a patch does.
func dropProvenance(doc map[string]any, toks ...string) {
	prov, _ := doc["provenance"].(map[string]any)
	if len(prov) == 0 {
		return
	}
	key := pointer(toks...)
	for k := range prov {
		if k == key || strings.HasPrefix(k, key+"/") {
			delete(prov, k)
		}
	}
	if len(prov) == 0 {
		delete(doc, "provenance")
	}
}

// pointer builds an RFC 6901 pointer from unescaped tokens.
func pointer(toks ...string) string {
	var b strings.Builder
	for _, t := range toks {
		b.WriteByte('/')
		b.WriteString(strings.ReplaceAll(strings.ReplaceAll(t, "~", "~0"), "/", "~1"))
	}
	return b.String()
}
