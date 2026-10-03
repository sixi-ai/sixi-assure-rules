package migrate

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

// Schema 1.1 (ADR-047 §1 to §3b, docs/18 D1): identities become entities, edge.protocol becomes an
// enum, app/api authn becomes a list, and three attributes get a per-type vocabulary
// (v11_attrs.go). Everything else 1.1 adds is optional and needs no step.
//
// Four of the changes replace a 1.0 value shape, so their reading stays tolerant for two MINOR
// versions (ADR-040 §4, until 1.3): Normalize maps a free-text protocol to the enum, wraps a
// single authn value in a list and rewrites the narrowed attributes (NormalizeNodeAttrs). The 1.0 → 1.1 step runs it, and model.ValidateJSON runs it on a
// document that already says 1.1, so an importer, a pattern or an agent proposal that still writes
// the 1.0 shape is read, not refused. The identity move runs in the step only: a 1.1 document
// declares its identities itself.

// Protocols is the 1.1 edge.protocol enum (model.schema.json edgeProtocol, without the empty value).
var Protocols = []string{"https", "grpc", "mqtt", "amqp", "opc_ua", "modbus", "ssh", "sql", "a2a", "mcp_stdio", "mcp_http", "other"}

// ProtocolOther is the escape value a protocol the enum does not know is mapped to.
const ProtocolOther = "other"

// protocolSpellings maps the squashed spelling of a 1.0 free-text protocol (lowercase, without
// spaces, hyphens and underscores) to its 1.1 value. The enum values themselves are added in init.
//
// https is only the value of a spelling that names TLS (https, wss, h2, which is HTTP/2 over TLS by
// definition). A plaintext or transport-neutral spelling (http, http/1.1, http/2, ws, websocket,
// sse, webhook, rest, graphql, soap) maps to other with an x_migrated_from note: reading it as
// https would state an encryption the 1.0 model never declared (the C4 technology text and the
// exports would print https on an unencrypted edge).
var protocolSpellings = map[string]string{
	"h2": "https", "wss": "https",
	"grpcs": "grpc", "grpcweb": "grpc",
	"mqtts":     "mqtt",
	"amqps":     "amqp",
	"opc.tcp":   "opc_ua",
	"modbustcp": "modbus", "modbus/tcp": "modbus", "modbusrtu": "modbus",
	"sftp": "ssh", "scp": "ssh",
	"tds": "sql", "postgres": "sql", "postgresql": "sql", "pg": "sql", "mysql": "sql", "jdbc": "sql", "odbc": "sql",
	"sql/tds": "sql",
	"stdio":   "mcp_stdio",
	"mcp":     "mcp_http", "streamablehttp": "mcp_http", "mcp/http": "mcp_http",
}

func init() {
	for _, p := range Protocols {
		protocolSpellings[squash(p)] = p
	}
}

func squash(s string) string {
	return strings.NewReplacer(" ", "", "-", "", "_", "").Replace(strings.ToLower(strings.TrimSpace(s)))
}

// CanonicalProtocol maps a protocol as 1.0 wrote it (free text) to the 1.1 enum. A known spelling
// maps to its value (opcua → opc_ua, tds → sql); anything else maps to "other". noted reports that
// the value carried more than its case, spacing and separators (tds is more than sql, in-process
// more than other), so the rewrite leaves an x_migrated_from note; an empty protocol stays empty.
func CanonicalProtocol(old string) (value string, noted bool) {
	if strings.TrimSpace(old) == "" {
		return "", old != ""
	}
	v, known := protocolSpellings[squash(old)]
	if !known {
		v = ProtocolOther
	}
	return v, squash(v) != squash(old)
}

// ValidProtocol reports whether p is a 1.1 protocol value (the empty value included).
func ValidProtocol(p string) bool { return p == "" || slices.Contains(Protocols, p) }

// Normalize applies the tolerant reading of the 1.0 values 1.1 replaced to doc in place and returns
// how many values it rewrote: every edge.protocol not in the enum goes through CanonicalProtocol
// (with an x_migrated_from note when the spelling carried information), a single string
// attrs.authn becomes a one-item list (an empty one is dropped), and the attributes 1.1 and 1.2
// narrowed per node type (log_sink.purpose, agent.egress_policy, mcp_server.exposure; agent.kind,
// tool.egress_policy) go through NormalizeNodeAttrs. It is idempotent.
func Normalize(doc map[string]any) int {
	n := 0
	for _, e := range elements(doc, ScopeEdges) {
		old, ok := e["protocol"].(string)
		if !ok || ValidProtocol(old) {
			continue
		}
		v, noted := CanonicalProtocol(old)
		if v == "" {
			delete(e, "protocol")
			id, _ := e["id"].(string)
			dropProvenance(doc, ScopeEdges, id, "protocol")
		} else {
			e["protocol"] = v
		}
		if noted && strings.TrimSpace(old) != "" {
			note(e, "protocol="+old)
		}
		n++
	}
	for _, nd := range elements(doc, ScopeNodes) {
		attrs, _ := nd["attrs"].(map[string]any)
		if attrs == nil {
			continue
		}
		t, _ := nd["type"].(string)
		id, _ := nd["id"].(string)
		before := attrKeys(attrs)
		n += NormalizeNodeAttrs(t, attrs)
		if s, ok := attrs["authn"].(string); ok {
			if s == "" {
				delete(attrs, "authn")
			} else {
				attrs["authn"] = []any{s}
			}
			n++
		}
		// A removed attribute takes its provenance entries with it (ADR-086): the sidecar must keep
		// resolving, or the rewrite would turn a value it never refuses into a refused document.
		for _, k := range RemovedKeys(before, attrs) {
			dropProvenance(doc, ScopeNodes, id, "attrs", k)
		}
	}
	return n
}

// attrKeys returns the keys of attrs.
func attrKeys(attrs map[string]any) []string {
	out := make([]string, 0, len(attrs))
	for k := range attrs {
		out = append(out, k)
	}
	return out
}

// RemovedKeys returns the keys of before that attrs no longer holds, sorted: the attributes a
// rewrite (NormalizeNodeAttrs) removed, so a caller drops their provenance entries.
func RemovedKeys(before []string, attrs map[string]any) []string {
	var out []string
	for _, k := range before {
		if _, ok := attrs[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// NormalizeJSON is Normalize for raw JSON: it returns raw unchanged (same bytes) when nothing needs
// rewriting, so the common case costs one light decode and never disturbs a stored document.
func NormalizeJSON(raw []byte) ([]byte, bool, error) {
	var probe struct {
		Nodes []struct {
			Type  string                     `json:"type"`
			Attrs map[string]json.RawMessage `json:"attrs"`
		} `json:"nodes"`
		Edges []struct {
			Protocol *json.RawMessage `json:"protocol"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		// Not the shape this reads (a schema error the validator reports with a path): leave it.
		return raw, false, nil //nolint:nilerr // the schema validator owns malformed shapes
	}
	needed := false
	for _, e := range probe.Edges {
		var s string
		if e.Protocol != nil && json.Unmarshal(*e.Protocol, &s) == nil && !ValidProtocol(s) {
			needed = true
			break
		}
	}
	for _, nd := range probe.Nodes {
		if needed {
			break
		}
		if v, ok := nd.Attrs["authn"]; ok && len(bytes.TrimSpace(v)) > 0 && bytes.TrimSpace(v)[0] == '"' {
			needed = true
		}
		if narrowed := narrowedAttrs[nd.Type]; len(narrowed) > 0 {
			attrs := map[string]any{}
			for k := range narrowed {
				var v any
				if raw, ok := nd.Attrs[k]; ok && json.Unmarshal(raw, &v) == nil {
					attrs[k] = v
				}
			}
			needed = needed || needsNarrowing(nd.Type, attrs)
		}
	}
	if !needed {
		return raw, false, nil
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return raw, false, nil //nolint:nilerr // the schema validator owns malformed shapes
	}
	if Normalize(doc) == 0 {
		return raw, false, nil
	}
	b, err := encode(doc)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// identityValues are the 1.0 agent.identity values, each with the kind (and, where the value
// names it, the credential type) of the identity entity the migration creates for it. "unknown"
// creates an identity without a kind: the agent runs as something the model does not say.
var identityValues = map[string]struct{ name, kind, credential string }{
	"agent_id":           {"Agent identity (agent_id)", "agent_identity", ""},
	"managed_identity":   {"Managed identity", "workload_identity", "managed_identity"},
	"shared":             {"Shared identity", "shared", ""},
	"user_impersonation": {"User impersonation", "user_account", ""},
	"none":               {"No identity", "none", ""},
	"unknown":            {"Unknown identity", "", ""},
}

// IdentityPrefix starts the id of an identity the migration creates: ident_<1.0 value>.
const IdentityPrefix = "ident_"

// migrateAgentIdentities creates one identity entity per distinct agent.identity value (in node
// order) and points every agent with that value at it through attrs.identity_id. The identity
// string stays on the agent (readable for two MINOR versions, ADR-040 §4) and the identity carries
// attrs.x_migrated_from naming the value it came from. An agent that already names an identity is
// left alone, and an id already in use gets a numeric suffix.
func migrateAgentIdentities(doc map[string]any) {
	used := map[string]bool{}
	for _, scope := range []string{ScopeNodes, ScopeEdges, ScopeGroups, "findings", "identities"} {
		for _, el := range elements(doc, scope) {
			if id, ok := el["id"].(string); ok {
				used[id] = true
			}
		}
	}
	identities, _ := doc["identities"].([]any)
	created := map[string]string{} // 1.0 value → identity id
	for _, nd := range elements(doc, ScopeNodes) {
		if t, _ := nd["type"].(string); t != "agent" {
			continue
		}
		attrs, _ := nd["attrs"].(map[string]any)
		if attrs == nil {
			continue
		}
		value, _ := attrs["identity"].(string)
		meta, known := identityValues[value]
		if !known {
			continue
		}
		if existing, ok := attrs["identity_id"].(string); ok && existing != "" {
			continue
		}
		id, ok := created[value]
		if !ok {
			id = freeID(used, IdentityPrefix+value)
			used[id] = true
			created[value] = id
			ident := map[string]any{"id": id, "name": meta.name,
				"attrs": map[string]any{MigratedFrom: "agent.identity=" + value}}
			if meta.kind != "" {
				ident["kind"] = meta.kind
			}
			if meta.credential != "" {
				ident["credential_type"] = meta.credential
			}
			identities = append(identities, ident)
		}
		attrs["identity_id"] = id
	}
	if len(created) > 0 {
		doc["identities"] = identities
	}
}

func freeID(used map[string]bool, base string) string {
	if !used[base] {
		return base
	}
	for i := 2; ; i++ {
		if c := base + "_" + strconv.Itoa(i); !used[c] {
			return c
		}
	}
}

func elements(doc map[string]any, scope string) []map[string]any {
	list, _ := doc[scope].([]any)
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// v10to11 is the 1.0 → 1.1 step (ADR-047 §5): the protocol enum, the authn list and the narrowed
// attributes (Normalize), then one identity entity per distinct agent.identity value.
func v10to11(doc map[string]any) (map[string]any, error) {
	Normalize(doc)
	migrateAgentIdentities(doc)
	doc[Field] = "1.1"
	return doc, nil
}
