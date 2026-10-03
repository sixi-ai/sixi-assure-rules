package model

import (
	"bytes"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model/migrate"
	modelschema "github.com/sixi-ai/sixi-assure-rules/schema"
)

// Schema 1.1 narrows three attributes 1.0 already accepted with wider values (x-attr-values):
// log_sink.purpose (free text in 1.0), agent.egress_policy (a boolean in 1.0) and
// mcp_server.exposure (internal/public/unknown in 1.0). ADR-040 §1 and §4: a MINOR is additive, so
// every value 1.0 accepted is migrated on read, never refused.

// schema10 compiles the published 1.0 file, the contract a 1.0 model was written against.
func schema10(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(modelschema.ModelSchemaV10))
	require.NoError(t, err)
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	require.NoError(t, c.AddResource("model-1.0.schema.json", doc))
	s, err := c.Compile("model-1.0.schema.json")
	require.NoError(t, err)
	return s
}

// TestNarrowedAttrsMatchTheSchema keeps migrate's list of narrowed attributes equal to the schema:
// every (type, attr) of x-attr-values whose 1.0 definition accepted a value outside the type's 1.1
// values is migrated, with exactly the 1.1 values.
func TestNarrowedAttrsMatchTheSchema(t *testing.T) {
	t.Parallel()
	var old struct {
		Defs struct {
			NodeType struct {
				Enum []string `json:"enum"`
			} `json:"nodeType"`
			NodeAttrs struct {
				Properties map[string]struct {
					Ref  string `json:"$ref"`
					Enum []any  `json:"enum"`
				} `json:"properties"`
			} `json:"nodeAttrs"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(modelschema.ModelSchemaV10, &old))
	narrowed := migrate.NarrowedAttrs()
	found := map[string]bool{}
	for nodeType := range attrCatalog() {
		if !slices.Contains(old.Defs.NodeType.Enum, nodeType) {
			continue // a type 1.1 added has no 1.0 values to migrate
		}
		for attr, values := range AttrValues(nodeType) {
			def, declared := old.Defs.NodeAttrs.Properties[attr]
			if !declared {
				continue // an attribute 1.1 added
			}
			var accepted []any
			switch {
			case def.Enum != nil:
				accepted = def.Enum
			case strings.HasSuffix(def.Ref, "/boolish"):
				accepted = []any{true, false}
			default:
				accepted = nil // free text: unbounded
			}
			wider := accepted == nil
			for _, v := range accepted {
				if !slices.Contains(values, v) {
					wider = true
				}
			}
			key := nodeType + "." + attr
			if !wider {
				assert.NotContains(t, narrowed[nodeType], attr, "%s is not narrowed", key)
				continue
			}
			found[key] = true
			require.Contains(t, narrowed[nodeType], attr, "%s narrows a 1.0 attribute: migrate.NarrowedAttrs must rewrite it", key)
			var want []string
			for _, v := range values {
				if s, ok := v.(string); ok && s != "" {
					want = append(want, s)
				}
			}
			assert.ElementsMatch(t, want, narrowed[nodeType][attr], key)
		}
	}
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Schema 1.2 (ADR-093 FS-02, FS-09) narrows agent.kind and tool.egress_policy, whose flat 1.0
	// values (gateway kinds, a boolean) no agent or tool profile listed: they are migrated too.
	assert.Equal(t, []string{"agent.egress_policy", "agent.kind", "log_sink.purpose", "mcp_server.exposure", "tool.egress_policy"}, keys)
	for nodeType, attrs := range narrowed {
		for attr := range attrs {
			assert.True(t, found[nodeType+"."+attr], "migrate narrows %s.%s, which the schema does not", nodeType, attr)
		}
	}
}

// TestNarrowed10ValuesValidateAfterUpgrade: every value the 1.0 schema accepts for a narrowed
// (type, attr) validates after the upgrade, as a 1.0 document, as a 1.1 document (tolerant
// reading) and as a Go value (Validate), and the rewrite is the documented one.
func TestNarrowed10ValuesValidateAfterUpgrade(t *testing.T) {
	t.Parallel()
	s10 := schema10(t)
	long := strings.Repeat("a", 1999) // within the longText bound; "purpose=" + it is past the note bound
	for _, tc := range []struct {
		name      string
		nodeType  string
		layer     string
		attr      string
		value     any
		wantAttrs map[string]any // the node's attrs after the upgrade
	}{
		{"log_sink free text", "log_sink", "platform", "purpose", "Audit trail for SIEM",
			map[string]any{"x_purpose": "Audit trail for SIEM", MigratedFromAttr: "purpose=Audit trail for SIEM"}},
		{"log_sink free text naming SOC", "log_sink", "platform", "purpose", "Audit trail for SOC",
			map[string]any{"x_purpose": "Audit trail for SOC", MigratedFromAttr: "purpose=Audit trail for SOC"}},
		{"log_sink enum spelling in another case", "log_sink", "platform", "purpose", "Security",
			map[string]any{"purpose": "security", MigratedFromAttr: "purpose=Security"}},
		{"log_sink long free text (the note is skipped past its bound; x_purpose keeps it)", "log_sink", "platform", "purpose", long,
			map[string]any{"x_purpose": long}},
		{"log_sink empty purpose", "log_sink", "platform", "purpose", "", map[string]any{"purpose": ""}},
		{"log_sink operational", "log_sink", "platform", "purpose", "operational", map[string]any{"purpose": "operational"}},
		{"log_sink security", "log_sink", "platform", "purpose", "security", map[string]any{"purpose": "security"}},
		{"log_sink evidence", "log_sink", "platform", "purpose", "evidence", map[string]any{"purpose": "evidence"}},
		{"agent egress_policy true", "agent", "ai", "egress_policy", true, map[string]any{MigratedFromAttr: "egress_policy=true"}},
		{"agent egress_policy false", "agent", "ai", "egress_policy", false, map[string]any{MigratedFromAttr: "egress_policy=false"}},
		{"mcp_server internal", "mcp_server", "app", "exposure", "internal",
			map[string]any{"exposure": "private_network", MigratedFromAttr: "exposure=internal"}},
		{"mcp_server unknown", "mcp_server", "app", "exposure", "unknown", map[string]any{MigratedFromAttr: "exposure=unknown"}},
		{"mcp_server public", "mcp_server", "app", "exposure", "public", map[string]any{"exposure": "public"}},
		{"mcp_server empty", "mcp_server", "app", "exposure", "", map[string]any{"exposure": ""}},
		// Schema 1.2 (ADR-093): an agent kind outside llm/orchestrator and a boolean tool egress
		// policy are removed, never refused.
		{"agent kind waf", "agent", "ai", "kind", "waf", map[string]any{MigratedFromAttr: "kind=waf"}},
		{"agent kind api", "agent", "ai", "kind", "api", map[string]any{MigratedFromAttr: "kind=api"}},
		{"agent kind empty", "agent", "ai", "kind", "", map[string]any{"kind": ""}},
		{"tool egress_policy true", "tool", "app", "egress_policy", true, map[string]any{MigratedFromAttr: "egress_policy=true"}},
		{"tool egress_policy false", "tool", "app", "egress_policy", false, map[string]any{MigratedFromAttr: "egress_policy=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := func(version string) map[string]any {
				return map[string]any{
					"schema_version": version, "id": "arch_n", "tenant_id": "t", "name": "narrowed", "version": 1,
					"attrs": map[string]any{}, "groups": []any{}, "edges": []any{}, "findings": []any{}, "evidence": []any{},
					"nodes": []any{map[string]any{"id": "n", "type": tc.nodeType, "name": "N", "layer": tc.layer,
						"attrs": map[string]any{tc.attr: tc.value}}},
				}
			}
			raw10 := marshal(t, doc("1.0"))
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw10))
			require.NoError(t, err)
			require.NoError(t, s10.Validate(inst), "the 1.0 schema accepts the value")

			a, err := ValidateJSON(raw10)
			require.NoError(t, err, "a 1.0 model with the value upgrades on read")
			assert.Equal(t, tc.wantAttrs, map[string]any(a.Node("n").Attrs))

			upgraded, _, _, err := migrate.Upgrade(raw10)
			require.NoError(t, err)
			_, err = ValidateJSON(upgraded)
			require.NoError(t, err, "the upgraded document validates as it is stored")

			a11, err := ValidateJSON(marshal(t, doc(CurrentSchemaVersion)))
			require.NoError(t, err, "a 1.1 document still carrying the 1.0 value is read (tolerant reading)")
			assert.Equal(t, tc.wantAttrs, map[string]any(a11.Node("n").Attrs))

			built := Empty("arch_go", "t", "built")
			built.Nodes = []Node{{ID: "n", Type: tc.nodeType, Name: "N", Layer: tc.layer, Attrs: Attrs{tc.attr: tc.value}}}
			require.NoError(t, Validate(built), "a Go value carrying the 1.0 value is mapped in place")
			assert.Equal(t, tc.wantAttrs, map[string]any(built.Nodes[0].Attrs))
		})
	}
}

func TestProtocolText(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		edge Edge
		want string
	}{
		{"no note reads the enum", Edge{Protocol: "https"}, "https"},
		{"empty", Edge{}, ""},
		{"migrated free text", Edge{Protocol: "other", Attrs: Attrs{MigratedFromAttr: "protocol=ftp"}}, "ftp"},
		{"among other notes", Edge{Protocol: "sql", Attrs: Attrs{MigratedFromAttr: "auth=legacy_token; protocol=tds"}}, "tds"},
		{"a note for another field", Edge{Protocol: "grpc", Attrs: Attrs{MigratedFromAttr: "auth=legacy_token"}}, "grpc"},
		{"a blank old value reads the enum", Edge{Protocol: "", Attrs: Attrs{MigratedFromAttr: "protocol=  "}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.edge.ProtocolText())
		})
	}
	// The tolerant reading of a Go value leaves the note ProtocolText reads.
	built := Empty("arch_p", "t", "p")
	built.Nodes = []Node{{ID: "a", Type: "app", Name: "A", Layer: "app"}, {ID: "b", Type: "app", Name: "B", Layer: "app"}}
	built.Edges = []Edge{{ID: "e", From: "a", To: "b", Kind: "calls", Protocol: "FTP", Auth: "none", Encryption: "none"}}
	require.NoError(t, Validate(built))
	assert.Equal(t, "other", built.Edges[0].Protocol)
	assert.Equal(t, "FTP", built.Edges[0].ProtocolText())
}
