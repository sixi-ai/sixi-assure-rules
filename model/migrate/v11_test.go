package migrate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalProtocol(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in    string
		want  string
		noted bool
	}{
		{"https", "https", false},
		{"HTTPS", "https", false}, // case and separators only: nothing lost, no note
		{" grpc ", "grpc", false},
		{"http", "other", true}, // plaintext: never read as https
		{"HTTP/1.1", "other", true},
		{"http/2", "other", true},
		{"ws", "other", true},
		{"WebSocket", "other", true},
		{"sse", "other", true},
		{"webhook", "other", true},
		{"REST", "other", true}, // transport-neutral: says nothing about TLS
		{"GraphQL", "other", true},
		{"wss", "https", true}, // TLS spellings
		{"h2", "https", true},
		{"opcua", "opc_ua", false},
		{"OPC UA", "opc_ua", false},
		{"opc-ua", "opc_ua", false},
		{"opc_ua", "opc_ua", false},
		{"tds", "sql", true},
		{"PostgreSQL", "sql", true},
		{"jdbc", "sql", true},
		{"mqtts", "mqtt", true},
		{"amqp", "amqp", false},
		{"Modbus/TCP", "modbus", true},
		{"sftp", "ssh", true},
		{"A2A", "a2a", false},
		{"stdio", "mcp_stdio", true},
		{"mcp-stdio", "mcp_stdio", false},
		{"MCP", "mcp_http", true},
		{"streamable_http", "mcp_http", true},
		{"in-process", "other", true},
		{"devtools", "other", true},
		{"Tcp", "other", true},
		{"other", "other", false},
		{"", "", false},
	} {
		got, noted := CanonicalProtocol(tc.in)
		assert.Equal(t, tc.want, got, tc.in)
		assert.Equal(t, tc.noted, noted, tc.in)
		assert.True(t, ValidProtocol(got), tc.in)
	}
	assert.False(t, ValidProtocol("tds"))
	assert.True(t, ValidProtocol(""))
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	doc := func() map[string]any {
		return map[string]any{
			"nodes": []any{
				map[string]any{"id": "a", "type": "app", "attrs": map[string]any{"authn": "oidc"}},
				map[string]any{"id": "b", "type": "api", "attrs": map[string]any{"authn": ""}},
				map[string]any{"id": "c", "type": "api", "attrs": map[string]any{"authn": []any{"oidc", "api_key"}}},
				map[string]any{"id": "d", "type": "queue"},
			},
			"edges": []any{
				map[string]any{"id": "e1", "protocol": "in-process", "attrs": map[string]any{}},
				map[string]any{"id": "e2", "protocol": "HTTPS"},
				map[string]any{"id": "e3", "protocol": "sql", "attrs": map[string]any{}},
				map[string]any{"id": "e4", "protocol": "tds", "attrs": map[string]any{MigratedFrom: "auth=legacy_token"}},
				map[string]any{"id": "e5", "protocol": "  "},
			},
		}
	}
	d := doc()
	n := Normalize(d)
	assert.Equal(t, 6, n)
	nodes := d["nodes"].([]any)
	assert.Equal(t, []any{"oidc"}, nodes[0].(map[string]any)["attrs"].(map[string]any)["authn"])
	assert.NotContains(t, nodes[1].(map[string]any)["attrs"], "authn", "an empty single value is dropped")
	assert.Equal(t, []any{"oidc", "api_key"}, nodes[2].(map[string]any)["attrs"].(map[string]any)["authn"], "a list is left alone")
	edges := d["edges"].([]any)
	e1 := edges[0].(map[string]any)
	assert.Equal(t, "other", e1["protocol"])
	assert.Equal(t, "protocol=in-process", e1["attrs"].(map[string]any)[MigratedFrom])
	e2 := edges[1].(map[string]any)
	assert.Equal(t, "https", e2["protocol"])
	assert.NotContains(t, e2, "attrs", "a case-only rewrite leaves no note")
	assert.Equal(t, "sql", edges[2].(map[string]any)["protocol"])
	e4 := edges[3].(map[string]any)
	assert.Equal(t, "auth=legacy_token; protocol=tds", e4["attrs"].(map[string]any)[MigratedFrom], "notes accumulate")
	assert.NotContains(t, edges[4].(map[string]any), "protocol", "a blank protocol is dropped")

	assert.Zero(t, Normalize(d), "Normalize is idempotent")
}

func TestNormalizeJSON(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		raw     string
		changed bool
		want    string
	}{
		{"canonical stays the same bytes", `{"nodes":[{"attrs":{"authn":["oidc"]}}],"edges":[{"protocol":"https"}]}`, false, ""},
		{"no edges or nodes", `{"id":"x"}`, false, ""},
		{"not an object is left to the validator", `[1,2]`, false, ""},
		{"wrong shape is left to the validator", `{"edges":"nope"}`, false, ""},
		{"free-text protocol", `{"edges":[{"id":"e","protocol":"tds","attrs":{}}]}`, true,
			`{"edges":[{"id":"e","protocol":"sql","attrs":{"x_migrated_from":"protocol=tds"}}]}`},
		{"a separator-only spelling needs no note", `{"edges":[{"id":"e","protocol":"opcua"}]}`, true,
			`{"edges":[{"id":"e","protocol":"opc_ua"}]}`},
		{"a log_sink's free-text purpose moves to x_purpose", `{"nodes":[{"id":"l","type":"log_sink","attrs":{"purpose":"Audit trail for SIEM"}}]}`, true,
			`{"nodes":[{"id":"l","type":"log_sink","attrs":{"x_purpose":"Audit trail for SIEM","x_migrated_from":"purpose=Audit trail for SIEM"}}]}`},
		{"an enum purpose on a log_sink stays the same bytes", `{"nodes":[{"type":"log_sink","attrs":{"purpose":"security"}}]}`, false, ""},
		{"free-text purpose on an agent is not narrowed", `{"nodes":[{"type":"agent","attrs":{"purpose":"plans the work"}}]}`, false, ""},
		{"a boolean agent egress_policy is removed", `{"nodes":[{"type":"agent","attrs":{"egress_policy":true}}]}`, true,
			`{"nodes":[{"type":"agent","attrs":{"x_migrated_from":"egress_policy=true"}}]}`},
		{"a boolean edge_device egress_policy stays", `{"nodes":[{"type":"edge_device","attrs":{"egress_policy":true}}]}`, false, ""},
		{"an internal mcp_server", `{"nodes":[{"type":"mcp_server","attrs":{"exposure":"internal"}}]}`, true,
			`{"nodes":[{"type":"mcp_server","attrs":{"exposure":"private_network","x_migrated_from":"exposure=internal"}}]}`},
		{"an internal app is not narrowed", `{"nodes":[{"type":"app","attrs":{"exposure":"internal"}}]}`, false, ""},
		{"single authn keeps big numbers exact", `{"x":12345678901234567890,"nodes":[{"attrs":{"authn":"oauth"}}]}`, true,
			`{"x":12345678901234567890,"nodes":[{"attrs":{"authn":["oauth"]}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, changed, err := NormalizeJSON([]byte(tc.raw))
			require.NoError(t, err)
			assert.Equal(t, tc.changed, changed)
			if !tc.changed {
				assert.Equal(t, tc.raw, string(got), "unchanged documents are returned byte for byte")
				return
			}
			assert.JSONEq(t, tc.want, string(got))
			assert.NotContains(t, string(got), "e+19", "numbers keep their exact text")
		})
	}
}

func TestMigrateAgentIdentities(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"no agents adds nothing", `{"nodes":[{"id":"n","type":"app","attrs":{"identity":"managed_identity"}}]}`,
			`{"nodes":[{"id":"n","type":"app","attrs":{"identity":"managed_identity"}}]}`},
		{"agents without a value add nothing", `{"nodes":[{"id":"n","type":"agent","attrs":{}},{"id":"m","type":"agent"}]}`,
			`{"nodes":[{"id":"n","type":"agent","attrs":{}},{"id":"m","type":"agent"}]}`},
		{"one identity per distinct value, in node order", `{"nodes":[
			{"id":"a","type":"agent","attrs":{"identity":"managed_identity"}},
			{"id":"b","type":"agent","attrs":{"identity":"agent_id"}},
			{"id":"c","type":"agent","attrs":{"identity":"managed_identity"}},
			{"id":"d","type":"agent","attrs":{"identity":"unknown"}}]}`,
			`{"nodes":[
			{"id":"a","type":"agent","attrs":{"identity":"managed_identity","identity_id":"ident_managed_identity"}},
			{"id":"b","type":"agent","attrs":{"identity":"agent_id","identity_id":"ident_agent_id"}},
			{"id":"c","type":"agent","attrs":{"identity":"managed_identity","identity_id":"ident_managed_identity"}},
			{"id":"d","type":"agent","attrs":{"identity":"unknown","identity_id":"ident_unknown"}}],
			"identities":[
			{"id":"ident_managed_identity","name":"Managed identity","kind":"workload_identity","credential_type":"managed_identity","attrs":{"x_migrated_from":"agent.identity=managed_identity"}},
			{"id":"ident_agent_id","name":"Agent identity (agent_id)","kind":"agent_identity","attrs":{"x_migrated_from":"agent.identity=agent_id"}},
			{"id":"ident_unknown","name":"Unknown identity","attrs":{"x_migrated_from":"agent.identity=unknown"}}]}`},
		{"a taken id gets a suffix; a named identity and an unknown value are left alone", `{
			"groups":[{"id":"ident_shared","kind":"zone"}],
			"edges":[{"id":"ident_shared_2"}],
			"nodes":[
			{"id":"a","type":"agent","attrs":{"identity":"shared"}},
			{"id":"b","type":"agent","attrs":{"identity":"shared","identity_id":"mine"}},
			{"id":"c","type":"agent","attrs":{"identity":"something-else"}}]}`,
			`{
			"groups":[{"id":"ident_shared","kind":"zone"}],
			"edges":[{"id":"ident_shared_2"}],
			"nodes":[
			{"id":"a","type":"agent","attrs":{"identity":"shared","identity_id":"ident_shared_3"}},
			{"id":"b","type":"agent","attrs":{"identity":"shared","identity_id":"mine"}},
			{"id":"c","type":"agent","attrs":{"identity":"something-else"}}],
			"identities":[{"id":"ident_shared_3","name":"Shared identity","kind":"shared","attrs":{"x_migrated_from":"agent.identity=shared"}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var doc map[string]any
			require.NoError(t, json.Unmarshal([]byte(tc.in), &doc))
			migrateAgentIdentities(doc)
			got, err := json.Marshal(doc)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(got))
		})
	}
}

func TestV10To11SetsTheVersion(t *testing.T) {
	t.Parallel()
	in := []byte(`{"schema_version":"1.0","nodes":[{"id":"a","type":"agent","attrs":{"identity":"none"}}],
		"edges":[{"id":"e","from":"a","to":"a","protocol":"in-process","attrs":{}}]}`)
	want := `{"schema_version":"1.1",
		"nodes":[{"id":"a","type":"agent","attrs":{"identity":"none","identity_id":"ident_none"}}],
		"edges":[{"id":"e","from":"a","to":"a","protocol":"other","attrs":{"x_migrated_from":"protocol=in-process"}}],
		"identities":[{"id":"ident_none","name":"No identity","kind":"none","attrs":{"x_migrated_from":"agent.identity=none"}}]}`
	// The step list up to 1.1 (1.2 became current with ADR-093 M1; this test pins the 1.0 → 1.1 step).
	got, from, to, err := upgradeWith(Steps()[:2], "1.1", in)
	require.NoError(t, err)
	assert.Equal(t, "1.0", from)
	assert.Equal(t, "1.1", to)
	assert.JSONEq(t, want, string(got))

	// The whole chain ends at the current version with the same content (1.1 → 1.2 is additive).
	got, _, to, err = Upgrade(in)
	require.NoError(t, err)
	assert.Equal(t, Current, to)
	assert.JSONEq(t, strings.Replace(want, `"schema_version":"1.1"`, `"schema_version":"`+Current+`"`, 1), string(got))
}

// TestNormalizeNodeAttrs covers every value the 1.0 schema accepted for each attribute 1.1 narrowed
// per node type (log_sink.purpose free text, agent.egress_policy boolean, mcp_server.exposure
// internal/public/unknown) and the 1.1 values, which pass untouched.
func TestNormalizeNodeAttrs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		nodeType string
		in       map[string]any
		want     map[string]any
		n        int
	}{
		{"log_sink free text", "log_sink", map[string]any{"purpose": "Audit trail for SIEM"},
			map[string]any{"x_purpose": "Audit trail for SIEM", MigratedFrom: "purpose=Audit trail for SIEM"}, 1},
		{"log_sink enum in another case", "log_sink", map[string]any{"purpose": " Security "},
			map[string]any{"purpose": "security", MigratedFrom: "purpose= Security "}, 1},
		{"log_sink enum value", "log_sink", map[string]any{"purpose": "evidence"}, map[string]any{"purpose": "evidence"}, 0},
		{"log_sink empty", "log_sink", map[string]any{"purpose": ""}, map[string]any{"purpose": ""}, 0},
		{"log_sink blank text is removed", "log_sink", map[string]any{"purpose": "  "},
			map[string]any{MigratedFrom: "purpose=  "}, 1},
		{"log_sink x_purpose taken", "log_sink", map[string]any{"purpose": "SOC feed", "x_purpose": "other text"},
			map[string]any{"x_purpose": "other text", "x_purpose_2": "SOC feed", MigratedFrom: "purpose=SOC feed"}, 1},
		{"log_sink notes accumulate", "log_sink", map[string]any{"purpose": "SOC", MigratedFrom: "auth=x"},
			map[string]any{"x_purpose": "SOC", MigratedFrom: "auth=x; purpose=SOC"}, 1},
		{"agent egress_policy true", "agent", map[string]any{"egress_policy": true}, map[string]any{MigratedFrom: "egress_policy=true"}, 1},
		{"agent egress_policy false", "agent", map[string]any{"egress_policy": false}, map[string]any{MigratedFrom: "egress_policy=false"}, 1},
		{"agent egress_policy enum", "agent", map[string]any{"egress_policy": "default_allow"}, map[string]any{"egress_policy": "default_allow"}, 0},
		{"agent egress_policy unknown string is the validator's", "agent", map[string]any{"egress_policy": "maybe"}, map[string]any{"egress_policy": "maybe"}, 0},
		{"edge_device keeps its boolean", "edge_device", map[string]any{"egress_policy": true}, map[string]any{"egress_policy": true}, 0},
		{"mcp_server internal", "mcp_server", map[string]any{"exposure": "internal"},
			map[string]any{"exposure": "private_network", MigratedFrom: "exposure=internal"}, 1},
		{"mcp_server unknown", "mcp_server", map[string]any{"exposure": "unknown"}, map[string]any{MigratedFrom: "exposure=unknown"}, 1},
		{"mcp_server public", "mcp_server", map[string]any{"exposure": "public"}, map[string]any{"exposure": "public"}, 0},
		{"mcp_server empty", "mcp_server", map[string]any{"exposure": ""}, map[string]any{"exposure": ""}, 0},
		{"mcp_server loopback", "mcp_server", map[string]any{"exposure": "loopback"}, map[string]any{"exposure": "loopback"}, 0},
		{"app keeps internal", "app", map[string]any{"exposure": "internal"}, map[string]any{"exposure": "internal"}, 0},
		{"nil attrs", "agent", nil, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.in
			n := NormalizeNodeAttrs(tc.nodeType, got)
			assert.Equal(t, tc.n, n)
			assert.Equal(t, tc.want, got)
			assert.Zero(t, NormalizeNodeAttrs(tc.nodeType, got), "idempotent")
		})
	}
}

func TestNarrowedAttrsIsACopy(t *testing.T) {
	t.Parallel()
	c := NarrowedAttrs()
	c["log_sink"]["purpose"][0] = "changed"
	assert.Equal(t, "operational", NarrowedAttrs()["log_sink"]["purpose"][0])
}
