package model

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Schema 1.1 (ADR-047 §1 to §3b, docs/18 D1/D3): identities as entities, the protocol enum, the new
// node types, group kinds and attributes, and the per-type values of shared attributes.

// agentic11 is a small valid 1.1 model using every new construct once.
func agentic11() map[string]any {
	return map[string]any{
		"schema_version": CurrentSchemaVersion, "id": "arch_11", "tenant_id": "t", "name": "1.1", "version": 1,
		"attrs": map[string]any{"owner": "CTO", "sponsor": "COO"},
		"identities": []any{
			map[string]any{"id": "id_agent", "name": "Planner identity", "kind": "agent_identity", "issuer": "https://login.example.org",
				"credential_type": "federated", "federation": "entra_agent_id", "credential_ttl": 3600, "rotation_days": 0,
				"sponsor": "Head of ops", "registry": "n_reg", "trust_domain": "example.org", "blueprint": "bp-planner",
				"attrs": map[string]any{"x_cost_centre": "CC-1"}},
			map[string]any{"id": "id_deploy", "kind": "workload_identity", "credential_type": "federated", "federation": "workload_identity_federation"},
		},
		"groups": []any{
			map[string]any{"id": "g_tenant", "kind": "tenant", "name": "Tenant A", "node_ids": []any{"n_agent", "n_mem"}},
			map[string]any{"id": "g_ch", "kind": "jurisdiction", "name": "Switzerland", "node_ids": []any{"n_agent"}},
		},
		"nodes": []any{
			map[string]any{"id": "n_api", "type": "api", "name": "API", "layer": "app", "attrs": map[string]any{
				"exposure": "public", "authn": []any{"oidc", "api_key"}, "input_guard": "reject", "secrets_delivery": "env",
				"environment": "staging", "redundancy": "zonal", "region": "ch", "region_name": "gcp/europe-west6", "identity_id": "id_deploy"}},
			map[string]any{"id": "n_agent", "type": "agent", "name": "Planner", "layer": "ai", "attrs": map[string]any{
				"identity": "agent_id", "identity_id": "id_agent", "autonomy": "autonomous", "purpose": "p", "owner": "o",
				"sponsor": "s", "inbound_auth": "oauth", "human_in_the_loop": []any{map[string]any{"tool_class": "payments", "disposition": "ask"}},
				"card_url": "https://agents.example.org/.well-known/agent-card.json", "card_signed": true,
				"security_schemes": []any{"oauth2"}, "egress_policy": "default_deny_allowlist", "egress_allowlist": []any{"api.example.org"},
				"hosting": "managed_platform", "sandbox": "managed"}},
			map[string]any{"id": "n_mem", "type": "agent_memory", "name": "Memory", "layer": "data", "attrs": map[string]any{
				"write_path": "every_step", "validated": false, "scope": "thread", "data_classes": []any{"pii", "internal"}}},
			map[string]any{"id": "n_reg", "type": "agent_registry", "name": "Registry", "layer": "identity", "attrs": map[string]any{
				"kind": "agent365", "verification": "signed", "trust_anchor": map[string]any{"key_id": "k1", "fetched_at": "2026-09-30T10:00:00Z"}}},
			map[string]any{"id": "n_vault", "type": "credential_broker", "name": "Token vault", "layer": "identity", "attrs": map[string]any{
				"issues": "short_lived_token", "max_lifetime": 900}},
			map[string]any{"id": "n_peer", "type": "external_agent", "name": "Partner agent", "layer": "ai", "attrs": map[string]any{
				"card_url": "https://partner.example.com/agent.json", "card_signed": false, "security_schemes": []any{"http_bearer"}}},
			map[string]any{"id": "n_mcp", "type": "mcp_server", "name": "MCP", "layer": "app", "attrs": map[string]any{
				"origin": "third_party", "scopes": []any{"read"}, "spec_version": "2026-07-28", "transport": "streamable_http",
				"auth_mode": "oauth21", "resource_metadata": true, "client_registration": "cimd", "registry_entry": "io.example/mcp",
				"sandbox": "container", "discover_supported": true, "cache_scope": "private", "exposure": "private_network"}},
			map[string]any{"id": "n_gw", "type": "gateway", "name": "MCP gateway", "layer": "platform", "attrs": map[string]any{
				"kind": "mcp", "functions": []any{"identity_termination", "policy"}}},
			map[string]any{"id": "n_llm", "type": "llm_endpoint", "name": "Gemini", "layer": "ai", "attrs": map[string]any{
				"provider": "google_vertex", "region": "eu", "network": "private",
				"retention_statement": map[string]any{"asserted_by": "Google Cloud", "asserted_at": "2026-09-01T00:00:00Z", "reference": "https://cloud.google.com/vertex-ai"}}},
			map[string]any{"id": "n_db", "type": "datastore", "name": "DB", "layer": "data", "attrs": map[string]any{
				"engine": "postgres", "data_class": "pii", "data_classes": []any{"pii", "confidential"}, "holds_credentials": true, "region": "ch"}},
			map[string]any{"id": "n_log", "type": "log_sink", "name": "Audit", "layer": "platform", "attrs": map[string]any{"retention_days": 365, "purpose": "evidence"}},
			map[string]any{"id": "n_dev", "type": "product", "name": "Box", "layer": "edge", "attrs": map[string]any{"cra_scope": true, "form": "image"}},
			map[string]any{"id": "n_plc", "type": "edge_device", "name": "PLC", "layer": "edge", "attrs": map[string]any{"site": "s", "attestation": "tpm", "egress_policy": true}},
		},
		"edges": []any{
			map[string]any{"id": "e1", "from": "n_api", "to": "n_agent", "kind": "calls", "protocol": "https", "auth": "token_exchange", "encryption": "tls",
				"attrs": map[string]any{"audience": "api://planner", "token_binding": "dpop", "token_lifetime": 300, "scopes": []any{"plan.write"},
					"delegation_depth": 1, "consent": "per_client", "guarded": true}},
			map[string]any{"id": "e2", "from": "n_agent", "to": "n_mcp", "kind": "calls", "protocol": "mcp_http", "auth": "token_passthrough", "encryption": "tls", "attrs": map[string]any{}},
			map[string]any{"id": "e3", "from": "n_agent", "to": "n_peer", "kind": "delegates", "protocol": "a2a", "auth": "public_client_id", "encryption": "tls", "attrs": map[string]any{}},
		},
		"findings": []any{}, "evidence": []any{},
	}
}

func marshal(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func TestSchema11ModelValidates(t *testing.T) {
	t.Parallel()
	a, err := ValidateJSON(marshal(t, agentic11()))
	require.NoError(t, err)
	require.Len(t, a.Identities, 2)
	id := a.IdentityOf(a.Node("n_agent"))
	require.NotNil(t, id)
	assert.Equal(t, "entra_agent_id", id.Federation)
	require.NotNil(t, id.CredentialTTL)
	assert.EqualValues(t, 3600, *id.CredentialTTL)
	require.NotNil(t, id.RotationDays, "a declared zero survives the round trip")
	assert.Zero(t, *id.RotationDays)
	assert.Nil(t, a.IdentityOf(a.Node("n_db")))
	assert.Nil(t, a.IdentityOf(nil))

	// The identities round-trip through the canonical form and the hash covers them.
	h1, err := Hash(a)
	require.NoError(t, err)
	b, err := a.Clone()
	require.NoError(t, err)
	b.Identities[0].Issuer = "https://other.example.org"
	h2, err := Hash(b)
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "identities are part of the designed model")
}

func TestSchema11Rejects(t *testing.T) {
	t.Parallel()
	node := func(m map[string]any, id string) map[string]any {
		for _, n := range m["nodes"].([]any) {
			if n.(map[string]any)["id"] == id {
				return n.(map[string]any)["attrs"].(map[string]any)
			}
		}
		t.Fatalf("no node %s", id)
		return nil
	}
	for _, tc := range []struct {
		name   string
		mutate func(m map[string]any)
		path   string
		msg    string
	}{
		{"unknown identity", func(m map[string]any) { node(m, "n_agent")["identity_id"] = "id_nope" }, "/nodes/1/attrs/identity_id", `unknown identity "id_nope"`},
		{"identity id clashes with a node", func(m map[string]any) {
			m["identities"].([]any)[1].(map[string]any)["id"] = "n_api"
			node(m, "n_api")["identity_id"] = "n_api"
		}, "/identities/1/id", "duplicate id"},
		{"registry is not a node", func(m map[string]any) { m["identities"].([]any)[0].(map[string]any)["registry"] = "n_none" }, "/identities/0/registry", "unknown node"},
		{"registry is not a registry", func(m map[string]any) { m["identities"].([]any)[0].(map[string]any)["registry"] = "n_db" }, "/identities/0/registry", "not an agent_registry"},
		{"unknown identity kind", func(m map[string]any) { m["identities"].([]any)[0].(map[string]any)["kind"] = "robot" }, "/identities/0/kind", ""},
		{"negative ttl", func(m map[string]any) { m["identities"].([]any)[0].(map[string]any)["credential_ttl"] = -1 }, "/identities/0/credential_ttl", ""},
		{"unknown identity member", func(m map[string]any) { m["identities"].([]any)[0].(map[string]any)["password"] = "x" }, "/identities/0", ""},
		{"gateway kind of a registry", func(m map[string]any) { node(m, "n_gw")["kind"] = "agent365" }, "/nodes/7/attrs/kind", "a gateway accepts api, ai, waf, mcp, a2a, egress"},
		{"registry kind of a gateway", func(m map[string]any) { node(m, "n_reg")["kind"] = "waf" }, "/nodes/3/attrs/kind", "a agent_registry accepts"},
		// A boolean egress_policy on an agent and a free-text log_sink purpose were 1.0 values: they
		// are migrated, not refused (TestNarrowed10ValuesValidateAfterUpgrade). A value no version
		// accepted still is.
		{"unknown egress policy on an agent", func(m map[string]any) { node(m, "n_agent")["egress_policy"] = "allow_some" }, "/nodes/1/attrs/egress_policy", ""},
		{"enum egress policy on an edge device", func(m map[string]any) { node(m, "n_plc")["egress_policy"] = "default_allow" }, "/nodes/12/attrs/egress_policy", "a edge_device accepts true, false"},
		{"managed sandbox on an MCP server", func(m map[string]any) { node(m, "n_mcp")["sandbox"] = "managed" }, "/nodes/6/attrs/sandbox", "a mcp_server accepts"},
		{"loopback exposure on an API", func(m map[string]any) { node(m, "n_api")["exposure"] = "loopback" }, "/nodes/0/attrs/exposure", "a api accepts internal, public, unknown"},
		{"log purpose that is not text", func(m map[string]any) { node(m, "n_log")["purpose"] = 42 }, "/nodes/10/attrs/purpose", ""},
		{"MCP exposure no version knew", func(m map[string]any) { node(m, "n_mcp")["exposure"] = "intranet" }, "/nodes/6/attrs/exposure", ""},
		{"protocol outside the enum on a 1.1 document stays readable", nil, "", ""},
		{"region name without a provider", func(m map[string]any) { node(m, "n_api")["region_name"] = "europe-west6" }, "/nodes/0/attrs/region_name", ""},
		{"unknown disposition", func(m map[string]any) {
			node(m, "n_agent")["human_in_the_loop"] = []any{map[string]any{"tool_class": "x", "disposition": "maybe"}}
		}, "/nodes/1/attrs/human_in_the_loop/0/disposition", ""},
		{"trust anchor with an unknown member", func(m map[string]any) {
			node(m, "n_reg")["trust_anchor"] = map[string]any{"key_id": "k", "secret": "s"}
		}, "/nodes/3/attrs/trust_anchor", ""},
		{"unknown edge token binding", func(m map[string]any) {
			m["edges"].([]any)[0].(map[string]any)["attrs"].(map[string]any)["token_binding"] = "cookie"
		}, "/edges/0/attrs/token_binding", ""},
		{"unknown group kind", func(m map[string]any) { m["groups"].([]any)[0].(map[string]any)["kind"] = "planet" }, "/groups/0/kind", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.mutate == nil {
				return // covered by TestTolerantReading
			}
			m := agentic11()
			tc.mutate(m)
			_, err := ValidateJSON(marshal(t, m))
			var ve *ValidationError
			require.True(t, errors.As(err, &ve), "%v", err)
			found := false
			for _, p := range ve.Problems {
				if p.Path == tc.path {
					found = true
					assert.Contains(t, p.Message, tc.msg)
				}
			}
			assert.True(t, found, "no problem at %s in %v", tc.path, ve.Problems)
			assert.NotContains(t, err.Error(), "keep everything", "a per-type error names the accepted values, not the value given")
		})
	}
}

// TestAttrValueInvariantsOnADecodedValue: Invariants alone (no normalisation) still enforces the
// per-type values, so a value that bypassed the tolerant reading is refused and the message names
// the accepted values, never the value given.
func TestAttrValueInvariantsOnADecodedValue(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, nodeType, attr string
		value                any
		msg                  string
	}{
		{"log purpose", "log_sink", "purpose", "keep everything", "a log_sink accepts operational, security, evidence"},
		{"agent egress", "agent", "egress_policy", true, "a agent accepts default_deny_allowlist, default_allow, undeclared"},
		{"mcp exposure", "mcp_server", "exposure", "internal", "a mcp_server accepts loopback, private_network, public"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := Empty("arch_i", "t", "i")
			a.Nodes = []Node{{ID: "n", Type: tc.nodeType, Name: "N", Layer: "app", Attrs: Attrs{tc.attr: tc.value}}}
			err := Invariants(a)
			var ve *ValidationError
			require.True(t, errors.As(err, &ve), "%v", err)
			require.Len(t, ve.Problems, 1)
			assert.Equal(t, "/nodes/0/attrs/"+tc.attr, ve.Problems[0].Path)
			assert.Equal(t, tc.msg, ve.Problems[0].Message)
		})
	}
}

// TestTolerantReading: for two MINOR versions a document already at 1.1 may still carry the 1.0
// shapes 1.1 replaced; they are mapped on read (ValidateJSON) and on a Go value (Validate).
func TestTolerantReading(t *testing.T) {
	t.Parallel()
	m := agentic11()
	m["edges"].([]any)[0].(map[string]any)["protocol"] = "in-process"
	m["edges"].([]any)[1].(map[string]any)["protocol"] = "MCP_HTTP"
	m["nodes"].([]any)[0].(map[string]any)["attrs"].(map[string]any)["authn"] = "oidc"
	a, err := ValidateJSON(marshal(t, m))
	require.NoError(t, err)
	assert.Equal(t, "other", a.Edge("e1").Protocol)
	assert.Equal(t, "protocol=in-process", a.Edge("e1").Attrs[MigratedFromAttr])
	assert.Equal(t, "mcp_http", a.Edge("e2").Protocol)
	assert.NotContains(t, a.Edge("e2").Attrs, MigratedFromAttr, "case only: nothing to note")
	assert.Equal(t, []any{"oidc"}, a.Node("n_api").Attrs["authn"])

	// A Go value an importer or a pattern built is mapped in place by Validate.
	built := Empty("arch_go", "t", "built")
	built.Nodes = []Node{
		{ID: "a", Type: "app", Name: "A", Layer: "app", Attrs: Attrs{"exposure": "internal", "authn": "oauth"}},
		{ID: "b", Type: "datastore", Name: "B", Layer: "data", Attrs: Attrs{"engine": "sql", "data_class": "internal", "region": "ch"}},
	}
	built.Edges = []Edge{{ID: "e", From: "a", To: "b", Kind: "reads", Protocol: "JDBC", Auth: "managed_identity", Encryption: "tls"}}
	require.NoError(t, Validate(built))
	assert.Equal(t, "sql", built.Edges[0].Protocol)
	assert.Equal(t, "protocol=JDBC", built.Edges[0].Attrs[MigratedFromAttr])
	assert.Equal(t, []any{"oauth"}, built.Nodes[0].Attrs["authn"])
	require.NoError(t, Validate(built), "the mapping is idempotent")
	assert.Equal(t, "protocol=JDBC", built.Edges[0].Attrs[MigratedFromAttr])
}

func TestIdentitiesAreIDAddressedInPatches(t *testing.T) {
	t.Parallel()
	a, err := ValidateJSON(marshal(t, agentic11()))
	require.NoError(t, err)
	out, err := Apply(a, []PatchOp{
		{Op: "replace", Path: "/identities/id_agent/credential_ttl", Value: json.RawMessage(`900`)},
		{Op: "add", Path: "/identities/-", Value: json.RawMessage(`{"id":"id_new","kind":"service_principal"}`)},
		{Op: "add", Path: "/nodes/n_vault/attrs/identity_id", Value: json.RawMessage(`"id_new"`)},
	}, false)
	require.NoError(t, err)
	assert.EqualValues(t, 900, *out.Identity("id_agent").CredentialTTL)
	assert.Equal(t, "id_new", out.IdentityOf(out.Node("n_vault")).ID)

	_, err = Apply(a, []PatchOp{{Op: "replace", Path: "/identities/id_nope/kind", Value: json.RawMessage(`"none"`)}}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `no identity with id "id_nope"`)

	// Removing an identity a node still runs as is refused by the invariant.
	_, err = Apply(a, []PatchOp{{Op: "remove", Path: "/identities/id_agent"}}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown identity "id_agent"`)

	// A model without identities gains the collection with one add.
	empty := Empty("arch_e", "t", "e")
	out, err = Apply(empty, []PatchOp{{Op: "add", Path: "/identities", Value: json.RawMessage(`[{"id":"id_1"}]`)}}, false)
	require.NoError(t, err)
	assert.Len(t, out.Identities, 1)
}

func TestAttrValuesAreReadFromTheSchema(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []any{"", "api", "ai", "waf", "mcp", "a2a", "egress"}, AttrValues("gateway")["kind"])
	assert.Equal(t, []any{true, false}, AttrValues("edge_gateway")["egress_policy"])
	assert.Contains(t, AttrValues("agent")["sandbox"], "managed")
	assert.NotContains(t, AttrValues("mcp_server")["sandbox"], "managed")
	assert.Empty(t, AttrValues("queue"))
	assert.Equal(t, []string{"write_path", "validated", "scope"}, RequiredAttrs("agent_memory"))
	assert.Equal(t, []string{"origin", "scopes"}, RequiredAttrs("mcp_server"), "mcp_server has its own profile with the tool's required attributes")
}
