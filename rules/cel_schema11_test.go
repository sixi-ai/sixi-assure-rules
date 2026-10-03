package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Schema 1.1 projection (docs/18 D1 item 6): every new attribute is readable through attr(), the
// identity a node runs as is resolved onto the node, and the new node types and group kinds are
// visible to the graph helpers. No rule reads them yet (D2 adds the rules).
func schema11Model(t *testing.T) *model.Architecture {
	t.Helper()
	ttl := int64(3600)
	a := model.Empty("arch_11", "t", "schema 1.1")
	a.Attrs["sponsor"] = "COO"
	a.Identities = []model.Identity{
		{ID: "id_agent", Kind: "agent_identity", Issuer: "https://login.example.org", CredentialType: "federated",
			Federation: "entra_agent_id", CredentialTTL: &ttl, Registry: "reg", Attrs: model.Attrs{"x_note": "ignored"}},
		{ID: "id_bare"},
	}
	a.Groups = []model.Group{
		{ID: "g_t", Kind: "tenant", Name: "Tenant", NodeIDs: []string{"ag", "mem"}},
		{ID: "g_j", Kind: "jurisdiction", Name: "CH", NodeIDs: []string{"ag"}},
	}
	a.Nodes = []model.Node{
		{ID: "ag", Type: "agent", Name: "Agent", Layer: "ai", Attrs: model.Attrs{"identity": "agent_id", "identity_id": "id_agent",
			"egress_policy": "default_allow", "sandbox": "managed", "hosting": "managed_platform",
			"human_in_the_loop": []any{map[string]any{"tool_class": "payments", "disposition": "ask"}}}},
		{ID: "mem", Type: "agent_memory", Name: "Memory", Layer: "data", Attrs: model.Attrs{"write_path": "every_step", "validated": false, "scope": "thread"}},
		{ID: "reg", Type: "agent_registry", Name: "Registry", Layer: "identity", Attrs: model.Attrs{"kind": "mcp", "verification": "namespace",
			"trust_anchor": map[string]any{"key_id": "k1", "fetched_at": "2026-09-30T10:00:00Z"}}},
		{ID: "vault", Type: "credential_broker", Name: "Vault", Layer: "identity", Attrs: model.Attrs{"issues": "short_lived_token", "max_lifetime": 900.0, "identity_id": "id_bare"}},
		{ID: "peer", Type: "external_agent", Name: "Peer", Layer: "ai", Attrs: model.Attrs{"card_signed": false}},
		{ID: "mcp", Type: "mcp_server", Name: "MCP", Layer: "app", Attrs: model.Attrs{"origin": "third_party", "scopes": []any{"r"},
			"exposure": "public", "auth_mode": "none", "transport": "streamable_http"}},
	}
	a.Edges = []model.Edge{
		{ID: "e1", From: "ag", To: "mcp", Kind: "calls", Protocol: "mcp_http", Auth: "token_passthrough", Encryption: "tls",
			Attrs: model.Attrs{"audience": "api://mcp", "token_binding": "none", "token_lifetime": 3600.0, "delegation_depth": 2.0, "scopes": []any{"r"}, "guarded": true}},
		{ID: "e2", From: "ag", To: "peer", Kind: "delegates", Protocol: "a2a", Auth: "jwt_assertion", Encryption: "tls", Attrs: model.Attrs{}},
		{ID: "e3", From: "peer", To: "ag", Kind: "calls", Protocol: "a2a", Auth: "public_client_id", Encryption: "tls", Attrs: model.Attrs{}},
	}
	require.NoError(t, model.Validate(a))
	return a
}

func TestSchema11Projection(t *testing.T) {
	t.Parallel()
	a := schema11Model(t)
	for _, tc := range []struct {
		name    string
		scope   string
		element string
		expr    string
		want    any
	}{
		{"identity resolved on the node", ScopeNode, "ag", `n.identity.federation == "entra_agent_id" && n.identity.issuer != ""`, true},
		{"identity kind", ScopeNode, "ag", `n.identity.kind`, "agent_identity"},
		{"declared ttl through attr", ScopeNode, "ag", `attr(n.identity, "credential_ttl", -1)`, int64(3600)},
		{"undeclared ttl defaults through attr", ScopeNode, "vault", `attr(n.identity, "credential_ttl", -1)`, int64(-1)},
		{"undeclared member reads empty at the top level", ScopeNode, "vault", `n.identity.issuer == "" && n.identity.id == "id_bare"`, true},
		{"a node without identity gets the empty one", ScopeNode, "mem", `n.identity.id == "" && size(n.identity.attrs) == 0`, true},
		{"x_ values of an identity stay out", ScopeNode, "ag", `has(n.identity.attrs.x_note)`, false},
		{"identity registry names the registry node", ScopeNode, "ag", `g.nodes("agent_registry").exists(r, r.id == n.identity.registry)`, true},
		{"identity on an edge endpoint", ScopeEdge, "e1", `e.from.identity.credential_type == "federated"`, true},
		{"graph identities", ScopeGraph, "", `g.identities.size()`, int64(2)},
		{"graph identities filter", ScopeGraph, "", `g.identities.filter(i, i.kind == "agent_identity").map(i, i.id)`, []any{"id_agent"}},
		{"new node types are visible", ScopeGraph, "", `g.has("agent_memory") && g.has("agent_registry") && g.has("credential_broker") && g.has("external_agent")`, true},
		{"new group kinds", ScopeNode, "ag", `n.inZone("tenant") && n.inZone("jurisdiction")`, true},
		{"memory not in a jurisdiction", ScopeNode, "mem", `n.inZone("jurisdiction")`, false},
		{"memory attrs", ScopeNode, "mem", `!attr(n, "validated", true) && attr(n, "scope", "") == "thread"`, true},
		{"registry trust anchor", ScopeNode, "reg", `attr(n, "trust_anchor", {}).key_id`, "k1"},
		{"broker lifetime", ScopeNode, "vault", `attr(n, "max_lifetime", 0) <= 900`, true},
		{"agent egress enum", ScopeNode, "ag", `attr(n, "egress_policy", "undeclared") == "default_allow"`, true},
		{"agent sandbox and hosting", ScopeNode, "ag", `attr(n, "sandbox", "") == "managed" && attr(n, "hosting", "") == "managed_platform"`, true},
		{"human in the loop", ScopeNode, "ag", `attr(n, "human_in_the_loop", []).exists(h, h.tool_class == "payments" && h.disposition == "ask")`, true},
		{"mcp exposure and auth mode", ScopeNode, "mcp", `attr(n, "exposure", "") == "public" && attr(n, "auth_mode", "") == "none"`, true},
		{"edge token attributes", ScopeEdge, "e1", `attr(e, "token_binding", "") == "none" && attr(e, "delegation_depth", 0) > 1 && attr(e, "token_lifetime", 0) == 3600`, true},
		{"edge passthrough and protocol enum", ScopeEdge, "e1", `e.auth == "token_passthrough" && e.protocol == "mcp_http"`, true},
		{"edge guarded", ScopeEdge, "e1", `attr(e, "guarded", false)`, true},
		{"public client id", ScopeEdge, "e3", `e.auth`, "public_client_id"},
		{"architecture sponsor", ScopeGraph, "", `attr(g, "sponsor", "")`, "COO"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := evalExpr(t, tc.scope, tc.expr, a, Policy{}, tc.element)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
