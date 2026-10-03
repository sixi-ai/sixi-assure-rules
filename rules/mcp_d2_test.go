package rules

// docs/18 D2 (ADR-047 §4): the mcp pack, the schema 1.1 rules D2 adds to the zt, a2a and net packs, and the optional
// `references:` field (documentation citations with url + fetched_at). The shipped-pack tests parse only the four packs
// D2 touches (no causes file), so they read the rules as written whatever other packs are doing.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// d2Rules are the rules docs/18 D2 ships, by pack.
var d2Rules = map[string][]string{
	"mcp": {"MCP-002", "MCP-003", "MCP-005", "MCP-009", "TSC-001", "HOV-003", "MEM-001", "ARH-001"},
	"zt":  {"AID-001", "AID-002", "AID-010", "AID-011", "WIS-004", "WIS-010", "WIS-011", "DLG-001", "DLG-003", "DLG-010"},
	"a2a": {"ATA-006", "ATA-010", "ATA-011"},
	"net": {"SEG-010", "SEG-011"},
}

func d2Catalog(t *testing.T) *Catalog {
	t.Helper()
	sources := make([]PackSource, 0, len(d2Rules))
	for pack := range d2Rules {
		// repoPath("packs") as one call: scripts/sync-public-rules.sh rewrites that spelling for the public mirror.
		b, err := os.ReadFile(filepath.Join(repoPath("packs"), pack+".yaml"))
		require.NoError(t, err)
		sources = append(sources, PackSource{Name: pack + ".yaml", Data: b, BaseDir: repoPath("packs")})
	}
	c, err := ParsePacks(sources, LoadOptions{})
	require.NoError(t, err)
	return c
}

func d2Evaluate(t *testing.T, c *Catalog, a *model.Architecture) map[string][]string {
	t.Helper()
	fs, err := New(c, nil).Evaluate(context.Background(), a, policyFromAttrs(a))
	require.NoError(t, err)
	return findingsByRule(fs)
}

// d2Cover evaluates with coverage (ADR-088 §4): the findings by rule and the coverage.
func d2Cover(t *testing.T, c *Catalog, a *model.Architecture) (map[string][]string, Coverage) {
	t.Helper()
	fs, cov, err := New(c, nil).EvaluateCoverage(context.Background(), a, policyFromAttrs(a))
	require.NoError(t, err)
	return findingsByRule(fs), cov
}

// referenceSection is the section a reference title names: the text after "<document>: " (or from the § where the
// title has no colon, "A2A Protocol Specification §8.4 Agent Card Signing"), without a trailing gloss in parentheses.
func referenceSection(title string) string {
	t := title
	if i := strings.LastIndex(t, " ("); i > 0 && strings.HasSuffix(t, ")") {
		t = t[:i]
	}
	if _, after, ok := strings.Cut(t, ": "); ok {
		return after
	}
	if i := strings.Index(t, "§"); i >= 0 {
		return t[i:]
	}
	return t
}

const referencePack = `
pack: tst
version: 0.1.0
rules:
  - id: TST-001
    title: Token passthrough
    scope: edge
    severity: critical
    condition: 'e.auth == "token_passthrough"'
    message: "{{e.from.name}} forwards a token."
    clauses: [OWASP:AgenticTop10:ASI03]
    remediation: "Exchange the token."
`

func TestPackReferences(t *testing.T) {
	t.Parallel()
	ok := `{ kind: document, title: "MCP Authorization", url: "https://example.org/spec/authorization", fetched_at: "2026-10-01" }`
	tests := []struct {
		name, refs, want string
		count            int
	}{
		{"none", "", "", 0},
		{"one", "    references:\n      - " + ok + "\n", "", 1},
		{"two", "    references:\n      - " + ok + "\n      - { kind: document, title: B, url: \"https://example.org/b\", fetched_at: \"2026-09-30\" }\n", "", 2},
		{"law is a clause, not a reference", "    references:\n      - { kind: clause, title: A, url: \"https://example.org/a\", fetched_at: \"2026-10-01\" }\n", `kind "clause" must be "document"`, 0},
		{"plain http", "    references:\n      - { kind: document, title: A, url: \"http://example.org/a\", fetched_at: \"2026-10-01\" }\n", "must be https", 0},
		{"no host", "    references:\n      - { kind: document, title: A, url: \"https:///a\", fetched_at: \"2026-10-01\" }\n", "has no host", 0},
		{"user information", "    references:\n      - { kind: document, title: A, url: \"https://u:p@example.org/a\", fetched_at: \"2026-10-01\" }\n", "user information", 0},
		{"whitespace", "    references:\n      - { kind: document, title: A, url: \"https://example.org/a b\", fetched_at: \"2026-10-01\" }\n", "whitespace", 0},
		{"no title", "    references:\n      - { kind: document, title: \"\", url: \"https://example.org/a\", fetched_at: \"2026-10-01\" }\n", "title is required", 0},
		{"timestamp, not a day", "    references:\n      - { kind: document, title: A, url: \"https://example.org/a\", fetched_at: \"2026-10-01T10:00:00Z\" }\n", "YYYY-MM-DD", 0},
		{"no date", "    references:\n      - { kind: document, title: A, url: \"https://example.org/a\" }\n", "fetched_at", 0},
		{"duplicate url", "    references:\n      - " + ok + "\n      - " + ok + "\n", "duplicate url", 0},
		{"unknown key", "    references:\n      - { kind: document, title: A, url: \"https://example.org/a\", fetched_at: \"2026-10-01\", quote: x }\n", "quote", 0},
		{"too many", "    references:\n" + strings.Repeat("      - "+ok+"\n", maxReferences+1), "at most", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := parseInline(t, referencePack+tc.refs)
			if tc.want != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.want)
				return
			}
			require.NoError(t, err)
			r, found := c.Rule("TST-001")
			require.True(t, found)
			require.Len(t, r.References, tc.count)
			assert.NotNil(t, r.References, "a rule without references has an empty list")
			for _, ref := range r.References {
				assert.Equal(t, ReferenceKindDocument, ref.Kind)
				assert.True(t, strings.HasPrefix(ref.URL, "https://"))
			}
		})
	}
}

// The content hash covers references (ADR-042 §4): a citation is part of what the rule says.
func TestReferencesAreHashed(t *testing.T) {
	t.Parallel()
	ref := func(day string) string {
		return referencePack + "    references:\n      - { kind: document, title: A, url: \"https://example.org/a\", fetched_at: \"" + day + "\" }\n"
	}
	a := mustInline(t, ref("2026-10-01")).Packs()[0].Hash()
	b := mustInline(t, ref("2026-10-02")).Packs()[0].Hash()
	c := mustInline(t, referencePack).Packs()[0].Hash()
	assert.NotEqual(t, a, b)
	assert.NotEqual(t, a, c)
}

// Every D2 rule is shipped where docs/03 says, and a rule that cites a specification lists it as a documentation
// reference (url + fetched_at). The finding carries the list as its structured `references` field (ADR-095, accepted
// with the change that removed the "Reference: …" sentence from the messages), so no message repeats it.
func TestD2ShippedRules(t *testing.T) {
	t.Parallel()
	c := d2Catalog(t)
	withRefs := map[string]bool{"MCP-002": true, "MCP-003": true, "MCP-005": true, "MCP-009": true, "TSC-001": true,
		"ARH-001": true, "ATA-010": true, "ATA-011": true, "SEG-010": true}
	for pack, ids := range d2Rules {
		for _, id := range ids {
			r, ok := c.Rule(id)
			require.True(t, ok, id)
			assert.Equal(t, pack, r.Pack, id)
			assert.NotEmpty(t, r.Fixtures.Positive, id)
			if !withRefs[id] {
				assert.Empty(t, r.References, id)
				continue
			}
			require.NotEmpty(t, r.References, "%s cites the specification it rests on", id)
			// ADR-095: the structured field carries the reference; the message no longer repeats it.
			assert.NotContains(t, r.Message, "Reference:", "%s: the finding's references field names the reference, not the message", id)
			for _, ref := range r.References {
				_, err := time.Parse(time.DateOnly, ref.FetchedAt)
				require.NoError(t, err, id)
				assert.NotEmpty(t, referenceSection(ref.Title), "%s: the title of %q names a section", id, ref.URL)
				for _, cl := range r.Clauses {
					assert.NotContains(t, cl, "MCP", "%s: the MCP specification is a reference, never a clause", id)
				}
			}
		}
	}
	r, _ := c.Rule("MCP-003")
	assert.Equal(t, "critical", r.Severity)
}

func TestReferenceSection(t *testing.T) {
	t.Parallel()
	for title, want := range map[string]string{
		"MCP 2026-07-28 Security Best Practices: Token Passthrough":                                                     "Token Passthrough",
		"MCP 2026-07-28 Client Registration: Dynamic Client Registration (deprecated)":                                  "Dynamic Client Registration",
		"MCP Registry (preview, API v0.1): server.json entries and namespace verification":                              "server.json entries and namespace verification",
		"A2A Protocol Specification §8.4.3 Signature Verification (key from kid/jku or a trusted key store)":            "§8.4.3 Signature Verification",
		"MCP 2026-07-28 Streamable HTTP: Security & Endpoint (bind locally to 127.0.0.1, authenticate all connections)": "Security & Endpoint",
	} {
		assert.Equal(t, want, referenceSection(title), title)
	}
}

// ADR-047 acceptance: edge.auth token_passthrough across a trust boundary raises the critical MCP rule with the
// specification citation (url + fetched_at). The golden bad twin's gateway → vendor server hop is the case.
func TestTokenPassthroughAcrossBoundaryIsCritical(t *testing.T) {
	t.Parallel()
	c := d2Catalog(t)
	a := loadModel(t, repoPath("golden-set", "models", "mcp-agent-platform-bad.json"))
	fs, err := New(c, nil).Evaluate(context.Background(), a, policyFromAttrs(a))
	require.NoError(t, err)
	var got *model.Finding
	for i := range fs {
		if fs[i].RuleID == "MCP-003" && slices.Equal(fs[i].IDs, []string{"e_mcpgw_market"}) {
			got = &fs[i]
		}
	}
	require.NotNil(t, got, "MCP-003 on the passthrough hop")
	assert.Equal(t, "critical", got.Severity)
	assert.Contains(t, got.Message, "token_passthrough")
	r, _ := c.Rule("MCP-003")
	require.NotEmpty(t, r.References)
	assert.True(t, strings.HasPrefix(r.References[0].URL, "https://"))
	assert.Equal(t, "2026-10-01", r.References[0].FetchedAt)
	// ADR-095: the finding carries the rule's references as a structured field (url + fetched_at), in rule order.
	require.Len(t, got.References, len(r.References))
	for i, ref := range r.References {
		assert.Equal(t, model.FindingReference{Kind: ref.Kind, Title: ref.Title, URL: ref.URL, FetchedAt: ref.FetchedAt}, got.References[i])
	}
	assert.NotContains(t, got.Message, "Reference:", "the message no longer repeats the reference")

	groups := map[string][]string{}
	for _, g := range a.Groups {
		for _, id := range g.NodeIDs {
			groups[id] = append(groups[id], g.ID)
		}
	}
	for _, gid := range groups["n_mcpgw"] {
		assert.NotContains(t, groups["n_mcp_market"], gid, "the hop crosses a boundary: no shared group")
	}

	good := loadModel(t, repoPath("golden-set", "models", "mcp-agent-platform.json"))
	for id, els := range d2Evaluate(t, c, good) {
		t.Errorf("good twin raises %s on %v", id, els)
	}
}

func d2Model(t *testing.T, raw string) *model.Architecture {
	t.Helper()
	a, err := model.ValidateJSON([]byte(raw))
	require.NoError(t, err)
	return a
}

const d2Agent10 = `{"id":"%s","type":"agent","name":"%s","layer":"ai","source":"design",
  "attrs":{"identity":"%s","autonomy":"assisted","purpose":"Fixture.","owner":"Owner"}}`

// D1 note: a 1.0 model gets one identity per distinct agent.identity value on read, so several agents share
// ident_agent_id. Those migrated identities carry no issuer, sponsor or registry: the D2 identity rules raise nothing on
// them and report the agents not_checked, never decided (ADR-088 §4); a migrated identity whose kind is shared still
// reads as shared. Migration is read from x_migrated_from (n.identity.migrated), never from the id: a native identity
// named ident_* is assessed, and so is a migrated one the architect has completed in place.
func TestD2IdentityRulesSkipMigratedIdentities(t *testing.T) {
	t.Parallel()
	c := d2Catalog(t)
	model10 := func(value string) string {
		return `{"schema_version":"1.0","id":"arch_d2_m","tenant_id":"t","name":"m","version":1,
  "attrs":{"owner":"Owner","regimes":["MCSB","NIST"]},"groups":[],
  "nodes":[` + fmt.Sprintf(d2Agent10, "n_a", "Agent A", value) + `,` + fmt.Sprintf(d2Agent10, "n_b", "Agent B", value) + `,
    {"id":"n_reg","type":"agent_registry","name":"Registry","layer":"identity","source":"design","attrs":{"kind":"agent365","verification":"reviewed"}}],
  "edges":[],"findings":[],"evidence":[]}`
	}
	model11 := func(identity string) string {
		return `{"schema_version":"1.1","id":"arch_d2_n","tenant_id":"t","name":"n","version":1,
  "attrs":{"owner":"Owner","regimes":["MCSB","NIST"]},"groups":[],
  "identities":[` + identity + `],
  "nodes":[
    {"id":"n_a","type":"agent","name":"Agent A","layer":"ai","source":"design","attrs":{"identity":"agent_id","identity_id":"id_x","autonomy":"assisted","purpose":"Fixture.","owner":"Owner"}},
    {"id":"n_b","type":"agent","name":"Agent B","layer":"ai","source":"design","attrs":{"identity":"agent_id","identity_id":"id_x","autonomy":"assisted","purpose":"Fixture.","owner":"Owner"}},
    {"id":"n_reg","type":"agent_registry","name":"Registry","layer":"identity","source":"design","attrs":{"kind":"agent365","verification":"reviewed"}}],
  "edges":[],"findings":[],"evidence":[]}`
	}
	native := strings.ReplaceAll(model11(`{"id":"id_x","name":"Fleet identity","kind":"agent_identity","federation":"entra_agent_id"}`), "id_x", "id_fleet")
	// A native identity whose id happens to start like a migrated one: the schema does not reserve the prefix.
	nativeIdentPrefix := strings.ReplaceAll(model11(`{"id":"id_x","name":"Orders identity","kind":"agent_identity"}`), "id_x", "ident_orders")
	// A migrated identity the architect completed in place through the property panel: a sponsor declared, no issuer,
	// no registry. It is assessed like a native one.
	completed := strings.ReplaceAll(model11(`{"id":"id_x","name":"Agent identity (agent_id)","kind":"agent_identity","sponsor":"Head of platforms","attrs":{"x_migrated_from":"agent.identity=agent_id"}}`), "id_x", "ident_agent_id")
	both := []string{"n_a", "n_b"}
	identityRules := []string{"AID-001", "AID-002", "AID-010", "AID-011"}
	tests := []struct {
		name       string
		raw        string
		want       map[string][]string
		notChecked map[string][]string
	}{
		{"migrated agent_id: one entity stands for every agent", model10("agent_id"), map[string][]string{},
			map[string][]string{"AID-001": both, "AID-002": both, "AID-010": both, "AID-011": both}},
		{"migrated shared: read as shared", model10("shared"), map[string][]string{"AID-002": both},
			map[string][]string{"AID-001": both, "AID-010": both, "AID-011": both}},
		{"native identity shared by two agents", native, map[string][]string{
			"AID-001": both, "AID-002": both, "AID-010": both, "AID-011": both}, map[string][]string{}},
		{"native identity named ident_*", nativeIdentPrefix, map[string][]string{
			"AID-001": both, "AID-002": both, "AID-010": both, "AID-011": both}, map[string][]string{}},
		{"migrated identity completed in place", completed, map[string][]string{
			"AID-002": both, "AID-010": both, "AID-011": both}, map[string][]string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := d2Model(t, tc.raw)
			got, cov := d2Cover(t, c, a)
			for _, id := range identityRules {
				els := got[id]
				slices.Sort(els)
				assert.Equal(t, tc.want[id], els, id)
				assert.Equal(t, tc.notChecked[id], cov.NotChecked[id], "%s: not_checked", id)
				if len(tc.notChecked[id]) == len(both) {
					assert.Equal(t, len(tc.want[id]), cov.Decided[id], "%s: a migrated agent is never counted decided", id)
				}
			}
		})
	}
}

// WIS-004 and WIS-011 decide on the identity's credential_type and federation: an identity that declares neither (and
// a node that names no identity) is not_checked, never decided; only a declared weak value reports.
func TestD2CredentialFactsAreRequired(t *testing.T) {
	t.Parallel()
	c := d2Catalog(t)
	raw := func(identity string) string {
		return `{"schema_version":"1.1","id":"arch_d2_w","tenant_id":"t","name":"w","version":1,
  "attrs":{"owner":"Owner","regimes":["MCSB","NIST"]},
  "groups":[{"id":"g_a","kind":"trust_boundary","name":"A","node_ids":["n_app"]},{"id":"g_b","kind":"trust_boundary","name":"B","node_ids":["n_api"]}],
  "identities":[` + identity + `],
  "nodes":[
    {"id":"n_app","type":"app","name":"Orders app","layer":"app","source":"design","attrs":{"identity_id":"id_app","provider_service":"azure/container-apps","authn":["oauth"],"secrets_in":"secret_store"}},
    {"id":"n_api","type":"api","name":"Billing API","layer":"app","source":"design","attrs":{"exposure":"internal","authn":["oauth"],"secrets_in":"secret_store"}}],
  "edges":[{"id":"e1","from":"n_app","to":"n_api","kind":"calls","protocol":"https","auth":"oauth_client","encryption":"tls","data_class":"internal","attrs":{"logged":true}}],
  "findings":[],"evidence":[]}`
	}
	tests := []struct {
		name                   string
		identity               string
		wis004, wis011         bool // fires
		wis004Open, wis011Open bool // not_checked
	}{
		{"neither fact declared", `{"id":"id_app","name":"App identity","kind":"workload_identity"}`, false, false, true, true},
		{"weak values declared", `{"id":"id_app","name":"App identity","kind":"workload_identity","credential_type":"client_secret","federation":"static_key"}`, true, true, false, false},
		{"strong values declared", `{"id":"id_app","name":"App identity","kind":"workload_identity","credential_type":"managed_identity","federation":"workload_identity_federation"}`, false, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, cov := d2Cover(t, c, d2Model(t, raw(tc.identity)))
			assert.Equal(t, tc.wis004, slices.Contains(got["WIS-004"], "n_app"), "WIS-004 fires")
			assert.Equal(t, tc.wis011, slices.Contains(got["WIS-011"], "e1"), "WIS-011 fires")
			assert.Equal(t, tc.wis004Open, slices.Contains(cov.NotChecked["WIS-004"], "n_app"), "WIS-004 not_checked")
			assert.Equal(t, tc.wis011Open, slices.Contains(cov.NotChecked["WIS-011"], "e1"), "WIS-011 not_checked")
		})
	}
}

// MCP-003 compares the audience with every name the server goes by (RFC 8707: the audience is a resource indicator):
// its identity_id, its identity's ref, its node id and its external_ref. A URI audience against a server that declares
// no URI-shaped name is not_checked (no ref) or outside the decision (only non-URI names), never a critical.
func TestMCP003Audience(t *testing.T) {
	t.Parallel()
	c := d2Catalog(t)
	const uri = "https://mcp.vendor.example/mcp"
	tests := []struct {
		name, auth, audience, ref, identityID string
		fires, notChecked                     bool
	}{
		{"token passthrough", "token_passthrough", "", uri, "id_mcp", true, false},
		{"audience is the identity's ref (the canonical server URI)", "token_exchange", uri, uri, "id_mcp", false, false},
		{"audience is the identity id", "token_exchange", "id_mcp", uri, "id_mcp", false, false},
		{"audience is the node id", "token_exchange", "n_mcp", uri, "id_mcp", false, false},
		{"audience is another server's URI", "token_exchange", "https://other.example/mcp", uri, "id_mcp", true, false},
		{"audience is another resource's name", "token_exchange", "market-data", uri, "id_mcp", true, false},
		{"URI audience, the identity declares no ref", "token_exchange", uri, "", "id_mcp", false, true},
		{"URI audience, the server names no identity", "token_exchange", uri, "", "", false, true},
		{"URI audience, the server's names are not URIs", "token_exchange", uri, "00000000-0000-0000-0000-0000000000aa", "id_mcp", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, repoPath("packs", "fixtures", "MCP-003.neg.json"))
			for i := range a.Identities {
				if a.Identities[i].ID == "id_mcp" {
					a.Identities[i].Ref = tc.ref
				}
			}
			for i := range a.Nodes {
				if a.Nodes[i].ID == "n_mcp" {
					if tc.identityID == "" {
						delete(a.Nodes[i].Attrs, "identity_id")
					} else {
						a.Nodes[i].Attrs["identity_id"] = tc.identityID
					}
				}
			}
			for i := range a.Edges {
				if a.Edges[i].ID == "e1" {
					a.Edges[i].Auth = tc.auth
					if tc.audience == "" {
						delete(a.Edges[i].Attrs, "audience")
					} else {
						a.Edges[i].Attrs["audience"] = tc.audience
					}
				}
			}
			got, cov := d2Cover(t, c, a)
			assert.Equal(t, tc.fires, slices.Contains(got["MCP-003"], "e1"), "fires")
			assert.Equal(t, tc.notChecked, slices.Contains(cov.NotChecked["MCP-003"], "e1"), "not_checked")
		})
	}
}

// SEG-011 needs a brokered route that does not use the reported edge: a dispatcher/worker loop through the broker is
// not one.
func TestSEG011RouteAvoidsTheEdge(t *testing.T) {
	t.Parallel()
	c := d2Catalog(t)
	edge := func(id, from, to, kind string) model.Edge {
		return model.Edge{ID: id, From: from, To: to, Kind: kind, Protocol: "a2a", Auth: "obo", Encryption: "tls",
			DataClass: "internal", Attrs: model.Attrs{"logged": true}}
	}
	tests := []struct {
		name  string
		edges []model.Edge
		fires bool
	}{
		{"direct edge beside the route through the gateway", []model.Edge{edge("e1", "n_orch", "n_worker", "delegates"),
			edge("e2", "n_orch", "n_a2agw", "delegates"), edge("e3", "n_a2agw", "n_worker", "delegates")}, true},
		{"dispatcher/worker loop", []model.Edge{edge("e_dispatch", "n_a2agw", "n_orch", "delegates"),
			edge("e1", "n_orch", "n_worker", "delegates"), edge("e_report", "n_worker", "n_a2agw", "calls")}, false},
		{"loop plus a real route through the gateway", []model.Edge{edge("e_dispatch", "n_a2agw", "n_orch", "delegates"),
			edge("e1", "n_orch", "n_worker", "delegates"), edge("e_report", "n_worker", "n_a2agw", "calls"),
			edge("e2", "n_orch", "n_a2agw", "delegates"), edge("e3", "n_a2agw", "n_worker", "delegates")}, true},
		{"two parallel direct edges are no route", []model.Edge{edge("e_dispatch", "n_a2agw", "n_orch", "delegates"),
			edge("e1", "n_orch", "n_worker", "delegates"), edge("e1b", "n_orch", "n_worker", "calls"),
			edge("e_report", "n_worker", "n_a2agw", "calls")}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, repoPath("packs", "fixtures", "SEG-011.neg.json"))
			a.Edges = tc.edges
			got := d2Evaluate(t, c, a)
			assert.Equal(t, tc.fires, slices.Contains(got["SEG-011"], "e1"))
		})
	}
}

// DLG-001 is the delegation-chain spec's rule: agent → agent delegates deeper than required("delegation_depth"), which
// falls back to ADR-047's 1 while policy.yaml has no row; a tenant requirement raises the limit. DLG-010 keeps
// ADR-047's "depth > 1 without token exchange" on the other hops, and neither reports the other's hop.
func TestDLG001DepthBeyondPolicy(t *testing.T) {
	t.Parallel()
	c := d2Catalog(t)
	tests := []struct {
		name        string
		depth       int64
		auth        string
		requirement int
		dlg001      bool
	}{
		{"spec positive: obo, depth 3", 3, "obo", 0, true},
		{"spec negative: depth 1", 1, "obo", 0, false},
		{"depth 2 above the default 1", 2, "token_exchange", 0, true},
		{"tenant allows 3", 3, "obo", 3, false},
		{"tenant allows 2, depth 3", 3, "obo", 2, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, repoPath("packs", "fixtures", "DLG-001.pos.json"))
			a.Edges[0].Attrs["delegation_depth"] = tc.depth
			a.Edges[0].Auth = tc.auth
			p := policyFromAttrs(a)
			if tc.requirement > 0 {
				p.Requirements = map[string]int{"delegation_depth": tc.requirement}
			}
			fs, err := New(c, nil).Evaluate(context.Background(), a, p)
			require.NoError(t, err)
			got := findingsByRule(fs)
			assert.Equal(t, tc.dlg001, slices.Contains(got["DLG-001"], "e1"), "DLG-001")
			assert.NotContains(t, got["DLG-010"], "e1", "an agent → agent delegates hop is DLG-001's, never DLG-010's")
		})
	}
}

// MCP-005 reads the 1.0 free-text protocol kept in e.protocol_text: an SSE hop into a server that declares no
// transport is the deprecated transport (docs/02 §8).
func TestMCP005ReadsProtocolText(t *testing.T) {
	t.Parallel()
	c := d2Catalog(t)
	for _, tc := range []struct {
		protocol string
		fires    bool
	}{{"SSE", true}, {"http+sse", true}, {"https", false}, {"http", false}} {
		t.Run(tc.protocol, func(t *testing.T) {
			t.Parallel()
			raw := `{"schema_version":"1.0","id":"arch_d2_sse","tenant_id":"t","name":"sse","version":1,
  "attrs":{"owner":"Owner","regimes":["OWASP"]},"groups":[],
  "nodes":[` + fmt.Sprintf(d2Agent10, "n_a", "Agent", "agent_id") + `,
    {"id":"n_mcp","type":"mcp_server","name":"Legacy server","layer":"app","source":"design","attrs":{"origin":"first_party","scopes":["read"]}}],
  "edges":[{"id":"e1","from":"n_a","to":"n_mcp","kind":"calls","protocol":"` + tc.protocol + `","auth":"agent_id","encryption":"tls","data_class":"internal","attrs":{}}],
  "findings":[],"evidence":[]}`
			got := d2Evaluate(t, c, d2Model(t, raw))
			assert.Equal(t, tc.fires, slices.Contains(got["MCP-005"], "n_mcp"))
		})
	}
}
