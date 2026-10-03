package migrate

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestV11to12 is the 1.1 → 1.2 step (ADR-093 M1): additive, so a model inside the 1.2 profiles
// changes only its version; the tolerant reading of the 1.0 shapes still runs on a stored 1.1
// document (ADR-040 §4, until 1.3); and the two attributes 1.2 narrows per type lose a value no 1.1
// profile listed, with an x_migrated_from note.
func TestV11to12(t *testing.T) {
	t.Parallel()
	node := func(typ string, attrs string) string {
		return `{"schema_version":"1.1","id":"a","nodes":[{"id":"n","type":"` + typ + `","attrs":` + attrs + `}],"edges":[]}`
	}
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"an llm agent stays", node("agent", `{"kind":"llm","autonomy":"semi"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"kind":"llm","autonomy":"semi"}}],"edges":[]}`},
		{"an orchestrator stays", node("agent", `{"kind":"orchestrator"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"kind":"orchestrator"}}],"edges":[]}`},
		{"an empty agent kind stays", node("agent", `{"kind":""}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"kind":""}}],"edges":[]}`},
		{"a registry kind on an agent is removed", node("agent", `{"kind":"agent365"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"x_migrated_from":"kind=agent365"}}],"edges":[]}`},
		{"a gateway kind on an agent is removed", node("agent", `{"kind":"waf","x_migrated_from":"egress_policy=true"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"x_migrated_from":"egress_policy=true; kind=waf"}}],"edges":[]}`},
		{"a boolean egress policy on a tool is removed", node("tool", `{"origin":"first_party","egress_policy":true}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"tool","attrs":{"origin":"first_party","x_migrated_from":"egress_policy=true"}}],"edges":[]}`},
		{"an enum egress policy on a tool stays", node("tool", `{"egress_policy":"default_allow"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"tool","attrs":{"egress_policy":"default_allow"}}],"edges":[]}`},
		{"a gateway kind stays on a gateway", node("gateway", `{"kind":"waf"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"gateway","attrs":{"kind":"waf"}}],"edges":[]}`},
		{"a boolean egress policy stays on an edge device", node("edge_device", `{"egress_policy":false}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"edge_device","attrs":{"egress_policy":false}}],"edges":[]}`},
		{"a stored 1.1 document keeps its tolerant reading: protocol", `{"schema_version":"1.1","id":"a","nodes":[],"edges":[{"id":"e","protocol":"HTTP","attrs":{}}]}`,
			`{"schema_version":"1.2","id":"a","nodes":[],"edges":[{"id":"e","protocol":"other","attrs":{"x_migrated_from":"protocol=HTTP"}}]}`},
		{"a stored 1.1 document keeps its tolerant reading: authn", node("api", `{"authn":"oidc"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"api","attrs":{"authn":["oidc"]}}],"edges":[]}`},
		// hosted_on on an agent or agent_memory names a node from 1.2; 1.1 accepted free text there.
		{"a free-text agent host is removed", node("agent", `{"hosted_on":"aks-prod-cluster"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"x_migrated_from":"hosted_on=aks-prod-cluster"}}],"edges":[]}`},
		{"a free-text memory host is removed", node("agent_memory", `{"hosted_on":"redis","scope":"session"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent_memory","attrs":{"scope":"session","x_migrated_from":"hosted_on=redis"}}],"edges":[]}`},
		{"an agent hosted on itself loses it", node("agent", `{"hosted_on":"n"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"x_migrated_from":"hosted_on=n"}}],"edges":[]}`},
		{"an agent hosted on a note loses it",
			`{"schema_version":"1.1","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"hosted_on":"t"}},{"id":"t","type":"note","attrs":{"text":"x"}}],"edges":[]}`,
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"x_migrated_from":"hosted_on=t"}},{"id":"t","type":"note","attrs":{"text":"x"}}],"edges":[]}`},
		{"an agent hosted on a drawn app keeps it",
			`{"schema_version":"1.1","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"hosted_on":"h"}},{"id":"h","type":"app","attrs":{}}],"edges":[]}`,
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"hosted_on":"h"}},{"id":"h","type":"app","attrs":{}}],"edges":[]}`},
		{"an empty agent host stays", node("agent", `{"hosted_on":""}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"hosted_on":""}}],"edges":[]}`},
		{"a free-text host stays on a tool (the 1.1 reading, TLS-002)", node("tool", `{"hosted_on":"vm-7"}`),
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"tool","attrs":{"hosted_on":"vm-7"}}],"edges":[]}`},
		// The provenance sidecar (ADR-086) keeps resolving: an entry on a removed value goes with it,
		// every other entry stays.
		{"a provenance entry on a narrowed agent kind goes with it",
			`{"schema_version":"1.1","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"kind":"api","owner":"o"}}],"edges":[],` +
				`"provenance":{"/nodes/n/attrs/kind":{"kind":"declared"},"/nodes/n/attrs/owner":{"kind":"declared"}}}`,
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"owner":"o","x_migrated_from":"kind=api"}}],"edges":[],` +
				`"provenance":{"/nodes/n/attrs/owner":{"kind":"declared"}}}`},
		{"a provenance entry on a dangling host goes with it and an emptied sidecar is removed",
			`{"schema_version":"1.1","id":"a","nodes":[{"id":"n/1","type":"agent","attrs":{"hosted_on":"vm-7"}}],"edges":[],` +
				`"provenance":{"/nodes/n~11/attrs/hosted_on":{"kind":"imported"}}}`,
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n/1","type":"agent","attrs":{"x_migrated_from":"hosted_on=vm-7"}}],"edges":[]}`},
		{"a provenance entry on a boolean tool egress policy goes with it",
			`{"schema_version":"1.1","id":"a","nodes":[{"id":"n","type":"tool","attrs":{"egress_policy":true}}],"edges":[],` +
				`"provenance":{"/nodes/n/attrs/egress_policy":{"kind":"declared"},"/nodes/n":{"kind":"declared"}}}`,
			`{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"tool","attrs":{"x_migrated_from":"egress_policy=true"}}],"edges":[],` +
				`"provenance":{"/nodes/n":{"kind":"declared"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, from, to, err := Upgrade([]byte(tc.raw))
			require.NoError(t, err)
			assert.Equal(t, "1.1", from)
			assert.Equal(t, "1.2", to)
			assert.JSONEq(t, tc.want, string(got))

			// Idempotent: the step run again on its own output changes nothing but nothing.
			var doc map[string]any
			require.NoError(t, json.Unmarshal(got, &doc))
			assert.Zero(t, Normalize(doc), "the upgraded document needs no further rewrite")
			assert.Zero(t, dropDanglingHosts(doc), "the upgraded document holds no dangling host")
		})
	}
}

// TestNarrowed12AttrsAreNarrowed: the 1.2 narrowings are part of NarrowedAttrs (the list the model
// package checks against the schema) with their 1.2 values.
func TestNarrowed12AttrsAreNarrowed(t *testing.T) {
	t.Parallel()
	n := NarrowedAttrs()
	assert.Equal(t, []string{"llm", "orchestrator"}, n["agent"]["kind"])
	assert.Equal(t, []string{"default_deny_allowlist", "default_allow", "undeclared", "disabled"}, n["tool"]["egress_policy"])
	n["agent"]["kind"][0] = "changed"
	assert.Equal(t, "llm", NarrowedAttrs()["agent"]["kind"][0], "NarrowedAttrs returns a copy")
}

// TestHostedOnTypes: the exported set is a copy.
func TestHostedOnTypes(t *testing.T) {
	t.Parallel()
	h := HostedOnTypes()
	assert.Equal(t, map[string]bool{"agent": true, "agent_memory": true}, h)
	h["app"] = true
	assert.False(t, HostedOnTypes()["app"], "HostedOnTypes returns a copy")
}

// TestNormalizeDropsProvenanceOfRemovedValues: the tolerant reading of a current document (Normalize,
// as model.ValidateJSON runs it) removes the sidecar entries of the values it removes, and only those.
func TestNormalizeDropsProvenanceOfRemovedValues(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"agent kind", `{"nodes":[{"id":"n","type":"agent","attrs":{"kind":"waf"}}],"provenance":{"/nodes/n/attrs/kind":{"kind":"declared"},"/attrs/owner":{"kind":"declared"}}}`,
			`{"nodes":[{"id":"n","type":"agent","attrs":{"x_migrated_from":"kind=waf"}}],"provenance":{"/attrs/owner":{"kind":"declared"}}}`},
		{"log sink purpose moved aside", `{"nodes":[{"id":"n","type":"log_sink","attrs":{"purpose":"audit trail"}}],"provenance":{"/nodes/n/attrs/purpose":{"kind":"imported"}}}`,
			`{"nodes":[{"id":"n","type":"log_sink","attrs":{"x_purpose":"audit trail","x_migrated_from":"purpose=audit trail"}}]}`},
		{"a rewritten value keeps its entry", `{"nodes":[{"id":"n","type":"mcp_server","attrs":{"exposure":"internal"}}],"provenance":{"/nodes/n/attrs/exposure":{"kind":"declared"}}}`,
			`{"nodes":[{"id":"n","type":"mcp_server","attrs":{"exposure":"private_network","x_migrated_from":"exposure=internal"}}],"provenance":{"/nodes/n/attrs/exposure":{"kind":"declared"}}}`},
		{"an empty authn", `{"nodes":[{"id":"n","type":"api","attrs":{"authn":""}}],"provenance":{"/nodes/n/attrs/authn":{"kind":"declared"}}}`,
			`{"nodes":[{"id":"n","type":"api","attrs":{}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var doc map[string]any
			require.NoError(t, json.Unmarshal([]byte(tc.raw), &doc))
			assert.Positive(t, Normalize(doc))
			got, err := json.Marshal(doc)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(got))
		})
	}
}
