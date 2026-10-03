package main

// Gateway functions (docs/18 B2b) and the agentic modelling limits (docs/18 E6), asserted on the shipped packs: which
// rule fires on which element, and which element a rule leaves not_checked because the fact it needs is undeclared
// (ADR-088 §4). The path-rule variant fixtures are pinned element by element in
// rules/allpaths_test.go; these tables add the coverage side and the node rules' mutations.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/rules"
)

func shippedEngine(t *testing.T) *rules.Engine {
	t.Helper()
	requireRepo(t)
	catalog, err := rules.LoadDir(repoPath("packs"))
	require.NoError(t, err)
	table, err := rules.LoadPolicyTable(repoPath("policy.yaml"))
	require.NoError(t, err)
	return rules.New(catalog, table, rules.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
}

// fixtureWith reads a rule fixture, applies mutate to its JSON and validates the result as a model.
func fixtureWith(t *testing.T, file string, mutate func(m map[string]any)) *model.Architecture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoPath("packs"), "fixtures", file))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	if mutate != nil {
		mutate(m)
	}
	out, err := json.Marshal(m)
	require.NoError(t, err)
	a, err := model.ValidateJSON(out)
	require.NoError(t, err, file)
	return a
}

func nodeAttrs(t *testing.T, m map[string]any, id string) map[string]any {
	t.Helper()
	for _, n := range m["nodes"].([]any) {
		nm := n.(map[string]any)
		if nm["id"] == id {
			attrs, _ := nm["attrs"].(map[string]any)
			if attrs == nil {
				attrs = map[string]any{}
				nm["attrs"] = attrs
			}
			return attrs
		}
	}
	t.Fatalf("node %s not in the fixture", id)
	return nil
}

func addNode(m map[string]any, id, typ, layer string, attrs map[string]any) {
	m["nodes"] = append(m["nodes"].([]any), map[string]any{"id": id, "type": typ, "name": id, "layer": layer, "attrs": attrs})
}

func addEdge(m map[string]any, id, from, to, kind string) {
	m["edges"] = append(m["edges"].([]any), map[string]any{"id": id, "from": from, "to": to, "kind": kind,
		"auth": "managed_identity", "encryption": "tls", "attrs": map[string]any{}})
}

// outcome is what one rule says about one element: it fires, it leaves the element not_checked, or it decides the
// element clean (in or out of its domain: either way neither a finding nor not_checked).
type outcome int

const (
	clean outcome = iota
	fires
	notChecked
)

func (o outcome) String() string {
	return [...]string{"clean", "fires", "not_checked"}[o]
}

type ruleCase struct {
	name    string
	file    string
	mutate  func(t *testing.T, m map[string]any)
	rule    string
	element string
	want    outcome
}

func runRuleCases(t *testing.T, cases []ruleCase) {
	t.Helper()
	eng := shippedEngine(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := fixtureWith(t, tc.file, func(m map[string]any) {
				if tc.mutate != nil {
					tc.mutate(t, m)
				}
			})
			fs, cov, err := eng.EvaluateCoverage(context.Background(), a, policyFor(a))
			require.NoError(t, err)
			got := clean
			for _, f := range fs {
				if f.RuleID == tc.rule && slices.Contains(f.IDs, tc.element) {
					got = fires
				}
			}
			if slices.Contains(cov.NotChecked[tc.rule], tc.element) {
				require.Equal(t, clean, got, "%s on %s: a finding is never also not_checked", tc.rule, tc.element)
				got = notChecked
			}
			assert.Equal(t, tc.want.String(), got.String(), "%s on %s", tc.rule, tc.element)
		})
	}
}

func setKind(id, kind string) func(t *testing.T, m map[string]any) {
	return func(t *testing.T, m map[string]any) { nodeAttrs(t, m, id)["kind"] = kind }
}

// B2b: a gateway of the right kind that declares no functions satisfies the path rule by its kind, and the hop out of
// it is not_checked (what it enforces is undeclared); declared functions decide; an absent kind is the complement
// rule's not_checked while the path rule reports the hop.
func TestGatewayFunctionsDecideOrLeaveNotChecked(t *testing.T) {
	t.Parallel()
	runRuleCases(t, []ruleCase{
		{name: "AI-001 AI gateway without functions", file: "AI-001.neg.json", rule: "AI-001", element: "e3", want: notChecked},
		{name: "AI-001 declared functions", file: "AI-001.functions.neg.json", rule: "AI-001", element: "e2", want: clean},
		{name: "AGW-003 declared functions exempt an API gateway", file: "AI-001.functions.neg.json", rule: "AGW-003", element: "e2", want: clean},
		{name: "AI-001 AI gateway missing a function", file: "AI-001.nofunc.pos.json", rule: "AI-001", element: "e2", want: fires},
		{name: "AI-001 two insufficient AI gateways in series", file: "AI-001.series.pos.json", rule: "AI-001", element: "e3", want: fires},
		{name: "AI-001 sufficient AI gateway upstream is credited", file: "AI-001.credited.neg.json", rule: "AI-001", element: "e3", want: clean},
		{name: "AI-001 direct hop still fires", file: "AI-001.pos.json", rule: "AI-001", element: "e1", want: fires},
		{name: "AGW-003 WAF before the model", file: "AGW-003.pos.json", rule: "AGW-003", element: "e_gw_llm", want: fires},
		{name: "AI-001 leaves the WAF hop to AGW-003", file: "AGW-003.pos.json", rule: "AI-001", element: "e_gw_llm", want: clean},
		{name: "AGW-003 gateway kind absent", file: "AGW-003.pos.json", mutate: setKind("n_gw", ""), rule: "AGW-003", element: "e_gw_llm", want: notChecked},
		{name: "AI-001 gateway of no kind is no AI gateway", file: "AGW-003.pos.json", mutate: setKind("n_gw", ""), rule: "AI-001", element: "e_gw_llm", want: fires},
		{name: "NET-003 WAF without functions", file: "NET-003.apigw.neg.json", rule: "NET-003", element: "e2", want: notChecked},
		{name: "NET-003 WAF declares policy", file: "NET-003.functions.neg.json", rule: "NET-003", element: "e2", want: clean},
		{name: "NET-003 WAF missing policy", file: "NET-003.nofunc.pos.json", rule: "NET-003", element: "e2", want: fires},
		{name: "APX-004 AI gateway before a public app", file: "APX-004.pos.json", rule: "APX-004", element: "e2", want: fires},
		{name: "NET-003 leaves the AI-gateway hop to APX-004", file: "APX-004.pos.json", rule: "NET-003", element: "e2", want: clean},
		{name: "APX-004 declared policy exempts", file: "APX-004.functions.neg.json", rule: "APX-004", element: "e2", want: clean},
		{name: "APX-004 gateway kind absent", file: "APX-004.pos.json", mutate: setKind("n_gw", ""), rule: "APX-004", element: "e2", want: notChecked},
		{name: "NET-003 gateway of no kind is no WAF", file: "APX-004.pos.json", mutate: setKind("n_gw", ""), rule: "NET-003", element: "e2", want: fires},
		{name: "STR-005 API gateway without functions", file: "STR-005.neg.json", rule: "STR-005", element: "e3", want: notChecked},
		{name: "STR-005 declared identity termination", file: "STR-005.functions.neg.json", rule: "STR-005", element: "e3", want: clean},
		{name: "STR-005 MCP gateway missing identity termination", file: "STR-005.nofunc.pos.json", rule: "STR-005", element: "e3", want: fires},
		{name: "STR-005 WAF that declares identity termination", file: "STR-005.waf.pos.json", mutate: func(t *testing.T, m map[string]any) {
			for _, n := range m["nodes"].([]any) {
				if nm := n.(map[string]any); nm["type"] == "gateway" {
					nm["attrs"].(map[string]any)["functions"] = []any{"identity_termination"}
				}
			}
		}, rule: "STR-005", element: "e2", want: clean},
		// Review fix (B2b finding 7): the walk blocks every gateway and credits one by what it declares, whatever its
		// kind, so a gateway of another kind further up that declares the functions counts, as it does on the hop.
		{name: "AI-001 API gateway declaring both functions further up", file: "AI-001.upstreamfn.neg.json", rule: "AI-001", element: "e3", want: clean},
		{name: "AGW-003 MCP gateway declaring both functions further up", file: "AGW-003.upstreamfn.neg.json", rule: "AGW-003", element: "e3", want: clean},
		{name: "NET-003 AI gateway declaring policy further up", file: "NET-003.upstreamfn.neg.json", rule: "NET-003", element: "e3", want: clean},
		{name: "APX-004 kindless gateway declaring policy further up", file: "APX-004.upstreamfn.neg.json", rule: "APX-004", element: "e3", want: clean},
		{name: "STR-005 WAF declaring identity termination further up", file: "STR-005.upstreamfn.neg.json", rule: "STR-005", element: "e3", want: clean},
		{name: "AI-001 the same API gateway without functions further up", file: "AI-001.upstreamfn.neg.json", mutate: func(t *testing.T, m map[string]any) {
			delete(nodeAttrs(t, m, "n_gw"), "functions")
		}, rule: "AI-001", element: "e3", want: fires},
		// Known limit (B2b findings 1 and 8, docs/03 Known limits): a gateway of the right kind that declares no
		// functions is credited by kind; only the hop out of it is not_checked. When it sits further up the walk the
		// reported hop is decided. This pins today's behaviour: it becomes not_checked once the function-aware walk
		// helper (TODO(decision), rules/cel.go) reports the crediting gateways to the coverage pass.
		{name: "AI-001 AI gateway without functions further up (known limit: decided)", file: "AI-001.kindupstream.neg.json", rule: "AI-001", element: "e3", want: clean},
		{name: "AI-001 AI gateway without functions on the hop", file: "AI-001.kindupstream.neg.json", rule: "AI-001", element: "e2", want: clean},
		{name: "NET-003 WAF without functions further up (known limit: decided)", file: "NET-003.kindupstream.neg.json", rule: "NET-003", element: "e3", want: clean},
		{name: "STR-005 API gateway without functions further up (known limit: decided)", file: "STR-005.kindupstream.neg.json", rule: "STR-005", element: "e3", want: clean},
	})
}

// gatewayChain rewrites a fixture as source → n uncredited gateways (cycling through kinds, each declaring a function
// none of the rules needs) → mid → target and returns the id of the hop into the target ("e_hop").
func gatewayChain(srcID, midType, targetID string, n int, kinds ...string) func(t *testing.T, m map[string]any) {
	return func(t *testing.T, m map[string]any) {
		var keep []any
		for _, x := range m["nodes"].([]any) {
			if id := x.(map[string]any)["id"]; id == srcID || id == targetID {
				keep = append(keep, x)
			}
		}
		require.Len(t, keep, 2, "the fixture has %s and %s", srcID, targetID)
		m["nodes"], m["edges"] = keep, []any{}
		prev := srcID
		for i := range n {
			id := "n_gw" + string(rune('a'+i))
			attrs := map[string]any{"logging": true, "functions": []any{"egress"}}
			if k := kinds[i%len(kinds)]; k != "" {
				attrs["kind"] = k
			}
			addNode(m, id, "gateway", "platform", attrs)
			addEdge(m, "e_"+id, prev, id, "calls")
			prev = id
		}
		addNode(m, "n_mid", midType, "app", map[string]any{"exposure": "internal", "authn": "oidc", "secrets_in": "secret_store"})
		addEdge(m, "e_mid", prev, "n_mid", "calls")
		addEdge(m, "e_hop", "n_mid", targetID, "calls")
	}
}

// The walk has no depth limit: uncredited gateways in series upstream of the reported hop's source are walked through,
// whatever their kinds, at any chain length. Until 2026-10-02 the CEL unrolled the walk through three and a fourth
// ended it (a known false-negative class pinned here as 4: clean); the function-aware g.upstreamAvoiding(id, types,
// kinds, needFunctions) of rules/cel.go made it exact, so the limit moved on purpose (Reconcile A,
// advisories SAA-2026-007 to 009) and every depth fires.
func TestGatewayWalkDepth(t *testing.T) {
	t.Parallel()
	cases := make([]ruleCase, 0, 18)
	for n, want := range map[int]outcome{1: fires, 2: fires, 3: fires, 4: fires, 5: fires, 6: fires} {
		suffix := string(rune('0' + n))
		cases = append(cases,
			ruleCase{name: "AI-001 " + suffix + " uncredited gateways", file: "AI-001.upstreamfn.neg.json",
				mutate: gatewayChain("n_agent", "api", "n_llm", n, "waf", "ai", "", "api"), rule: "AI-001", element: "e_hop", want: want},
			ruleCase{name: "NET-003 " + suffix + " uncredited gateways", file: "NET-003.upstreamfn.neg.json",
				mutate: gatewayChain("n_user", "app", "n_app", n, "ai", "api", "", "waf"), rule: "NET-003", element: "e_hop", want: want},
			ruleCase{name: "STR-005 " + suffix + " uncredited gateways", file: "STR-005.upstreamfn.neg.json",
				mutate: gatewayChain("n_agent", "app", "n_mcp", n, "waf", "mcp", "", "api"), rule: "STR-005", element: "e_hop", want: want},
		)
	}
	runRuleCases(t, cases)
}

// E6 limitation 22: TPR-001 reads function-typed managed services (a provider service or a provider other than
// self_hosted) and fires on a declared outsourcing_registered: false; an undeclared register status is not_checked.
func TestTPR001ByFunctionNotType(t *testing.T) {
	t.Parallel()
	logs := func(attrs map[string]any) func(t *testing.T, m map[string]any) {
		return func(t *testing.T, m map[string]any) {
			a := nodeAttrs(t, m, "n_logs")
			for k, v := range attrs {
				a[k] = v
			}
		}
	}
	extra := func(typ, layer string, attrs map[string]any) func(t *testing.T, m map[string]any) {
		return func(t *testing.T, m map[string]any) {
			addNode(m, "n_x", typ, layer, attrs)
			addEdge(m, "e_x", "n_gw", "n_x", "reads")
		}
	}
	managedNo := map[string]any{"provider_service": "azure/monitor", "outsourcing_registered": false}
	functionTypes := []struct{ typ, layer string }{{"datastore", "data"}, {"secret_store", "platform"}, {"queue", "platform"}, {"identity_provider", "platform"}}
	cases := make([]ruleCase, 0, 9+len(functionTypes))
	cases = append(cases, []ruleCase{
		{name: "log sink with a provider service, declared unregistered", file: "TPR-001.neg.json", mutate: logs(managedNo), rule: "TPR-001", element: "n_logs", want: fires},
		{name: "log sink with a provider service, register undeclared", file: "TPR-001.neg.json", mutate: logs(map[string]any{"provider_service": "azure/monitor"}), rule: "TPR-001", element: "n_logs", want: notChecked},
		{name: "log sink with a provider service, registered", file: "TPR-001.neg.json", mutate: logs(map[string]any{"provider_service": "azure/monitor", "outsourcing_registered": true}), rule: "TPR-001", element: "n_logs", want: clean},
		{name: "log sink with no provider declared", file: "TPR-001.neg.json", mutate: logs(map[string]any{"outsourcing_registered": false}), rule: "TPR-001", element: "n_logs", want: clean},
		{name: "self-hosted log sink", file: "TPR-001.neg.json", mutate: logs(map[string]any{"provider": "self_hosted", "outsourcing_registered": false}), rule: "TPR-001", element: "n_logs", want: clean},
		{name: "gateway with a provider", file: "TPR-001.neg.json", mutate: func(t *testing.T, m map[string]any) {
			a := nodeAttrs(t, m, "n_gw")
			a["provider"], a["outsourcing_registered"] = "azure", false
		}, rule: "TPR-001", element: "n_gw", want: fires},
		{name: "llm endpoint registered (unchanged)", file: "TPR-001.neg.json", rule: "TPR-001", element: "n_llm", want: clean},
		{name: "llm endpoint register undeclared fires (unchanged)", file: "TPR-001.neg.json", mutate: func(t *testing.T, m map[string]any) {
			delete(nodeAttrs(t, m, "n_llm"), "outsourcing_registered")
		}, rule: "TPR-001", element: "n_llm", want: fires},
		{name: "app on a managed platform is not in scope", file: "TPR-001.neg.json", mutate: extra("app", "app", map[string]any{"exposure": "internal", "provider_service": "gcp/cloud-run", "outsourcing_registered": false}), rule: "TPR-001", element: "n_x", want: clean},
	}...)
	for _, typ := range functionTypes {
		cases = append(cases, ruleCase{name: typ.typ + " managed, declared unregistered", file: "TPR-001.neg.json",
			mutate: extra(typ.typ, typ.layer, map[string]any{"provider_service": "gcp/managed", "outsourcing_registered": false}),
			rule:   "TPR-001", element: "n_x", want: fires})
	}
	runRuleCases(t, cases)
}

// E6 limitation 24: SEG-005 on a store shared across environments.
func TestSEG005EnvironmentMismatch(t *testing.T) {
	t.Parallel()
	db := func(env string) func(t *testing.T, m map[string]any) {
		return func(t *testing.T, m map[string]any) {
			if env == "" {
				delete(nodeAttrs(t, m, "n_db"), "environment")
				return
			}
			nodeAttrs(t, m, "n_db")["environment"] = env
		}
	}
	both := func(t *testing.T, m map[string]any, dbEnv string, callers ...string) {
		db(dbEnv)(t, m)
		nodeAttrs(t, m, "n_app")["environment"] = callers[0]
		for i, env := range callers[1:] {
			id := "n_app" + string(rune('b'+i))
			addNode(m, id, "app", "app", map[string]any{"exposure": "internal", "environment": env})
			addEdge(m, "e_"+id, id, "n_db", "writes")
		}
	}
	runRuleCases(t, []ruleCase{
		{name: "staging service reads the production store", file: "SEG-005.pos.json", rule: "SEG-005", element: "n_db", want: fires},
		{name: "production service reads the production store", file: "SEG-005.neg.json", rule: "SEG-005", element: "n_db", want: clean},
		{name: "store declared shared", file: "SEG-005.neg.json", mutate: db("shared"), rule: "SEG-005", element: "n_db", want: fires},
		{name: "undeclared store, staging and production callers", file: "SEG-005.neg.json", mutate: func(t *testing.T, m map[string]any) {
			both(t, m, "", "staging", "production")
		}, rule: "SEG-005", element: "n_db", want: fires},
		{name: "undeclared store, one environment calls", file: "SEG-005.neg.json", mutate: db(""), rule: "SEG-005", element: "n_db", want: notChecked},
		{name: "unknown environments are not compared", file: "SEG-005.neg.json", mutate: func(t *testing.T, m map[string]any) {
			both(t, m, "production", "unknown", "production")
		}, rule: "SEG-005", element: "n_db", want: clean},
	})
}

// E6 limitation 23: WIS-006 on secrets delivered as environment variables.
func TestWIS006SecretsDelivery(t *testing.T) {
	t.Parallel()
	app := func(attrs map[string]any, drop ...string) func(t *testing.T, m map[string]any) {
		return func(t *testing.T, m map[string]any) {
			a := nodeAttrs(t, m, "n_app")
			for _, k := range drop {
				delete(a, k)
			}
			for k, v := range attrs {
				a[k] = v
			}
		}
	}
	runRuleCases(t, []ruleCase{
		{name: "env delivery from a secret store", file: "WIS-006.pos.json", rule: "WIS-006", element: "n_app", want: fires},
		{name: "mounted files", file: "WIS-006.neg.json", rule: "WIS-006", element: "n_app", want: clean},
		{name: "fetched at runtime", file: "WIS-006.neg.json", mutate: app(map[string]any{"secrets_delivery": "api"}), rule: "WIS-006", element: "n_app", want: clean},
		{name: "plain env storage is ZT-007's, not WIS-006's", file: "WIS-006.pos.json", mutate: app(map[string]any{"secrets_in": "env_plain"}), rule: "WIS-006", element: "n_app", want: clean},
		{name: "plain env storage raises ZT-007", file: "WIS-006.pos.json", mutate: app(map[string]any{"secrets_in": "env_plain"}), rule: "ZT-007", element: "n_app", want: fires},
		{name: "delivery undeclared", file: "WIS-006.neg.json", mutate: app(nil, "secrets_delivery"), rule: "WIS-006", element: "n_app", want: notChecked},
		{name: "no secrets declared at all", file: "WIS-006.neg.json", mutate: app(nil, "secrets_delivery", "secrets_in"), rule: "WIS-006", element: "n_app", want: clean},
	})
}
