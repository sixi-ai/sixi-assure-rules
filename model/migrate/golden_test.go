package migrate_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/model/migrate"
)

// Migration golden pairs (ADR-040 Consequences): testdata/pairs/<name>.<version>.json for a version
// older than the current one is a frozen input — a copy of every golden-set model as it was stored
// at 0.9, 1.0 and 1.1, plus synthetic models — and <name>.<current>.json is what Upgrade must turn
// every input of that name into. A new step adds the previous expected file as a frozen input and
// regenerates the expected files with `go test ./internal/model/migrate -run TestGoldenPairs
// -update`; the diff is reviewed like code and the inputs never change.

var update = flag.Bool("update", false, "rewrite the expected files of the migration golden pairs")

const pairsDir = "testdata/pairs"

// goldenDir is the golden set (spelled as a filepath.Join so the open-source staging rewrites it).
var goldenDir = filepath.Join("..", "..", "golden-set", "models")

type pair struct {
	name    string
	inputs  map[string]string // version → frozen input file
	newPath string
}

// oldest returns the input at the oldest version (0.9 where there is one).
func (p pair) oldest() (version, path string) {
	for v, f := range p.inputs {
		if version == "" || older(v, version) {
			version, path = v, f
		}
	}
	return version, path
}

// older orders two MAJOR.MINOR versions numerically.
func older(a, b string) bool {
	var am, an, bm, bn int
	_, _ = fmt.Sscanf(a, "%d.%d", &am, &an)
	_, _ = fmt.Sscanf(b, "%d.%d", &bm, &bn)
	return am < bm || (am == bm && an < bn)
}

func pairs(t *testing.T) []pair {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(pairsDir, "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, matches)
	byName := map[string]*pair{}
	var names []string
	for _, m := range matches {
		base := strings.TrimSuffix(filepath.Base(m), ".json")
		// <name>.<MAJOR>.<MINOR>: the version is the last two dot-separated parts.
		parts := strings.Split(base, ".")
		require.GreaterOrEqual(t, len(parts), 3, "pair file %s is named <model>.<MAJOR>.<MINOR>.json", m)
		name := strings.Join(parts[:len(parts)-2], ".")
		version := parts[len(parts)-2] + "." + parts[len(parts)-1]
		require.True(t, migrate.Valid(version), m)
		p, ok := byName[name]
		if !ok {
			p = &pair{name: name, inputs: map[string]string{}, newPath: filepath.Join(pairsDir, name+"."+migrate.Current+".json")}
			byName[name] = p
			names = append(names, name)
		}
		if version != migrate.Current {
			p.inputs[version] = m
		}
	}
	sort.Strings(names)
	out := make([]pair, 0, len(names))
	for _, n := range names {
		require.NotEmpty(t, byName[n].inputs, "pair %s has at least one frozen input", n)
		out = append(out, *byName[n])
	}
	return out
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err)
	return b
}

func indent(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, json.Indent(&buf, raw, "", "  "))
	buf.WriteByte('\n')
	return buf.Bytes()
}

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// rewrites12 are the synthetic pairs whose 1.1 input carries a value the 1.1 → 1.2 step removes (a
// free-text hosted_on on an agent or agent_memory): their 1.2 file is reviewed, not derived.
var rewrites12 = map[string]bool{"dangling-agent-host": true}

func TestGoldenPairs(t *testing.T) {
	t.Parallel()
	for _, p := range pairs(t) {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			_, oldestPath := p.oldest()
			if *update {
				got, _, _, err := migrate.Upgrade(read(t, oldestPath))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(p.newPath, indent(t, got), 0o600))
			}
			for version, path := range p.inputs {
				old := read(t, path)
				v, err := migrate.Version(old)
				require.NoError(t, err)
				assert.Equal(t, version, v, "a frozen input carries the version its file name says (%s)", path)

				got, from, to, err := migrate.Upgrade(old)
				require.NoError(t, err)
				assert.Equal(t, version, from)
				assert.Equal(t, migrate.Current, to)
				assert.JSONEq(t, string(read(t, p.newPath)), string(got), "Upgrade(%s) differs from the golden pair", path)
			}

			// 0.9 → 1.0 sets the field and changes nothing else.
			if in09, ok := p.inputs["0.9"]; ok {
				if in10, ok := p.inputs["1.0"]; ok {
					before := decode(t, read(t, in09))
					before[migrate.Field] = "1.0"
					assert.Equal(t, decode(t, read(t, in10)), before, "the 1.0 input is the 0.9 input with schema_version 1.0")
				}
			}
			// 1.1 → 1.2 (ADR-093 M1) is additive: every pair's 1.2 file is its 1.1 input with
			// schema_version 1.2, so no golden model changes beyond its version. The synthetic pairs
			// in rewrites12 hold the 1.1 values the step removes (TestV11to12 has one case each).
			if in11, ok := p.inputs["1.1"]; ok && !rewrites12[p.name] {
				at12 := p.newPath // the expected file while 1.2 is current, the frozen 1.2 input after
				if in12, frozen := p.inputs["1.2"]; frozen {
					at12 = in12
				}
				before := decode(t, read(t, in11))
				before[migrate.Field] = "1.2"
				assert.Equal(t, decode(t, read(t, at12)), before, "the 1.2 file is the 1.1 input with schema_version 1.2")
			}
		})
	}
}

// TestIdentityMigration is the ADR-047 acceptance on every pair: a 1.0 model upgrades with one
// identity entity per distinct agent.identity value, every agent points at the identity of its
// value, the identity string stays readable, and every protocol is an enum value.
func TestIdentityMigration(t *testing.T) {
	t.Parallel()
	for _, p := range pairs(t) {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			_, oldestPath := p.oldest()
			before := decode(t, read(t, oldestPath))
			after := decode(t, read(t, p.newPath))
			distinct := map[string]bool{}
			for _, n := range list(before["nodes"]) {
				if n["type"] == "agent" {
					if v, _ := attrsOf(n)["identity"].(string); v != "" {
						distinct[v] = true
					}
				}
			}
			byID := map[string]map[string]any{}
			for _, id := range list(after["identities"]) {
				byID[id["id"].(string)] = id
			}
			assert.Len(t, byID, len(distinct), "one identity per distinct agent.identity value")
			for _, n := range list(after["nodes"]) {
				value, _ := attrsOf(n)["identity"].(string)
				if n["type"] != "agent" || value == "" {
					continue
				}
				id, _ := attrsOf(n)["identity_id"].(string)
				ident, ok := byID[id]
				require.True(t, ok, "agent %v names identity %q", n["id"], id)
				assert.Equal(t, "agent.identity="+value, attrsOf(ident)[migrate.MigratedFrom], "the identity says where it came from")
			}
			for _, e := range list(after["edges"]) {
				proto, _ := e["protocol"].(string)
				assert.True(t, migrate.ValidProtocol(proto), "edge %v protocol %q is an enum value", e["id"], proto)
			}
		})
	}
}

func list(v any) []map[string]any {
	items, _ := v.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, x := range items {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func attrsOf(m map[string]any) map[string]any {
	a, _ := m["attrs"].(map[string]any)
	return a
}

// nativeAtCurrent are golden models authored at the current schema version that have no frozen
// older inputs, each with the reason. A model is listed here only when no older version can express
// it: its upgrade could never equal the golden file. Every entry must exist, be stored at
// migrate.Current and have no pair (a model that gains a pair leaves this list).
var nativeAtCurrent = map[string]string{
	// docs/18 D2: the MCP agent platform is the schema 1.1 acceptance pair. It declares native
	// identity entities (issuer, sponsor, registry, federation, credential type) and the 1.1-only
	// node types agent_registry, credential_broker, external_agent and agent_memory, which 1.0 cannot
	// carry; a 1.0 copy would upgrade to migrated identities (x_migrated_from), not to this file. It
	// is stored at the current version (1.2 from ADR-093 M1, which changes nothing in it but the
	// version; TestNativeModelsAreTheirOwn11Upgrade checks that).
	"mcp-agent-platform":     "schema 1.1 native (docs/18 D2): identities and 1.1-only node types",
	"mcp-agent-platform-bad": "schema 1.1 native (docs/18 D2): identities and 1.1-only node types",
	// docs/18 WS-I I2 (swarm team 03): the agentic runtime pair declares the 1.1-only node types agent_memory and
	// agent_registry and the 1.1 attributes of team 03's rules (resource_metadata, verification, scope, write_path,
	// guarded, approval_identity), none of the 1.2 framework vocabulary; it is stored at the current version.
	"team03-agentic-runtime":     "schema 1.1 native (docs/18 WS-I I2, swarm team 03): agent_memory and agent_registry",
	"team03-agentic-runtime-bad": "schema 1.1 native (docs/18 WS-I I2, swarm team 03): agent_memory and agent_registry",
	// docs/18 WS-I I2 (swarm team 02): the identity and zero-trust pair declares native identity entities (credential
	// types, rotation) and the 1.1 attributes of team 02's rules (authn lists, inbound_auth, security_schemes, card_url,
	// edge audience, scopes and token_lifetime), none of the 1.2 framework vocabulary; it is stored at the current version.
	"team02-identity-zero-trust":     "schema 1.1 native (docs/18 WS-I I2, swarm team 02): identities and 1.1 token attributes",
	"team02-identity-zero-trust-bad": "schema 1.1 native (docs/18 WS-I I2, swarm team 02): identities and 1.1 token attributes",
	// docs/18 WS-I I2 (swarm team 01): the import-provenance pair is born at 1.1 with a provenance sidecar (ADR-086,
	// docs/02 §9), which 0.9 or 1.0 cannot carry, and the gateway's functions[] (ADR-047 §3); stored at the current
	// version, which changes nothing in it but the version.
	"team01-import-provenance":     "schema 1.1 native (docs/18 WS-I I2): provenance sidecar and gateway functions",
	"team01-import-provenance-bad": "schema 1.1 native (docs/18 WS-I I2): provenance sidecar and gateway functions",
	// docs/18 WS-I I2 (swarm team 04): the gateways, network and data pair is born at 1.1: gateway functions[] and the
	// mcp and egress gateway kinds (ADR-047 §3) and the protocol enum (mcp_stdio) carry its findings, and 0.9 or 1.0 can
	// carry none of them; stored at the current version, which changes nothing in it but the version.
	"team04-gateways-network-data":     "schema 1.1 native (docs/18 WS-I I2): gateway functions, gateway kinds and the protocol enum",
	"team04-gateways-network-data-bad": "schema 1.1 native (docs/18 WS-I I2): gateway functions, gateway kinds and the protocol enum",
	// docs/18 WS-M M3 and M5 (ADR-093): the five framework pairs are born at 1.2. agent.framework, guardrails[],
	// max_iterations, hosted_on on agents and memories, the delegation attributes, protocols[] and integrity on hosted
	// runtimes and a workflow group carry their findings and blueprints, and no older version can express them.
	"fw-langgraph":                 "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary",
	"fw-langgraph-bad":             "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary",
	"fw-ms-agent-framework":        "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary and a workflow group",
	"fw-ms-agent-framework-bad":    "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary and a workflow group",
	"fw-foundry-agent-service":     "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary",
	"fw-foundry-agent-service-bad": "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary",
	"fw-google-adk":                "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary",
	"fw-google-adk-bad":            "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary",
	"fw-openai-agents":             "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary",
	"fw-openai-agents-bad":         "schema 1.2 native (docs/18 WS-M M3, M5): framework vocabulary",
	// docs/18 WS-I I2 (swarm team 07): the attack-testing pair is born at 1.1: its gateways declare functions[] (ADR-047
	// §3), which 0.9 or 1.0 cannot carry, and the good twin's evaluation scope names prompt_injection where the bad twin's
	// leaves it out (AEI-001, AEI-002); stored at the current version, which changes nothing in it but the version.
	"team07-attack-testing":     "schema 1.1 native (docs/18 WS-I I2, swarm team 07): gateway functions",
	"team07-attack-testing-bad": "schema 1.1 native (docs/18 WS-I I2, swarm team 07): gateway functions",
	// Born at 1.1 or later (the D2 handover, Reconcile A 2026-10-02): the golden pairs added on 2026-10-01 (swarm
	// teams 05, 06 and 09, and the machinery pair) were authored at schema 1.1 and given 0.9, 1.0 and 1.1 "inputs"
	// written after the fact, which no stored model ever was (two of them even carried gateway functions[], an
	// attribute 0.9 and 1.0 do not have). Those inputs are removed; the models are checked at the current version
	// only, and TestNativeModelsAreTheirOwn11Upgrade checks the 1.1 → 1.2 step on them. The six templates and the
	// a2a mesh existed at 1.0 and keep their pairs.
	"team05-records-resilience":     "born at 1.1 (docs/18 WS-I I2, swarm team 05)",
	"team05-records-resilience-bad": "born at 1.1 (docs/18 WS-I I2, swarm team 05)",
	"dora-third-party":              "born at 1.1 (docs/18 WS-I I2, swarm team 06)",
	"dora-third-party-bad":          "born at 1.1 (docs/18 WS-I I2, swarm team 06)",
	"cra-agent-product":             "born at 1.1 (docs/18 WS-I I2, swarm team 06)",
	"cra-agent-product-bad":         "born at 1.1 (docs/18 WS-I I2, swarm team 06)",
	"nis2-ledger":                   "born at 1.1 (docs/18 WS-I I2, swarm team 06)",
	"nis2-ledger-bad":               "born at 1.1 (docs/18 WS-I I2, swarm team 06)",
	"swiss-ledger":                  "born at 1.1 (docs/18 WS-I I2, swarm team 06)",
	"swiss-ledger-bad":              "born at 1.1 (docs/18 WS-I I2, swarm team 06)",
	"team09-learning-guard-gmp":     "born at 1.1 (docs/18 WS-I I2, swarm team 09)",
	"team09-learning-guard-gmp-bad": "born at 1.1 (docs/18 WS-I I2, swarm team 09)",
	"machinery-learning-guard":      "born at 1.1 (docs/18 WS-I I2, swarm team 09)",
	"machinery-learning-guard-bad":  "born at 1.1 (docs/18 WS-I I2, swarm team 09)",
}

// TestEveryGoldenModelHasAPair keeps the pairs complete and the golden set at the current version:
// every golden model is its pair's expected file (the server's upgrade of the frozen inputs), or is
// listed in nativeAtCurrent with its reason.
func TestEveryGoldenModelHasAPair(t *testing.T) {
	t.Parallel()
	have := map[string]pair{}
	for _, p := range pairs(t) {
		have[p.name] = p
	}
	models, err := filepath.Glob(filepath.Join(goldenDir, "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, models)
	seenNative := map[string]bool{}
	for _, m := range models {
		name := strings.TrimSuffix(filepath.Base(m), ".json")
		if reason, native := nativeAtCurrent[name]; native {
			seenNative[name] = true
			assert.NotEmpty(t, reason, "golden model %s: an exemption gives its reason", name)
			_, paired := have[name]
			assert.False(t, paired, "golden model %s has a migration pair: drop it from nativeAtCurrent", name)
			v, err := migrate.Version(read(t, m))
			require.NoError(t, err)
			assert.Equal(t, migrate.Current, v, "native golden model %s is stored at the current schema version", name)
			continue
		}
		p, ok := have[name]
		if !assert.True(t, ok, "golden model %s has no migration pair in %s", name, pairsDir) {
			continue
		}
		raw := read(t, m)
		v, err := migrate.Version(raw)
		require.NoError(t, err)
		assert.Equal(t, migrate.Current, v, "golden model %s is stored at the current schema version", name)
		assert.JSONEq(t, string(read(t, p.newPath)), string(raw), "golden model %s is the upgrade of its frozen inputs", name)
		assert.Contains(t, p.inputs, "0.9", "golden model %s keeps its frozen 0.9 input", name)
		assert.Contains(t, p.inputs, "1.0", "golden model %s keeps its frozen 1.0 input", name)
		assert.Contains(t, p.inputs, "1.1", "golden model %s keeps its frozen 1.1 input", name)
	}
	for name := range nativeAtCurrent {
		assert.True(t, seenNative[name], "nativeAtCurrent names %s, which is not a golden model", name)
	}
	assert.Contains(t, have, "synthetic", "the synthetic 0.9 model is part of the pairs")
	assert.Contains(t, have, "agentic", "the synthetic agentic 1.0 model is part of the pairs")
}

// TestNativeModelsAreTheirOwn11Upgrade: a golden model native to 1.1 has no frozen inputs, so the
// 1.1 → 1.2 step is checked on it directly. Read back as a 1.1 document it upgrades to itself: the
// step changes nothing but the version on a model inside the 1.2 profiles.
func TestNativeModelsAreTheirOwn11Upgrade(t *testing.T) {
	t.Parallel()
	for name := range nativeAtCurrent {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stored := decode(t, read(t, filepath.Join(goldenDir, name+".json")))
			as11 := decode(t, read(t, filepath.Join(goldenDir, name+".json")))
			as11[migrate.Field] = "1.1"
			raw, err := json.Marshal(as11)
			require.NoError(t, err)
			got, from, to, err := migrate.Upgrade(raw)
			require.NoError(t, err)
			assert.Equal(t, "1.1", from)
			assert.Equal(t, migrate.Current, to)
			assert.Equal(t, stored, decode(t, got), "%s upgrades from 1.1 to itself", name)
		})
	}
}

// TestUpgradedModelsHashAsTheirUpgrade: an old model loads (upgrade on read), is re-saved at the
// current version the way the store writes it (the canonical form, findings and evidence left out)
// and read back, and the hash is the same at every step: schema_version is inside the hash from
// 1.0, and an older model is hashed after its upgrade.
func TestUpgradedModelsHashAsTheirUpgrade(t *testing.T) {
	t.Parallel()
	for _, p := range pairs(t) {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			fromOld, fromNew, resaved := loadThree(t, p)
			hOld, err := model.Hash(fromOld)
			require.NoError(t, err)
			hNew, err := model.Hash(fromNew)
			require.NoError(t, err)
			hResaved, err := model.Hash(resaved)
			require.NoError(t, err)
			assert.Equal(t, hNew, hOld, "an old model hashes as its upgrade")
			assert.Equal(t, hNew, hResaved, "re-saving at the current version keeps the hash")
		})
	}
}

// loadThree reads a pair as the engine sees it: the oldest input upgraded on read, the expected
// model at the current version, and the oldest input after a save at the current version and a
// read back.
func loadThree(t *testing.T, p pair) (fromOld, fromNew, resaved *model.Architecture) {
	t.Helper()
	_, oldest := p.oldest()
	fromOld, err := model.ValidateJSON(read(t, oldest))
	require.NoError(t, err, "the oldest input upgrades on read")
	assert.Equal(t, model.CurrentSchemaVersion, fromOld.SchemaVersion)
	fromNew, err = model.ValidateJSON(read(t, p.newPath))
	require.NoError(t, err)
	assert.Equal(t, model.CurrentSchemaVersion, fromNew.SchemaVersion)

	canon, err := model.Canonical(fromOld)
	require.NoError(t, err)
	assert.Contains(t, string(canon), `"schema_version":"`+model.CurrentSchemaVersion+`"`, "the saved form carries the version")
	// The stored form leaves findings and evidence out; the store's read path puts them back
	// empty before anything evaluates it.
	var stored map[string]any
	require.NoError(t, json.Unmarshal(canon, &stored))
	stored["findings"], stored["evidence"] = []any{}, []any{}
	storedRaw, err := json.Marshal(stored)
	require.NoError(t, err)
	resaved, err = model.ValidateJSON(storedRaw)
	require.NoError(t, err)
	return fromOld, fromNew, resaved
}
