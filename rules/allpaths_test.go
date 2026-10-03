package rules

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// The path rules read all paths (ADR-088 §1 and Amendments, docs/03 "Path rules"): a finding is raised when any walk to
// the protected hop avoids the control, on the last ungated hop. Each rewritten rule's positive fixture is a "parallel
// gateway" pair (a direct edge beside a gated route fires, all routes gated is silent); the variant fixtures
// packs/fixtures/<RULE>.<variant>.{pos,neg}.json pin chains, gateway kinds (B2a) and hosted_on (B3).

// variantFixtureRe matches the variant files this test owns (the pack declares only <RULE>.pos|neg|kb.json).
var variantFixtureRe = regexp.MustCompile(`^[A-Z]{2,5}-[0-9]{3}\.[a-z]+\.(pos|neg)\.json$`)

// pathFixtureCases: fixture file → rule → the exact elements it fires on (empty: silent).
var pathFixtureCases = map[string]map[string][]string{
	// AI-001 (absorbs LOG-004) needs an AI gateway on every path (B2a).
	"AI-001.pos.json":       {"AI-001": {"e1"}},
	"AI-001.neg.json":       {"AI-001": {}},
	"AI-001.chain.pos.json": {"AI-001": {"e2"}}, // agent → tool → model: the tool → model hop
	// An API gateway is not an AI gateway. The hop out of it moved from AI-001 to AGW-003 when the swarm complement
	// was built (docs/18 B2b, ADR-088 Amendments (a): one finding per hop).
	"AI-001.apigw.pos.json": {"AI-001": {}, "AGW-003": {"e2"}},
	// B2b gateway functions: declared functions decide whatever the kind; an AI gateway whose functions lack
	// observability or policy is walked through, alone, in series, and credited when a sufficient one is upstream.
	"AI-001.functions.neg.json": {"AI-001": {}, "AGW-003": {}},
	"AI-001.nofunc.pos.json":    {"AI-001": {"e2"}, "AGW-003": {}},
	"AI-001.series.pos.json":    {"AI-001": {"e3"}},
	// The function-aware walk (cel.go upstreamAvoiding with needFunctions) is exact at any chain length: five gateways
	// in series, none crediting the hop, report the last hop (the CEL unrolling stopped after three: Reconcile A).
	"AI-001.deepseries.pos.json": {"AI-001": {"e6"}, "AGW-003": {}},
	"AI-001.credited.neg.json":   {"AI-001": {}},
	// B2b review fix: the walk blocks every gateway and credits one by what it declares, whatever its kind, so a gateway
	// of another kind that declares the functions further up counts; one of the right kind that declares none is
	// credited by kind (the hop is then decided, not not_checked: docs/03 Known limits).
	"AI-001.upstreamfn.neg.json":   {"AI-001": {}, "AGW-003": {}},
	"AI-001.kindupstream.neg.json": {"AI-001": {}},
	"AGW-003.upstreamfn.neg.json":  {"AGW-003": {}, "AI-001": {}},
	"AGW-003.pos.json":             {"AGW-003": {"e_gw_llm"}, "AI-001": {}},
	"AGW-003.neg.json":             {"AGW-003": {}, "AI-001": {}},
	// AI-003: the hop into and out of a human step are the approval itself.
	"AI-003.pos.json":       {"AI-003": {"e1"}},
	"AI-003.neg.json":       {"AI-003": {}},
	"AI-003.chain.pos.json": {"AI-003": {"e2"}}, // agent → app ─writes(high)→ ledger
	// NET-003 needs an api or waf gateway (B2a).
	"NET-003.pos.json": {"NET-003": {"e1"}},
	"NET-003.neg.json": {"NET-003": {}},
	// An AI gateway is not a WAF. The hop out of it moved from NET-003 to APX-004 when the swarm complement was built
	// (docs/18 B2b, ADR-088 Amendments (a): one finding per hop).
	"NET-003.aigw.pos.json":  {"NET-003": {}, "APX-004": {"e2"}},
	"NET-003.apigw.neg.json": {"NET-003": {}},
	// B2b gateway functions: a WAF that declares policy counts, one whose declared functions lack it does not; an AI
	// gateway that declares policy is credited (functions decide once declared).
	"NET-003.functions.neg.json":    {"NET-003": {}, "APX-004": {}},
	"NET-003.nofunc.pos.json":       {"NET-003": {"e2"}, "APX-004": {}},
	"APX-004.pos.json":              {"APX-004": {"e2"}, "NET-003": {}},
	"APX-004.neg.json":              {"APX-004": {}, "NET-003": {}},
	"APX-004.functions.neg.json":    {"APX-004": {}, "NET-003": {}},
	"NET-003.upstreamfn.neg.json":   {"NET-003": {}, "APX-004": {}},
	"NET-003.kindupstream.neg.json": {"NET-003": {}},
	"APX-004.upstreamfn.neg.json":   {"APX-004": {}, "NET-003": {}},
	// NET-005: broker or DMZ on every path from the edge layer.
	"NET-005.pos.json":       {"NET-005": {"e1"}},
	"NET-005.neg.json":       {"NET-005": {}},
	"NET-005.chain.pos.json": {"NET-005": {"e2"}}, // edge → ingest API → store: the hop into the store
	// An edge-layer broker (IoT Operations on site) is the conduit, not edge traffic: edge → broker → app → store is silent.
	"NET-005.edgebroker.neg.json": {"NET-005": {}},
	// STR-005 needs an ai or api gateway (B2a); a hop out of a human step is the person's.
	"STR-005.pos.json":       {"STR-005": {"e1"}},
	"STR-005.neg.json":       {"STR-005": {}},
	"STR-005.aigw.neg.json":  {"STR-005": {}},
	"STR-005.mcpgw.neg.json": {"STR-005": {}}, // a gateway of kind mcp (schema 1.1) is credited
	"STR-005.waf.pos.json":   {"STR-005": {"e2"}},
	"STR-005.chain.pos.json": {"STR-005": {"e2"}},
	"STR-005.human.neg.json": {"STR-005": {}},
	// B2b: a gateway counts when it declares identity_termination; an mcp gateway whose functions lack it does not.
	"STR-005.functions.neg.json":    {"STR-005": {}},
	"STR-005.nofunc.pos.json":       {"STR-005": {"e3"}},
	"STR-005.upstreamfn.neg.json":   {"STR-005": {}},
	"STR-005.kindupstream.neg.json": {"STR-005": {}},
	// AGT-003: any gateway; the agent's own content safety also decides.
	"AGT-003.pos.json":        {"AGT-003": {"e1"}},
	"AGT-003.neg.json":        {"AGT-003": {}},
	"AGT-003.safety.neg.json": {"AGT-003": {}},
	"AGT-003.chain.pos.json":  {"AGT-003": {"e2"}},
	// An agent with content safety between the unscreened agent and the third-party tool screens the content.
	"AGT-003.screened.neg.json": {"AGT-003": {}},
	// AGT-006: a human step on every path from the autonomous agent.
	"AGT-006.pos.json":       {"AGT-006": {"e1"}},
	"AGT-006.neg.json":       {"AGT-006": {}},
	"AGT-006.chain.pos.json": {"AGT-006": {"e2"}},
	// ATA-010 reads integrity only (C2 handover): card_signed without a verified signature or a pinned copy fires.
	"ATA-010.cardsigned.pos.json": {"ATA-010": {"e1"}},
	// DATA-003 and DATA-004 read data_classes[] with data_class (schema 1.1, self-assessment limitation 6).
	"DATA-003.classes.pos.json": {"DATA-003": {"n_db"}},
	"DATA-004.classes.pos.json": {"DATA-004": {"n_db"}},
	// A store that declares no data_class and lists a sensitive class in data_classes[] only: the condition decides
	// it and the rule fires (data_classes_test.go pins that it is decided, never not_checked).
	"DATA-003.classesonly.pos.json": {"DATA-003": {"n_db"}},
	"DATA-004.classesonly.pos.json": {"DATA-004": {"n_db"}},
	// ADR-093 FS-23: a shared access signature (auth sas) is a shared secret like api_key (sas_test.go).
	"ZT-001.sas.pos.json":  {"ZT-001": {"e1"}},
	"ZT-006.sas.pos.json":  {"ZT-006": {"e3"}},
	"WIS-001.sas.pos.json": {"WIS-001": {"n_kv"}},
	"WIS-010.sas.pos.json": {"WIS-010": {"e1"}},
	"STR-006.sas.pos.json": {"STR-006": {"e1"}},
	"RAG-001.sas.pos.json": {"RAG-001": {"e1"}},
	"ATA-002.sas.pos.json": {"ATA-002": {"e1"}},
	// LPV-002/003: scopes: [] on an imported element is the importer's placeholder (ADR-093-C2): silent here,
	// not_checked in lpv_imported_test.go.
	"LPV-002.imported.neg.json": {"LPV-002": {}},
	"LPV-003.imported.neg.json": {"LPV-003": {}},
	// OT-009 needs a machine write to protect (team 09 handover): a command-signing key, even a public one, in a model
	// with no writes or executes edge into an edge_device is silent.
	"OT-009.nomachine.neg.json": {"OT-009": {}},
	// B3: one credential, one finding; co-located hops are exempt as in NET-006.
	"ZT-001.pos.json":             {"ZT-001": {"e1"}, "STR-006": {}},
	"ZT-001.hosted.pos.json":      {"ZT-001": {"e2"}, "STR-006": {}}, // the hop into the database itself reports
	"ZT-001.colocated.neg.json":   {"ZT-001": {}, "STR-006": {}, "NET-006": {}},
	"ZT-001.lowestid.pos.json":    {"ZT-001": {"e1"}, "STR-006": {}},       // no hop into the database: the lowest edge id
	"ZT-001.twosecrets.pos.json":  {"ZT-001": {"e1", "e2"}, "STR-006": {}}, // one finding per secret
	"STR-006.pos.json":            {"STR-006": {"e1"}},
	"STR-006.hosted.pos.json":     {"STR-006": {"e3"}, "ZT-001": {}}, // the hop into the host reports
	"STR-006.colocated.neg.json":  {"STR-006": {}},
	"STR-006.lowestid.pos.json":   {"STR-006": {"e1"}},       // no hop into the host: the lowest edge id
	"STR-006.twosecrets.pos.json": {"STR-006": {"e1", "e2"}}, // one finding per secret
}

func TestPathRuleFixtures(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	for file, want := range pathFixtureCases {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, filepath.Join(repoPath("packs"), "fixtures", file))
			fs, err := eng.Evaluate(context.Background(), a, policyFromAttrs(a))
			require.NoError(t, err)
			got := findingsByRule(fs)
			for rule, ids := range want {
				_, ok := c.Rule(rule)
				require.True(t, ok, rule)
				fired := got[rule]
				sort.Strings(fired)
				assert.Equal(t, ids, append([]string{}, fired...), "%s: %s fires on", file, rule)
			}
		})
	}
}

// Every variant file on disk is asserted above, so none is dead weight.
func TestVariantFixturesAreAsserted(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(filepath.Join(repoPath("packs"), "fixtures"))
	require.NoError(t, err)
	n := 0
	for _, e := range entries {
		if !variantFixtureRe.MatchString(e.Name()) {
			continue
		}
		n++
		assert.Contains(t, pathFixtureCases, e.Name(), "variant fixture %s is not asserted by TestPathRuleFixtures", e.Name())
	}
	assert.Positive(t, n)
}

// Each rewritten rule's patch_template turns the design it fires on into one it is silent on (docs/18 B1): the parallel
// positive fixture and the chains the template can fix. Two limits are pinned with the elements the rule still fires
// on after its own patch (docs/03): AGT-003's template sets content_safety on e.from, which is the agent only on a
// direct hop, so on a chain the finding stays on the hop; ZT-001 and STR-006 report one finding per shared secret
// (B3) but the patch replaces auth on the reported hop only, so the finding moves to the sibling hop that uses the
// same secret (the message names it), and one acceptance per hop is expected.
func TestPathRulePatchesEvaluateClean(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	ctx := context.Background()
	tests := []struct {
		rule, file string
		after      []string // the elements the rule fires on after its patch; empty: clean
	}{
		{"AI-001", "AI-001.pos.json", nil},
		{"AI-001", "AI-001.chain.pos.json", nil},
		// The API-gateway hop is AGW-003's since B2b; its template inserts the same AI gateway AI-001's does.
		{"AGW-003", "AI-001.apigw.pos.json", nil},
		{"AGW-003", "AGW-003.pos.json", nil},
		{"AI-001", "AI-001.nofunc.pos.json", nil},
		{"AI-003", "AI-003.pos.json", nil},
		{"AI-003", "AI-003.chain.pos.json", nil},
		{"STR-005", "STR-005.pos.json", nil},
		{"STR-005", "STR-005.chain.pos.json", nil},
		{"STR-005", "STR-005.waf.pos.json", nil},
		{"AGT-003", "AGT-003.pos.json", nil},
		{"AGT-003", "AGT-003.chain.pos.json", []string{"e2"}},
		{"AGT-006", "AGT-006.pos.json", nil},
		{"AGT-006", "AGT-006.chain.pos.json", nil},
		{"ZT-001", "ZT-001.pos.json", nil},
		{"ZT-001", "ZT-001.hosted.pos.json", []string{"e1"}},
		{"STR-006", "STR-006.pos.json", nil},
		{"STR-006", "STR-006.hosted.pos.json", []string{"e1"}},
	}
	for _, tc := range tests {
		t.Run(tc.rule+"/"+tc.file, func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, filepath.Join(repoPath("packs"), "fixtures", tc.file))
			p := policyFromAttrs(a)
			before, err := eng.Evaluate(ctx, a, p)
			require.NoError(t, err)
			i := slices.IndexFunc(before, func(f model.Finding) bool { return f.RuleID == tc.rule })
			require.GreaterOrEqual(t, i, 0, "%s fires on %s", tc.rule, tc.file)
			require.True(t, before[i].HasPatch)
			ops, ok, err := eng.PatchForFinding(ctx, a, before[i], p)
			require.NoError(t, err)
			require.True(t, ok)
			next, err := model.Apply(a, ops, false)
			require.NoError(t, err, "the rendered patch applies")
			require.NoError(t, model.Validate(next), "the patched design is a valid model")
			after, err := eng.Evaluate(ctx, next, p)
			require.NoError(t, err)
			fired := findingsByRule(after)[tc.rule]
			sort.Strings(fired)
			want := tc.after
			if want == nil {
				want = []string{}
			}
			assert.Equal(t, want, append([]string{}, fired...), "%s after its own patch on %s", tc.rule, filepath.Base(tc.file))
		})
	}
}

// One credential, one finding (B3): the message of ZT-001 and STR-006 names the other hops that use the same secret
// into the same host, so the person who accepts the patch on the reported hop knows the finding stands for them too.
func TestSharedSecretMessageNamesSiblings(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	tests := []struct {
		file, rule, want string
	}{
		{"ZT-001.hosted.pos.json", "ZT-001", "Web app accesses SQL DB with a shared secret (connection_string). The same secret also reaches Audit table (e1), pgvector index (e3): this finding stands for those hops too, and each needs the same change."},
		{"ZT-001.pos.json", "ZT-001", ""},
		{"ZT-001.twosecrets.pos.json", "ZT-001", "Web app accesses SQL DB with a shared secret (connection_string)."},
		{"STR-006.hosted.pos.json", "STR-006", "Web app → Function host authenticates with a shared secret (api_key) instead of a workload identity. The same secret also reaches Orders API (e1), Stock API (e2): this finding stands for those hops too, and each needs the same change."},
		{"STR-006.twosecrets.pos.json", "STR-006", "Web app → Function host authenticates with a shared secret (api_key) instead of a workload identity."},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, filepath.Join(repoPath("packs"), "fixtures", tc.file))
			fs, err := eng.Evaluate(context.Background(), a, policyFromAttrs(a))
			require.NoError(t, err)
			var msgs []string
			for _, f := range fs {
				if f.RuleID == tc.rule {
					msgs = append(msgs, f.Message)
				}
			}
			require.NotEmpty(t, msgs)
			if tc.want == "" {
				assert.NotContains(t, msgs[0], "The same secret also reaches", "a single hop names no sibling")
				return
			}
			assert.Contains(t, msgs, tc.want)
		})
	}
}
