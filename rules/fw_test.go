package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// docs/18 WS-M M3 and M4 (ADR-093 decisions 3, 8 and 9): the fw pack, the three amendments of
// docs/research/07-agentic-frameworks/00-synthesis.md §4.3 and the framework-native remediation.

// The amendment variants live in packs/fixtures/amendments/ (outside the variant glob of TestPathRuleFixtures,
// which owns the path rules' variants). Each is asserted element by element; a file on disk that no case names fails.
var amendmentFixtureCases = map[string]struct {
	rule string
	want []string // the element ids the rule fires on; nil = silent
}{
	// A-1 (SD-2): agents hosted on one app that run as the app's identity are one principal.
	"ZT-002.cohosted.neg.json":   {rule: "ZT-002"},                                     // the host identity is a dedicated (shared-kind) workload identity
	"ZT-002.cohosted.pos.json":   {"ZT-002", []string{"n_sup"}},                        // the host runs as a user account: assessed once, lowest agent id
	"ZT-003.cohosted.neg.json":   {rule: "ZT-003"},                                     // an in-process hop carries no token
	"ZT-003.boundary.pos.json":   {"ZT-003", []string{"e1"}},                           // co-hosted but split by a trust boundary: the TLS-001 guard
	"AID-002.cohosted.neg.json":  {rule: "AID-002"},                                    // two agents on one host share its identity: one principal
	"AID-002.elsewhere.pos.json": {"AID-002", []string{"n_remote", "n_sup", "n_work"}}, // a third agent elsewhere on the same identity
	// ARH-001 reads code-executing tools with the FS-08 isolation values.
	"ARH-001.tool.pos.json":     {"ARH-001", []string{"n_agent"}}, // sandbox process: a child process of the host is no isolation for a tool
	"ARH-001.toolnone.pos.json": {"ARH-001", []string{"n_agent"}}, // no sandbox declared on the tool reads none
	"ARH-001.tool.neg.json":     {rule: "ARH-001"},                // wasm
	"ARH-001.toolvm.neg.json":   {rule: "ARH-001"},                // vm
}

func TestFWAmendmentFixtures(t *testing.T) {
	t.Parallel()
	c, err := LoadDir(repoPath("packs"))
	require.NoError(t, err)
	eng := New(c, DefaultPolicyTable())
	dir := repoPath("packs", "fixtures", "amendments")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.Contains(t, amendmentFixtureCases, e.Name(), "amendment fixture %s is not asserted", e.Name())
	}
	for name, tc := range amendmentFixtureCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := loadModel(t, filepath.Join(dir, name))
			fs, err := eng.Evaluate(context.Background(), a, policyFromAttrs(a))
			require.NoError(t, err)
			got := findingsByRule(fs)[tc.rule]
			sort.Strings(got)
			if tc.want == nil {
				assert.Empty(t, got, "%s stays silent", tc.rule)
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// A-1 states its reason in the finding: the ZT-002 message on a co-hosted principal names the host and the agents.
func TestZT002CohostedMessageNamesTheHost(t *testing.T) {
	t.Parallel()
	c, err := LoadDir(repoPath("packs"))
	require.NoError(t, err)
	a := loadModel(t, repoPath("packs", "fixtures", "amendments", "ZT-002.cohosted.pos.json"))
	fs, err := New(c, DefaultPolicyTable()).Evaluate(context.Background(), a, policyFromAttrs(a))
	require.NoError(t, err)
	for _, f := range fs {
		if f.RuleID == "ZT-002" {
			assert.Contains(t, f.Message, "Agent server")
			assert.Contains(t, f.Message, "Supervisor agent, Research worker agent")
			assert.Contains(t, f.Message, "assessed once for the host")
			return
		}
	}
	t.Fatal("ZT-002 did not fire")
}

// The fw pack (docs/03 §FW): thirteen rules, the conditions read only schema 1.2 vocabulary, every rule cites corpus
// clauses and carries at least one framework-native sentence.
func TestFWPackShape(t *testing.T) {
	t.Parallel()
	c, err := LoadDir(repoPath("packs"))
	require.NoError(t, err)
	var ids []string
	for _, r := range c.Rules() {
		if r.Pack != "fw" {
			continue
		}
		ids = append(ids, r.ID)
		assert.NotEmpty(t, r.Clauses, r.ID)
		assert.NotEmpty(t, r.Remediation, r.ID)
		assert.NotEmpty(t, r.RemediationByFramework, "%s: a framework-native sentence (ADR-093 decision 9)", r.ID)
		for fw, fr := range r.RemediationByFramework {
			assert.Equal(t, fw, fr.Framework)
			assert.True(t, frameworkSourceRe.MatchString(fr.Source), "%s %s: %s pins a commit", r.ID, fw, fr.Source)
		}
		cause, ok := c.CauseOf(r.ID)
		require.True(t, ok, r.ID)
		assert.Equal(t, "framework-settings", cause.ID, r.ID)
	}
	want := []string{}
	for i := 1; i <= 13; i++ {
		want = append(want, fmt.Sprintf("FW-%03d", i))
	}
	assert.Equal(t, want, ids)
}

// M4: the 35 sentences of 00-synthesis.md §5 ship on the seven rules, one per framework the research read
// (LangGraph, Microsoft Agent Framework, Foundry Agent Service, Google ADK, OpenAI Agents SDK), CrewAI where it has one.
func TestSevenRulesCarryFrameworkSentences(t *testing.T) {
	t.Parallel()
	c, err := LoadDir(repoPath("packs"))
	require.NoError(t, err)
	five := []string{"google_adk", "foundry_agent_service", "langgraph", "ms_agent_framework", "openai_agents"}
	total := 0
	for _, id := range []string{"AI-003", "AGT-003", "AGT-005", "AGT-006", "ZT-002", "ZT-003", "AI-010"} {
		r, ok := c.Rule(id)
		require.True(t, ok, id)
		for _, fw := range five {
			fr, ok := r.RemediationFor(fw)
			if assert.True(t, ok, "%s: a %s sentence", id, fw) {
				assert.NotEmpty(t, fr.Text)
				assert.NotRegexp(t, `\[[A-Z]+/`, fr.Text, "%s %s: citations travel in source, not in the text", id, fw)
				total++
			}
		}
	}
	assert.Equal(t, 35, total)
}

func TestRemediationByFrameworkValidation(t *testing.T) {
	t.Parallel()
	const src = "https://raw.githubusercontent.com/langchain-ai/langgraph/4be610c6bc7c042038f671d6def9f523ca385a69/libs/x.py#L1-L2"
	pack := func(entry string) string {
		return `pack: t
version: 0.0.1
rules:
  - id: TST-001
    title: t
    scope: node
    severity: low
    condition: 'n.type == "agent"'
    message: "m"
    clauses: [OWASP:LLMTop10:LLM01]
    remediation: "generic"
    remediation_by_framework:
` + entry
	}
	for _, tc := range []struct {
		name, entry, wantErr string
	}{
		{"ok", "      langgraph: { text: 'Set it.', source: '" + src + "' }\n", ""},
		{"unknown framework", "      autogen: { text: 'Set it.', source: '" + src + "' }\n", "unknown framework"},
		{"empty text", "      langgraph: { text: '', source: '" + src + "' }\n", "text is required"},
		{"branch, not commit", "      langgraph: { text: 'Set it.', source: 'https://raw.githubusercontent.com/langchain-ai/langgraph/main/libs/x.py' }\n", "pinned to a 40-hex commit"},
		{"not https", "      langgraph: { text: 'Set it.', source: 'http://raw.githubusercontent.com/a/b/4be610c6bc7c042038f671d6def9f523ca385a69/x' }\n", "must be https"},
		{"other host", "      langgraph: { text: 'Set it.', source: 'https://example.com/a/b/4be610c6bc7c042038f671d6def9f523ca385a69/x' }\n", "pinned to a 40-hex commit"},
		{"unknown key", "      langgraph: { text: 'Set it.', source: '" + src + "', url: 'x' }\n", "unknown field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := parseInline(t, pack(tc.entry))
			if tc.wantErr == "" {
				require.NoError(t, err)
				r, _ := c.Rule("TST-001")
				fr, ok := r.RemediationFor("langgraph")
				require.True(t, ok)
				assert.Equal(t, FrameworkRemediation{Framework: "langgraph", Text: "Set it.", Source: src}, fr)
				_, ok = r.RemediationFor("google_adk")
				assert.False(t, ok, "no sentence: the generic remediation applies")
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// The pack hash covers remediation_by_framework: a changed sentence is a changed pack (ADR-042 §4).
func TestRemediationByFrameworkIsHashed(t *testing.T) {
	t.Parallel()
	base := "pack: t\nversion: 1\nrules:\n  - id: TST-001\n    remediation_by_framework: {langgraph: {text: 'A', source: 's'}}\n"
	changed := strings.Replace(base, "'A'", "'B'", 1)
	a, err := CanonicalPack([]byte(base))
	require.NoError(t, err)
	b, err := CanonicalPack([]byte(changed))
	require.NoError(t, err)
	assert.NotEqual(t, string(a), string(b))
}

// FrameworkOf: which agent's framework a finding speaks to.
func TestFrameworkOf(t *testing.T) {
	t.Parallel()
	ag := func(id, fw string, extra ...string) model.Node {
		attrs := model.Attrs{}
		if fw != "" {
			attrs["framework"] = fw
		}
		if len(extra) == 2 {
			attrs[extra[0]] = extra[1]
		}
		return model.Node{ID: id, Type: "agent", Name: id, Layer: "ai", Attrs: attrs}
	}
	n := func(id, typ string) model.Node {
		return model.Node{ID: id, Type: typ, Name: id, Layer: "app", Attrs: model.Attrs{}}
	}
	ed := func(id, from, to, kind string) model.Edge { return model.Edge{ID: id, From: from, To: to, Kind: kind} }
	a := &model.Architecture{ID: "arch_x",
		Nodes: []model.Node{
			ag("a_lg", "langgraph", "hosted_on", "n_app"), ag("a_lg2", "langgraph", "hosted_on", "n_app"), ag("a_adk", "google_adk"), ag("a_none", ""),
			n("n_app", "app"), n("t_lg", "tool"), n("t_shared", "tool"), n("m_adk", "agent_memory"), n("t_far", "tool"), n("x_mid", "api"), n("t_alone", "tool"),
		},
		Edges: []model.Edge{
			ed("e_lg_tool", "a_lg", "t_lg", "calls"), ed("e_lg_shared", "a_lg", "t_shared", "calls"), ed("e_adk_shared", "a_adk", "t_shared", "calls"),
			ed("e_adk_mem", "a_adk", "m_adk", "writes"), ed("e_lg_adk", "a_lg", "a_adk", "delegates"), ed("e_tool_tool", "t_lg", "t_far", "calls"),
			ed("e_mid", "x_mid", "t_alone", "calls"), ed("e_lg_lg2", "a_lg", "a_lg2", "delegates"), ed("e_none_adk", "a_none", "a_adk", "delegates"),
		},
	}
	for _, tc := range []struct {
		name string
		ids  []string
		want string
	}{
		{"agent", []string{"a_adk"}, "google_adk"},
		{"agent without a framework", []string{"a_none"}, ""},
		{"tool reached by one agent", []string{"t_lg"}, "langgraph"},
		{"memory written by one agent", []string{"m_adk"}, "google_adk"},
		{"tool shared by two frameworks: generic", []string{"t_shared"}, ""},
		{"two hops away", []string{"t_far"}, "langgraph"},
		{"no agent within two hops", []string{"t_alone"}, ""},
		// A delegation between two frameworks settles none: the rule may remediate either end (FW-006 the delegate),
		// so neither end's sentence is safe. This case pinned "langgraph" (the source) before the review fix.
		{"edge between agents of two frameworks: generic", []string{"e_lg_adk"}, ""},
		{"edge between agents of one framework", []string{"e_lg_lg2"}, "langgraph"},
		{"edge from an agent to a tool", []string{"e_lg_tool"}, "langgraph"},
		{"edge between an undeclared and a declared agent", []string{"e_none_adk"}, "google_adk"},
		{"edge between tools", []string{"e_tool_tool"}, "langgraph"},
		{"host of agents", []string{"n_app"}, "langgraph"},
		{"first id that settles", []string{"t_shared", "a_adk"}, "google_adk"},
		{"architecture: agents disagree", []string{"arch_x"}, ""},
		{"unknown id", []string{"nope"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, FrameworkOf(a, tc.ids))
		})
	}
	assert.Empty(t, FrameworkOf(nil, []string{"a_lg"}))
}

// FW-006 on a cross-framework delegation (a LangGraph supervisor delegating to an ADK agent): the rule's patch and
// sentence apply to the delegate, so the LangGraph sentence (pre_model_hook) must not show; the generic remediation
// stands alone. On a same-framework delegation the framework's sentence shows.
func TestFW006CrossFrameworkDelegationFallsBackToGeneric(t *testing.T) {
	t.Parallel()
	c, err := LoadDir(repoPath("packs"))
	require.NoError(t, err)
	agent := func(id, fw string, guarded bool) model.Node {
		attrs := model.Attrs{"framework": fw}
		if guarded {
			attrs["guardrails"] = []any{map[string]any{"stage": "input"}}
		}
		return model.Node{ID: id, Type: "agent", Name: id, Layer: "ai", Attrs: attrs}
	}
	build := func(workerFW string) *model.Architecture {
		return &model.Architecture{ID: "arch_fw006", Name: "fw006", SchemaVersion: model.CurrentSchemaVersion,
			Nodes: []model.Node{agent("a_sup", "langgraph", true), agent("a_worker", workerFW, false)},
			Edges: []model.Edge{{ID: "e_del", From: "a_sup", To: "a_worker", Kind: "delegates"}}}
	}
	eng := New(c, DefaultPolicyTable())
	for _, tc := range []struct {
		name, workerFW, want string
	}{
		{"langgraph to google_adk: generic", "google_adk", ""},
		{"langgraph to langgraph: LangGraph sentence", "langgraph", "langgraph"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := build(tc.workerFW)
			fs, err := eng.Evaluate(context.Background(), a, policyFromAttrs(a))
			require.NoError(t, err)
			var ids []string
			for _, f := range fs {
				if f.RuleID == "FW-006" {
					ids = f.IDs
				}
			}
			require.NotEmpty(t, ids, "FW-006 fires on the delegation")
			fr, ok := c.FrameworkRemediationFor("FW-006", a, ids)
			if tc.want == "" {
				assert.False(t, ok, "no sentence for the wrong framework: got %q", fr.Text)
				return
			}
			require.True(t, ok)
			assert.Equal(t, tc.want, fr.Framework)
		})
	}
}

// M4 merge gate at the catalog: the same AI-003 finding on a LangGraph agent and on an ADK agent selects each
// framework's own sentence, and an agent with no framework falls back to the generic remediation.
func TestFrameworkRemediationForSameFinding(t *testing.T) {
	t.Parallel()
	c, err := LoadDir(repoPath("packs"))
	require.NoError(t, err)
	a := loadModel(t, repoPath("packs", "fixtures", "ZT-002.pos.json"))
	var agentID string
	for i := range a.Nodes {
		if a.Nodes[i].Type == "agent" {
			agentID = a.Nodes[i].ID
			break
		}
	}
	require.NotEmpty(t, agentID)
	set := func(fw string) *model.Architecture {
		b, err := a.Clone()
		require.NoError(t, err)
		for i := range b.Nodes {
			if b.Nodes[i].ID == agentID {
				if fw == "" {
					delete(b.Nodes[i].Attrs, "framework")
				} else {
					b.Nodes[i].Attrs["framework"] = fw
				}
			}
		}
		return b
	}
	r, _ := c.Rule("ZT-002")
	lg, ok := c.FrameworkRemediationFor("ZT-002", set("langgraph"), []string{agentID})
	require.True(t, ok)
	adk, ok := c.FrameworkRemediationFor("ZT-002", set("google_adk"), []string{agentID})
	require.True(t, ok)
	assert.Equal(t, r.RemediationByFramework["langgraph"], lg)
	assert.Equal(t, r.RemediationByFramework["google_adk"], adk)
	assert.NotEqual(t, lg.Text, adk.Text)
	_, ok = c.FrameworkRemediationFor("ZT-002", set(""), []string{agentID})
	assert.False(t, ok, "no framework: the generic remediation stands alone")
	_, ok = c.FrameworkRemediationFor("ZT-001", set("langgraph"), []string{agentID})
	assert.False(t, ok, "a rule without sentences")
	assert.Equal(t, "LangGraph", FrameworkLabel("langgraph"))
	assert.Equal(t, "x", FrameworkLabel("x"))
}

// CLAUDE.md §1.5: the framework sentences render in the finding card, the lens and every export, so the shipped
// catalog's sentences use the product wording (assesses, evidences, proposes, records; never certifies, confirms,
// guarantees, compliant, attests) and cite no internal research file a report reader cannot open. Code identifiers
// in backticks (`require_confirmation=True`) are an SDK's own names and are not read as wording.
func TestShippedFrameworkSentencesUseProductWording(t *testing.T) {
	t.Parallel()
	c, err := LoadDir(repoPath("packs"))
	require.NoError(t, err)
	forbidden := regexp.MustCompile(`(?i)\b(compliant|compliance|certif\w*|confirm\w*|guarantee\w*|attest\w*)\b`)
	internalRef := regexp.MustCompile(`[\w-]+\.md\b|§|\bADR-\d+|\bSD-\d+`)
	code := regexp.MustCompile("`[^`]*`")
	n := 0
	for _, r := range c.Rules() {
		for fw, fr := range r.RemediationByFramework {
			n++
			prose := code.ReplaceAllString(fr.Text, "")
			assert.False(t, forbidden.MatchString(prose), "%s %s: forbidden wording %q in %q", r.ID, fw, forbidden.FindString(prose), fr.Text)
			assert.False(t, internalRef.MatchString(prose), "%s %s: internal reference %q in %q", r.ID, fw, internalRef.FindString(prose), fr.Text)
		}
	}
	assert.Greater(t, n, 35, "the seven rules' 35 sentences and the fw pack's are checked")
}
