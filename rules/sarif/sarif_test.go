package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sample() []Finding {
	return []Finding{
		{
			RuleID: "AI-003", Pack: "ai", Severity: "high", Title: "High-consequence action without human approval",
			Message:     "Operations agent writes Core ledger with no approval step.",
			Remediation: "Insert a human approval step.",
			Citations:   []string{"AIACT:2024/1689:Art14", "FINMA:08/2024:Governance"},
			ElementIDs:  []string{"e_agent_ledger"},
		},
		{
			RuleID: "LOG-001", Pack: "log", Severity: "medium", Title: "No central log sink",
			Message: "Nothing ships logs.", ElementIDs: []string{"n2", "n1"},
		},
		{
			RuleID: "AI-003", Pack: "ai", Severity: "high", Title: "High-consequence action without human approval",
			Message: "Second occurrence.", Citations: []string{"AIACT:2024/1689:Art14"}, ElementIDs: []string{"e2"},
			Status: "accepted",
		},
	}
}

func TestLevel(t *testing.T) {
	tests := []struct{ severity, want string }{
		{"critical", "error"}, {"high", "error"}, {" HIGH ", "error"},
		{"medium", "warning"}, {"low", "note"}, {"info", "note"}, {"", "note"}, {"bogus", "note"},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.Equal(t, tc.want, Level(tc.severity))
		})
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name      string
		a, b      []string
		ruleA     string
		ruleB     string
		wantEqual bool
	}{
		{name: "order of element ids does not matter", ruleA: "R-1", ruleB: "R-1", a: []string{"n1", "n2"}, b: []string{"n2", "n1"}, wantEqual: true},
		{name: "duplicates and whitespace do not matter", ruleA: "R-1", ruleB: " R-1 ", a: []string{"n1", " n1"}, b: []string{"n1"}, wantEqual: true},
		{name: "another rule differs", ruleA: "R-1", ruleB: "R-2", a: []string{"n1"}, b: []string{"n1"}},
		{name: "another element differs", ruleA: "R-1", ruleB: "R-1", a: []string{"n1"}, b: []string{"n2"}},
		{name: "no separator ambiguity", ruleA: "R-1", ruleB: "R-1", a: []string{"ab", "c"}, b: []string{"a", "bc"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fa, fb := Fingerprint(tc.ruleA, tc.a), Fingerprint(tc.ruleB, tc.b)
			assert.Len(t, fa, 32)
			assert.Equal(t, tc.wantEqual, fa == fb)
		})
	}
}

func TestBuildLog(t *testing.T) {
	log := Build(sample(), Options{ToolVersion: "1.2.3", ArtifactURI: "arch/model.sixi.json"})

	assert.Equal(t, "2.1.0", log.Version)
	assert.Equal(t, SchemaURI, log.Schema)
	require.Len(t, log.Runs, 1)
	d := log.Runs[0].Tool.Driver
	assert.Equal(t, "Sixi Assure", d.Name)
	assert.Equal(t, "https://sixi.ai", d.InformationURI)
	assert.Equal(t, "1.2.3", d.Version)

	require.Len(t, d.Rules, 2, "one descriptor per rule id")
	assert.Equal(t, "AI-003", d.Rules[0].ID)
	assert.Equal(t, "LOG-001", d.Rules[1].ID)
	ai := d.Rules[0]
	assert.Equal(t, "High-consequence action without human approval", ai.ShortDescription.Text)
	assert.Contains(t, ai.Help.Text, "Remediation: Insert a human approval step.")
	assert.Contains(t, ai.Help.Text, "AIACT:2024/1689:Art14")
	assert.Contains(t, ai.Help.Text, "FINMA:08/2024:Governance")
	assert.Subset(t, ai.Properties.Tags, []string{"security", "pack:ai", "AIACT:2024/1689:Art14", "FINMA:08/2024:Governance"})
	assert.Equal(t, "8.0", ai.Properties.SecuritySeverity)
	assert.Equal(t, "error", ai.DefaultConfiguration.Level)
	assert.Contains(t, d.Rules[1].Help.Text, "no clause", "a rule without citations says so, it invents none")

	res := log.Runs[0].Results
	require.Len(t, res, 3)
	tests := []struct {
		name       string
		r          Result
		ruleIndex  int
		level      string
		msgHas     []string
		elements   []string
		suppressed bool
	}{
		{name: "high finding", r: res[0], ruleIndex: 0, level: "error",
			msgHas: []string{"Operations agent", "AIACT:2024/1689:Art14", "FINMA:08/2024:Governance"}, elements: []string{"e_agent_ledger"}},
		{name: "medium finding without citations", r: res[1], ruleIndex: 1, level: "warning",
			msgHas: []string{"Nothing ships logs.", "Cites: no clause."}, elements: []string{"n2", "n1"}},
		{name: "decided finding is suppressed", r: res[2], ruleIndex: 0, level: "error",
			msgHas: []string{"Second occurrence."}, elements: []string{"e2"}, suppressed: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.ruleIndex, tc.r.RuleIndex)
			assert.Equal(t, d.Rules[tc.ruleIndex].ID, tc.r.RuleID)
			assert.Equal(t, tc.level, tc.r.Level)
			for _, s := range tc.msgHas {
				assert.Contains(t, tc.r.Message.Text, s)
			}
			require.Len(t, tc.r.Locations, 1)
			loc := tc.r.Locations[0]
			assert.Equal(t, "arch/model.sixi.json", loc.PhysicalLocation.ArtifactLocation.URI)
			assert.Equal(t, 1, loc.PhysicalLocation.Region.StartLine)
			names := []string{}
			for _, l := range loc.LogicalLocations {
				names = append(names, l.Name)
			}
			assert.Equal(t, tc.elements, names)
			assert.Equal(t, Fingerprint(tc.r.RuleID, tc.elements), tc.r.PartialFingerprints[FingerprintKey])
			assert.Equal(t, tc.suppressed, len(tc.r.Suppressions) > 0)
		})
	}
}

func TestBuildUnknownClauseIsNotInvented(t *testing.T) {
	known := func(id string) bool { return id == "AIACT:2024/1689:Art14" }
	log := Build(sample()[:1], Options{ArtifactURI: "m.json", ClauseKnown: known})
	r := log.Runs[0].Results[0]
	assert.Contains(t, r.Message.Text, "AIACT:2024/1689:Art14,")
	assert.Contains(t, r.Message.Text, "FINMA:08/2024:Governance (no clause found)")
	assert.Contains(t, log.Runs[0].Tool.Driver.Rules[0].Help.Text, "FINMA:08/2024:Governance (no clause found)")
	assert.Equal(t, []string{"AIACT:2024/1689:Art14", "FINMA:08/2024:Governance"}, r.Properties.Clauses,
		"the ids the rule cited are kept as they are")
}

func TestBuildPerFindingArtifactAndLine(t *testing.T) {
	log := Build([]Finding{{RuleID: "R-1", Severity: "low", ArtifactURI: "b.json", Line: 7}}, Options{ArtifactURI: "a.json"})
	loc := log.Runs[0].Results[0].Locations[0].PhysicalLocation
	assert.Equal(t, "b.json", loc.ArtifactLocation.URI)
	assert.Equal(t, 7, loc.Region.StartLine)
	assert.Equal(t, "R-1", log.Runs[0].Tool.Driver.Rules[0].ShortDescription.Text, "no title → the rule id")
}

func TestBuildEmptyIsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Build(nil, Options{ArtifactURI: "m.json"}).Write(&buf))
	var doc map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	runs := doc["runs"].([]any)
	run := runs[0].(map[string]any)
	assert.Equal(t, []any{}, run["results"], "results is an empty array, never null")
	assert.Equal(t, []any{}, run["tool"].(map[string]any)["driver"].(map[string]any)["rules"])
}

func TestWriteShape(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, Build(sample(), Options{ToolVersion: "v", ArtifactURI: "m.json"}).Write(&buf))
	out := buf.String()
	for _, key := range []string{`"$schema"`, `"ruleId"`, `"partialFingerprints"`, `"logicalLocations"`,
		`"artifactLocation"`, `"shortDescription"`, `"security-severity"`, `"informationUri"`} {
		assert.Contains(t, out, key)
	}
	assert.NotContains(t, out, "\\u003c", "HTML is not escaped into unicode sequences")
}

func TestControlCharactersAreStripped(t *testing.T) {
	log := Build([]Finding{{RuleID: "R-1\x1b[31m", Severity: "high", Message: "line one\nline two\x07"}}, Options{})
	r := log.Runs[0].Results[0]
	assert.Equal(t, "R-1[31m", r.RuleID)
	assert.NotContains(t, r.Message.Text, "\n")
	assert.NotContains(t, r.Message.Text, "\x07")
}

func TestLineOf(t *testing.T) {
	jsonDoc := "{\n  \"nodes\": [\n    {\"id\": \"n10\"},\n    {\"id\": \"n1\", \"name\": \"x\"}\n  ],\n  \"edges\": [{\"id\":\"e1\",\"from\":\"n1\"}]\n}\n"
	yamlDoc := "nodes:\n  - id: n10\n  - id: n1\n    name: x\n"
	xmlDoc := "<mxfile>\n<mxCell id=\"c7\" value=\"\"/>\n</mxfile>\n"
	tests := []struct {
		name, doc, id string
		want          int
	}{
		{"json node", jsonDoc, "n1", 4},
		{"json prefix does not match", jsonDoc, "n10", 3},
		{"json edge", jsonDoc, "e1", 6},
		{"yaml", yamlDoc, "n1", 3},
		{"xml", xmlDoc, "c7", 2},
		{"absent", jsonDoc, "zz", 0},
		{"empty id", jsonDoc, "", 0},
		{"regexp metacharacters are literal", "{\"id\": \"a.b\"}", "a+b", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, LineOf([]byte(tc.doc), tc.id))
		})
	}
	assert.Equal(t, 6, FirstLine([]byte(jsonDoc), []string{"zz", "e1", "n1"}))
}

func TestSummary(t *testing.T) {
	forbidden := []string{"compliant", "certified", "guarantee", "confirms", "confirmed"}
	tests := []struct {
		name    string
		in      []Finding
		opts    SummaryOptions
		has     []string
		hasNot  []string
		maxRows int
	}{
		{
			name: "counts and table", in: sample(), opts: SummaryOptions{Subject: "arch/model.sixi.json"},
			has: []string{"## Sixi Assure design assessment", "`arch/model.sixi.json`", "**2 open findings**",
				"1 already decided by a reviewer", "| high | 1 |", "| medium | 1 |", "| high | `AI-003` |",
				"`AIACT:2024/1689:Art14`, `FINMA:08/2024:Governance`", "`e_agent_ledger`", "no clause", "assesses", "evidences"},
			hasNot: []string{"Second occurrence", "Gate:"},
		},
		{
			name: "gate refused", in: sample()[:1], opts: SummaryOptions{Gate: &Gate{FailOn: "high"}},
			has: []string{"**Gate: refused** at high or above", "**1 open finding**"},
		},
		{
			name: "gate passed", in: sample()[1:2], opts: SummaryOptions{Gate: &Gate{FailOn: "high", Passed: true}},
			has: []string{"**Gate: passed** (fails on high or above)"},
		},
		{
			name: "no findings", in: nil,
			has: []string{"**0 open findings**", "raised no open finding"}, hasNot: []string{"| Severity |"},
		},
		{
			name: "unknown clause marked", in: sample()[:1],
			opts: SummaryOptions{ClauseKnown: func(id string) bool { return strings.HasPrefix(id, "AIACT") }},
			has:  []string{"`FINMA:08/2024:Governance` (no clause found)"},
		},
		{
			name: "untrusted model text is escaped",
			in: []Finding{{RuleID: "R|1", Severity: "high", Title: "Ping @admins <img src=x> [x](http://evil) | col",
				ElementIDs: []string{"n`1"}}},
			has:    []string{"&#64;admins", "&lt;img src=x&gt;", "\\[x\\]\\(http&#58;//evil\\)", "\\| col", "`R\\|1`", "`n'1`"},
			hasNot: []string{"@admins", "<img", "[x](http"},
		},
		{
			name: "rows capped", in: []Finding{{RuleID: "A", Severity: "low"}, {RuleID: "B", Severity: "critical"}, {RuleID: "C", Severity: "low"}},
			opts: SummaryOptions{MaxRows: 2}, has: []string{"| critical | `B` |", "and 1 more finding"}, hasNot: []string{"`C`"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := Summary(tc.in, tc.opts)
			for _, s := range tc.has {
				assert.Contains(t, out, s)
			}
			for _, s := range tc.hasNot {
				assert.NotContains(t, out, s)
			}
			lower := strings.ToLower(out)
			for _, w := range forbidden {
				assert.NotContains(t, lower, w, "wording rule (CLAUDE.md §1.5)")
			}
		})
	}
}

func TestHelpWording(t *testing.T) {
	log := Build(sample(), Options{})
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		lower := strings.ToLower(r.Help.Text + r.Help.Markdown)
		for _, w := range []string{"compliant", "certified", "guarantee", "confirms"} {
			assert.NotContains(t, lower, w)
		}
	}
}

func TestSummaryBreaksBareURLAutolinks(t *testing.T) {
	tests := []struct {
		name, title string
		has, hasNot []string
	}{
		{name: "https", title: "see https://x.y/login now", has: []string{"https&#58;//x.y/login"}, hasNot: []string{"https://", "://x.y"}},
		{name: "http upper", title: "HTTP://x.y", has: []string{"HTTP&#58;//x.y"}, hasNot: []string{"://"}},
		{name: "www", title: "visit www.x.y today", has: []string{"www&#46;x.y"}, hasNot: []string{"www.x.y"}},
		{name: "WWW mixed case", title: "Www.x.y", has: []string{"Www&#46;x.y"}, hasNot: []string{"Www.x.y"}},
		{name: "ordinary dots stay readable", title: "Agent writes ledger. No approval.", has: []string{"Agent writes ledger. No approval."}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := Summary([]Finding{{RuleID: "R-1", Severity: "high", Title: tc.title}}, SummaryOptions{})
			for _, s := range tc.has {
				assert.Contains(t, out, s)
			}
			for _, s := range tc.hasNot {
				assert.NotContains(t, out, s)
			}
		})
	}
}

func TestMDCodeStripsLineBreaks(t *testing.T) {
	tests := []struct{ in, want string }{
		{"models/a.json", "models/a.json"},
		{"a`b|c", "a'b\\|c"},
		{"x.json\n## Injected\n[click](https://evil)", "x.json ## Injected [click](https://evil)"},
		{"a\r\x1b[31mb", "a [31mb"},
	}
	for _, tc := range tests {
		got := MDCode(tc.in)
		assert.Equal(t, tc.want, got)
		assert.NotContains(t, got, "\n")
		assert.NotContains(t, got, "\r")
	}
}

func TestResultMessageEscapesSARIFLinks(t *testing.T) {
	log := Build([]Finding{{RuleID: "R-1", Severity: "high", Message: `Click [here](1) or \[x\]`,
		Citations: []string{"AIACT:2024/1689:Art14"}}}, Options{})
	got := log.Runs[0].Results[0].Message.Text
	assert.Equal(t, `Click \[here\](1) or \\\[x\\\] Cites: AIACT:2024/1689:Art14.`, got)
	assert.NotContains(t, got, " [here]")
}

// ADR-095: a rule's documentation references reach result.properties.references and the rule's help as documentation,
// never as a clause; a reference without an https url or a title is dropped.
func TestBuildCarriesTheRulesReferences(t *testing.T) {
	spec := Reference{Kind: "document", Title: "MCP 2026-07-28 Authorization: Token Handling",
		URL: "https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/x.mdx", FetchedAt: "2026-10-01"}
	tests := []struct {
		name string
		refs []Reference
		want []Reference
	}{
		{name: "none", refs: nil, want: nil},
		{name: "one document", refs: []Reference{spec}, want: []Reference{spec}},
		{name: "kind defaults to document", refs: []Reference{{Title: spec.Title, URL: spec.URL, FetchedAt: spec.FetchedAt}}, want: []Reference{spec}},
		{name: "a non-https url is dropped", refs: []Reference{spec, {Kind: "document", Title: "x", URL: "javascript:alert(1)", FetchedAt: "2026-10-01"}}, want: []Reference{spec}},
		{name: "an untitled reference is dropped", refs: []Reference{{Kind: "document", URL: spec.URL}}, want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log := Build([]Finding{{RuleID: "MCP-003", Pack: "mcp", Severity: "high", Title: "Token passthrough",
				Message: "m", Citations: []string{"OWASP:AgenticTop10:ASI03"}, ElementIDs: []string{"e1"}, References: tc.refs}}, Options{})
			res := log.Runs[0].Results[0]
			assert.Equal(t, tc.want, res.Properties.References)
			assert.Equal(t, []string{"OWASP:AgenticTop10:ASI03"}, res.Properties.Clauses, "a reference is never a clause")
			help := log.Runs[0].Tool.Driver.Rules[0].Help
			if tc.want == nil {
				assert.NotContains(t, help.Text, "Documentation")
				return
			}
			assert.Contains(t, help.Text, "Documentation (not a clause): "+spec.Title+" <"+spec.URL+"> (fetched 2026-10-01)")
			assert.Contains(t, help.Markdown, "**Documentation (not a clause):**")
			raw, err := json.Marshal(log)
			require.NoError(t, err)
			assert.Contains(t, string(raw), `"references":[{"kind":"document"`)
		})
	}
}
