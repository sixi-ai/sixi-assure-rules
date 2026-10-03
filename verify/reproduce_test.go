package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/rules"
)

const tinyPack = `pack: tiny
version: 0.1.0
rules:
  - id: TNY-001
    title: Public app without a WAF
    scope: node
    severity: high
    condition: n.type == "app" && attr(n, "exposure", "") == "public" && !attr(n, "waf", false)
    message: "{{n.name}} is public without a WAF"
    clauses: ["FINMA:2023/1:Rz64"]
    remediation: Put a WAF in front of it.
`

const tinyModel = `{"id":"arch_t","tenant_id":"t","name":"T","version":2,"attrs":{},"groups":[],
"nodes":[{"id":"n_web","type":"app","name":"Web","attrs":{"exposure":"public","waf":false}},
{"id":"n_shop","type":"app","name":"Shop","attrs":{"exposure":"public"}},
{"id":"n_api","type":"app","name":"API","attrs":{"exposure":"private"}}],"edges":[],"findings":[],"evidence":[]}`

// tinyReport writes packs/tiny.yaml and report.json (the rules' own results, the snapshot and the
// pack hash) into a temporary directory; mutate edits the report before it is written.
func tinyReport(t *testing.T, mutate func(doc map[string]any)) (dir string) {
	t.Helper()
	dir = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "packs"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packs", "tiny.yaml"), []byte(tinyPack), 0o600))
	cat, err := rules.ParsePacks([]rules.PackSource{{Name: "tiny.yaml", Data: []byte(tinyPack)}}, rules.LoadOptions{CostLimit: rules.DefaultCostLimit})
	require.NoError(t, err)
	var arch model.Architecture
	require.NoError(t, json.Unmarshal([]byte(tinyModel), &arch))
	snap, err := model.Canonical(&arch)
	require.NoError(t, err)
	found, err := rules.New(cat, nil).Evaluate(context.Background(), &arch, rules.Policy{})
	require.NoError(t, err)
	require.Len(t, found, 2)
	findings := make([]map[string]any, 0, len(found))
	for _, f := range found {
		els := []map[string]any{}
		for _, id := range f.IDs {
			els = append(els, map[string]any{"id": id})
		}
		findings = append(findings, map[string]any{"rule_id": f.RuleID, "pack": f.Pack, "status": "open", "elements": els})
	}
	doc := map[string]any{
		"schema": "sixi-assure/assurance-report/v1", "kind": "assurance_report", "generated_at": "2026-10-01T12:00:00Z",
		"architecture":  map[string]any{"id": "arch_t", "version": 2, "hash": model.HashBytes(snap)},
		"snapshot_hash": model.HashBytes(snap), "pack_hash": cat.Hash(), "pack_hash_format": rules.PackHashFormat,
		"rule_packs": []map[string]any{{"pack": "tiny", "version": "0.1.0", "hash": cat.Packs()[0].Hash(), "rules": 1}},
		"regimes":    []string{}, "summary": map[string]any{"accepted_risks": 0}, "findings": findings,
		"snapshot": json.RawMessage(snap),
	}
	if mutate != nil {
		mutate(doc)
	}
	writeJSON(t, filepath.Join(dir, "report.json"), doc)
	return dir
}

func TestReproduceReport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		mutate    func(doc map[string]any)
		editPack  bool
		allow     bool
		check     string
		want      Status
		contain   string
		missing   int
		extra     int
		wantRerun bool
	}{
		{name: "reproduced", check: "findings", want: Pass, wantRerun: true},
		{name: "a finding the rules do not produce", mutate: func(d map[string]any) {
			d["findings"] = append(d["findings"].([]map[string]any), map[string]any{"rule_id": "TNY-001", "elements": []map[string]any{{"id": "n_api"}}})
		}, check: "findings", want: Fail, extra: 1, wantRerun: true},
		{name: "a finding left out", mutate: func(d map[string]any) { d["findings"] = d["findings"].([]map[string]any)[:1] },
			check: "findings", want: Fail, missing: 1, wantRerun: true},
		{name: "pack changed: refused", editPack: true, check: "pack hash", want: Fail, contain: "refused"},
		{name: "pack changed: allowed", editPack: true, allow: true, check: "pack hash", want: Flag, contain: "tiny: content differs", wantRerun: true},
		{name: "pack hash not present", mutate: func(d map[string]any) { delete(d, "pack_hash") }, check: "pack hash", want: NotChecked, contain: NotPresent, wantRerun: true},
		{name: "snapshot changed", mutate: func(d map[string]any) { d["snapshot_hash"] = strings.Repeat("0", 64) }, check: "snapshot hash", want: Fail},
		{name: "snapshot not present", mutate: func(d map[string]any) { delete(d, "snapshot") }, check: "snapshot", want: NotChecked, contain: NotPresent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := tinyReport(t, tc.mutate)
			if tc.editPack {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "packs", "tiny.yaml"), []byte(strings.Replace(tinyPack, "severity: high", "severity: low", 1)), 0o600))
			}
			r, err := Run(context.Background(), Options{Path: filepath.Join(dir, "report.json"), RulesDir: filepath.Join(dir, "packs"), AllowPackMismatch: tc.allow, Now: t0})
			require.NoError(t, err)
			c := checkOf(t, r, SectionReproducibility, tc.check)
			assert.Equal(t, tc.want, c.Status, c.Detail)
			assert.Contains(t, c.Detail, tc.contain)
			require.NotNil(t, r.Reproduction)
			assert.Equal(t, tc.wantRerun, r.Reproduction.Ran)
			assert.Len(t, r.Reproduction.Missing, tc.missing)
			assert.Len(t, r.Reproduction.Extra, tc.extra)
			// A report alone has no chain and no signature beside it: those are not made, never passed.
			assert.Equal(t, NotChecked, checkOf(t, r, SectionChain, "report chain head").Status)
		})
	}
}

func TestReproduceNeedsPacks(t *testing.T) {
	t.Parallel()
	dir := tinyReport(t, nil)
	r, err := Run(context.Background(), Options{Path: filepath.Join(dir, "report.json"), DefaultRulesDir: filepath.Join(dir, "nowhere"), Now: t0})
	require.NoError(t, err)
	c := checkOf(t, r, SectionReproducibility, "rule packs")
	assert.Equal(t, NotChecked, c.Status)
	assert.Contains(t, c.Detail, NotPresent)
	assert.Equal(t, ResultIncomplete, r.Result)

	_, err = Run(context.Background(), Options{Path: filepath.Join(dir, "report.json"), RulesDir: filepath.Join(dir, "nowhere"), Now: t0})
	require.NoError(t, err, "an explicit --rules that is not a directory is a failed check, not an unreadable input")
}

func TestCompareIgnoresElementOrder(t *testing.T) {
	t.Parallel()
	doc := &reportDoc{Findings: []reportFinding{{RuleID: "R-1", Elements: []struct {
		ID string `json:"id"`
	}{{ID: "b"}, {ID: "a"}}}}}
	rep := &Reproduction{}
	compare(rep, doc, []model.Finding{{RuleID: "R-1", IDs: []string{"a", "b"}}, {RuleID: "R-2", IDs: []string{"c"}}})
	assert.Equal(t, []RuleElement{{RuleID: "R-1", Elements: []string{"a", "b"}}}, rep.Matched)
	assert.Equal(t, []RuleElement{{RuleID: "R-2", Elements: []string{"c"}}}, rep.Missing)
	assert.Empty(t, rep.Extra)
}

func TestAdvisories(t *testing.T) {
	t.Parallel()
	dir := tinyReport(t, nil)
	list := func(advisories string) string {
		p := filepath.Join(t.TempDir(), "advisories.json")
		require.NoError(t, os.WriteFile(p, []byte(`{"schema":"sixi-assure/rule-advisories/v1","updated":"2026-10-01","signature":null,"advisories":[`+advisories+`]}`), 0o600))
		return p
	}
	hit := `{"advisory_id":"SAA-2026-009","pack":"tiny","pack_version":"0.1.0","affected_rules":["TNY-001","TNY-002"],"nature":"false_negative","published":"2026-10-01","summary":"x","replacement_pack_version":"0.1.1"}`
	miss := `{"advisory_id":"SAA-2026-010","pack":"tiny","pack_version":"0.0.9","affected_rules":["TNY-001"],"nature":"wrong_citation","published":"2026-10-01","summary":"x","replacement_pack_version":null}`
	tests := []struct {
		name  string
		file  string
		check string
		want  Status
		hits  int
	}{
		{name: "hit", file: list(hit + "," + miss), check: "SAA-2026-009", want: Flag, hits: 1},
		{name: "no hit", file: list(miss), check: "advisories", want: Pass},
		{name: "empty list", file: list(""), check: "advisories", want: Pass},
	}
	for _, tc := range tests {
		r, err := Run(context.Background(), Options{Path: filepath.Join(dir, "report.json"), RulesDir: filepath.Join(dir, "packs"), AdvisoriesFile: tc.file, Now: t0})
		require.NoError(t, err, tc.name)
		c := checkOf(t, r, SectionAdvisories, tc.check)
		assert.Equal(t, tc.want, c.Status, "%s: %s", tc.name, c.Detail)
		require.Len(t, r.Advisories, tc.hits, tc.name)
		if tc.hits > 0 {
			assert.Equal(t, []string{"TNY-001"}, r.Advisories[0].RulesWithFindings)
			assert.Equal(t, []string{"TNY-002"}, r.Advisories[0].RulesSilent)
			assert.True(t, r.OK(), "an advisory flags; it does not make a hash wrong")
		}
		assert.Equal(t, Info, checkOf(t, r, SectionAdvisories, "advisory list").Status, "an unsigned list informs")
	}
}

// A snapshot recorded at an older schema is upgraded on read before the re-run (docs/18 D1), so a
// report exported at 1.0 still reproduces; a snapshot from a schema newer than the verifier is a
// failed re-run, never a guess.
func TestReproduceUpgradesTheSnapshot(t *testing.T) {
	t.Parallel()
	withVersion := func(version string) func(doc map[string]any) {
		return func(doc map[string]any) {
			var snap map[string]any
			require.NoError(t, json.Unmarshal(doc["snapshot"].(json.RawMessage), &snap))
			snap["schema_version"] = version
			// The 1.0 shape of authn (one value) is read too.
			snap["nodes"].([]any)[0].(map[string]any)["attrs"].(map[string]any)["authn"] = "oidc"
			raw, err := json.Marshal(snap)
			require.NoError(t, err)
			canon, err := model.CanonicalJSON(raw)
			require.NoError(t, err)
			doc["snapshot"] = json.RawMessage(canon)
			doc["snapshot_hash"] = model.HashBytes(canon)
		}
	}
	for _, tc := range []struct {
		version string
		check   string
		want    Status
		note    bool
	}{
		{"1.0", "findings", Pass, true},
		{"0.9", "findings", Pass, true},
		{model.CurrentSchemaVersion, "findings", Pass, false},
		{"9.0", "re-run", Fail, false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			dir := tinyReport(t, withVersion(tc.version))
			r, err := Run(context.Background(), Options{Path: filepath.Join(dir, "report.json"), RulesDir: filepath.Join(dir, "packs"), Now: t0})
			require.NoError(t, err)
			c := checkOf(t, r, SectionReproducibility, tc.check)
			assert.Equal(t, tc.want, c.Status, c.Detail)
			require.NotNil(t, r.Reproduction)
			upgraded := false
			for _, n := range r.Reproduction.Notes {
				upgraded = upgraded || strings.Contains(n, "upgraded on read to "+model.CurrentSchemaVersion)
			}
			assert.Equal(t, tc.note, upgraded, "the report says the snapshot was upgraded")
		})
	}
}
