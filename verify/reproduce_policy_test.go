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

// A reviewer bundle carries the organisation's policy at bundle time (policy.json, docs/18 A5):
// its allowed regions and its enabled-regime filter. The re-run reads it, so a bundle whose findings
// depend on either reproduces; without it the policy table's defaults and the model's own regimes
// are used and the output says so.

const regionPack = `pack: region
version: 0.1.0
rules:
  - id: REG-001
    title: Personal data outside the allowed regions
    scope: node
    severity: high
    condition: 'attr(n, "data_class", "") == "pii" && !(attr(n, "region", "") in tenant.allowed_regions)'
    message: "{{n.name}} keeps personal data outside the allowed regions"
    clauses: ["FADP:2020:Art16"]
    remediation: Move it.
`

const doraPack = `pack: dorax
version: 0.1.0
regimes: [DORA]
rules:
  - id: DRX-001
    title: Every app is listed
    scope: node
    severity: low
    condition: n.type == "app"
    message: "{{n.name}} is an app"
    clauses: ["DORA:2022/2554:Art28(3)"]
    remediation: List it.
`

const policyModel = `{"id":"arch_p","tenant_id":"t","name":"P","version":1,"attrs":{"regimes":["DORA","GDPR"]},"groups":[],
"nodes":[{"id":"n_eu","type":"app","name":"EU","attrs":{"data_class":"pii","region":"eu-west"}},
{"id":"n_us","type":"app","name":"US","attrs":{"data_class":"pii","region":"us-east"}}],"edges":[],"findings":[],"evidence":[]}`

// policyBundle writes a bundle directory (no manifest: every member is read) whose report holds
// the findings the rules produce under pol, with policy.json when withPolicy.
func policyBundle(t *testing.T, pol rules.Policy, policyJSON string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "rules"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules", "region.yaml"), []byte(regionPack), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules", "dorax.yaml"), []byte(doraPack), 0o600))
	cat, err := rules.ParsePacks([]rules.PackSource{{Name: "region.yaml", Data: []byte(regionPack)}, {Name: "dorax.yaml", Data: []byte(doraPack)}},
		rules.LoadOptions{CostLimit: rules.DefaultCostLimit})
	require.NoError(t, err)
	var arch model.Architecture
	require.NoError(t, json.Unmarshal([]byte(policyModel), &arch))
	snap, err := model.Canonical(&arch)
	require.NoError(t, err)
	found, err := rules.New(cat, nil).Evaluate(context.Background(), &arch, pol)
	require.NoError(t, err)
	findings := make([]map[string]any, 0, len(found))
	for _, f := range found {
		els := []map[string]any{}
		for _, id := range f.IDs {
			els = append(els, map[string]any{"id": id})
		}
		findings = append(findings, map[string]any{"rule_id": f.RuleID, "pack": f.Pack, "status": "open", "elements": els})
	}
	writeJSON(t, filepath.Join(dir, MemberReport), map[string]any{
		"schema": "sixi-assure/assurance-report/v1", "kind": "assurance_report", "generated_at": "2026-10-01T12:00:00Z",
		"architecture":  map[string]any{"id": "arch_p", "version": 1, "hash": model.HashBytes(snap)},
		"snapshot_hash": model.HashBytes(snap), "pack_hash": cat.Hash(), "pack_hash_format": rules.PackHashFormat,
		"regimes": []string{}, "summary": map[string]any{"accepted_risks": 0}, "findings": findings,
		"snapshot": json.RawMessage(snap),
	})
	if policyJSON != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, MemberPolicy), []byte(policyJSON), 0o600))
	}
	return dir
}

func TestReproduceReadsTheBundlePolicy(t *testing.T) {
	t.Parallel()
	orgPolicy := rules.Policy{AllowedRegions: []string{"eu-west"}, Regimes: []string{"GDPR"}}
	const policyJSON = `{"schema":"sixi-assure/bundle-policy/v1","allowed_regions":["eu-west"],"allowed_regions_from":"organisation",
"regime_filter":["GDPR"],"regimes":["GDPR"]}`
	tests := []struct {
		name     string
		ranUnder rules.Policy
		policy   string
		want     Status
		missing  int
		matched  int
		regimes  []string
		note     string
	}{
		{name: "the organisation's policy, carried", ranUnder: orgPolicy, policy: policyJSON, want: Pass, matched: 1,
			regimes: []string{"GDPR"}, note: "from the bundle's policy.json (organisation)"},
		{name: "the organisation's policy, not carried: the defaults find more", ranUnder: orgPolicy, want: Fail, missing: 3, matched: 1,
			regimes: []string{"DORA", "GDPR"}, note: "the organisation's setting is " + NotPresent},
		{name: "regions only, no filter", ranUnder: rules.Policy{AllowedRegions: []string{"eu-west"}, Regimes: []string{"DORA", "GDPR"}},
			policy: `{"allowed_regions":["eu-west"],"allowed_regions_from":"deployment default","regime_filter":[]}`, want: Pass, matched: 3,
			regimes: []string{"DORA", "GDPR"}, note: "names no filter"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := policyBundle(t, tc.ranUnder, tc.policy)
			r, err := Run(context.Background(), Options{Path: dir, Now: t0})
			require.NoError(t, err)
			c := checkOf(t, r, SectionReproducibility, "findings")
			assert.Equal(t, tc.want, c.Status, c.Detail)
			require.NotNil(t, r.Reproduction)
			assert.Len(t, r.Reproduction.Missing, tc.missing)
			assert.Len(t, r.Reproduction.Matched, tc.matched)
			assert.Equal(t, tc.regimes, r.Reproduction.Regimes)
			assert.Contains(t, strings.Join(r.Reproduction.Notes, "\n"), tc.note)
		})
	}
}

func TestReproduceRefusesAPolicyThatDoesNotParse(t *testing.T) {
	t.Parallel()
	dir := policyBundle(t, rules.Policy{Regimes: []string{"DORA", "GDPR"}}, `{"allowed_regions": "not a list"}`)
	r, err := Run(context.Background(), Options{Path: dir, Now: t0})
	require.NoError(t, err)
	assert.Equal(t, Fail, checkOf(t, r, SectionReproducibility, MemberPolicy).Status)
	assert.False(t, r.OK())
}
