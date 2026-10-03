package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/rules"
)

// A pack whose only rule reads the `prov` variable: an imported fact past its cadence (ADR-086 §7, PRV-005's clock).
const provPack = `pack: tprv
version: 0.1.0
rules:
  - id: TPV-001
    title: Imported fact past its cadence
    scope: node
    severity: medium
    condition: prov.available && n.id in prov.elements && prov.elements[n.id].expired
    message: "{{n.name}} is past its cadence"
    clauses: ["FINMA:2023/1:Rz64"]
    remediation: Import the source again.
`

// provModel imports n_web from a plan fetched on 2026-01-01 with a 7-day cadence: fresh on 2026-01-02, stale today.
const provModel = `{"schema_version":"` + model.CurrentSchemaVersion + `","id":"arch_t","tenant_id":"t","name":"T","version":2,"attrs":{},"groups":[],
"nodes":[{"id":"n_web","type":"app","name":"Web","layer":"app","source":"declared","attrs":{}}],"edges":[],"findings":[],"evidence":[],
"provenance":{"/nodes/n_web":{"kind":"imported","identifier":"terraform_plan:main","hash":"` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `",
"imported_by":"usr_1","imported_at":"2026-01-01T00:00:00Z","fetched_at":"2026-01-01T00:00:00Z","cadence_days":7,
"last_seen_import":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}`

// packReport writes packs/<name> and a report.json over modelJSON whose findings are empty: what the rules produced
// when the report was generated, while the imported fact was fresh.
func packReport(t *testing.T, name, pack, modelJSON string, mutate func(doc map[string]any)) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "packs"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packs", name), []byte(pack), 0o600))
	cat, err := rules.ParsePacks([]rules.PackSource{{Name: name, Data: []byte(pack)}}, rules.LoadOptions{CostLimit: rules.DefaultCostLimit})
	require.NoError(t, err)
	arch, err := model.ValidateJSON([]byte(modelJSON))
	require.NoError(t, err)
	snap, err := model.Canonical(arch)
	require.NoError(t, err)
	doc := map[string]any{
		"schema": "sixi-assure/assurance-report/v1", "kind": "assurance_report", "generated_at": "2026-01-02T00:00:00Z",
		"architecture":  map[string]any{"id": "arch_t", "version": 2, "hash": model.HashBytes(snap)},
		"snapshot_hash": model.HashBytes(snap), "pack_hash": cat.Hash(), "pack_hash_format": rules.PackHashFormat,
		"rule_packs": []map[string]any{{"pack": "tprv", "version": "0.1.0", "hash": cat.Packs()[0].Hash(), "rules": 1}},
		"regimes":    []string{}, "summary": map[string]any{"accepted_risks": 0}, "findings": []map[string]any{},
		"snapshot": json.RawMessage(snap),
	}
	if mutate != nil {
		mutate(doc)
	}
	writeJSON(t, filepath.Join(dir, "report.json"), doc)
	return dir
}

// ADR-086 §7, docs/18 C5: the verifier pins `prov` to the report's own clock, so a report produced while an imported
// fact was fresh reproduces after its cadence has elapsed; without the pin the re-run would raise a finding the
// signed report never had.
func TestReproducePinsTheProvenanceClock(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		generated string // "" removes generated_at
		want      Status
		note      string
		missing   int
	}{
		{"produced while fresh, verified after the cadence: reproduces", "2026-01-02T00:00:00Z", Pass, "the report's generated_at 2026-01-02T00:00:00Z", 0},
		{"no clock in the report: computed as of now, and it says so", "", Fail, "computed as of now", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := packReport(t, "tprv.yaml", provPack, provModel, func(doc map[string]any) {
				if tc.generated == "" {
					delete(doc, "generated_at")
				} else {
					doc["generated_at"] = tc.generated
				}
			})
			r, err := Run(context.Background(), Options{Path: filepath.Join(dir, "report.json"), RulesDir: filepath.Join(dir, "packs"), Now: t0})
			require.NoError(t, err)
			c := checkOf(t, r, SectionReproducibility, "findings")
			assert.Equal(t, tc.want, c.Status, c.Detail)
			require.NotNil(t, r.Reproduction)
			assert.True(t, r.Reproduction.Ran)
			assert.Empty(t, r.Reproduction.Extra)
			assert.Len(t, r.Reproduction.Missing, tc.missing, "a finding the re-run produces and the report lacks")
			assert.True(t, slices.ContainsFunc(r.Reproduction.Notes, func(n string) bool { return strings.Contains(n, tc.note) }),
				"%v", r.Reproduction.Notes)
		})
	}
}

func TestEvaluationClock(t *testing.T) {
	t.Parallel()
	produced := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	updated := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	bundle := &source{kind: KindBundleDir, fsys: fstest.MapFS{MemberManifest: {Data: []byte(`{"produced_at":"2026-03-04T05:06:07Z"}`)}}}
	lone := &source{kind: KindReport, fsys: fstest.MapFS{MemberManifest: {Data: []byte(`{"produced_at":"2026-03-04T05:06:07Z"}`)}}}
	tests := []struct {
		name string
		src  *source
		doc  *reportDoc
		arch *model.Architecture
		want time.Time
	}{
		{"a bundle's produced_at", bundle, &reportDoc{GeneratedAt: "2026-01-01T00:00:00Z"}, nil, produced},
		{"a lone report's generated_at, never a sibling manifest", lone, &reportDoc{GeneratedAt: "2026-01-01T00:00:00Z"}, nil,
			time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"the snapshot's updated_at", nil, &reportDoc{}, &model.Architecture{UpdatedAt: &updated}, updated},
		{"nothing: the zero time (now)", nil, &reportDoc{}, &model.Architecture{}, time.Time{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, note := evaluationClock(tc.src, tc.doc, tc.arch)
			assert.True(t, tc.want.Equal(got), "%s != %s", got, tc.want)
			assert.NotEmpty(t, note)
		})
	}
}
