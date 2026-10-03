package verify

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// sampleBundle writes a small reviewer bundle with the members the sample reads and a manifest
// listing them, and returns its directory and the members.
func sampleBundle(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	members := map[string]any{
		MemberPopulation: map[string]any{"schema": "sixi-assure/bundle-population/v1", "arch_id": "arch_s", "version": 3,
			"obligations": []map[string]any{
				{"clause_id": "AIACT:2024/1689:Art50(2)", "regime": "AIACT", "status": "evidenced", "latest_record_id": "ev_002",
					"latest_record_hash": "h2", "decision": "evidenced", "freshness": "fresh"},
				{"clause_id": "DORA:2022/2554:Art9", "regime": "DORA", "status": "open", "freshness": "none"},
				{"clause_id": "DORA:2022/2554:Art24", "regime": "DORA", "status": "evidenced", "latest_record_id": "ev_003",
					"latest_record_hash": "h3", "decision": "evidenced", "freshness": "fresh"},
				{"clause_id": "GDPR:Art32", "regime": "GDPR", "status": "not_checked", "freshness": "none"},
				{"clause_id": "FINMA:08/2024:Inventory", "regime": "FINMA", "status": "checked", "freshness": "none"},
			}},
		MemberReport: map[string]any{"schema": "sixi-assure/assurance-report/v1", "kind": "assurance_report",
			"architecture":  map[string]any{"id": "arch_s", "version": 3, "hash": "modelhash", "ai_act_tier": "limited"},
			"snapshot_hash": "snaphash", "chain_head": "headhash",
			"findings": []map[string]any{
				{"id": "f1", "rule_id": "DORA-001", "severity": "high", "status": "open", "elements": []map[string]any{{"id": "n_b"}, {"id": "n_a"}},
					"clauses": []map[string]any{{"id": "DORA:2022/2554:Art9"}}},
				{"id": "f2", "rule_id": "DORA-002", "severity": "medium", "status": "open", "elements": []map[string]any{{"id": "n_c"}},
					"clauses": []map[string]any{{"id": "DORA:2022/2554:Art9"}, {"id": "DORA:2022/2554:Art9"}}},
			},
			"accepted_risks": []map[string]any{}},
		MemberCustody: map[string]any{"records": []map[string]any{{"record_id": "ev_002", "artefact_hash": "art2", "location": "dms://42",
			"custodian": "not recorded", "system_of_record": "not recorded"}}},
		MemberPatches: map[string]any{"patches": []map[string]any{
			{"version": 2, "actor_id": "u_arch", "before_hash": "a", "after_hash": "b", "accepted_at": "2026-09-30T10:00:00Z"},
			{"version": 3, "actor_id": "u_arch", "before_hash": "b", "after_hash": "c", "accepted_at": "2026-09-30T11:00:00Z"}}},
		MemberReviews: map[string]any{"reviews": []map[string]any{{"id": "rev_1", "version": 3, "decisions": []map[string]any{
			{"id": "dec_1", "user_id": "u_rev", "role": "reviewer", "decision": "approve", "decided_at": "2026-09-30T12:00:00Z"}}}}},
		MemberChain: map[string]any{"events": []map[string]any{
			{"id": "ev_001", "type": "model_created", "actor": "u_arch", "ts": "2026-09-30T09:00:00Z", "payload": map[string]any{}},
			{"id": "ev_002", "type": "evidence_record", "actor": "u_rev", "ts": "2026-09-30T13:00:00Z",
				"payload": map[string]any{"clause_id": "AIACT:2024/1689:Art50(2)"}},
			{"id": "ev_003", "type": "evidence_record", "actor": "u_rev", "ts": "2026-09-30T14:00:00Z",
				"payload": map[string]any{"clause_id": "DORA:2022/2554:Art24", "external_signer": "sixi-scanner (verified)", "signature": "verified"}},
		}},
	}
	dir := t.TempDir()
	raw := map[string][]byte{}
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]map[string]string, 0, len(names))
	for _, name := range names {
		raw[name] = writeJSON(t, filepath.Join(dir, name), members[name])
		items = append(items, map[string]string{"path": name, "sha256": model.HashBytes(raw[name])})
	}
	raw[MemberManifest] = writeJSON(t, filepath.Join(dir, MemberManifest), map[string]any{"bundle_id": "exp_bundle", "arch_id": "arch_s",
		"version": 3, "items": items})
	return dir, raw
}

func sampleOf(t *testing.T, raw []byte) SampleDoc {
	t.Helper()
	var doc SampleDoc
	require.NoError(t, json.Unmarshal(raw, &doc))
	return doc
}

func clauses(doc SampleDoc) []string {
	out := make([]string, 0, len(doc.Rows))
	for _, r := range doc.Rows {
		out = append(out, r.ClauseID)
	}
	return out
}

func TestSampleParamsNormalise(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      SampleParams
		wantErr bool
		size    int
	}{
		{name: "seeded", in: SampleParams{Method: SampleRandomSeeded, Seed: "s", Size: 3}, size: 3},
		{name: "seeded without seed", in: SampleParams{Method: SampleRandomSeeded, Size: 3}, wantErr: true},
		{name: "seeded size zero", in: SampleParams{Method: SampleRandomSeeded, Seed: "s"}, wantErr: true},
		{name: "seeded size too large", in: SampleParams{Method: SampleRandomSeeded, Seed: "s", Size: MaxSampleSize + 1}, wantErr: true},
		{name: "seeded with a list", in: SampleParams{Method: SampleRandomSeeded, Seed: "s", Size: 1, List: []string{"x"}}, wantErr: true},
		{name: "seed with a line break", in: SampleParams{Method: SampleRandomSeeded, Seed: "a\nb", Size: 1}, wantErr: true},
		{name: "list sizes itself", in: SampleParams{Method: SampleList, List: []string{"b", "a", "a", " "}}, size: 2},
		{name: "list with a wrong size", in: SampleParams{Method: SampleList, List: []string{"a"}, Size: 4}, wantErr: true},
		{name: "list with a seed", in: SampleParams{Method: SampleList, List: []string{"a"}, Seed: "s"}, wantErr: true},
		{name: "empty list", in: SampleParams{Method: SampleList}, wantErr: true},
		{name: "unknown method", in: SampleParams{Method: "judgement", Size: 1}, wantErr: true},
	}
	for _, tc := range tests {
		got, err := tc.in.Normalise()
		if tc.wantErr {
			assert.ErrorIs(t, err, ErrSample, tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
		assert.Equal(t, tc.size, got.Size, tc.name)
	}
}

func TestSampleBundle(t *testing.T) {
	t.Parallel()
	dir, raw := sampleBundle(t)
	fsys := os.DirFS(dir)
	tests := []struct {
		name    string
		params  SampleParams
		want    []string
		stratum int
		check   func(t *testing.T, doc SampleDoc)
	}{
		{name: "the whole population when the size covers it", params: SampleParams{Method: SampleRandomSeeded, Seed: "seed-1", Size: 10},
			want: []string{"AIACT:2024/1689:Art50(2)", "DORA:2022/2554:Art24", "DORA:2022/2554:Art9", "FINMA:08/2024:Inventory", "GDPR:Art32"}, stratum: 5},
		{name: "regime stratum", params: SampleParams{Method: SampleRandomSeeded, Seed: "seed-1", Size: 10, Strata: SampleStrata{Regime: []string{"DORA"}}},
			want: []string{"DORA:2022/2554:Art24", "DORA:2022/2554:Art9"}, stratum: 2},
		{name: "severity stratum takes the worst finding", params: SampleParams{Method: SampleRandomSeeded, Seed: "x", Size: 10,
			Strata: SampleStrata{Severity: []string{"high"}}}, want: []string{"DORA:2022/2554:Art9"}, stratum: 1,
			check: func(t *testing.T, doc SampleDoc) {
				row := doc.Rows[0]
				assert.Equal(t, []string{"n_a", "n_b", "n_c"}, row.Elements)
				assert.Len(t, row.Findings, 2, "a finding citing the clause twice is listed once")
				assert.Nil(t, row.Record)
				assert.Equal(t, StratumNone, row.Provenance)
			}},
		{name: "provenance stratum", params: SampleParams{Method: SampleRandomSeeded, Seed: "x", Size: 10,
			Strata: SampleStrata{Provenance: []string{ProvenanceImported}}}, want: []string{"DORA:2022/2554:Art24"}, stratum: 1,
			check: func(t *testing.T, doc SampleDoc) {
				row := doc.Rows[0]
				require.NotNil(t, row.Record)
				assert.Equal(t, "sixi-scanner (verified)", row.Record.Signer)
				assert.Equal(t, "u_rev", row.Recorder)
				assert.True(t, row.Record.OnChain)
			}},
		{name: "tier stratum that excludes everything", params: SampleParams{Method: SampleRandomSeeded, Seed: "x", Size: 10,
			Strata: SampleStrata{Tier: []string{"high"}}}, want: []string{}, stratum: 0},
		{name: "list", params: SampleParams{Method: SampleList, List: []string{"GDPR:Art32", "AIACT:2024/1689:Art50(2)", "NOPE:1"}},
			want: []string{"AIACT:2024/1689:Art50(2)", "GDPR:Art32"}, stratum: 5,
			check: func(t *testing.T, doc SampleDoc) {
				assert.Equal(t, []string{"NOPE:1"}, doc.NotInPop)
				row := doc.Rows[0]
				require.NotNil(t, row.Custody)
				assert.Equal(t, "dms://42", row.Custody.Location)
				assert.Equal(t, ProvenanceDeclared, row.Provenance)
				assert.Equal(t, "limited", row.Tier)
				assert.Equal(t, []int{2, 3}, row.Patches)
				assert.Equal(t, []string{"dec_1"}, row.Decisions)
				assert.Empty(t, row.Key, "a list draws no key")
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := SampleBundle(fsys, tc.params)
			require.NoError(t, err)
			doc := sampleOf(t, out)
			assert.Equal(t, tc.want, clauses(doc))
			assert.Equal(t, tc.stratum, doc.StratumSize)
			assert.Equal(t, len(tc.want), doc.Drawn)
			assert.Equal(t, 5, doc.PopulationSize)
			assert.Equal(t, model.HashBytes(raw[MemberPopulation]), doc.PopulationHash)
			assert.Equal(t, doc.PopulationHash, doc.Hashes.LedgerHash)
			assert.Equal(t, "modelhash", doc.Hashes.ModelHash)
			assert.Equal(t, "headhash", doc.Hashes.ChainHead)
			assert.Equal(t, "exp_bundle", doc.BundleID)
			assert.Len(t, doc.Patches, 2)
			if tc.check != nil {
				tc.check(t, doc)
			}
			again, err := SampleBundle(fsys, tc.params)
			require.NoError(t, err)
			assert.Equal(t, out, again, "the same input draws the same bytes")
			assert.NotContains(t, string(out), "drawn_at", "sample.json carries no time")
		})
	}
}

// A row lists the accepted patches that touched one of its elements when patches.json states the
// elements each patch touched (docs/18 F2); otherwise every accepted patch, and the sheet says so.
func TestSamplePatchScope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		patches []map[string]any
		scope   string
		rows    map[string][]int // clause id → accepted_patch_versions
		// rowScope is each row's patch_scope (clause id → scope).
		rowScope map[string]string
	}{
		{name: "patches.json without element ids", scope: PatchScopeArchitecture,
			patches: []map[string]any{
				{"version": 2, "actor_id": "u", "before_hash": "a", "after_hash": "b", "accepted_at": "2026-09-30T10:00:00Z"},
				{"version": 3, "actor_id": "u", "before_hash": "b", "after_hash": "c", "accepted_at": "2026-09-30T11:00:00Z"}},
			rows:     map[string][]int{"DORA:2022/2554:Art9": {2, 3}, "GDPR:Art32": {2, 3}},
			rowScope: map[string]string{"DORA:2022/2554:Art9": PatchScopeArchitecture, "GDPR:Art32": PatchScopeArchitecture}},
		{name: "patches.json with element ids", scope: PatchScopeElement,
			patches: []map[string]any{
				{"version": 2, "actor_id": "u", "before_hash": "a", "after_hash": "b", "accepted_at": "2026-09-30T10:00:00Z", "element_ids": []string{"n_z"}},
				{"version": 3, "actor_id": "u", "before_hash": "b", "after_hash": "c", "accepted_at": "2026-09-30T11:00:00Z", "element_ids": []string{"n_c", "n_c", "n_y"}},
				{"version": 4, "actor_id": "u", "before_hash": "c", "after_hash": "d", "accepted_at": "2026-09-30T12:00:00Z", "element_ids": []string{}}},
			// Review 3b finding 8: GDPR:Art32 names no element (no open finding cites it), so it lists every
			// accepted patch at architecture scope instead of none: the patch that fixed its last finding stays on it.
			rows:     map[string][]int{"DORA:2022/2554:Art9": {3}, "GDPR:Art32": {2, 3, 4}},
			rowScope: map[string]string{"DORA:2022/2554:Art9": PatchScopeElement, "GDPR:Art32": PatchScopeArchitecture}},
		{name: "one record without element ids widens the sheet", scope: PatchScopeArchitecture,
			patches: []map[string]any{
				{"version": 2, "actor_id": "u", "before_hash": "a", "after_hash": "b", "accepted_at": "2026-09-30T10:00:00Z", "element_ids": []string{"n_a"}},
				{"version": 3, "actor_id": "u", "before_hash": "b", "after_hash": "c", "accepted_at": "2026-09-30T11:00:00Z"}},
			rows:     map[string][]int{"DORA:2022/2554:Art9": {2, 3}, "GDPR:Art32": {2, 3}},
			rowScope: map[string]string{"DORA:2022/2554:Art9": PatchScopeArchitecture, "GDPR:Art32": PatchScopeArchitecture}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := sampleBundle(t)
			writeJSON(t, filepath.Join(dir, MemberPatches), map[string]any{"patches": tc.patches})
			require.NoError(t, os.Remove(filepath.Join(dir, MemberManifest))) // the edited member no longer matches it
			out, err := SampleBundle(os.DirFS(dir), SampleParams{Method: SampleList, List: []string{"DORA:2022/2554:Art9", "GDPR:Art32"}})
			require.NoError(t, err)
			doc := sampleOf(t, out)
			assert.Equal(t, tc.scope, doc.PatchScope)
			assert.Contains(t, doc.Note, "patch_scope")
			require.Len(t, doc.Rows, len(tc.rows))
			for _, row := range doc.Rows {
				assert.Equal(t, tc.rows[row.ClauseID], row.Patches, row.ClauseID)
				assert.Equal(t, tc.rowScope[row.ClauseID], row.PatchScope, row.ClauseID)
				assert.Equal(t, []string{"dec_1"}, row.Decisions, "a design-review decision is of a whole version")
			}
		})
	}
}

// The seeded draw takes the smallest keys, and another seed draws another subset.
func TestSampleSeededDraw(t *testing.T) {
	t.Parallel()
	dir, _ := sampleBundle(t)
	draws := map[string]bool{}
	for _, seed := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		out, err := SampleBundle(os.DirFS(dir), SampleParams{Method: SampleRandomSeeded, Seed: seed, Size: 2})
		require.NoError(t, err)
		doc := sampleOf(t, out)
		require.Len(t, doc.Rows, 2)
		keys := []string{}
		for _, r := range doc.Rows {
			assert.Equal(t, drawKey(seed, r.ClauseID, r.Regime), r.Key)
			keys = append(keys, r.Key)
		}
		// No undrawn row has a smaller key than a drawn one.
		var pop samplePopulation
		raw, err := os.ReadFile(filepath.Join(dir, MemberPopulation))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &pop))
		sort.Strings(keys)
		for _, r := range pop.Rows {
			k := drawKey(seed, r.ClauseID, r.Regime)
			if k != keys[0] && k != keys[1] {
				assert.Greater(t, k, keys[1], "seed %s: an undrawn row has a smaller key", seed)
			}
		}
		draws[clauses(doc)[0]+clauses(doc)[1]] = true
	}
	assert.Greater(t, len(draws), 1, "different seeds draw different subsets")
}

// A member that does not hash as the manifest lists is refused; so is a bundle without a population.
func TestSampleBundleRefusesTamperedMembers(t *testing.T) {
	t.Parallel()
	dir, _ := sampleBundle(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, MemberPopulation), []byte(`{"obligations":[]}`), 0o600))
	_, err := SampleBundle(os.DirFS(dir), SampleParams{Method: SampleRandomSeeded, Seed: "s", Size: 1})
	require.ErrorIs(t, err, ErrSample)
	assert.Contains(t, err.Error(), "the manifest lists")

	empty := t.TempDir()
	_, err = SampleBundle(os.DirFS(empty), SampleParams{Method: SampleRandomSeeded, Seed: "s", Size: 1})
	require.ErrorIs(t, err, ErrSample)
	assert.Contains(t, err.Error(), "population.json")
}

// The zip in memory (the server) and the file on disk (assure sample) draw the same bytes.
func TestSampleZipAndFileAgree(t *testing.T) {
	t.Parallel()
	_, raw := sampleBundle(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		w, err := zw.Create("exp_bundle/" + name)
		require.NoError(t, err)
		_, err = w.Write(raw[name])
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	p := SampleParams{Method: SampleRandomSeeded, Seed: "same", Size: 3, Strata: SampleStrata{Regime: []string{"DORA", "GDPR", "AIACT"}}}
	fromZip, err := SampleZip(buf.Bytes(), p)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "bundle.zip")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	fromFile, err := SampleFile(path, p)
	require.NoError(t, err)
	assert.Equal(t, fromZip, fromFile)

	_, err = SampleZip([]byte("not a zip"), p)
	require.ErrorIs(t, err, ErrSample)
}
