package model_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/secretguard"
)

// ADR-086 (docs/02 §Provenance): the sidecar is a root map keyed by id-addressed JSON pointers, server-owned,
// scanned by the secret guard, in the canonical hash from schema 1.1 and resolved by upgrade on read.

var (
	t0      = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	tAccept = time.Date(2026, 9, 2, 9, 30, 0, 0, time.UTC)
)

const hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// provArch is baseArch with n_db imported from a Terraform plan and its encryption attribute declared by hand.
func provArch(t *testing.T) map[string]any {
	t.Helper()
	doc := baseArch(t)
	doc["nodes"].([]any)[1].(map[string]any)["source"] = "declared"
	doc["nodes"].([]any)[1].(map[string]any)["attrs"] = map[string]any{"encryption_key": "cmk"}
	doc["provenance"] = map[string]any{
		"/nodes/n_db": map[string]any{"kind": "imported", "identifier": "terraform_plan:main", "hash": hashA,
			"imported_by": "usr_1", "imported_at": "2026-09-01T08:00:00Z", "fetched_at": "2026-09-01T08:00:00Z",
			"cadence_days": 30, "last_seen_import": hashA},
		"/nodes/n_db/attrs/encryption_key": map[string]any{"kind": "declared", "declared_by": "usr_2",
			"declared_at": "2026-09-01T09:00:00Z"},
	}
	return doc
}

func mustValidate(t *testing.T, doc map[string]any) *model.Architecture {
	t.Helper()
	a, err := model.ValidateJSON(raw(t, doc))
	require.NoError(t, err)
	return a
}

func TestProvenanceSchemaAndInvariants(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(doc map[string]any)
		wantErr string // a problem path; "" = valid
	}{
		{"valid sidecar", func(map[string]any) {}, ""},
		{"no sidecar", func(d map[string]any) { delete(d, "provenance") }, ""},
		{"edge member key", func(d map[string]any) {
			d["provenance"].(map[string]any)["/edges/e1/auth"] = map[string]any{"kind": "declared"}
		}, ""},
		{"root attribute key", func(d map[string]any) {
			d["attrs"] = map[string]any{"owner": "platform"}
			d["provenance"].(map[string]any)["/attrs/owner"] = map[string]any{"kind": "declared"}
		}, ""},
		{"unknown element", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_gone"] = map[string]any{"kind": "declared"}
		}, "/provenance"},
		{"unknown attribute", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_api/attrs/waf"] = map[string]any{"kind": "declared"}
		}, "/provenance"},
		{"layout member is not a fact", func(d map[string]any) {
			d["nodes"].([]any)[0].(map[string]any)["position"] = map[string]any{"x": 1, "y": 2}
			d["provenance"].(map[string]any)["/nodes/n_api/position"] = map[string]any{"kind": "declared"}
		}, "/provenance"},
		{"source is server-written", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_api/source"] = map[string]any{"kind": "imported"}
		}, "/provenance"},
		{"unknown kind", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_api"] = map[string]any{"kind": "verified"}
		}, "/provenance/~1nodes~1n_api/kind"},
		{"stale is not a kind", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_api"] = map[string]any{"kind": "stale"}
		}, "/provenance/~1nodes~1n_api/kind"},
		{"unknown member", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_api"] = map[string]any{"kind": "declared", "note": "x"}
		}, "/provenance/~1nodes~1n_api"},
		{"actor is an id, never an e-mail", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_api"] = map[string]any{"kind": "declared", "declared_by": "ana@example.test"}
		}, "/provenance/~1nodes~1n_api/declared_by"},
		{"hash is a hex SHA-256", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_api"] = map[string]any{"kind": "imported", "hash": "md5:abc"}
		}, "/provenance/~1nodes~1n_api/hash"},
		{"key outside the model", func(d map[string]any) {
			d["provenance"].(map[string]any)["/findings/f1"] = map[string]any{"kind": "declared"}
		}, "/provenance"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := provArch(t)
			tc.mutate(doc)
			_, err := model.ValidateJSON(raw(t, doc))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			var ve *model.ValidationError
			require.ErrorAs(t, err, &ve)
			paths := make([]string, 0, len(ve.Problems))
			for _, p := range ve.Problems {
				paths = append(paths, p.Path)
			}
			assert.Contains(t, paths, tc.wantErr)
		})
	}
}

// ADR-086 §5: the guard scans keys and values; the error names the pointer and the detector, never the value.
func TestProvenanceSecretGuard(t *testing.T) {
	const awsKey = "AKIAIOSFODNN7EXAMPLE"
	tests := []struct {
		name   string
		mutate func(doc map[string]any)
	}{
		{"credential-shaped identifier", func(d map[string]any) {
			e := d["provenance"].(map[string]any)["/nodes/n_db"].(map[string]any)
			e["identifier"] = "s3://plans/" + awsKey
		}},
		{"credential in a version", func(d map[string]any) {
			e := d["provenance"].(map[string]any)["/nodes/n_db"].(map[string]any)
			e["version"] = "ghp_EXAMPLEnotarealtoken0123456789abcdef"
		}},
		{"credential-shaped key", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_db/attrs/"+awsKey] = map[string]any{"kind": "declared"}
		}},
		{"credential after an x_ prefix inside a key", func(d map[string]any) {
			d["provenance"].(map[string]any)["/nodes/n_db/attrs/x_"+awsKey] = map[string]any{"kind": "declared"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := provArch(t)
			tc.mutate(doc)
			_, err := model.ValidateJSON(raw(t, doc))
			require.Error(t, err)
			assert.ErrorIs(t, err, secretguard.ErrSecretDetected)
			var v *secretguard.Violation
			require.ErrorAs(t, err, &v)
			assert.True(t, strings.HasPrefix(v.Finding.Path, "/provenance"), v.Finding.Path)
			if tc.name != "credential-shaped key" {
				// The document walk names a key violation by the key's own pointer (secretguard.walk, ADR-041); the
				// token check names /provenance only, and a value never appears.
				assert.NotContains(t, err.Error(), "EXAMPLE")
			}
		})
	}
}

func TestPatchesCannotWriteProvenance(t *testing.T) {
	a := mustValidate(t, provArch(t))
	tests := []model.PatchOp{
		{Op: "add", Path: "/provenance", Value: json.RawMessage(`{}`)},
		{Op: "add", Path: "/provenance/~1nodes~1n_api", Value: json.RawMessage(`{"kind":"imported"}`)},
		{Op: "replace", Path: "/provenance/~1nodes~1n_db", Value: json.RawMessage(`{"kind":"observed"}`)},
		{Op: "remove", Path: "/provenance/~1nodes~1n_db"},
		{Op: "copy", From: "/provenance/~1nodes~1n_db", Path: "/attrs/x_copy"},
	}
	for _, op := range tests {
		t.Run(op.Op+" "+op.Path, func(t *testing.T) {
			_, err := model.Apply(a, []model.PatchOp{op}, false)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "managed by the server")
		})
	}
}

func TestApplyPrunesRemovedFacts(t *testing.T) {
	a := mustValidate(t, provArch(t))
	tests := []struct {
		name    string
		ops     []model.PatchOp
		gone    []string
		staying []string
	}{
		{"removing an attribute drops its key", []model.PatchOp{{Op: "remove", Path: "/nodes/n_db/attrs/encryption_key"}},
			[]string{"/nodes/n_db/attrs/encryption_key"}, []string{"/nodes/n_db"}},
		{"removing the element drops every key under it", []model.PatchOp{
			{Op: "remove", Path: "/edges/e1"}, {Op: "remove", Path: "/nodes/n_db"}},
			[]string{"/nodes/n_db", "/nodes/n_db/attrs/encryption_key"}, nil},
		{"an unrelated change keeps the sidecar", []model.PatchOp{{Op: "replace", Path: "/nodes/n_api/name", Value: json.RawMessage(`"Edge API"`)}},
			nil, []string{"/nodes/n_db", "/nodes/n_db/attrs/encryption_key"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next, err := model.Apply(a, tc.ops, false)
			require.NoError(t, err)
			for _, k := range tc.gone {
				assert.NotContains(t, next.Provenance, k)
			}
			for _, k := range tc.staying {
				assert.Contains(t, next.Provenance, k)
			}
		})
	}
}

func TestProvenanceOfMostSpecificAndUpgradeOnRead(t *testing.T) {
	doc := provArch(t)
	doc["nodes"] = append(doc["nodes"].([]any),
		map[string]any{"id": "n_legacy", "type": "app", "name": "Legacy", "layer": "app", "source": "declared",
			"external_ref": "azurerm_linux_web_app.legacy", "attrs": map[string]any{}},
		map[string]any{"id": "n_bare", "type": "app", "name": "Bare", "layer": "app", "source": "declared", "attrs": map[string]any{}},
		map[string]any{"id": "n_obs", "type": "app", "name": "Seen", "layer": "app", "source": "observed", "attrs": map[string]any{}},
	)
	doc["edges"] = append(doc["edges"].([]any), map[string]any{"id": "e2", "from": "n_legacy", "to": "n_bare", "kind": "calls",
		"auth": "managed_identity", "encryption": "tls", "attrs": map[string]any{}})
	a := mustValidate(t, doc)
	before, err := json.Marshal(a.Provenance)
	require.NoError(t, err)

	tests := []struct {
		pointer, kind, identifier string
	}{
		{"/nodes/n_db", model.ProvenanceImported, "terraform_plan:main"},
		{"/nodes/n_db/name", model.ProvenanceImported, "terraform_plan:main"},
		{"/nodes/n_db/attrs/encryption_key", model.ProvenanceDeclared, ""},
		{"/nodes/n_api", model.ProvenanceDeclared, ""},
		{"/nodes/n_legacy", model.ProvenanceImported, "azurerm_linux_web_app.legacy"},
		{"/nodes/n_bare/attrs/x", model.ProvenanceImported, model.PreV11Import},
		{"/nodes/n_obs", model.ProvenanceObserved, ""},
		{"/edges/e1", model.ProvenanceDeclared, ""},
		{"/edges/e2/auth", model.ProvenanceImported, "azurerm_linux_web_app.legacy"},
		{"/groups/none", model.ProvenanceDeclared, ""},
	}
	for _, tc := range tests {
		t.Run(tc.pointer, func(t *testing.T) {
			e := a.ProvenanceOf(tc.pointer)
			assert.Equal(t, tc.kind, e.Kind)
			assert.Equal(t, tc.identifier, e.Identifier)
		})
	}
	after, err := json.Marshal(a.Provenance)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after), "upgrade on read resolves without writing")
}

func TestStampPatch(t *testing.T) {
	tests := []struct {
		name     string
		doc      func(t *testing.T) map[string]any
		ops      []model.PatchOp
		declared []string // pointers expected to resolve declared
		stamped  []string // pointers expected stored as declared by usr_actor at tAccept
		imported []string // pointers expected still imported
		noSide   bool     // the model keeps no sidecar
		sources  map[string]string
	}{
		{name: "a patch on an imported fact resets it to declared with the actor", doc: provArch,
			ops:     []model.PatchOp{{Op: "add", Path: "/nodes/n_db/attrs/backup", Value: json.RawMessage(`true`)}},
			stamped: []string{"/nodes/n_db/attrs/backup"}, imported: []string{"/nodes/n_db", "/nodes/n_db/attrs/region"},
			sources: map[string]string{"n_db": model.SourceDeclared}},
		{name: "replacing a member of an imported node", doc: provArch,
			ops:     []model.PatchOp{{Op: "replace", Path: "/nodes/n_db/name", Value: json.RawMessage(`"Ledger"`)}},
			stamped: []string{"/nodes/n_db/name"}, imported: []string{"/nodes/n_db"}},
		{name: "layout never declares a fact", doc: provArch,
			ops:      []model.PatchOp{{Op: "add", Path: "/nodes/n_db/position", Value: json.RawMessage(`{"x":5,"y":6}`)}},
			imported: []string{"/nodes/n_db", "/nodes/n_db/position"}},
		{name: "an added node is declared as a whole", doc: provArch,
			ops: []model.PatchOp{{Op: "add", Path: "/nodes/-", Value: json.RawMessage(
				`{"id":"n_new","type":"app","name":"New","layer":"app","source":"declared","attrs":{}}`)}},
			stamped: []string{"/nodes/n_new"}, sources: map[string]string{"n_new": model.SourceDesign}},
		{name: "editing source never raises a tier", doc: provArch,
			ops:      []model.PatchOp{{Op: "replace", Path: "/nodes/n_api/source", Value: json.RawMessage(`"declared"`)}},
			declared: []string{"/nodes/n_api"}, sources: map[string]string{"n_api": model.SourceDesign}},
		{name: "a model without a sidecar keeps none for declared facts", doc: baseArch,
			ops:    []model.PatchOp{{Op: "add", Path: "/nodes/n_api/attrs/waf", Value: json.RawMessage(`true`)}},
			noSide: true},
		{name: "setting source on a model without a sidecar never raises a tier", doc: baseArch,
			ops:      []model.PatchOp{{Op: "replace", Path: "/nodes/n_api/source", Value: json.RawMessage(`"declared"`)}},
			declared: []string{"/nodes/n_api"}, sources: map[string]string{"n_api": model.SourceDesign}},
		{name: "a node added with source declared is declared", doc: baseArch,
			ops: []model.PatchOp{{Op: "add", Path: "/nodes/-", Value: json.RawMessage(
				`{"id":"n_new","type":"app","name":"New","layer":"app","source":"declared","attrs":{}}`)}},
			stamped: []string{"/nodes/n_new"}, sources: map[string]string{"n_new": model.SourceDesign}},
		{name: "touching a pre-1.1 imported fact creates the sidecar", doc: func(t *testing.T) map[string]any {
			d := baseArch(t)
			d["nodes"].([]any)[1].(map[string]any)["source"] = "declared"
			return d
		}, ops: []model.PatchOp{{Op: "add", Path: "/nodes/n_db/attrs/backup", Value: json.RawMessage(`true`)}},
			stamped: []string{"/nodes/n_db/attrs/backup"}, declared: []string{"/nodes/n_api"}, imported: []string{"/nodes/n_db"},
			sources: map[string]string{"n_db": model.SourceDeclared, "n_api": model.SourceDesign}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prev := mustValidate(t, tc.doc(t))
			next, err := model.Apply(prev, tc.ops, false)
			require.NoError(t, err)
			model.StampPatch(prev, next, "usr_actor", tAccept)
			if tc.noSide {
				assert.Empty(t, next.Provenance)
			}
			for _, p := range tc.declared {
				assert.Equal(t, model.ProvenanceDeclared, next.KindOf(p), p)
			}
			for _, p := range tc.stamped {
				e, stored := next.Provenance[p]
				require.True(t, stored, p)
				assert.Equal(t, model.ProvenanceDeclared, e.Kind, p)
				assert.Equal(t, "usr_actor", e.DeclaredBy, p)
				require.NotNil(t, e.DeclaredAt)
				assert.True(t, e.DeclaredAt.Equal(tAccept))
			}
			for _, p := range tc.imported {
				assert.Equal(t, model.ProvenanceImported, next.KindOf(p), p)
			}
			for id, src := range tc.sources {
				assert.Equal(t, src, next.Node(id).Source, id)
			}
			// The result is a valid model: every key resolves.
			require.NoError(t, model.Validate(next))
		})
	}
}

func TestRecordImportAndStampAccepted(t *testing.T) {
	a := mustValidate(t, baseArch(t))
	src := model.ImportSource{Identifier: "terraform_plan:main", Hash: hashA, FetchedAt: t0, CadenceDays: 30, SignatureVerified: true}
	a.RecordImport(src, a.ElementPointers(), "", t0)
	require.NoError(t, model.Validate(a))
	for _, p := range []string{"/nodes/n_api", "/nodes/n_db", "/edges/e1"} {
		e := a.Provenance[p]
		assert.Equal(t, model.ProvenanceImported, e.Kind)
		assert.Equal(t, "terraform_plan:main", e.Identifier)
		assert.Equal(t, hashA, e.Hash)
		assert.Equal(t, hashA, e.LastSeenImport)
		assert.Equal(t, 30, e.CadenceDays)
		assert.Empty(t, e.ImportedBy, "a preview names no actor")
	}
	assert.Equal(t, model.SourceDeclared, a.Node("n_api").Source, "source is written from the sidecar")

	// The client posts the preview back: the server stamps the actor and never trusts a signature claim.
	a.StampAccepted("usr_accept", tAccept)
	e := a.Provenance["/nodes/n_db"]
	assert.Equal(t, "usr_accept", e.ImportedBy)
	require.NotNil(t, e.ImportedAt)
	assert.True(t, e.ImportedAt.Equal(tAccept))
	assert.False(t, e.SignatureVerified)
	require.NoError(t, model.Validate(a))

	// A model accepted without a sidecar keeps none.
	b := mustValidate(t, baseArch(t))
	b.StampAccepted("usr_accept", tAccept)
	assert.Nil(t, b.Provenance)
}

func TestFreshnessAndDrift(t *testing.T) {
	a := mustValidate(t, baseArch(t))
	first := model.ImportSource{Identifier: "registry:retail", Hash: hashA, FetchedAt: t0, CadenceDays: 7}
	a.RecordImport(first, a.ElementPointers(), "usr_1", t0)
	e := a.Provenance["/nodes/n_db"]
	tests := []struct {
		name string
		asOf time.Time
		want bool
	}{
		{"within the cadence", t0.Add(7 * 24 * time.Hour), false},
		{"past the cadence", t0.Add(7*24*time.Hour + time.Second), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, e.Expired(tc.asOf)) })
	}
	assert.False(t, model.ProvenanceEntry{Kind: model.ProvenanceDeclared, FetchedAt: &t0, CadenceDays: 1}.Expired(t0.AddDate(1, 0, 0)),
		"a declared fact never expires by the clock")
	assert.False(t, a.Drifted(e), "one import: nothing to drift from")

	// A later import of the same identifier carries n_api only.
	hashB := strings.Repeat("b", 64)
	a.RecordImport(model.ImportSource{Identifier: "registry:retail", Hash: hashB, FetchedAt: t0.Add(48 * time.Hour), CadenceDays: 7},
		[]string{"/nodes/n_api"}, "usr_1", t0.Add(48*time.Hour))
	assert.Equal(t, hashB, a.LatestImport("registry:retail"))
	assert.True(t, a.Drifted(a.Provenance["/nodes/n_db"]))
	assert.False(t, a.Drifted(a.Provenance["/nodes/n_api"]))
	assert.Equal(t, []string{"/edges/e1", "/nodes/n_db"}, a.DriftedElements("registry:retail"))

	// The import diff is a patch a person accepts: applying it yields a valid model without the drifted facts.
	ops := a.DriftRemovalOps("registry:retail")
	require.NotEmpty(t, ops)
	next, err := model.Apply(a, ops, false)
	require.NoError(t, err)
	assert.Nil(t, next.Node("n_db"))
	assert.Nil(t, next.Edge("e1"))
	assert.NotContains(t, next.Provenance, "/nodes/n_db")
	assert.Empty(t, mustValidate(t, baseArch(t)).DriftRemovalOps("registry:retail"))
}

// ADR-086 §6: the hash includes the sidecar from schema 1.1, and a model without one hashes as before.
func TestCanonicalHashAndProvenance(t *testing.T) {
	plain := mustValidate(t, baseArch(t))
	c, err := model.Canonical(plain)
	require.NoError(t, err)
	assert.NotContains(t, string(c), "provenance", "omitempty: a model without a sidecar hashes as it always did")

	with := mustValidate(t, provArch(t))
	h1, err := model.Hash(with)
	require.NoError(t, err)
	changed := mustValidate(t, provArch(t))
	e := changed.Provenance["/nodes/n_db"]
	e.CadenceDays = 31
	changed.Provenance["/nodes/n_db"] = e
	h2, err := model.Hash(changed)
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "the sidecar is inside the hash")
}

// ADR-086 Acceptance: schema round trip on every golden model, with and without a materialised sidecar; without one
// the hash is unchanged.
func TestGoldenModelsRoundTripWithProvenance(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "golden-set", "models", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, err := os.ReadFile(f) // #nosec G304 -- checked-in golden model
			require.NoError(t, err)
			a, err := model.ValidateJSON(b)
			require.NoError(t, err)
			// docs/18 WS-I I2 (swarm team 01): the import-provenance pair carries a stored sidecar so the golden set
			// exercises the prov pack (cmd/eval TestEveryPackIsExercisedByAGoldenModel), and the MCP platform good twin
			// records its registry and card claims as imported (PRV-003 silent, review fix of 2026-10-02); every other
			// model has none.
			if !strings.HasPrefix(filepath.Base(f), "team01-import-provenance") && filepath.Base(f) != "mcp-agent-platform.json" {
				assert.Empty(t, a.Provenance)
			}
			h0, err := model.Hash(a)
			require.NoError(t, err)

			out, err := json.Marshal(a)
			require.NoError(t, err)
			again, err := model.ValidateJSON(out)
			require.NoError(t, err)
			h1, err := model.Hash(again)
			require.NoError(t, err)
			assert.Equal(t, h0, h1)

			again.MaterializeProvenance(nil)
			sources := map[string]string{}
			for _, n := range again.Nodes {
				sources[n.ID] = n.Source
			}
			again.SyncSources()
			for _, n := range again.Nodes {
				assert.Equal(t, sources[n.ID], n.Source, "materialising never changes a source")
			}
			out, err = json.Marshal(again)
			require.NoError(t, err)
			third, err := model.ValidateJSON(out)
			require.NoError(t, err)
			assert.Equal(t, len(again.Provenance), len(third.Provenance))
		})
	}
}

// ADR-086 §7: a source's own date never silences freshness. A preview drops a date later than now plus the skew; an
// accepted import bounds it by the acceptance; StampAccepted does the same for a posted preview.
func TestFetchedAtIsBoundedBySourceAndAcceptance(t *testing.T) {
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		src  time.Time
		at   time.Time
		want *time.Time // nil: no fetch date in the preview
	}{
		{"preview with a future plan timestamp drops it", future, time.Time{}, nil},
		{"preview with a past timestamp keeps it", t0, time.Time{}, &t0},
		{"acceptance bounds a future timestamp", future, tAccept, &tAccept},
		{"acceptance keeps an earlier timestamp", t0, tAccept, &t0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := mustValidate(t, baseArch(t))
			a.RecordImport(model.ImportSource{Identifier: "terraform_plan:main", Hash: hashA, FetchedAt: tc.src, CadenceDays: 30},
				a.ElementPointers(), "", tc.at)
			got := a.Provenance["/nodes/n_db"].FetchedAt
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.True(t, got.Equal(*tc.want), got)
		})
	}

	t.Run("StampAccepted bounds a posted fetch date by the acceptance", func(t *testing.T) {
		doc := provArch(t)
		doc["provenance"].(map[string]any)["/nodes/n_db"].(map[string]any)["fetched_at"] = "2099-01-01T00:00:00Z"
		a := mustValidate(t, doc)
		a.StampAccepted("usr_accept", tAccept)
		e := a.Provenance["/nodes/n_db"]
		require.NotNil(t, e.FetchedAt)
		assert.True(t, e.FetchedAt.Equal(tAccept))
		assert.True(t, e.Expired(tAccept.AddDate(0, 0, 31)), "the cadence runs from the acceptance, not from 2099")
	})
}

// ADR-086 §4: provenance a client posts without the server's seal is not believed.
func TestDistrustProvenance(t *testing.T) {
	doc := provArch(t)
	doc["nodes"].([]any)[0].(map[string]any)["source"] = "observed"
	a := mustValidate(t, doc)
	assert.True(t, a.HasObserved())
	entries, sources := a.DistrustProvenance()
	assert.Equal(t, 2, entries)
	assert.Equal(t, 2, sources)
	assert.Nil(t, a.Provenance)
	assert.False(t, a.HasObserved())
	for _, n := range a.Nodes {
		assert.Equal(t, model.SourceDesign, n.Source, n.ID)
		assert.Equal(t, model.ProvenanceDeclared, a.KindOf(model.ElementPointer("nodes", n.ID)), n.ID)
	}
	a.StampAccepted("usr_accept", tAccept)
	assert.Nil(t, a.Provenance, "nothing to stamp: the model resolves declared")
	require.NoError(t, model.Validate(a))
}

// ADR-086 §4 and §7: an import merged into a model refreshes every element it carries and keeps the declared keys of
// the values it did not rewrite.
func TestMergeImportKeepsWhatTheImportDidNotRewrite(t *testing.T) {
	a := mustValidate(t, provArch(t))
	later := tAccept.Add(24 * time.Hour)
	hashB := strings.Repeat("b", 64)
	src := model.ImportSource{Identifier: "terraform_plan:main", Hash: hashB, CadenceDays: 30}
	tests := []struct {
		name      string
		rewritten []string
		keepAttr  bool
	}{
		{"an untouched declared attribute stays declared", nil, true},
		{"a rewritten attribute is imported again", []string{"/nodes/n_db/attrs/encryption_key"}, false},
		{"an element rewritten whole drops every key below it", []string{"/nodes/n_db"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := a.Clone()
			require.NoError(t, err)
			b.MergeImport(src, []string{"/nodes/n_db"}, tc.rewritten, "usr_import", later)
			e := b.Provenance["/nodes/n_db"]
			assert.Equal(t, hashB, e.LastSeenImport)
			require.NotNil(t, e.FetchedAt)
			assert.True(t, e.FetchedAt.Equal(later), "the fetch date is refreshed whether or not the merge changed it")
			_, kept := b.Provenance["/nodes/n_db/attrs/encryption_key"]
			assert.Equal(t, tc.keepAttr, kept)
			want := model.ProvenanceImported
			if tc.keepAttr {
				want = model.ProvenanceDeclared
			}
			assert.Equal(t, want, b.KindOf("/nodes/n_db/attrs/encryption_key"))
			require.NoError(t, model.Validate(b))
		})
	}
}

// ADR-086 §2: the sidecar does not grow with every patch. Many patches by one person on one node leave a bounded
// number of keys, and the latest declaration date.
func TestStampPatchKeepsTheSidecarBounded(t *testing.T) {
	cur := mustValidate(t, provArch(t))
	add := model.PatchOp{Op: "add", Path: "/nodes/-", Value: json.RawMessage(`{"id":"n_new","type":"app","name":"New","layer":"app","attrs":{}}`)}
	next, err := model.Apply(cur, []model.PatchOp{add}, false)
	require.NoError(t, err)
	model.StampPatch(cur, next, "usr_actor", tAccept)
	cur = next
	before := len(cur.Provenance)
	last := tAccept
	for i := range 200 {
		op := model.PatchOp{Op: "add", Path: "/nodes/n_new/attrs/x_k" + strings.Repeat("a", 1+i%40) + string(rune('a'+i%26)),
			Value: json.RawMessage(`"v"`)}
		next, err := model.Apply(cur, []model.PatchOp{op}, false)
		require.NoError(t, err)
		last = tAccept.Add(time.Duration(i+1) * time.Minute)
		model.StampPatch(cur, next, "usr_actor", last)
		cur = next
	}
	assert.Equal(t, before, len(cur.Provenance), "every attribute the same person declared folds into the node's key")
	e := cur.Provenance["/nodes/n_new"]
	assert.Equal(t, "usr_actor", e.DeclaredBy)
	require.NotNil(t, e.DeclaredAt)
	assert.True(t, e.DeclaredAt.Equal(last), "the folded key carries the latest declaration")
	require.NoError(t, model.Validate(cur))

	// Another person's declaration stays its own key.
	op := model.PatchOp{Op: "add", Path: "/nodes/n_new/attrs/x_other", Value: json.RawMessage(`"v"`)}
	next, err = model.Apply(cur, []model.PatchOp{op}, false)
	require.NoError(t, err)
	model.StampPatch(cur, next, "usr_other", last.Add(time.Minute))
	assert.Equal(t, "usr_other", next.Provenance["/nodes/n_new/attrs/x_other"].DeclaredBy)
}

// The schema's limit on /provenance is MaxProvenanceKeys, and it leaves room for one key per element at the
// collections' maxItems: the fold (compactProvenance) can always bring a sidecar within it.
func TestProvenanceLimitFollowsTheCollectionLimits(t *testing.T) {
	var schema struct {
		Properties map[string]struct {
			MaxItems int `json:"maxItems"`
		} `json:"properties"`
		Defs map[string]struct {
			MaxProperties int `json:"maxProperties"`
		} `json:"$defs"`
	}
	b, err := os.ReadFile(filepath.Join("..", "schema", "model.schema.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &schema))
	assert.Equal(t, model.MaxProvenanceKeys, schema.Defs["provenance"].MaxProperties)
	sum := 0
	for _, c := range []string{"nodes", "edges", "groups", "identities"} {
		require.Positive(t, schema.Properties[c].MaxItems, c)
		sum += schema.Properties[c].MaxItems
	}
	assert.Equal(t, model.MaxProvenanceElements, sum)
	assert.Greater(t, model.MaxProvenanceKeys, model.MaxProvenanceElements)
}
