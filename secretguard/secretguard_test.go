package secretguard

import (
	"context"
	"encoding/json"
	"errors"

	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtures reads testdata/<kind>/*.txt; the file stem of a positive names the detector it seeds.
func fixtures(t *testing.T, kind string) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", kind, "*.txt"))
	require.NoError(t, err)
	require.NotEmpty(t, paths, "no %s fixtures", kind)
	out := make(map[string]string, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p) //nolint:gosec // fixture path is built from a glob of testdata
		require.NoError(t, err)
		out[strings.TrimSuffix(filepath.Base(p), ".txt")] = string(b)
	}
	return out
}

func TestPositiveFixturesAreDetected(t *testing.T) {
	ctx := context.Background()
	for name, body := range fixtures(t, "positives") {
		t.Run(name, func(t *testing.T) {
			res := Scan(ctx, SourceModel, body)
			names := map[string]Finding{}
			for _, f := range res.Findings {
				names[f.Detector] = f
			}
			f, ok := names[name]
			require.True(t, ok, "fixture %s must trip detector %s, got %v", name, name, res.Findings)
			assert.Equal(t, Rejecting(name), f.Reject)
			assert.Equal(t, Rejecting(name), res.Rejects(), "fixture %s reject outcome", name)
			assert.Greater(t, f.Confidence, 0.0)
			assert.Regexp(t, `^bytes\[\d+:\d+\]$`, f.Path)
			if Rejecting(name) {
				var v *Violation
				require.ErrorAs(t, res.Err(), &v)
				assert.ErrorIs(t, v, ErrSecretDetected)
				assert.NotContains(t, v.Error(), "EXAMPLE", "the error must not echo the value")
			} else {
				assert.NoError(t, res.Err(), "warn-only detector must not refuse")
			}
		})
	}
}

// Every detector in the table needs a fixture: the suite is the ADR-041 acceptance corpus.
func TestEveryDetectorHasAPositiveFixture(t *testing.T) {
	have := fixtures(t, "positives")
	for _, d := range Detectors() {
		_, ok := have[d]
		assert.True(t, ok, "detector %s has no testdata/positives/%s.txt fixture", d, d)
	}
}

func TestNegativeFixturesAreNotRefused(t *testing.T) {
	ctx := context.Background()
	for name, body := range fixtures(t, "negatives") {
		t.Run(name, func(t *testing.T) {
			res := Scan(ctx, SourceModel, body)
			for _, f := range res.Findings {
				assert.False(t, f.Reject, "detector %s must not refuse ordinary content", f.Detector)
			}
			assert.NoError(t, res.Err())
		})
	}
}

func TestScanValueAndDocumentReportJSONPointers(t *testing.T) {
	ctx := context.Background()
	t.Run("value", func(t *testing.T) {
		res := ScanValue(ctx, SourceModel, "/nodes/0/description", "key AKIAIOSFODNN7EXAMPLE pasted here")
		require.True(t, res.Rejects())
		assert.Equal(t, "/nodes/0/description", res.Findings[0].Path)
	})

	doc := map[string]any{
		"name": "Payments platform",
		"nodes": []any{
			map[string]any{"id": "n_api", "attrs": map[string]any{
				"x_runbook": "https://wiki.example.test/n_api",
				"x_note":    "AKIAIOSFODNN7EXAMPLE",
			}},
		},
	}
	res := ScanDocument(ctx, SourceModel, doc)
	require.True(t, res.Rejects())
	var v *Violation
	require.ErrorAs(t, res.Err(), &v)
	assert.Equal(t, "/nodes/0/attrs/x_note", v.Finding.Path)
	assert.Equal(t, "aws_access_key", v.Finding.Detector)
	assert.Equal(t, "/nodes/0/attrs/x_note: aws_access_key", v.Detail())
	assert.True(t, errors.Is(v, ErrSecretDetected))
}

func TestScanDocumentEscapesPointerTokensAndScansKeys(t *testing.T) {
	ctx := context.Background()
	// An x_* extension key is user-authored too (schema allows 60 characters of [A-Za-z0-9_]).
	// The hit is reported at the object that holds the key, never at the key's own pointer: that pointer would echo
	// the credential in the 422 detail and the log (integration 3b item 9; this assertion pinned the key's pointer
	// before).
	doc := map[string]any{"attrs": map[string]any{"x_AKIAIOSFODNN7EXAMPLE": 1}}
	res := ScanDocument(ctx, SourceModel, doc)
	require.True(t, res.Rejects())
	assert.Equal(t, "/attrs", res.Findings[0].Path)
	assert.True(t, res.Findings[0].InKey)

	doc = map[string]any{"a/b~c": "postgres://u:EXAMPLEnotarealpassword@db.example.test:5432/x"}
	res = ScanDocument(ctx, SourceModel, doc)
	require.True(t, res.Rejects())
	assert.Equal(t, "/a~1b~0c", res.Findings[0].Path)
}

func TestEntropyWarnsOnlyAndRaisesConfidence(t *testing.T) {
	ctx := context.Background()
	res := Scan(ctx, SourceModel, "opaque handle qX7pZ2mR8vKd3LwNsT5yBc1JhGfQe0AiUoPzXn4V stored on the node")
	require.False(t, res.Rejects(), "entropy alone never refuses")
	require.Len(t, res.Findings, 1)
	assert.Equal(t, detectorEntropy, res.Findings[0].Detector)

	// Entropy beside a rejecting detector raises that detector's confidence instead.
	plain := Scan(ctx, SourceModel, "token ghp_EXAMPLEnotarealtoken0123456789abcdef0 in the note")
	var withEntropy Result
	for _, f := range plain.Findings {
		if f.Detector == "github_token" {
			withEntropy.Findings = append(withEntropy.Findings, f)
		}
	}
	require.Len(t, withEntropy.Findings, 1)
	assert.GreaterOrEqual(t, withEntropy.Findings[0].Confidence, 0.95)
}

func TestJWTRequiresADecodableHeader(t *testing.T) {
	ctx := context.Background()
	// Three dotted base64url-looking segments that are not a JOSE header: not a JWT.
	assert.False(t, Scan(ctx, SourceModel, "eyJnotbase64url!!!.aaaaaaaaaa.bbbbbbbb").Rejects())
	assert.False(t, Scan(ctx, SourceModel, "release eyJ0000000000.2024010112.build9 of the gateway").Rejects())
}

func TestShortValuesAreSkipped(t *testing.T) {
	assert.Empty(t, Scan(context.Background(), SourceModel, "AKIA").Findings)
}

func TestPathHashIsStableAndOpaque(t *testing.T) {
	h := PathHash("/nodes/0/attrs/x_note")
	assert.Len(t, h, 64)
	assert.Equal(t, h, PathHash("/nodes/0/attrs/x_note"))
	assert.NotEqual(t, h, PathHash("/nodes/1/attrs/x_note"))
}

func TestCheckHelpers(t *testing.T) {
	ctx := context.Background()
	assert.NoError(t, Check(ctx, SourceMessage, "Explain the trust boundary between the gateway and the model."))
	assert.ErrorIs(t, CheckBytes(ctx, SourceImport, []byte("AKIAIOSFODNN7EXAMPLE in a draw.io label")), ErrSecretDetected)
	assert.ErrorIs(t, CheckValue(ctx, SourceBrief, "/brief", "use sk-ant-api03-EXAMPLEnotarealkey0123456789abcdef"), ErrSecretDetected)
	assert.ErrorIs(t, CheckDocument(ctx, SourceProposal, map[string]any{"v": "AKIAIOSFODNN7EXAMPLE"}), ErrSecretDetected)
}

// bigModel builds a document the size of a 500-node architecture (~5 000 string leaves).
func bigModel(nodes int) map[string]any {
	ns := make([]any, 0, nodes)
	for i := 0; i < nodes; i++ {
		id := "n_" + strconv.Itoa(i)
		ns = append(ns, map[string]any{
			"id": id, "type": "app", "name": "Service " + id, "source": "design",
			"description": "Handles the " + id + " part of the payments platform and reports to the control plane.",
			"attrs": map[string]any{
				"owner": "platform-team", "region": "switzerlandnorth", "data_class": "confidential",
				"external_ref": "CMDB-" + strconv.Itoa(100000+i), "purpose": "serves the retail channel",
				"x_runbook": "https://wiki.example.test/runbooks/" + id, "x_bu": "retail banking",
			},
		})
	}
	es := make([]any, 0, nodes)
	for i := 0; i < nodes; i++ {
		es = append(es, map[string]any{
			"id": "e_" + strconv.Itoa(i), "from": "n_" + strconv.Itoa(i), "to": "n_0",
			"kind": "calls", "label": "synchronous call over mTLS", "protocol": "https",
			"attrs": map[string]any{"description": "carries customer records between the two services"},
		})
	}
	return map[string]any{"id": "arch_bench", "name": "Benchmark", "nodes": ns, "edges": es}
}

// ADR-041 §Consequences: the guard must stay far below the findings budget on a 500-node model.
func TestScanDocumentStaysFastOnA500NodeModel(t *testing.T) {
	doc := bigModel(500)
	ctx := context.Background()
	require.False(t, ScanDocument(ctx, SourceModel, doc).Rejects())
	start := time.Now()
	for i := 0; i < 5; i++ {
		ScanDocument(ctx, SourceModel, doc)
	}
	per := time.Since(start) / 5
	t.Logf("scan of a 500-node model: %s", per)
	// Budget is 50 ms in production; 250 ms here, 4 s under the race detector with every package
	// running in parallel (the measurement is logged either way).
	budget := 250 * time.Millisecond
	if raceEnabled {
		budget = 4 * time.Second
	}
	assert.Less(t, per, budget)
}

func BenchmarkScanDocument500Nodes(b *testing.B) {
	doc := bigModel(500)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScanDocument(ctx, SourceModel, doc)
	}
}

func BenchmarkScanProse(b *testing.B) {
	ctx := context.Background()
	s := "The retrieval agent calls the model gateway over mutual TLS inside the Swiss North region."
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Scan(ctx, SourceModel, s)
	}
}

// The findings must serialise without the value (they are copied onto evidence payloads).
func TestFindingJSONCarriesNoValue(t *testing.T) {
	res := Scan(context.Background(), SourceModel, "key AKIAIOSFODNN7EXAMPLE")
	b, err := json.Marshal(res)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "AKIA")
	assert.Contains(t, string(b), `"detector":"aws_access_key"`)
}

// TestCredentialShapedKeyIsNeverEchoed (integration 3b item 9): a credential-shaped object key is refused, and
// nothing the caller is shown or the log receives (the pointer, the detail, the error) contains the key; a value hit
// still names its own pointer.
func TestCredentialShapedKeyIsNeverEchoed(t *testing.T) {
	t.Parallel()
	const key = "AKIAIOSFODNN7EXAMPLE"
	// Review 3b finding 6: a key that only warns (a high-entropy token) is still not echoed when a value below it
	// rejects; the value's hit is reported at the pointer of the object holding the key, at any depth below it.
	const warnKey = "x_Zk8Qp2Lr7Vt9Wm3Xn6Yb4Hc1Jd5Ke0Fg2Sa"
	warnOnly := ScanDocument(context.Background(), SourceModel, map[string]any{"attrs": map[string]any{warnKey: "v"}})
	require.False(t, warnOnly.Rejects(), "the key alone only warns")
	require.NotEmpty(t, warnOnly.Findings, "the key alone produces a warn-level finding")
	type keyCase struct {
		name       string
		doc        any
		wantPath   string
		wantDetail string
		wantInKey  bool
		// wantUnder is true for a hit below a key that was itself flagged (review 3b finding 6).
		wantUnder bool
	}
	cases := []keyCase{
		{"an extension key on a node", map[string]any{"nodes": []any{map[string]any{"attrs": map[string]any{"x_" + key: true}}}},
			"/nodes/0/attrs", "/nodes/0/attrs: aws_access_key in an object key", true, false},
		{"a key at the document root", map[string]any{"x_" + key: "v"}, "", "(document root): aws_access_key in an object key", true, false},
		{"a nested key under an escaped token", map[string]any{"a/b": map[string]any{key: 1}}, "/a~1b", "/a~1b: aws_access_key in an object key", true, false},
		{"a value still names its own pointer", map[string]any{"attrs": map[string]any{"x_note": key}},
			"/attrs/x_note", "/attrs/x_note: aws_access_key", false, false},
		{"a rejecting value under a warn-level key", map[string]any{"attrs": map[string]any{warnKey: map[string]any{"v": key}}},
			"/attrs", "/attrs: aws_access_key under a flagged object key", false, true},
		{"a rejecting value deeper under a warn-level key", map[string]any{"attrs": map[string]any{warnKey: []any{map[string]any{"a/b": key}}}},
			"/attrs", "/attrs: aws_access_key under a flagged object key", false, true},
		{"a rejecting key under a warn-level key", map[string]any{"attrs": map[string]any{warnKey: map[string]any{"x_" + key: 1}}},
			"/attrs", "/attrs: aws_access_key in an object key", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := ScanDocument(context.Background(), SourceModel, tc.doc)
			require.True(t, res.Rejects())
			var v *Violation
			require.ErrorAs(t, res.Err(), &v)
			assert.Equal(t, tc.wantPath, v.Finding.Path)
			assert.Equal(t, tc.wantInKey, v.Finding.InKey)
			assert.Equal(t, tc.wantUnder, v.Finding.UnderKey)
			assert.Equal(t, tc.wantDetail, v.Detail())
			if tc.wantInKey || tc.wantUnder {
				for _, secret := range []string{key, warnKey, strings.TrimPrefix(warnKey, "x_")} {
					assert.NotContains(t, v.Finding.Path, secret)
					assert.NotContains(t, v.Detail(), secret)
					assert.NotContains(t, v.Error(), secret)
				}
				for _, f := range res.Findings {
					assert.NotContains(t, f.Path, strings.TrimPrefix(warnKey, "x_"), "no finding, warn-only included, names the key")
				}
			}
		})
	}
}
