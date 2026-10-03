package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

var updateVectors = flag.Bool("update-vectors", false, "rewrite testdata/chain-vectors.json")

// vectorFile is the published hash-chain test vectors (docs/18 A4): a chain export the verifier
// reads as it is, plus, per event, the canonical payload and the exact pre-image of its hash, so a
// third party checks every value with sha256sum alone (see the notes in the file).
type vectorFile struct {
	Notes    []string      `json:"notes"`
	ArchID   string        `json:"arch_id"`
	Events   []vectorEvent `json:"events"`
	HeadHash string        `json:"head_hash"`
	Count    int           `json:"count"`
	Anchors  []chainAnchor `json:"anchors"`
}

type vectorEvent struct {
	ID          string          `json:"id"`
	ArchID      string          `json:"arch_id"`
	Version     int             `json:"version"`
	Type        string          `json:"type"`
	Payload     json.RawMessage `json:"payload"`
	PayloadHash string          `json:"payload_hash"`
	PrevHash    string          `json:"prev_hash"`
	Hash        string          `json:"hash"`
	Actor       string          `json:"actor"`
	TS          string          `json:"ts"`
	Seq         int64           `json:"seq"`
	AnchoredBy  *string         `json:"anchored_by"`
	// PayloadCanonical is the payload exactly as hashed; Preimage the string the hash covers.
	PayloadCanonical string `json:"payload_canonical"`
	Preimage         string `json:"preimage"`
}

var vectorNotes = []string{
	"Hash-chain test vectors of the Sixi Assure evidence chain (ADR-012, docs/18 A4). Check them with standard tools:",
	"payload_hash = sha256 of payload_canonical: printf '%s' \"$(jq -r '.events[0].payload_canonical' chain-vectors.json)\" | sha256sum",
	"(canonical: object keys sorted byte-wise, no insignificant whitespace, strings in UTF-8 with no HTML escaping, numbers as written)",
	"hash = sha256 of the pre-image: printf '%s' \"$(jq -r '.events[0].preimage' chain-vectors.json)\" | sha256sum",
	"preimage = prev_hash|payload_hash|type|actor|version|ts, joined by '|', ts in RFC 3339 UTC with the fraction truncated to microseconds and trailing zeros dropped (Go's time.RFC3339Nano)",
	"the first prev_hash is 64 zeros (genesis); each prev_hash is the hash before it; head_hash is the last hash",
	"assure verify chain-vectors.json recomputes them too (the file is a chain export; no anchor, so every event reads as unanchored)",
}

func vectorEvents() []testEvent {
	return []testEvent{
		{typ: "model_created", payload: `{"hash":"6e0a0d0f8c4b2f7d6d0a5e3c1b9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a19","name_sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","nodes":7}`,
			actor: "user:usr_vectors", version: 1, ts: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)},
		{typ: "patch_accepted", payload: `{"after":"b1","before":"a0","ops":3,"rationale_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`,
			actor: "user:usr_vectors", version: 2, ts: time.Date(2026, 10, 1, 9, 30, 15, 123456789, time.UTC)},
		{typ: "finding_status", payload: `{"finding":"f_1","note":"Zürich – «größer» <&>","rule_id":"NET-003","status":"accepted"}`,
			actor: "agent_key:ak_vectors", version: 2, ts: time.Date(2026, 10, 1, 10, 0, 0, 500000000, time.UTC)},
		{typ: "export_generated", payload: `{"format":"json","kind":"assurance_report","nested":{"b":[3,1,2],"a":1.50},"sha256":"5d41402abc4b2a76b9719d911017c592"}`,
			actor: "user:usr_vectors", version: 2, ts: time.Date(2026, 10, 1, 10, 15, 0, 1000, time.UTC)},
	}
}

func TestChainVectors(t *testing.T) {
	path := filepath.Join("testdata", "chain-vectors.json")
	exp := buildChain(t, "arch_vectors", vectorEvents())
	markAnchored(&exp)
	vf := vectorFile{Notes: vectorNotes, ArchID: exp.ArchID, HeadHash: exp.HeadHash, Count: len(exp.Events), Anchors: []chainAnchor{}}
	for _, e := range exp.Events {
		ts := e.TS.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
		vf.Events = append(vf.Events, vectorEvent{ID: e.ID, ArchID: e.ArchID, Version: e.Version, Type: e.Type, Payload: e.Payload,
			PayloadHash: e.PayloadHash, PrevHash: e.PrevHash, Hash: e.Hash, Actor: e.Actor, TS: ts, Seq: *e.Seq,
			PayloadCanonical: string(e.Payload),
			Preimage:         strings.Join([]string{e.PrevHash, e.PayloadHash, e.Type, e.Actor, strconv.Itoa(e.Version), ts}, "|")})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(vf))
	want := buf.Bytes()
	if *updateVectors {
		require.NoError(t, os.WriteFile(path, want, 0o600))
	}
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "testdata/chain-vectors.json is stale: go test ./internal/verify -run TestChainVectors -update-vectors")

	// What a third party does with sha256sum, done here with the same primitives.
	var read vectorFile
	require.NoError(t, json.Unmarshal(got, &read))
	prev := GenesisHash
	for _, e := range read.Events {
		canon, err := model.CanonicalJSON(e.Payload)
		require.NoError(t, err)
		assert.Equal(t, string(canon), e.PayloadCanonical, "payload_canonical is the canonical payload")
		sum := sha256.Sum256([]byte(e.PayloadCanonical))
		assert.Equal(t, hex.EncodeToString(sum[:]), e.PayloadHash)
		assert.Equal(t, prev, e.PrevHash)
		sum = sha256.Sum256([]byte(e.Preimage))
		assert.Equal(t, hex.EncodeToString(sum[:]), e.Hash, e.ID)
		prev = e.Hash
	}
	assert.Equal(t, prev, read.HeadHash)

	// The verifier reads the file as a chain export.
	r := &Report{}
	st := verifyChain(r, got)
	require.NotNil(t, st)
	assert.Equal(t, Pass, checkOf(t, r, SectionChain, "chain arch_vectors").Status)
	assert.Equal(t, Pass, checkOf(t, r, SectionChain, "head").Status)
	assert.Equal(t, Pass, checkOf(t, r, SectionChain, "anchored_by").Status)
}

func TestVerifyChain(t *testing.T) {
	t.Parallel()
	base := func(t *testing.T) chainExport {
		exp := buildChain(t, "arch_1", vectorEvents())
		markAnchored(&exp)
		return exp
	}
	tests := []struct {
		name    string
		mutate  func(e *chainExport)
		check   string
		want    Status
		contain string
	}{
		{name: "intact", mutate: func(*chainExport) {}, check: "chain arch_1", want: Pass},
		{name: "payload changed", mutate: func(e *chainExport) { e.Events[1].Payload = json.RawMessage(`{"after":"b2","before":"a0","ops":3}`) },
			check: "chain arch_1", want: Fail, contain: "payload changed"},
		{name: "payload and payload hash changed", mutate: func(e *chainExport) {
			e.Events[1].Payload = json.RawMessage(`{"ops":4}`)
			e.Events[1].PayloadHash, _ = PayloadHash(e.Events[1].Payload)
		}, check: "chain arch_1", want: Fail, contain: "recomputes to"},
		{name: "actor changed", mutate: func(e *chainExport) { e.Events[2].Actor = "user:someone_else" }, check: "chain arch_1", want: Fail, contain: "event ev_003 recomputes"},
		{name: "time moved", mutate: func(e *chainExport) { e.Events[0].TS = e.Events[0].TS.Add(time.Second) }, check: "chain arch_1", want: Fail, contain: "ev_001"},
		{name: "event removed", mutate: func(e *chainExport) {
			e.Events = append(e.Events[:1], e.Events[2:]...)
			n := len(e.Events)
			e.Count = &n
		}, check: "chain arch_1", want: Fail, contain: "does not link"},
		{name: "partial export", mutate: func(e *chainExport) { n := 9; e.Count = &n }, check: "chain arch_1", want: Fail, contain: "an export with limit"},
		{name: "head named wrongly", mutate: func(e *chainExport) { e.HeadHash = e.Events[0].Hash }, check: "head", want: Fail},
		{name: "head absent", mutate: func(e *chainExport) { e.HeadHash = "" }, check: "head", want: NotChecked, contain: NotPresent},
		{name: "anchored_by absent", mutate: func(e *chainExport) {
			for i := range e.Events {
				e.Events[i].AnchoredBy = nil
			}
		}, check: "anchored_by", want: NotChecked, contain: NotPresent},
		{name: "anchored_by wrong", mutate: func(e *chainExport) { e.Events[0].AnchoredBy = json.RawMessage(`"anc_forged"`) }, check: "anchored_by", want: Fail},
		{name: "another architecture's event", mutate: func(e *chainExport) { e.Events[3].ArchID = "arch_2" }, check: "chain arch_1", want: Fail, contain: "belongs to"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			exp := base(t)
			tc.mutate(&exp)
			raw, err := json.Marshal(exp)
			require.NoError(t, err)
			r := &Report{}
			verifyChain(r, raw)
			c := checkOf(t, r, SectionChain, tc.check)
			assert.Equal(t, tc.want, c.Status, c.Detail)
			assert.Contains(t, c.Detail, tc.contain)
		})
	}
}

func TestVerifyChainRejectsEmptyAndGarbage(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`{"arch_id":"a","events":[],"head_hash":""}`, `{"events":"no"}`} {
		r := &Report{}
		assert.Nil(t, verifyChain(r, []byte(raw)), raw)
		require.Len(t, r.Checks, 1)
		assert.Equal(t, Fail, r.Checks[0].Status)
	}
}
