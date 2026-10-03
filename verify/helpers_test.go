package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// testEvent is one event to chain in a test.
type testEvent struct {
	typ     string
	payload string
	actor   string
	version int
	ts      time.Time
}

// buildChain chains events from genesis with ChainHash (the store's function, mirrored) the way the
// store appends them, with seq 1…n and the anchored_by marks of the given receipts.
func buildChain(t *testing.T, archID string, evs []testEvent) chainExport {
	t.Helper()
	exp := chainExport{ArchID: archID}
	prev := GenesisHash
	for i, e := range evs {
		// The store keeps the canonical payload (AppendEvidence) and hashes exactly that.
		canon, err := model.CanonicalJSON([]byte(e.payload))
		require.NoError(t, err)
		ph := model.HashBytes(canon)
		seq := int64(i + 1)
		h := ChainHash(prev, ph, e.typ, e.actor, e.version, e.ts)
		exp.Events = append(exp.Events, chainEvent{ID: fmt.Sprintf("ev_%03d", i+1), ArchID: archID, Version: e.version,
			Type: e.typ, Payload: json.RawMessage(canon), PayloadHash: ph, PrevHash: prev, Hash: h, Actor: e.actor, TS: e.ts, Seq: &seq})
		prev = h
	}
	exp.HeadHash = prev
	n := len(evs)
	exp.Count = &n
	return exp
}

// markAnchored sets every event's anchored_by from the export's anchors (store.CoverEvents's rule).
func markAnchored(exp *chainExport) {
	anchors := okAnchors(exp.Anchors)
	for i := range exp.Events {
		var by *string
		for _, a := range anchors {
			if a.HeadSeq >= *exp.Events[i].Seq {
				id := a.ID
				by = &id
				break
			}
		}
		raw, _ := json.Marshal(by)
		exp.Events[i].AnchoredBy = raw
	}
}

func writeJSON(t *testing.T, path string, v any) []byte {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	b, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, b, 0o600))
	return b
}

// testKey is an organisation key with its published entry.
type testKey struct {
	priv ed25519.PrivateKey
	pub  Key
}

func newTestKey(t *testing.T, custody, provider string, from time.Time, to *time.Time) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return testKey{priv: priv, pub: Key{KeyID: KeyID(pub), Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub),
		Custody: custody, Provider: provider, State: "active", ValidFrom: from, ValidTo: to}}
}

// checkOf returns the first check with this section and name.
func checkOf(t *testing.T, r *Report, section, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Section == section && c.Name == name {
			return c
		}
	}
	require.Failf(t, "check not found", "%s / %s in %+v", section, name, r.Checks)
	return Check{}
}

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
