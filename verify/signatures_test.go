package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

func TestParseKeys(t *testing.T) {
	t.Parallel()
	one := `{"key_id":"0123456789abcdef","public_key":"x","valid_from":"2026-01-01T00:00:00Z"}`
	tests := []struct {
		name, raw string
		n         int
		wantErr   bool
	}{
		{name: "GET /evidence/keys", raw: `{"keys":[` + one + `,` + one + `]}`, n: 2},
		{name: "bare array", raw: `[` + one + `]`, n: 1},
		{name: "GET /evidence/key", raw: one, n: 1},
		{name: "empty list", raw: `{"keys":[]}`, n: 0},
		{name: "not keys", raw: `{"hello":"world"}`, wantErr: true},
		{name: "not json", raw: `keys`, wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParseKeys([]byte(tc.raw))
		if tc.wantErr {
			assert.Error(t, err, tc.name)
			continue
		}
		require.NoError(t, err, tc.name)
		assert.Len(t, got, tc.n, tc.name)
	}
}

func TestCheckWindow(t *testing.T) {
	t.Parallel()
	to := t0.Add(24 * time.Hour)
	tests := []struct {
		name string
		from time.Time
		to   *time.Time
		at   time.Time
		ok   bool
	}{
		{name: "inside", from: t0, to: &to, at: t0.Add(time.Hour), ok: true},
		{name: "open window", from: t0, at: t0.Add(1000 * time.Hour), ok: true},
		{name: "inside the grace before valid_from", from: t0, at: t0.Add(-WindowGrace + time.Second), ok: true},
		{name: "before the grace", from: t0, at: t0.Add(-WindowGrace - time.Second)},
		{name: "at valid_to is outside", from: t0, to: &to, at: to},
		{name: "after valid_to", from: t0, to: &to, at: to.Add(time.Second)},
		{name: "no time", from: t0, at: time.Time{}},
		{name: "instance key without a window", at: t0, ok: true},
	}
	for _, tc := range tests {
		err := CheckWindow(tc.from, tc.to, tc.at)
		if tc.ok {
			assert.NoError(t, err, tc.name)
		} else {
			assert.ErrorIs(t, err, ErrOutsideWindow, tc.name)
		}
	}
}

func TestKeyringRefusesKeysThatDoNotHashToTheirID(t *testing.T) {
	t.Parallel()
	k := newTestKey(t, CustodyVendor, "sealed", t0, nil)
	bad := k.pub
	bad.KeyID = "ffffffffffffffff"
	kr := newKeyring("test", []Key{k.pub, bad})
	assert.Contains(t, kr.invalid["ffffffffffffffff"], "not the hash")
	r := &Report{}
	kr.custody(r)
	assert.Equal(t, Info, checkOf(t, r, SectionKeys, "key "+k.pub.KeyID).Status)
	assert.Equal(t, Fail, checkOf(t, r, SectionKeys, "key ffffffffffffffff").Status)
	assert.Contains(t, checkOf(t, r, SectionKeys, "key "+k.pub.KeyID).Detail, "relies on the vendor's custodian")
}

// signEnvelope signs data the way the server does (export.SignatureMessage; the cross-check with the
// server's own function is in cmd/assure).
func signEnvelope(t *testing.T, k testKey, data []byte, e envelope) []byte {
	t.Helper()
	sum := sha256.Sum256(data)
	e.SignatureFormat, e.Algorithm, e.SHA256 = ExportSignatureFormat, "ed25519", hex.EncodeToString(sum[:])
	e.KeyID, e.Custody, e.Provider = k.pub.KeyID, k.pub.Custody, k.pub.Provider
	if !k.pub.ValidFrom.IsZero() {
		from := k.pub.ValidFrom
		e.KeyValidFrom = &from
	}
	msg, err := envelopeMessage(e)
	require.NoError(t, err)
	e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, msg))
	b, err := json.Marshal(e)
	require.NoError(t, err)
	return b
}

func TestCheckEnvelope(t *testing.T) {
	t.Parallel()
	expired := t0.Add(time.Hour)
	key := newTestKey(t, CustodyVendor, "sealed", t0.Add(-24*time.Hour), nil)
	rotated := newTestKey(t, CustodyVendor, "sealed", t0.Add(-24*time.Hour), &expired)
	other := newTestKey(t, CustodyCustomer, "kms", t0.Add(-24*time.Hour), nil)
	data := []byte(`{"schema":"sixi-assure/assurance-report/v1"}`)
	base := envelope{ExportID: "exp_1", ArchID: "arch_1", Kind: "assurance_report", Format: "json", SnapshotHash: "s", PackHash: "p",
		CorpusHash: "c", ChainHead: "h", SignedAt: t0.Add(2 * time.Hour)}
	tests := []struct {
		name    string
		signer  testKey
		list    []Key
		data    []byte
		mutate  func(map[string]any)
		own     stated
		want    Status
		contain string
	}{
		{name: "valid", signer: key, list: []Key{key.pub}, want: Pass, own: stated{snapshotHash: "s", packHash: "p", corpusHash: "c", chainHead: "h", keyID: key.pub.KeyID}},
		{name: "file changed", signer: key, list: []Key{key.pub}, data: []byte(`{"schema":"forged"}`), want: Fail, contain: "the file changed"},
		{name: "signed after the key was rotated", signer: rotated, list: []Key{rotated.pub}, want: Fail, contain: "outside the key's validity window"},
		{name: "key not listed", signer: key, list: []Key{other.pub}, want: Fail, contain: "not in the key list"},
		{name: "another key's signature", signer: other, list: []Key{key.pub, other.pub}, mutate: func(m map[string]any) { m["key_id"] = key.pub.KeyID }, want: Fail, contain: "does not verify"},
		{name: "custody edited", signer: key, list: []Key{key.pub}, mutate: func(m map[string]any) { m["custody"] = "customer" }, want: Fail, contain: "does not verify"},
		{name: "pack hash disagrees with the file", signer: key, list: []Key{key.pub}, own: stated{packHash: "another"}, want: Fail, contain: "pack_hash"},
		{name: "unknown format", signer: key, list: []Key{key.pub}, mutate: func(m map[string]any) { m["signature_format"] = "sixi-assure/export-signature/v9" }, want: NotChecked},
		{name: "no key list", signer: key, want: NotChecked, contain: NotPresent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sig := signEnvelope(t, tc.signer, data, base)
			if tc.mutate != nil {
				var m map[string]any
				require.NoError(t, json.Unmarshal(sig, &m))
				tc.mutate(m)
				var err error
				sig, err = json.Marshal(m)
				require.NoError(t, err)
			}
			var kr *keyring
			if tc.list != nil {
				kr = newKeyring("test", tc.list)
			}
			in := data
			if tc.data != nil {
				in = tc.data
			}
			r := &Report{}
			checkEnvelope(r, kr, "report", in, sig, tc.own)
			c := checkOf(t, r, SectionSignatures, "report signature")
			assert.Equal(t, tc.want, c.Status, c.Detail)
			assert.Contains(t, c.Detail, tc.contain)
		})
	}
}

// spotCheckFile signs a snapshot as the server's EvidenceSigner does (version 2, or version 1 over
// the 32 hash bytes).
func spotCheckFile(t *testing.T, k testKey, snapshot string, version int) []byte {
	t.Helper()
	canon, err := model.CanonicalJSON([]byte(snapshot))
	require.NoError(t, err)
	rc := receipt{Version: version, SnapshotHash: model.HashBytes(canon), Algorithm: "ed25519", KeyID: k.pub.KeyID,
		PublicKey: k.pub.PublicKey, SignedAt: t0, Custody: k.pub.Custody, Provider: k.pub.Provider}
	if version >= 2 && !k.pub.ValidFrom.IsZero() {
		from := k.pub.ValidFrom
		rc.KeyValidFrom = &from
	}
	msg, err := receiptMessage(rc)
	require.NoError(t, err)
	rc.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, msg))
	b, err := json.Marshal(map[string]any{"snapshot": json.RawMessage(snapshot), "receipt": rc})
	require.NoError(t, err)
	return b
}

func TestVerifySpotCheck(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, CustodyVendor, "sealed", t0.Add(-time.Hour), nil)
	later := t0.Add(time.Hour)
	future := newTestKey(t, CustodyVendor, "sealed", later, nil)
	snap := `{"arch_id":"arch_1","version":3,"generated_at":"2026-10-01T12:00:00Z","evidence_head":"abc","regimes":[{"code":"FINMA"}]}`
	tests := []struct {
		name    string
		file    []byte
		list    []Key
		check   string
		want    Status
		contain string
	}{
		{name: "v2 with the key list", file: spotCheckFile(t, key, snap, 2), list: []Key{key.pub}, check: "receipt signature", want: Pass},
		{name: "v1 with the key list", file: spotCheckFile(t, key, snap, 0), list: []Key{key.pub}, check: "receipt signature", want: Pass},
		{name: "without a key list the embedded key is not trusted", file: spotCheckFile(t, key, snap, 2), check: "receipt signature", want: NotChecked, contain: "integrity only"},
		{name: "snapshot generated before the key's window", file: spotCheckFile(t, future, snap, 2), list: []Key{future.pub}, check: "receipt signature", want: Fail, contain: "validity window"},
		{name: "snapshot changed", file: func() []byte {
			b := spotCheckFile(t, key, snap, 2)
			var m map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(b, &m))
			m["snapshot"] = json.RawMessage(`{"arch_id":"arch_1","version":4,"generated_at":"2026-10-01T12:00:00Z"}`)
			out, _ := json.Marshal(m)
			return out
		}(), list: []Key{key.pub}, check: "snapshot hash", want: Fail},
	}
	for _, tc := range tests {
		r := &Report{}
		var kr *keyring
		if tc.list != nil {
			kr = newKeyring("test", tc.list)
		}
		verifySpotCheck(r, tc.file, kr)
		c := checkOf(t, r, SectionSignatures, tc.check)
		assert.Equal(t, tc.want, c.Status, "%s: %s", tc.name, c.Detail)
		assert.Contains(t, c.Detail, tc.contain, tc.name)
	}
}
