package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// ---- detached export signatures (docs/18 A2: report.json.sig, GET /exports/{id}/signature) ------

// ExportSignatureFormat is the first line of the version 1 export signature message.
const ExportSignatureFormat = "sixi-assure/export-signature/v1"

// envelope is the detached signature of an export. Every field but Signature is in the signed
// message; the public key is not: it comes from the key list, never from the file being checked.
type envelope struct {
	SignatureFormat string     `json:"signature_format"`
	Algorithm       string     `json:"algorithm"`
	ExportID        string     `json:"export_id"`
	ArchID          string     `json:"arch_id"`
	Kind            string     `json:"kind"`
	Format          string     `json:"format"`
	SHA256          string     `json:"sha256"`
	SnapshotHash    string     `json:"snapshot_hash"`
	PackHash        string     `json:"pack_hash"`
	CorpusHash      string     `json:"corpus_hash"`
	ChainHead       string     `json:"chain_head"`
	KeyID           string     `json:"key_id"`
	Custody         string     `json:"custody"`
	Provider        string     `json:"provider"`
	KeyValidFrom    *time.Time `json:"key_valid_from,omitempty"`
	SignedAt        time.Time  `json:"signed_at"`
	Signature       string     `json:"signature"`
}

// envelopeMessage is the byte string an export signature covers (version 1): the header line, then
// one "name: value" line each for export_id, arch_id, kind, format, sha256, snapshot_hash, pack_hash,
// corpus_hash, chain_head, algorithm, key_id, custody, provider, key_valid_from (RFC 3339 nano, UTC;
// empty for the instance key) and signed_at (RFC 3339 nano, UTC), joined by "\n" without a trailing
// newline. It is the server's export.SignatureMessage; a test in cmd/assure signs with the server
// and verifies here.
func envelopeMessage(e envelope) ([]byte, error) {
	if len(e.SHA256) != 64 || strings.ToLower(e.SHA256) != e.SHA256 {
		return nil, errors.New("the signature's sha256 is not 64 lower-case hex characters")
	}
	if _, err := hex.DecodeString(e.SHA256); err != nil {
		return nil, errors.New("the signature's sha256 is not hex")
	}
	if e.SignedAt.IsZero() {
		return nil, errors.New("the signature carries no signing time")
	}
	from := ""
	if e.KeyValidFrom != nil {
		from = e.KeyValidFrom.UTC().Format(time.RFC3339Nano)
	}
	fields := [][2]string{
		{"export_id", e.ExportID}, {"arch_id", e.ArchID}, {"kind", e.Kind}, {"format", e.Format},
		{"sha256", e.SHA256}, {"snapshot_hash", e.SnapshotHash}, {"pack_hash", e.PackHash},
		{"corpus_hash", e.CorpusHash}, {"chain_head", e.ChainHead}, {"algorithm", e.Algorithm},
		{"key_id", e.KeyID}, {"custody", e.Custody}, {"provider", e.Provider},
		{"key_valid_from", from}, {"signed_at", e.SignedAt.UTC().Format(time.RFC3339Nano)},
	}
	lines := []string{ExportSignatureFormat}
	for _, f := range fields {
		if strings.ContainsAny(f[1], "\r\n") {
			return nil, fmt.Errorf("the signature's %s contains a line break", f[0])
		}
		lines = append(lines, f[0]+": "+f[1])
	}
	return []byte(strings.Join(lines, "\n")), nil
}

// stated is what a signed file says about itself; the signature's copy of each must agree.
type stated struct {
	snapshotHash, packHash, corpusHash, chainHead, keyID string
}

// checkEnvelope verifies a detached export signature over data: the file's sha256, the message,
// the Ed25519 signature against the listed key, the custody, provider and valid_from the signature
// states against the listed key's, and signed_at inside the key's validity window.
func checkEnvelope(r *Report, kr *keyring, item string, data, sigFile []byte, own stated) {
	name := item + " signature"
	var e envelope
	if err := json.Unmarshal(sigFile, &e); err != nil {
		r.add(SectionSignatures, name, Fail, "the signature file is not a signature envelope: %v", err)
		return
	}
	if e.SignatureFormat != ExportSignatureFormat {
		r.add(SectionSignatures, name, NotChecked, "signature format %q is not one verifier %s knows", oneLine(e.SignatureFormat), Version)
		return
	}
	if !strings.EqualFold(e.Algorithm, "ed25519") {
		r.add(SectionSignatures, name, Fail, "algorithm %q is not ed25519", oneLine(e.Algorithm))
		return
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != e.SHA256 {
		r.add(SectionSignatures, name, Fail, "the file's sha256 %s is not the %s the signature covers (the file changed)", short(got), short(e.SHA256))
		return
	}
	for _, c := range [][3]string{{"snapshot_hash", own.snapshotHash, e.SnapshotHash}, {"pack_hash", own.packHash, e.PackHash},
		{"corpus_hash", own.corpusHash, e.CorpusHash}, {"chain_head", own.chainHead, e.ChainHead}, {"key_id", own.keyID, e.KeyID}} {
		if c[1] != "" && c[1] != c[2] {
			r.add(SectionSignatures, name, Fail, "the signature states %s %s, the file %s", c[0], short(c[2]), short(c[1]))
			return
		}
	}
	msg, err := envelopeMessage(e)
	if err != nil {
		r.add(SectionSignatures, name, Fail, "%v", err)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		r.add(SectionSignatures, name, Fail, "the signature is not a base64 Ed25519 signature")
		return
	}
	if kr == nil {
		r.add(SectionSignatures, name, NotChecked, "key list %s: the signature names key %s (custody %s) and is not checked without it (pass --keys with a saved GET /evidence/keys)",
			NotPresent, e.KeyID, orNA(e.Custody))
		return
	}
	if err := kr.verify(item, e.KeyID, msg, sig, e.SignedAt); err != nil {
		r.add(SectionSignatures, name, Fail, "%v", err)
		return
	}
	k := kr.keys[e.KeyID]
	switch {
	case k.Custody != "" && k.Custody != e.Custody:
		r.add(SectionSignatures, name, Fail, "the signature states custody %q, the key list %q", e.Custody, k.Custody)
		return
	case k.Provider != "" && k.Provider != e.Provider:
		r.add(SectionSignatures, name, Fail, "the signature states provider %q, the key list %q", e.Provider, k.Provider)
		return
	case !k.ValidFrom.IsZero() && (e.KeyValidFrom == nil || !e.KeyValidFrom.Equal(k.ValidFrom)):
		r.add(SectionSignatures, name, Fail, "the signature's key_valid_from is not the listed key's valid_from")
		return
	}
	r.add(SectionSignatures, name, Pass, "Ed25519 by key %s (custody %s) over the file's sha256 and its snapshot, pack, corpus and chain hashes, signed %s, inside the key's validity window",
		e.KeyID, orNA(e.Custody), e.SignedAt.UTC().Format(time.RFC3339))
}

// ---- spot-check receipts (ADR-028; the server's export.ReceiptMessage) ---------------------------

// receipt is a spot-check receipt. The snapshot is hashed as received, never re-marshalled through
// a struct (ADR-087 §4), so a later change to a snapshot field's Go type cannot break old receipts.
type receipt struct {
	Version      int        `json:"receipt_version"`
	SnapshotHash string     `json:"snapshot_hash"`
	Algorithm    string     `json:"algorithm"`
	KeyID        string     `json:"key_id"`
	PublicKey    string     `json:"public_key"`
	Signature    string     `json:"signature"`
	SignedAt     time.Time  `json:"signed_at"`
	Custody      string     `json:"custody"`
	Provider     string     `json:"provider"`
	KeyValidFrom *time.Time `json:"key_valid_from"`
}

type spotCheck struct {
	Snapshot json.RawMessage `json:"snapshot"`
	Receipt  receipt         `json:"receipt"`
}

// receiptHeader is the first line of a version 2 receipt message.
const receiptHeader = "sixi-assure/spot-check-receipt/v2"

// ReceiptMessage is the byte string a spot-check receipt's signature covers: version 2, one line each
// for the header, snapshot_hash, algorithm, key_id, custody, provider and key_valid_from (RFC 3339
// nano, UTC; empty for the instance key); version 1, the 32 bytes of the snapshot hash. It is the
// server's export.ReceiptMessage; a test in cmd/assure signs with the server and verifies here.
func receiptMessage(r receipt) ([]byte, error) {
	switch r.Version {
	case 0, 1:
		digest, err := hex.DecodeString(r.SnapshotHash)
		if err != nil || len(digest) != sha256.Size {
			return nil, errors.New("the receipt's snapshot hash is not 64 hex characters")
		}
		return digest, nil
	case 2:
		from := ""
		if r.KeyValidFrom != nil {
			from = r.KeyValidFrom.UTC().Format(time.RFC3339Nano)
		}
		for _, f := range []string{r.SnapshotHash, r.Algorithm, r.KeyID, r.Custody, r.Provider} {
			if strings.ContainsAny(f, "\r\n") {
				return nil, errors.New("a receipt field contains a line break")
			}
		}
		return []byte(strings.Join([]string{receiptHeader, "snapshot_hash: " + r.SnapshotHash, "algorithm: " + r.Algorithm,
			"key_id: " + r.KeyID, "custody: " + r.Custody, "provider: " + r.Provider, "key_valid_from: " + from}, "\n")), nil
	default:
		return nil, fmt.Errorf("receipt version %d is not one this verifier version knows", r.Version)
	}
}

// verifySpotCheck checks a spot-check artefact: the snapshot hash, then the signature against the
// key list. The key the receipt carries is never trusted by itself: without a key list the
// signature is checked against it for integrity and the check is reported as not made.
func verifySpotCheck(r *Report, data []byte, kr *keyring) {
	var sc spotCheck
	if err := json.Unmarshal(data, &sc); err != nil {
		r.add(SectionSignatures, "spot-check receipt", Fail, "not a spot-check artefact: %v", err)
		return
	}
	canon, err := model.CanonicalJSON(sc.Snapshot)
	if err != nil {
		r.add(SectionSignatures, "snapshot hash", Fail, "the snapshot is not valid JSON: %v", err)
		return
	}
	rc := sc.Receipt
	if got := model.HashBytes(canon); got != rc.SnapshotHash {
		r.add(SectionSignatures, "snapshot hash", Fail, "the snapshot hashes to %s, the receipt names %s", short(got), short(rc.SnapshotHash))
		return
	}
	r.add(SectionSignatures, "snapshot hash", Pass, "sha256 of the canonical snapshot is the receipt's %s", short(rc.SnapshotHash))
	var meta struct {
		ArchID      string    `json:"arch_id"`
		Version     int       `json:"version"`
		GeneratedAt time.Time `json:"generated_at"`
		Evidence    string    `json:"evidence_head"`
	}
	_ = json.Unmarshal(sc.Snapshot, &meta)
	if meta.Evidence != "" {
		r.add(SectionChain, "evidence head", NotChecked, "the snapshot of %s v%d names chain head %s; the chain export is %s",
			oneLine(meta.ArchID), meta.Version, short(meta.Evidence), NotPresent)
	}
	msg, err := receiptMessage(rc)
	if err != nil {
		r.add(SectionSignatures, "receipt signature", Fail, "%v", err)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(rc.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		r.add(SectionSignatures, "receipt signature", Fail, "the signature is not a base64 Ed25519 signature")
		return
	}
	embedded, err := base64.StdEncoding.DecodeString(rc.PublicKey)
	if err != nil || len(embedded) != ed25519.PublicKeySize {
		embedded = nil
	}
	if kr == nil {
		if embedded != nil && ed25519.Verify(embedded, msg, sig) && KeyID(embedded) == rc.KeyID {
			r.add(SectionSignatures, "receipt signature", NotChecked,
				"key list %s: the signature verifies against the key the receipt carries (%s), which shows integrity only, not who signed; pass --keys with a saved GET /evidence/keys", NotPresent, rc.KeyID)
			return
		}
		r.add(SectionSignatures, "receipt signature", Fail, "the signature does not verify even against the key the receipt carries")
		return
	}
	if k, ok := kr.keys[rc.KeyID]; ok && rc.PublicKey != "" && k.PublicKey != rc.PublicKey {
		r.add(SectionSignatures, "receipt signature", Fail, "the receipt carries another public key than the listed key %s", rc.KeyID)
		return
	}
	if err := kr.verify("spot-check receipt", rc.KeyID, msg, sig, meta.GeneratedAt); err != nil {
		r.add(SectionSignatures, "receipt signature", Fail, "%v", err)
		return
	}
	k := kr.keys[rc.KeyID]
	// What the receipt states about its key must be the listed key's (the server's matchPublished):
	// signed in a version 2 receipt, an unverified statement a version 1 receipt may omit.
	signed := rc.Version >= 2
	var problem string
	switch {
	case signed && rc.Custody != CustodyVendor && rc.Custody != CustodyCustomer:
		problem = fmt.Sprintf("the receipt states custody %q, neither vendor nor customer", rc.Custody)
	case signed && rc.Provider == "":
		problem = "the receipt names no provider"
	case k.Custody != "" && (rc.Custody != "" || signed) && rc.Custody != k.Custody:
		problem = fmt.Sprintf("the receipt states custody %q, the key list %q", rc.Custody, k.Custody)
	case k.Provider != "" && (rc.Provider != "" || signed) && rc.Provider != k.Provider:
		problem = fmt.Sprintf("the receipt states provider %q, the key list %q", rc.Provider, k.Provider)
	case signed && !k.ValidFrom.IsZero() && (rc.KeyValidFrom == nil || !rc.KeyValidFrom.Equal(k.ValidFrom)):
		problem = "the receipt's key_valid_from is not the listed key's valid_from"
	}
	if problem != "" {
		r.add(SectionSignatures, "receipt custody", Fail, "%s", problem)
		return
	}
	r.add(SectionSignatures, "receipt signature", Pass, "receipt v%d by key %s over the snapshot generated %s, inside the key's validity window",
		max(rc.Version, 1), rc.KeyID, meta.GeneratedAt.UTC().Format(time.RFC3339))
}
