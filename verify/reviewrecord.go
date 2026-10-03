package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// The management assertion and the independent review record (docs/18 WS-F F3, F5, F6; ADR-089
// §4 and §5).
//
// Three messages are signed outside Sixi with Ed25519 keys whose public halves an organisation's
// admin registers in its reviewer key registry: the holder's acknowledgement of a registration,
// the sponsor's management assertion over a bundle hash, and the reviewer's review statement.
// Each message is the format line, a newline, and the canonical JSON (sorted keys, no
// insignificant white space) of the fields below. The server builds the same bytes with these
// functions (POST …/message endpoints hand them to the signer), and the offline verifier rebuilds
// them from the bundle's review_record.json. A signature here shows that the holder of a
// registered key signed these words; who the holder is and whether they are independent is what
// the registry and the statement declare, and the verifier leaves that trust to the reader.

// Message formats.
const (
	RegistrationFormat = "sixi-assure/reviewer-key-registration/v1"
	AssertionFormat    = "sixi-assure/management-assertion/v1"
	StatementFormat    = "sixi-assure/review-statement/v1"
)

// MemberReviewRecord is the bundle member that carries the registry, the assertions and the
// review statements of the architecture.
const MemberReviewRecord = "review_record.json"

// ReviewRecordSchema names review_record.json's shape.
const ReviewRecordSchema = "sixi-assure/bundle-review-record/v1"

// SectionReview is the verifier's section for the review record.
const SectionReview = "review"

// Key purposes.
const (
	PurposeReview              = "review"
	PurposeManagementAssertion = "management_assertion"
	// PurposeAttestor is an external signer's key whose detached signature over an obligation record makes it
	// signature_verified (docs/18 E2, ADR-090 §2; obligations.ArtefactSignatureMessage). It signs no review record.
	PurposeAttestor = "attestor"
)

// Registry states.
const (
	KeyPending = "pending"
	KeyActive  = "active"
	KeyRevoked = "revoked"
)

// Review opinions: the closed list of ADR-089 §5.
const (
	OpinionNoExceptions = "reviewed_no_exceptions_noted"
	OpinionExceptions   = "reviewed_exceptions_listed"
	OpinionUnable       = "unable_to_conclude"
)

// OpinionText is how each opinion reads.
var OpinionText = map[string]string{
	OpinionNoExceptions: "reviewed, no exceptions noted",
	OpinionExceptions:   "reviewed, exceptions listed",
	OpinionUnable:       "unable to conclude",
}

// Reviewer functions the customer designates as independent of the development team.
var ReviewerFunctions = []string{"internal_risk", "validation", "internal_audit", "external_reviewer"}

// AssertionText is the closed-list text of the management assertion (ADR-089 §4); asOf is a date
// (YYYY-MM-DD). It says what the sponsor states; it is not a statement of Sixi.
func AssertionText(asOf string) string {
	return "The model represents the design as intended as of " + asOf + "; all known exceptions are in the ledger; " +
		"records were made by the persons named."
}

// KeyRegistration is what the holder of a registered key signs to acknowledge it.
type KeyRegistration struct {
	Organisation   string `json:"organisation"`
	RegistrationID string `json:"registration_id"`
	KeyID          string `json:"key_id"`
	Fingerprint    string `json:"fingerprint"`
	PublicKey      string `json:"public_key"`
	Purpose        string `json:"purpose"`
	// Holder is "user:<id>" for a member of the organisation or "external:<sha256 of the name>".
	Holder       string `json:"holder"`
	Registrar    string `json:"registrar"`
	RegisteredAt string `json:"registered_at"`
	ValidFrom    string `json:"valid_from"`
	ValidTo      string `json:"valid_to"`
}

// ManagementAssertion is what the sponsor signs over a bundle hash.
type ManagementAssertion struct {
	Organisation string `json:"organisation"`
	ArchID       string `json:"arch_id"`
	Version      int    `json:"version"`
	ModelHash    string `json:"model_hash"`
	BundleID     string `json:"bundle_id"`
	BundleSHA256 string `json:"bundle_sha256"`
	AsOf         string `json:"as_of"`
	// Sponsor is the architecture's declared sponsor (schema 1.1 root attribute), as declared.
	Sponsor string `json:"sponsor"`
	KeyID   string `json:"key_id"`
	// Holder is the signing key's registered holder ("user:<id>" or "external:<sha256 of the
	// normalised name>"): the server refuses a key whose holder is not the declared sponsor, and the
	// signature covers who held the key, so the first page and the verifier name the holder, not
	// just the sponsor as declared.
	Holder    string `json:"holder"`
	Statement string `json:"statement"`
}

// Independence is the reviewer's declaration (ADR-089 §5).
type Independence struct {
	InvolvedInDesign   bool   `json:"involved_in_design"`
	CommercialInterest bool   `json:"commercial_interest"`
	RelationshipToSixi bool   `json:"relationship_to_sixi"`
	Note               string `json:"note"`
}

// ReviewStatement is what the reviewer signs (ADR-089 §5).
type ReviewStatement struct {
	Organisation   string       `json:"organisation"`
	ArchID         string       `json:"arch_id"`
	Function       string       `json:"function"`
	Independence   Independence `json:"independence"`
	Qualifications string       `json:"qualifications"`
	SampleID       string       `json:"sample_id"`
	SampleHash     string       `json:"sample_hash"`
	Procedures     []string     `json:"procedures"`
	Limitations    string       `json:"limitations"`
	Opinion        string       `json:"opinion"`
	Exceptions     []string     `json:"exceptions"`
	Standard       string       `json:"standard"`
	ModelHash      string       `json:"model_hash"`
	ChainHead      string       `json:"chain_head"`
	FindingsHash   string       `json:"findings_hash"`
	LedgerHash     string       `json:"ledger_hash"`
	AssertionHash  string       `json:"assertion_hash"`
	KeyID          string       `json:"key_id"`
	StatementDate  string       `json:"statement_date"`
}

// messageOf is the format line, a newline and the canonical JSON of v.
func messageOf(format string, v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	canon, err := model.CanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	return append([]byte(format+"\n"), canon...), nil
}

// RegistrationMessage is the byte string the holder signs to acknowledge a registration.
func RegistrationMessage(r KeyRegistration) ([]byte, error) { return messageOf(RegistrationFormat, r) }

// AssertionMessage is the byte string the sponsor signs.
func AssertionMessage(a ManagementAssertion) ([]byte, error) { return messageOf(AssertionFormat, a) }

// StatementMessage is the byte string the reviewer signs. Nil lists are written as empty lists.
func StatementMessage(s ReviewStatement) ([]byte, error) {
	if s.Procedures == nil {
		s.Procedures = []string{}
	}
	if s.Exceptions == nil {
		s.Exceptions = []string{}
	}
	return messageOf(StatementFormat, s)
}

// MaxStatementJSON bounds the JSON of a review statement as it is stored: review_statements keeps
// length(statement::text) <= 65536 (migrations/00048), and PostgreSQL's jsonb text form adds a space
// after every separator, at most a few hundred for the bounded lists of ReviewStatementInput. A
// statement whose encoding exceeds this is refused before its message is handed out for signing.
const MaxStatementJSON = 65536 - 1024

// NormaliseHolderName is the form of a person's name the registry hashes and compares: white space
// trimmed and collapsed to single spaces, lower case. "Chief  Operating Officer" and "chief operating
// officer" are the same holder.
func NormaliseHolderName(name string) string {
	return strings.ToLower(strings.Join(strings.Fields(name), " "))
}

// HolderNameHash is the hex sha256 of a normalised name: what the registry stores for an external
// holder (holder_name_sha256), and what a declared sponsor must hash to for that holder's key to
// sign the sponsor's assertion.
func HolderNameHash(name string) string {
	sum := sha256.Sum256([]byte(NormaliseHolderName(name)))
	return hex.EncodeToString(sum[:])
}

// ExternalHolder is the registry's holder string for an external person named name.
func ExternalHolder(name string) string { return "external:" + HolderNameHash(name) }

// MessageHash is the sha256 of a signed message (an assertion's hash, which a statement names).
func MessageHash(msg []byte) string { return model.HashBytes(msg) }

// ReviewerPublicKey decodes an Ed25519 public key given as standard base64 (44 characters) or hex
// (64 characters) and returns it with its base64 form, its fingerprint (sha256, hex) and its key id
// (the fingerprint's first 16 characters).
func ReviewerPublicKey(s string) (pub ed25519.PublicKey, b64, fingerprint, keyID string, err error) {
	s = strings.TrimSpace(s)
	var raw []byte
	if len(s) == 2*ed25519.PublicKeySize {
		raw, err = hex.DecodeString(strings.ToLower(s))
	} else {
		raw, err = base64.StdEncoding.DecodeString(s)
	}
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "", "", "", errors.New("not an Ed25519 public key in base64 or hex")
	}
	sum := sha256.Sum256(raw)
	fp := hex.EncodeToString(sum[:])
	return ed25519.PublicKey(raw), base64.StdEncoding.EncodeToString(raw), fp, fp[:16], nil
}

// CheckSignature verifies a standard-base64 Ed25519 signature over msg with a registered key.
func CheckSignature(publicKey string, msg []byte, signature string) error {
	pub, _, _, _, err := ReviewerPublicKey(publicKey)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("the signature is not a base64 Ed25519 signature")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("the Ed25519 signature does not verify against the registered key")
	}
	return nil
}

// ReviewRecordDoc is review_record.json.
type ReviewRecordDoc struct {
	Schema       string            `json:"schema"`
	Organisation string            `json:"organisation"`
	ArchID       string            `json:"arch_id"`
	ReviewerKeys []RecordKey       `json:"reviewer_keys"`
	Assertions   []RecordAssertion `json:"management_assertions"`
	Statements   []RecordStatement `json:"review_statements"`
	Note         string            `json:"note"`
}

// RecordKey is one registry entry as the bundle carries it.
type RecordKey struct {
	Registration    KeyRegistration `json:"registration"`
	State           string          `json:"state"`
	AcknowledgedAt  string          `json:"acknowledged_at,omitempty"`
	Acknowledgement string          `json:"acknowledgement,omitempty"`
	RevokedAt       string          `json:"revoked_at,omitempty"`
}

// RecordAssertion is one management assertion as the bundle carries it.
type RecordAssertion struct {
	ID          string              `json:"id"`
	Assertion   ManagementAssertion `json:"assertion"`
	Signature   string              `json:"signature"`
	SHA256      string              `json:"sha256"`
	SubmittedBy string              `json:"submitted_by"`
	SubmittedAt string              `json:"submitted_at"`
	Current     bool                `json:"current"`
}

// RecordStatement is one review statement as the bundle carries it.
type RecordStatement struct {
	ID          string          `json:"id"`
	Statement   ReviewStatement `json:"statement"`
	Signature   string          `json:"signature"`
	SHA256      string          `json:"sha256"`
	SubmittedBy string          `json:"submitted_by"`
	SubmittedAt string          `json:"submitted_at"`
	Stale       bool            `json:"stale"`
}

// ReviewRecordNote is review_record.json's note.
const ReviewRecordNote = "The reviewer key registry, the management assertions and the independent review records of this " +
	"architecture. Each signature was made outside Sixi with a key an organisation admin registered and its holder " +
	"acknowledged; no private key reaches Sixi. A review record is the statement of the reviewer, not of Sixi: Sixi does " +
	"not accredit reviewers, and independence is declared per review. A record whose model hash is not the current one is " +
	"stale: the model changed after the review."

// RegistrationDate is the day a registration was made, for "registered by <registrar> on <date>".
func RegistrationDate(r KeyRegistration) string {
	if t, err := time.Parse(time.RFC3339Nano, r.RegisteredAt); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	return oneLine(r.RegisteredAt)
}

// ValidAgainst is the verifier's sentence about a signature by a registered key.
func ValidAgainst(r KeyRegistration) string {
	return fmt.Sprintf("valid against key %s registered by %s on %s", r.Fingerprint, oneLine(r.Registrar), RegistrationDate(r))
}

// keyUsableAt reports why a registered key could not have signed at the given time ("" when it could).
func keyUsableAt(k RecordKey, at string) string {
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return "the submission carries no readable time"
	}
	if from, err := time.Parse(time.RFC3339Nano, k.Registration.ValidFrom); err == nil && t.Before(from.Add(-WindowGrace)) {
		return "submitted before the key's valid_from"
	}
	if to, err := time.Parse(time.RFC3339Nano, k.Registration.ValidTo); err == nil && !t.Before(to) {
		return "submitted after the key's valid_to"
	}
	if rev, err := time.Parse(time.RFC3339Nano, k.RevokedAt); err == nil && !t.Before(rev) {
		return "submitted after the key was revoked"
	}
	if ack, err := time.Parse(time.RFC3339Nano, k.AcknowledgedAt); err != nil || t.Before(ack) {
		return "submitted before the holder acknowledged the key"
	}
	return ""
}

// readOutOfBandKeys reads --reviewer-keys: a saved GET /settings/reviewer-keys ({"keys": [...]}),
// a bare array, or a review_record.json; it returns fingerprints by key id.
func readOutOfBandKeys(file string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Clean(file)) // #nosec G304 -- the reviewer names the registry file
	if err != nil {
		return nil, err
	}
	type entry struct {
		KeyID        string          `json:"key_id"`
		Fingerprint  string          `json:"fingerprint"`
		Registration KeyRegistration `json:"registration"`
	}
	var list struct {
		Keys         []entry `json:"keys"`
		ReviewerKeys []entry `json:"reviewer_keys"`
	}
	var entries []entry
	if err := json.Unmarshal(data, &list); err == nil && (list.Keys != nil || list.ReviewerKeys != nil) {
		entries = append(entries, list.Keys...)
		entries = append(entries, list.ReviewerKeys...)
	} else if err := json.Unmarshal(data, &entries); err != nil {
		return nil, errors.New("not a reviewer key list: expected GET /settings/reviewer-keys or a review_record.json")
	}
	out := map[string]string{}
	for _, e := range entries {
		id, fp := e.KeyID, e.Fingerprint
		if id == "" {
			id, fp = e.Registration.KeyID, e.Registration.Fingerprint
		}
		if id != "" && fp != "" {
			out[id] = strings.ToLower(fp)
		}
	}
	return out, nil
}

// checkReviewRecord verifies review_record.json: every acknowledgement, assertion and statement
// signature against the registered key it names; that every signed record is of this bundle's
// organisation and architecture (review_record.json's, the manifest's and report.json's); that an
// assertion's key is held by the holder it signs and, for an external holder, by the declared
// sponsor; that a statement is bound to a verified assertion of the same model and was not signed
// by the assertion's holder; its currency against report.json's architecture hash; and, when
// sample.json is in the bundle, its scope. rep is the bundle's report.json (nil when absent).
func checkReviewRecord(r *Report, src *source, oob map[string]string, oobFrom string, rep *reportDoc) {
	raw, ok, err := src.read(MemberReviewRecord)
	switch {
	case err != nil:
		r.add(SectionReview, MemberReviewRecord, Fail, "reading it: %v", err)
		return
	case !ok:
		r.add(SectionReview, "review record", Info, "%s is %s: the bundle carries no management assertion and no independent review record", MemberReviewRecord, NotPresent)
		return
	}
	var doc ReviewRecordDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		r.add(SectionReview, MemberReviewRecord, Fail, "not a review record: %v", err)
		return
	}
	if doc.Schema != ReviewRecordSchema {
		r.add(SectionReview, MemberReviewRecord, NotChecked, "schema %q is not one verifier %s knows", oneLine(doc.Schema), Version)
		return
	}
	// The record is of this bundle: the architecture review_record.json names is the manifest's and
	// report.json's. A record of another architecture is not this bundle's, whoever signed it.
	var bundleArch, bundleArchFrom string
	if mraw, ok, err := src.read(MemberManifest); err == nil && ok {
		var m struct {
			ArchID string `json:"arch_id"`
		}
		if json.Unmarshal(mraw, &m) == nil && m.ArchID != "" {
			bundleArch, bundleArchFrom = m.ArchID, MemberManifest
		}
	}
	if rep != nil && rep.Architecture.ID != "" {
		if bundleArch != "" && rep.Architecture.ID != bundleArch {
			r.add(SectionReview, MemberReviewRecord, Fail, "%s names architecture %s, %s names %s", MemberManifest, oneLine(bundleArch),
				MemberReport, oneLine(rep.Architecture.ID))
			return
		}
		bundleArch, bundleArchFrom = rep.Architecture.ID, MemberReport
	}
	if bundleArch != "" && doc.ArchID != bundleArch {
		r.add(SectionReview, MemberReviewRecord, Fail, "the record is of architecture %s, this bundle's %s is of %s", oneLine(doc.ArchID),
			bundleArchFrom, oneLine(bundleArch))
		return
	}
	// ownRecord says why a signed record is not of this record's organisation and architecture ("" when it is).
	ownRecord := func(org, arch string) string {
		switch {
		case org != doc.Organisation:
			return fmt.Sprintf("it is of organisation %s, not this record's %s", oneLine(org), oneLine(doc.Organisation))
		case arch != doc.ArchID:
			return fmt.Sprintf("it is of architecture %s, not this record's %s", oneLine(arch), oneLine(doc.ArchID))
		}
		return ""
	}
	currentHash := ""
	if rep != nil {
		currentHash = rep.Architecture.Hash
	}
	keys := map[string]RecordKey{}
	for _, k := range doc.ReviewerKeys {
		reg := k.Registration
		name := "reviewer key " + oneLine(reg.KeyID)
		_, _, fp, kid, err := ReviewerPublicKey(reg.PublicKey)
		switch {
		case err != nil:
			r.add(SectionReview, name, Fail, "%v", err)
			continue
		case fp != reg.Fingerprint || kid != reg.KeyID:
			r.add(SectionReview, name, Fail, "the registered fingerprint or key id is not the hash of the public key")
			continue
		case reg.Organisation != doc.Organisation:
			r.add(SectionReview, name, Fail, "the key is registered in organisation %s, not this record's %s", oneLine(reg.Organisation), oneLine(doc.Organisation))
			continue
		}
		if oob != nil {
			if want, listed := oob[reg.KeyID]; !listed {
				r.add(SectionReview, name, Flag, "key %s is not in %s: its fingerprint is not confirmed out of band", reg.Fingerprint, oobFrom)
			} else if want != reg.Fingerprint {
				r.add(SectionReview, name, Fail, "%s lists key %s with another fingerprint", oobFrom, reg.KeyID)
				continue
			}
		}
		if k.State == KeyPending || k.Acknowledgement == "" {
			r.add(SectionReview, name, Info, "key %s (%s) registered by %s on %s is not acknowledged by its holder: it signs nothing here",
				reg.Fingerprint, oneLine(reg.Purpose), oneLine(reg.Registrar), RegistrationDate(reg))
			continue
		}
		msg, err := RegistrationMessage(reg)
		if err == nil {
			err = CheckSignature(reg.PublicKey, msg, k.Acknowledgement)
		}
		if err != nil {
			r.add(SectionReview, name, Fail, "the holder's acknowledgement does not verify: %v", err)
			continue
		}
		keys[reg.KeyID] = k
		r.add(SectionReview, name, Pass, "key %s (%s) held by %s, registered by %s on %s, acknowledged by its holder's signature on %s; state %s",
			reg.Fingerprint, oneLine(reg.Purpose), oneLine(reg.Holder), oneLine(reg.Registrar), RegistrationDate(reg), oneLine(k.AcknowledgedAt), oneLine(k.State))
	}
	if len(doc.Assertions) == 0 && len(doc.Statements) == 0 {
		r.add(SectionReview, "review record", Info, "the bundle records no management assertion and no independent review record")
		return
	}
	signedBy := func(name, purpose, keyID string, msg []byte, sig, at string) (KeyRegistration, bool) {
		k, ok := keys[keyID]
		switch {
		case !ok:
			r.add(SectionReview, name, Fail, "key %s is not an acknowledged key of the registry in this bundle", oneLine(keyID))
			return KeyRegistration{}, false
		case k.Registration.Purpose != purpose:
			r.add(SectionReview, name, Fail, "key %s is registered for %s, not %s", keyID, oneLine(k.Registration.Purpose), purpose)
			return KeyRegistration{}, false
		}
		if why := keyUsableAt(k, at); why != "" {
			r.add(SectionReview, name, Fail, "key %s: %s", keyID, why)
			return KeyRegistration{}, false
		}
		if err := CheckSignature(k.Registration.PublicKey, msg, sig); err != nil {
			r.add(SectionReview, name, Fail, "%v", err)
			return KeyRegistration{}, false
		}
		return k.Registration, true
	}
	// currency reports a record's currency against report.json's architecture hash, and flags a
	// stored currency that disagrees with it.
	currency := func(name, modelHash string, storedStale bool) {
		if currentHash == "" {
			if storedStale {
				r.add(SectionReview, name+" currency", Info, "stale as %s states it: the model changed after this record (model hash %s); %s is %s, so currency is not recomputed",
					MemberReviewRecord, short(modelHash), MemberReport, NotPresent)
			}
			return
		}
		stale := modelHash != currentHash
		if stale != storedStale {
			r.add(SectionReview, name+" currency", Flag, "%s states stale=%t, but against %s's architecture hash %s the record is stale=%t",
				MemberReviewRecord, storedStale, MemberReport, short(currentHash), stale)
			return
		}
		if stale {
			r.add(SectionReview, name+" currency", Info, "stale: the model changed after this record (model hash %s, %s states %s)",
				short(modelHash), MemberReport, short(currentHash))
		}
	}
	type verifiedAssertion struct {
		modelHash, holder string
	}
	assertions := map[string]verifiedAssertion{}
	for _, a := range doc.Assertions {
		name := "management assertion " + oneLine(a.ID)
		msg, err := AssertionMessage(a.Assertion)
		if err != nil {
			r.add(SectionReview, name, Fail, "%v", err)
			continue
		}
		if MessageHash(msg) != a.SHA256 {
			r.add(SectionReview, name, Fail, "the assertion hashes to %s, the record states %s", short(MessageHash(msg)), short(a.SHA256))
			continue
		}
		if a.Assertion.Statement != AssertionText(a.Assertion.AsOf) {
			r.add(SectionReview, name, Fail, "the assertion's text is not the closed-list text")
			continue
		}
		if why := ownRecord(a.Assertion.Organisation, a.Assertion.ArchID); why != "" {
			r.add(SectionReview, name, Fail, "the signed assertion is not of this bundle: %s", why)
			continue
		}
		reg, ok := signedBy(name, PurposeManagementAssertion, a.Assertion.KeyID, msg, a.Signature, a.SubmittedAt)
		if !ok {
			continue
		}
		if a.Assertion.Holder != reg.Holder {
			r.add(SectionReview, name, Fail, "the assertion states key holder %s, the registry registers key %s to %s",
				oneLine(a.Assertion.Holder), reg.KeyID, oneLine(reg.Holder))
			continue
		}
		binding := "that member is the declared sponsor is the registry's statement, not checked here"
		if ext, found := strings.CutPrefix(reg.Holder, "external:"); found {
			if ext != HolderNameHash(a.Assertion.Sponsor) {
				r.add(SectionReview, name, Fail, "the key's external holder is not the declared sponsor %q (sha256 of the normalised name differs)",
					oneLine(a.Assertion.Sponsor))
				continue
			}
			binding = "the holder's name hash matches the declared sponsor"
		}
		assertions[a.SHA256] = verifiedAssertion{modelHash: a.Assertion.ModelHash, holder: reg.Holder}
		r.add(SectionReview, name, Pass, "signed with management_assertion key held by %s (sponsor as declared: %s; %s) over bundle %s (sha256 %s) as of %s: %s",
			oneLine(reg.Holder), oneLine(a.Assertion.Sponsor), binding, oneLine(a.Assertion.BundleID), short(a.Assertion.BundleSHA256),
			oneLine(a.Assertion.AsOf), ValidAgainst(reg))
		switch {
		case currentHash == "":
		case a.Current && a.Assertion.ModelHash != currentHash:
			r.add(SectionReview, name+" currency", Flag, "%s marks this assertion current, but it is over model %s and %s's architecture hash is %s",
				MemberReviewRecord, short(a.Assertion.ModelHash), MemberReport, short(currentHash))
		case a.Assertion.ModelHash != currentHash:
			r.add(SectionReview, name+" currency", Info, "stale: the model changed after this assertion (model hash %s, %s states %s)",
				short(a.Assertion.ModelHash), MemberReport, short(currentHash))
		}
	}
	var sampleHash string
	if raw, ok, err := src.read(MemberSample); err == nil && ok {
		sampleHash = model.HashBytes(raw)
	}
	for _, s := range doc.Statements {
		name := "independent review record " + oneLine(s.ID)
		msg, err := StatementMessage(s.Statement)
		if err != nil {
			r.add(SectionReview, name, Fail, "%v", err)
			continue
		}
		if MessageHash(msg) != s.SHA256 {
			r.add(SectionReview, name, Fail, "the statement hashes to %s, the record states %s", short(MessageHash(msg)), short(s.SHA256))
			continue
		}
		if _, known := OpinionText[s.Statement.Opinion]; !known {
			r.add(SectionReview, name, Fail, "opinion %q is not on the closed list", oneLine(s.Statement.Opinion))
			continue
		}
		if why := ownRecord(s.Statement.Organisation, s.Statement.ArchID); why != "" {
			r.add(SectionReview, name, Fail, "the signed statement is not of this bundle: %s", why)
			continue
		}
		va, ok := assertions[s.Statement.AssertionHash]
		if !ok {
			r.add(SectionReview, name, Fail, "the statement names assertion %s, which is not a verified assertion of this record", short(s.Statement.AssertionHash))
			continue
		}
		if va.modelHash != s.Statement.ModelHash {
			r.add(SectionReview, name, Fail, "the statement is over model %s, the assertion it names over model %s", short(s.Statement.ModelHash), short(va.modelHash))
			continue
		}
		reg, ok := signedBy(name, PurposeReview, s.Statement.KeyID, msg, s.Signature, s.SubmittedAt)
		if !ok {
			continue
		}
		if reg.Holder == va.holder {
			r.add(SectionReview, name, Fail, "the review key and the assertion's key are held by the same person (%s): no separation between the asserting and the reviewing person",
				oneLine(reg.Holder))
			continue
		}
		r.add(SectionReview, name, Pass, "statement of the reviewer (%s, opinion: %s), %s", oneLine(s.Statement.Function),
			OpinionText[s.Statement.Opinion], ValidAgainst(reg))
		currency(name, s.Statement.ModelHash, s.Stale)
		switch sampleHash {
		case "":
			r.add(SectionReview, name+" scope", Info, "the review's scope is sample %s (sha256 %s); %s is %s", oneLine(s.Statement.SampleID),
				short(s.Statement.SampleHash), MemberSample, NotPresent)
		case s.Statement.SampleHash:
			r.add(SectionReview, name+" scope", Pass, "the review's scope is this bundle's %s (sha256 %s)", MemberSample, short(sampleHash))
		default:
			r.add(SectionReview, name+" scope", Info, "the review's scope is sample %s (sha256 %s), not this bundle's %s",
				oneLine(s.Statement.SampleID), short(s.Statement.SampleHash), MemberSample)
		}
	}
}

// checkSampleSignature verifies sample.json.sig, the organisation's signature over sample.json.
func checkSampleSignature(r *Report, src *source, kr *keyring) {
	data, ok, err := src.read(MemberSample)
	if err != nil {
		r.add(SectionSignatures, "sample signature", Fail, "reading %s: %v", MemberSample, err)
		return
	}
	if !ok {
		return
	}
	sig, ok, err := src.read(MemberSampleSig)
	switch {
	case err != nil:
		r.add(SectionSignatures, "sample signature", Fail, "reading %s: %v", MemberSampleSig, err)
	case !ok:
		r.add(SectionSignatures, "sample signature", NotChecked, "%s is %s: the sample sheet is not signed by the organisation's key", MemberSampleSig, NotPresent)
	default:
		checkEnvelope(r, kr, "sample", data, sig, stated{})
	}
}

// KnownPurpose reports whether p is a registry purpose.
func KnownPurpose(p string) bool {
	return slices.Contains([]string{PurposeReview, PurposeManagementAssertion, PurposeAttestor}, p)
}
