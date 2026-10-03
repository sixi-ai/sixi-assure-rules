package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reviewerKey is a key a reviewer or a sponsor holds outside Sixi, and its registry entry.
type reviewerKey struct {
	priv ed25519.PrivateKey
	reg  KeyRegistration
}

func newReviewerKey(t *testing.T, purpose, holder string) reviewerKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, b64, fp, kid, err := ReviewerPublicKey(base64.StdEncoding.EncodeToString(pub))
	require.NoError(t, err)
	return reviewerKey{priv: priv, reg: KeyRegistration{Organisation: "tenant_r", RegistrationID: "rk_" + kid, KeyID: kid, Fingerprint: fp,
		PublicKey: b64, Purpose: purpose, Holder: holder, Registrar: "u_admin", RegisteredAt: t0.Format(time.RFC3339Nano),
		ValidFrom: t0.Format(time.RFC3339Nano)}}
}

func (k reviewerKey) sign(t *testing.T, msg []byte) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.priv, msg))
}

func (k reviewerKey) record(t *testing.T) RecordKey {
	t.Helper()
	msg, err := RegistrationMessage(k.reg)
	require.NoError(t, err)
	return RecordKey{Registration: k.reg, State: KeyActive, AcknowledgedAt: t0.Add(time.Minute).Format(time.RFC3339Nano), Acknowledgement: k.sign(t, msg)}
}

// reviewRecord builds a review record with one acknowledged sponsor key, one acknowledged
// reviewer key, one assertion and one statement bound to it.
func reviewRecord(t *testing.T) (ReviewRecordDoc, reviewerKey, reviewerKey) {
	t.Helper()
	sponsor := newReviewerKey(t, PurposeManagementAssertion, "user:u_sponsor")
	reviewer := newReviewerKey(t, PurposeReview, "user:u_reviewer")
	a := ManagementAssertion{Organisation: "tenant_r", ArchID: "arch_r", Version: 3, ModelHash: "m", BundleID: "exp_b",
		BundleSHA256: strings.Repeat("b", 64), AsOf: "2026-10-01", Sponsor: "COO", KeyID: sponsor.reg.KeyID, Holder: sponsor.reg.Holder,
		Statement: AssertionText("2026-10-01")}
	amsg, err := AssertionMessage(a)
	require.NoError(t, err)
	s := ReviewStatement{Organisation: "tenant_r", ArchID: "arch_r", Function: "internal_audit",
		Independence: Independence{Note: "not involved"}, Qualifications: "CISA", SampleID: "smp_1", SampleHash: strings.Repeat("c", 64),
		Procedures: []string{"re-ran the rules", "inspected 5 artefacts"}, Limitations: "design-time only", Opinion: OpinionExceptions,
		Exceptions: []string{"one artefact missing"}, Standard: "IIA", ModelHash: "m", ChainHead: "h", FindingsHash: "f", LedgerHash: "l",
		AssertionHash: MessageHash(amsg), KeyID: reviewer.reg.KeyID, StatementDate: "2026-10-02"}
	smsg, err := StatementMessage(s)
	require.NoError(t, err)
	at := t0.Add(time.Hour).Format(time.RFC3339Nano)
	return ReviewRecordDoc{Schema: ReviewRecordSchema, Organisation: "tenant_r", ArchID: "arch_r",
		ReviewerKeys: []RecordKey{sponsor.record(t), reviewer.record(t)},
		Assertions: []RecordAssertion{{ID: "ma_1", Assertion: a, Signature: sponsor.sign(t, amsg), SHA256: MessageHash(amsg),
			SubmittedBy: "u_sponsor", SubmittedAt: at, Current: true}},
		Statements: []RecordStatement{{ID: "rs_1", Statement: s, Signature: reviewer.sign(t, smsg), SHA256: MessageHash(smsg),
			SubmittedBy: "u_reviewer", SubmittedAt: at}},
		Note: ReviewRecordNote}, sponsor, reviewer
}

func runReviewRecord(t *testing.T, doc *ReviewRecordDoc, oob string) *Report {
	t.Helper()
	return runReviewRecordWith(t, doc, oob, nil)
}

// reportOf is the part of report.json the review check reads: the architecture and its hash.
func reportOf(archID, hash string) *reportDoc {
	var rep reportDoc
	rep.Architecture.ID, rep.Architecture.Hash = archID, hash
	return &rep
}

// resignAssertion re-hashes and re-signs the first assertion with key k, and re-points the
// statement at it (re-signed with reviewer), so only the mutation under test differs.
func resignAssertion(t *testing.T, d *ReviewRecordDoc, k, reviewer reviewerKey) {
	t.Helper()
	msg, err := AssertionMessage(d.Assertions[0].Assertion)
	require.NoError(t, err)
	d.Assertions[0].SHA256, d.Assertions[0].Signature = MessageHash(msg), k.sign(t, msg)
	d.Statements[0].Statement.AssertionHash = d.Assertions[0].SHA256
	resignStatement(t, d, reviewer)
}

func resignStatement(t *testing.T, d *ReviewRecordDoc, k reviewerKey) {
	t.Helper()
	msg, err := StatementMessage(d.Statements[0].Statement)
	require.NoError(t, err)
	d.Statements[0].SHA256, d.Statements[0].Signature = MessageHash(msg), k.sign(t, msg)
}

func runReviewRecordWith(t *testing.T, doc *ReviewRecordDoc, oob string, rep *reportDoc) *Report {
	t.Helper()
	dir := t.TempDir()
	if doc != nil {
		writeJSON(t, filepath.Join(dir, MemberReviewRecord), doc)
	}
	var keys map[string]string
	if oob != "" {
		var err error
		keys, err = readOutOfBandKeys(oob)
		require.NoError(t, err)
	}
	r := &Report{}
	checkReviewRecord(r, &source{kind: KindBundleDir, name: dir, fsys: os.DirFS(dir)}, keys, oob, rep)
	r.finish()
	return r
}

func TestMessagesAreFormatLineAndCanonicalJSON(t *testing.T) {
	t.Parallel()
	msg, err := StatementMessage(ReviewStatement{Opinion: OpinionUnable})
	require.NoError(t, err)
	first, rest, ok := strings.Cut(string(msg), "\n")
	require.True(t, ok)
	assert.Equal(t, StatementFormat, first)
	assert.Contains(t, rest, `"exceptions":[]`, "nil lists are signed as empty lists")
	assert.NotContains(t, rest, "\n")
	assert.Less(t, strings.Index(rest, `"arch_id"`), strings.Index(rest, `"chain_head"`), "keys are sorted")

	a := AssertionText("2026-10-01")
	assert.Contains(t, a, "as of 2026-10-01")
	for _, w := range []string{"certif", "guarantee", "attest", "compliant", "confirm"} {
		assert.NotContains(t, strings.ToLower(a), w)
	}
}

func TestReviewerPublicKey(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, b64, fp, kid, err := ReviewerPublicKey(base64.StdEncoding.EncodeToString(pub))
	require.NoError(t, err)
	_, b64h, fph, kidh, err := ReviewerPublicKey(strings.ToUpper(hexOf(pub)))
	require.NoError(t, err)
	assert.Equal(t, []string{b64, fp, kid}, []string{b64h, fph, kidh}, "hex and base64 name the same key")
	assert.Equal(t, KeyID(pub), kid)
	for _, bad := range []string{"", "zz", strings.Repeat("a", 63), base64.StdEncoding.EncodeToString([]byte("short"))} {
		_, _, _, _, err := ReviewerPublicKey(bad)
		assert.Error(t, err, bad)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func TestCheckReviewRecord(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(t *testing.T, d *ReviewRecordDoc, sponsor, reviewer reviewerKey)
		rep    *reportDoc // report.json beside the record (nil: absent)
		check  string     // the check that carries the outcome
		want   Status
		detail string
	}{
		{name: "valid statement", check: "independent review record rs_1", want: Pass, detail: "valid against key"},
		{name: "valid assertion", check: "management assertion ma_1", want: Pass, detail: "registered by u_admin on 2026-10-01"},
		{name: "acknowledged key", check: "reviewer key", want: Pass, detail: "acknowledged by its holder"},
		{name: "a statement changed after signing", check: "independent review record rs_1", want: Fail, detail: "hashes to",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, _ reviewerKey) {
				d.Statements[0].Statement.Opinion = OpinionNoExceptions
			}},
		{name: "a statement re-hashed but not re-signed", check: "independent review record rs_1", want: Fail, detail: "does not verify",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, _ reviewerKey) {
				d.Statements[0].Statement.Exceptions = nil
				msg, err := StatementMessage(d.Statements[0].Statement)
				require.NoError(t, err)
				d.Statements[0].SHA256 = MessageHash(msg)
			}},
		{name: "a statement signed with the sponsor's key", check: "independent review record rs_1", want: Fail, detail: "registered for management_assertion",
			mutate: func(t *testing.T, d *ReviewRecordDoc, sponsor, _ reviewerKey) {
				d.Statements[0].Statement.KeyID = sponsor.reg.KeyID
				msg, err := StatementMessage(d.Statements[0].Statement)
				require.NoError(t, err)
				d.Statements[0].SHA256, d.Statements[0].Signature = MessageHash(msg), sponsor.sign(t, msg)
			}},
		{name: "a statement that names another assertion", check: "independent review record rs_1", want: Fail, detail: "not a verified assertion",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, reviewer reviewerKey) {
				d.Statements[0].Statement.AssertionHash = strings.Repeat("0", 64)
				msg, err := StatementMessage(d.Statements[0].Statement)
				require.NoError(t, err)
				d.Statements[0].SHA256, d.Statements[0].Signature = MessageHash(msg), reviewer.sign(t, msg)
			}},
		{name: "an opinion off the closed list", check: "independent review record rs_1", want: Fail, detail: "closed list",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, reviewer reviewerKey) {
				d.Statements[0].Statement.Opinion = "compliant"
				msg, err := StatementMessage(d.Statements[0].Statement)
				require.NoError(t, err)
				d.Statements[0].SHA256, d.Statements[0].Signature = MessageHash(msg), reviewer.sign(t, msg)
			}},
		{name: "submitted after revocation", check: "independent review record rs_1", want: Fail, detail: "revoked",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, _ reviewerKey) {
				d.ReviewerKeys[1].RevokedAt = t0.Add(30 * time.Minute).Format(time.RFC3339Nano)
			}},
		{name: "an unacknowledged key signs nothing", check: "independent review record rs_1", want: Fail, detail: "not an acknowledged key",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, _ reviewerKey) {
				d.ReviewerKeys[1].State, d.ReviewerKeys[1].Acknowledgement = KeyPending, ""
			}},
		{name: "a forged acknowledgement", check: "reviewer key", want: Fail, detail: "acknowledgement does not verify",
			mutate: func(t *testing.T, d *ReviewRecordDoc, sponsor, _ reviewerKey) {
				msg, err := RegistrationMessage(d.ReviewerKeys[1].Registration)
				require.NoError(t, err)
				d.ReviewerKeys[1].Acknowledgement = sponsor.sign(t, msg)
			}},
		{name: "an assertion with other words", check: "management assertion ma_1", want: Fail, detail: "closed-list",
			mutate: func(t *testing.T, d *ReviewRecordDoc, sponsor, _ reviewerKey) {
				d.Assertions[0].Assertion.Statement = "Sixi certifies this design."
				msg, err := AssertionMessage(d.Assertions[0].Assertion)
				require.NoError(t, err)
				d.Assertions[0].SHA256, d.Assertions[0].Signature = MessageHash(msg), sponsor.sign(t, msg)
			}},
		{name: "stale review is shown", check: "independent review record rs_1 currency", want: Info, detail: "stale",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, _ reviewerKey) { d.Statements[0].Stale = true }},
		// The signed records are tied to the bundle they are in (a validly signed record of another
		// architecture or organisation, placed here by whoever signs the bundle, fails).
		{name: "an assertion of another architecture", check: "management assertion ma_1", want: Fail, detail: "not of this bundle",
			mutate: func(t *testing.T, d *ReviewRecordDoc, sponsor, reviewer reviewerKey) {
				d.Assertions[0].Assertion.ArchID = "arch_other"
				resignAssertion(t, d, sponsor, reviewer)
			}},
		{name: "a statement of another organisation", check: "independent review record rs_1", want: Fail, detail: "organisation tenant_other",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, reviewer reviewerKey) {
				d.Statements[0].Statement.Organisation = "tenant_other"
				resignStatement(t, d, reviewer)
			}},
		{name: "a statement of another architecture", check: "independent review record rs_1", want: Fail, detail: "architecture arch_other",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, reviewer reviewerKey) {
				d.Statements[0].Statement.ArchID = "arch_other"
				resignStatement(t, d, reviewer)
			}},
		{name: "a record of another architecture than the report", check: MemberReviewRecord, want: Fail, detail: "this bundle's report.json is of arch_bundle",
			rep: reportOf("arch_bundle", "m")},
		{name: "a statement over another model than its assertion", check: "independent review record rs_1", want: Fail, detail: "the assertion it names over model",
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, reviewer reviewerKey) {
				d.Statements[0].Statement.ModelHash = "m2"
				resignStatement(t, d, reviewer)
			}},
		// The assertion names who held the key, and that is the registry's holder.
		{name: "an assertion naming another holder", check: "management assertion ma_1", want: Fail, detail: "states key holder user:u_architect",
			mutate: func(t *testing.T, d *ReviewRecordDoc, sponsor, reviewer reviewerKey) {
				d.Assertions[0].Assertion.Holder = "user:u_architect"
				resignAssertion(t, d, sponsor, reviewer)
			}},
		{name: "an external holder who is not the declared sponsor", check: "management assertion ma_1", want: Fail, detail: "not the declared sponsor",
			mutate: func(t *testing.T, d *ReviewRecordDoc, sponsor, reviewer reviewerKey) {
				externalSponsor(t, d, sponsor, reviewer, "Head of Lending")
			}},
		{name: "an external holder who is the declared sponsor", check: "management assertion ma_1", want: Pass, detail: "name hash matches the declared sponsor",
			mutate: func(t *testing.T, d *ReviewRecordDoc, sponsor, reviewer reviewerKey) {
				externalSponsor(t, d, sponsor, reviewer, "  coo ")
			}},
		{name: "the assertion's holder reviews their own assertion", check: "independent review record rs_1", want: Fail, detail: "same person",
			mutate: func(t *testing.T, d *ReviewRecordDoc, sponsor, reviewer reviewerKey) {
				d.ReviewerKeys[1].Registration.Holder = sponsor.reg.Holder
				msg, err := RegistrationMessage(d.ReviewerKeys[1].Registration)
				require.NoError(t, err)
				d.ReviewerKeys[1].Acknowledgement = reviewer.sign(t, msg)
			}},
		// Currency is computed against report.json's architecture hash, not taken from the record.
		{name: "currency recomputed: current", check: "independent review record rs_1", want: Pass, detail: "valid against key", rep: reportOf("arch_r", "m")},
		{name: "currency recomputed: stale", check: "independent review record rs_1 currency", want: Info, detail: "report.json states m2",
			rep:    reportOf("arch_r", "m2"),
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, _ reviewerKey) { d.Statements[0].Stale = true }},
		{name: "a record that hides its staleness", check: "independent review record rs_1 currency", want: Flag, detail: "states stale=false",
			rep: reportOf("arch_r", "m2")},
		{name: "a record that claims staleness it does not have", check: "independent review record rs_1 currency", want: Flag, detail: "states stale=true",
			rep:    reportOf("arch_r", "m"),
			mutate: func(t *testing.T, d *ReviewRecordDoc, _, _ reviewerKey) { d.Statements[0].Stale = true }},
		{name: "an assertion marked current over an old model", check: "management assertion ma_1 currency", want: Flag, detail: "marks this assertion current",
			rep: reportOf("arch_r", "m2")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, sponsor, reviewer := reviewRecord(t)
			if tc.mutate != nil {
				tc.mutate(t, &doc, sponsor, reviewer)
			}
			r := runReviewRecordWith(t, &doc, "", tc.rep)
			var c Check
			for _, x := range r.Checks {
				if strings.HasPrefix(x.Name, tc.check) && (tc.check != "reviewer key" || x.Name == "reviewer key "+reviewer.reg.KeyID) {
					c = x
					break
				}
			}
			require.NotEmpty(t, c.Name, "check %s missing: %+v", tc.check, r.Checks)
			assert.Equal(t, tc.want, c.Status, c.Detail)
			assert.Contains(t, c.Detail, tc.detail)
		})
	}
}

// externalSponsor re-registers the sponsor's key to an external holder named name, re-acknowledges
// it and re-signs the assertion (and the statement that names it).
func externalSponsor(t *testing.T, d *ReviewRecordDoc, sponsor, reviewer reviewerKey, name string) {
	t.Helper()
	d.ReviewerKeys[0].Registration.Holder = ExternalHolder(name)
	msg, err := RegistrationMessage(d.ReviewerKeys[0].Registration)
	require.NoError(t, err)
	d.ReviewerKeys[0].Acknowledgement = sponsor.sign(t, msg)
	d.Assertions[0].Assertion.Holder = ExternalHolder(name)
	resignAssertion(t, d, sponsor, reviewer)
}

func TestHolderNameHashNormalises(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"Chief Operating Officer", "  chief   operating\tofficer ", true},
		{"COO", "coo", true},
		{"COO", "CFO", false},
		{"Anna Muster", "Anna Mustermann", false},
	} {
		assert.Equal(t, tc.same, HolderNameHash(tc.a) == HolderNameHash(tc.b), "%q vs %q", tc.a, tc.b)
	}
	assert.Equal(t, "external:"+HolderNameHash("COO"), ExternalHolder("coo"))
	assert.Len(t, HolderNameHash("x"), 64)
}

func TestCheckReviewRecordNamesTheKey(t *testing.T) {
	t.Parallel()
	doc, _, reviewer := reviewRecord(t)
	r := runReviewRecord(t, &doc, "")
	c := checkOf(t, r, SectionReview, "independent review record rs_1")
	assert.Equal(t, "statement of the reviewer (internal_audit, opinion: reviewed, exceptions listed), valid against key "+
		reviewer.reg.Fingerprint+" registered by u_admin on 2026-10-01", c.Detail)
	assert.True(t, r.OK())
}

func TestCheckReviewRecordAbsentOrEmpty(t *testing.T) {
	t.Parallel()
	r := runReviewRecord(t, nil, "")
	assert.Equal(t, Info, checkOf(t, r, SectionReview, "review record").Status)
	assert.Equal(t, ResultVerified, r.Result, "an older bundle without a review record is not incomplete for it")

	empty := ReviewRecordDoc{Schema: ReviewRecordSchema}
	r = runReviewRecord(t, &empty, "")
	assert.Contains(t, checkOf(t, r, SectionReview, "review record").Detail, "no management assertion")

	other := ReviewRecordDoc{Schema: "something/else"}
	r = runReviewRecord(t, &other, "")
	assert.Equal(t, NotChecked, checkOf(t, r, SectionReview, MemberReviewRecord).Status)
}

// The registry obtained out of band is the reader's anchor of trust: a key it lists with another
// fingerprint fails, a key it does not list is flagged.
func TestCheckReviewRecordOutOfBandRegistry(t *testing.T) {
	t.Parallel()
	doc, sponsor, reviewer := reviewRecord(t)
	dir := t.TempDir()
	agree := filepath.Join(dir, "agree.json")
	writeJSON(t, agree, map[string]any{"keys": []map[string]any{
		{"key_id": sponsor.reg.KeyID, "fingerprint": sponsor.reg.Fingerprint},
		{"key_id": reviewer.reg.KeyID, "fingerprint": reviewer.reg.Fingerprint}}})
	r := runReviewRecord(t, &doc, agree)
	assert.True(t, r.OK())
	assert.Zero(t, r.Flagged)

	partial := filepath.Join(dir, "partial.json")
	writeJSON(t, partial, map[string]any{"keys": []map[string]any{{"key_id": sponsor.reg.KeyID, "fingerprint": sponsor.reg.Fingerprint}}})
	r = runReviewRecord(t, &doc, partial)
	assert.Equal(t, 1, r.Flagged)

	wrong := filepath.Join(dir, "wrong.json")
	writeJSON(t, wrong, map[string]any{"keys": []map[string]any{{"key_id": reviewer.reg.KeyID, "fingerprint": strings.Repeat("e", 64)}}})
	r = runReviewRecord(t, &doc, wrong)
	assert.False(t, r.OK())

	_, err := readOutOfBandKeys(filepath.Join(dir, "missing.json"))
	require.Error(t, err)
	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`"nope"`), 0o600))
	_, err = readOutOfBandKeys(bad)
	require.Error(t, err)
}
