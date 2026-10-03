package verify

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/verify/tsp"
)

// anchorOpts are the trust inputs of the anchor checks.
type anchorOpts struct {
	roots     *x509.CertPool
	rootsFrom string
	now       time.Time
}

// anchorResult is one receipt after its checks.
type anchorResult struct {
	a       chainAnchor
	headIdx int
	status  Status
	detail  string
	info    tsp.TokenInfo
	chain   []byte
	// validNow is whether the authority's chain verifies at the verification time too; expiredAt
	// is when it stopped (zero when it did not expire).
	validNow  bool
	expiredAt time.Time
	// name is the check's name: "anchor <id>", or "reanchor receipt <file>" for a receipt beside the input.
	name string
}

// systemRoots returns the operating system's roots where they are files the verifier can read
// (Linux and the BSDs). On macOS and Windows the system pool is verified through the operating
// system, which may fetch revocation data online, so it is never used: pass --roots there.
func systemRoots() (*x509.CertPool, string) {
	switch runtime.GOOS {
	case "darwin", "ios", "windows", "js", "wasip1", "plan9":
		return nil, ""
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		return nil, ""
	}
	return pool, "the system roots"
}

// LoadRoots reads PEM certificates (one or more) into a pool.
func LoadRoots(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("no PEM certificate in the roots file")
	}
	return pool, nil
}

// pemToDER concatenates the DER of every CERTIFICATE block (what tsp.Verify reads as a chain).
func pemToDER(data []byte) ([]byte, error) {
	var out []byte
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, b.Bytes...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificate in the file")
	}
	return out, nil
}

// verifyAnchors checks every receipt against the chain (position, recomputed head, chain_anchored
// record), its token against the head hash and the authority's chain, the long-term rule, and
// prints the unanchored tail.
//
// The reanchor receipts beside the input (receipts.go) count like the export's own anchors, with no chain_anchored
// record: a receipt for another chain, or one that does not read, fails.
func verifyAnchors(r *Report, src *source, st *chainState, o anchorOpts, offline []loadedReceipt) {
	anchors := okAnchors(st.exp.Anchors)
	receipts := map[string]bool{}
	results := make([]*anchorResult, 0, len(anchors)+len(offline))
	for _, a := range anchors {
		receipts[a.EventID] = true
		res := checkAnchor(src, st, a, o, false)
		res.name = "anchor " + a.ID
		results = append(results, res)
	}
	for _, rc := range offline {
		name := "reanchor receipt " + filepath.Base(rc.path)
		switch {
		case rc.err != nil:
			r.add(SectionAnchors, name, Fail, "%v", rc.err)
			continue
		case rc.archID != "" && st.exp.ArchID != "" && rc.archID != st.exp.ArchID:
			r.add(SectionAnchors, name, Fail, "the receipt anchors architecture %s, not this chain's %s", rc.archID, st.exp.ArchID)
			continue
		}
		res := checkAnchor(src, st, rc.a, o, true)
		res.name = name
		results = append(results, res)
	}
	applyLongTerm(results, o)
	for _, res := range results {
		r.add(SectionAnchors, res.name, res.status, "%s", res.detail)
	}
	for _, e := range st.exp.Events {
		if e.Type == model.EvidenceChainAnchored && !receipts[e.ID] {
			r.add(SectionAnchors, "chain_anchored record "+e.ID, Fail, "the record has no receipt in this export (a receipt was removed)")
		}
	}
	if len(anchors) == 0 {
		r.add(SectionAnchors, "anchors", Info, "the export lists no receipt")
	}
	if len(offline) > 0 {
		r.add(SectionAnchors, "reanchor receipts", Info, "%d receipt(s) of assure reanchor read beside the input or named with --receipts", len(offline))
	}
	r.Unanchored = tailLine(st, results)
	r.add(SectionAnchors, "unanchored tail", Info, "%s", r.Unanchored)
}

// checkAnchor checks one anchor; offline is a reanchor receipt beside the input, which has no chain_anchored record
// and carries its token inline.
func checkAnchor(src *source, st *chainState, a chainAnchor, o anchorOpts, offline bool) *anchorResult {
	res := &anchorResult{a: a, headIdx: -1}
	fail := func(format string, args ...any) *anchorResult {
		res.status, res.detail = Fail, fmt.Sprintf(format, args...)
		return res
	}
	i, found := st.eventAt(a)
	switch {
	case !found:
		return fail("no event at the anchored position (seq %d, event %s)", a.HeadSeq, a.HeadEventID)
	case st.exp.Events[i].ID != a.HeadEventID:
		return fail("the event at seq %d is %s, not the anchored event %s", a.HeadSeq, st.exp.Events[i].ID, a.HeadEventID)
	case st.recomputed[i] != a.HeadHash:
		return fail("the event at seq %d recomputes to %s, not the anchored head %s (chain rewritten after the anchor)", a.HeadSeq, short(st.recomputed[i]), short(a.HeadHash))
	}
	res.headIdx = i
	recordNote := ""
	if offline {
		recordNote = "; a receipt of assure reanchor beside the input (the exported chain holds no chain_anchored record of it)"
	} else if a.EventID == "" {
		recordNote = "; its chain_anchored record id is " + NotPresent
	} else if j, ok := st.byID[a.EventID]; !ok {
		return fail("its chain_anchored record %s is not in the chain", a.EventID)
	} else {
		ev := st.exp.Events[j]
		var p struct {
			HeadHash      string `json:"head_hash"`
			ReceiptSHA256 string `json:"receipt_sha256"`
		}
		if ev.Type != model.EvidenceChainAnchored || j <= i || json.Unmarshal(ev.Payload, &p) != nil || p.HeadHash != a.HeadHash ||
			(a.ReceiptSHA256 != "" && p.ReceiptSHA256 != a.ReceiptSHA256) {
			return fail("its chain_anchored record %s does not match the receipt", a.EventID)
		}
		if a.ReceiptSHA256 == "" {
			a.ReceiptSHA256 = p.ReceiptSHA256
			res.a.ReceiptSHA256 = p.ReceiptSHA256
		}
	}
	token, chain := a.Token, a.CertChain
	if len(token) == 0 {
		data, ok, err := src.read(MemberAnchors + "/" + a.ID + ".tsr")
		if err != nil {
			return fail("reading its token: %v", err)
		}
		if !ok {
			res.status = NotChecked
			res.detail = fmt.Sprintf("its position and record match the recomputed chain (head %s, seq %d)%s; the RFC 3161 token is %s "+
				"(a chain export carries receipt hashes; the reviewer bundle carries anchors/%s.tsr)", short(a.HeadHash), a.HeadSeq, recordNote, NotPresent, a.ID)
			return res
		}
		token = data
	}
	if len(chain) == 0 {
		data, ok, err := src.read(MemberAnchors + "/" + a.ID + ".certs.pem")
		if err != nil {
			return fail("reading its certificates: %v", err)
		}
		if ok {
			if chain, err = pemToDER(data); err != nil {
				return fail("anchors/%s.certs.pem: %v", a.ID, err)
			}
		}
	}
	res.chain = chain
	sum := sha256.Sum256(token)
	if a.ReceiptSHA256 != "" && hex.EncodeToString(sum[:]) != a.ReceiptSHA256 {
		return fail("the token's sha256 %s is not the receipt %s the chain records", short(hex.EncodeToString(sum[:])), short(a.ReceiptSHA256))
	}
	var info tsp.TokenInfo
	var err error
	if o.roots != nil {
		info, err = tsp.Verify(token, chain, a.HeadHash, o.roots)
	} else {
		info, err = tsp.VerifyUnrooted(token, chain, a.HeadHash)
	}
	switch {
	case errors.Is(err, tsp.ErrHashMismatch):
		return fail("the token signs another hash than the anchored head %s (chain rewritten after the anchor)", short(a.HeadHash))
	case errors.Is(err, tsp.ErrUntrusted) && o.roots != nil:
		return fail("the authority's certificate does not chain to %s at the signed time: %v (pass --roots with the authority's root)", o.rootsFrom, err)
	case err != nil:
		return fail("the token does not verify: %v", err)
	}
	res.info = info
	if a.SignedAt != nil && !info.SignedAt.Truncate(time.Microsecond).Equal(a.SignedAt.UTC().Truncate(time.Microsecond)) {
		return fail("the export's signed_at %s is not the token's time %s", a.SignedAt.UTC().Format(time.RFC3339Nano), info.SignedAt.Format(time.RFC3339Nano))
	}
	who := subject(info.Signer)
	if o.roots == nil {
		res.status = NotChecked
		res.detail = fmt.Sprintf("the token signs head %s (seq %d) at %s, signed by %s; the authority's chain to a trusted root is not checked: "+
			"--roots %s and the system roots are not read on %s", short(a.HeadHash), a.HeadSeq, info.SignedAt.Format(time.RFC3339), who, NotPresent, runtime.GOOS)
		return res
	}
	res.validNow, res.expiredAt, err = chainValidAt(info, chain, o.roots, o.now)
	if err != nil {
		return fail("the authority's chain does not verify today (%s): %v", o.now.UTC().Format(time.RFC3339), err)
	}
	res.status = Pass
	res.detail = fmt.Sprintf("the token signs head %s (seq %d, event %s) at %s; signed by %s, chain to %s at the signed time%s",
		short(a.HeadHash), a.HeadSeq, a.HeadEventID, info.SignedAt.Format(time.RFC3339), who, o.rootsFrom, recordNote)
	return res
}

// chainValidAt verifies the authority's chain again at the verification time. An expired chain is
// not an error here: applyLongTerm decides it.
func chainValidAt(info tsp.TokenInfo, chain []byte, roots *x509.CertPool, now time.Time) (bool, time.Time, error) {
	inter := x509.NewCertPool()
	for _, c := range info.Certificates {
		if !c.Equal(info.Signer) {
			inter.AddCert(c)
		}
	}
	if extra, err := x509.ParseCertificates(chain); err == nil {
		for _, c := range extra {
			inter.AddCert(c)
		}
	}
	_, err := info.Signer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}})
	if err == nil {
		return true, time.Time{}, nil
	}
	var cie x509.CertificateInvalidError
	if errors.As(err, &cie) && cie.Reason == x509.Expired && cie.Cert != nil && now.After(cie.Cert.NotAfter) {
		return false, cie.Cert.NotAfter.UTC(), nil
	}
	return false, time.Time{}, err
}

// applyLongTerm is the long-term validation rule (ADR-087 §5, docs/18 A8): an anchor whose
// authority chain has expired by the verification time is accepted when a later anchor, signed
// after it and valid today, signs the same or a later head; its hash commits to every event before
// it. Without one the anchor fails: re-anchor the head (assure reanchor) before the chain expires.
func applyLongTerm(results []*anchorResult, o anchorOpts) {
	for _, res := range results {
		if res.status != Pass || res.validNow {
			continue
		}
		var later *anchorResult
		for _, b := range results {
			if b != res && b.status == Pass && b.validNow && b.headIdx >= res.headIdx && b.info.SignedAt.After(res.info.SignedAt) {
				later = b
				break
			}
		}
		if later == nil {
			res.status = Fail
			res.detail = fmt.Sprintf("%s; but the authority's certificate chain expired on %s and no later anchor valid today (%s) signs this or a later head: "+
				"re-anchor the chain (assure reanchor) and verify again", res.detail, res.expiredAt.Format(time.RFC3339), o.now.UTC().Format(time.RFC3339))
			continue
		}
		res.detail = fmt.Sprintf("%s; long-term: the authority's chain expired on %s, and the later anchor %s (signed %s, valid today) signs head seq %d, at or after this one",
			res.detail, res.expiredAt.Format(time.RFC3339), later.a.ID, later.info.SignedAt.Format(time.RFC3339), later.a.HeadSeq)
	}
}

// tailLine is the sentence about the events after the last anchor that did not fail.
func tailLine(st *chainState, results []*anchorResult) string {
	var last *anchorResult
	for _, res := range results {
		if res.status != Fail && res.headIdx >= 0 && (last == nil || res.headIdx > last.headIdx) {
			last = res
		}
	}
	total := len(st.exp.Events)
	if last == nil {
		return fmt.Sprintf("no anchor in this input: all %d events are unanchored", total)
	}
	after, records := 0, 0
	for _, e := range st.exp.Events[last.headIdx+1:] {
		after++
		if e.Type == model.EvidenceChainAnchored {
			records++
		}
	}
	at := "time " + NotPresent
	switch {
	case !last.info.SignedAt.IsZero():
		at = last.info.SignedAt.UTC().Format(time.RFC3339)
	case last.a.SignedAt != nil:
		at = last.a.SignedAt.UTC().Format(time.RFC3339)
	}
	if after == 0 {
		return fmt.Sprintf("no event after the last anchor %s (%s): the head itself is anchored", last.a.ID, at)
	}
	return fmt.Sprintf("events after %s are unanchored: %d of %d, after anchor %s (head seq %d), of which %d chain_anchored record(s)",
		at, after, total, last.a.ID, last.a.HeadSeq, records)
}

func subject(c *x509.Certificate) string {
	if c == nil {
		return "an unknown signer"
	}
	if c.Subject.CommonName != "" {
		return "CN=" + c.Subject.CommonName
	}
	return c.Subject.String()
}
