package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Options is one verification.
type Options struct {
	// Path is the input: a JSON report, a spot-check receipt, a chain export, or a bundle directory
	// or zip.
	Path string
	// KeysFile is a saved GET /evidence/keys; it takes precedence over a bundle's keys.json, which
	// is checked against it.
	KeysFile string
	// RootsFile holds PEM roots for the time-stamp authorities; without it the system roots are
	// used where they are files (Linux, BSD).
	RootsFile string
	// RulesDir holds the rule packs to re-run when the bundle carries none; DefaultRulesDir is
	// tried last.
	RulesDir        string
	DefaultRulesDir string
	// PolicyFile is the policy table (else the one beside the packs, else the built-in defaults).
	PolicyFile string
	// AdvisoriesFile is the rule-pack advisory list (advisories.json).
	AdvisoriesFile string
	// ReviewerKeysFile is the organisation's reviewer key registry obtained out of band (a saved
	// GET /settings/reviewer-keys): the bundle's registry is checked against it (reviewrecord.go).
	ReviewerKeysFile string
	// AllowPackMismatch re-runs the rules even when the combined pack hash is not the report's.
	AllowPackMismatch bool
	// Receipts names reanchor receipts (assure reanchor) to count as anchors of a chain export or bundle,
	// besides the <Path>.reanchor-*.json receipts read from beside the input (receipts.go).
	Receipts []string
	// Now is the verification time (the long-term rule checks the authorities' chains at it);
	// zero means the clock.
	Now time.Time
	// Tool names the command in the output ("assure verify", "assure-check verify").
	Tool string
}

// Run verifies one input. An error is an input it cannot read at all (ErrInput) or an unreadable
// trust input; everything else is a check in the report.
func Run(ctx context.Context, o Options) (*Report, error) {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	tool := o.Tool
	if tool == "" {
		tool = "assure verify"
	}
	src, err := open(o.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	r := &Report{Tool: tool, Version: Version, Input: o.Path, Kind: src.kind, VerifiedAt: now.UTC()}

	ao := anchorOpts{now: now}
	if o.RootsFile != "" {
		data, err := os.ReadFile(filepath.Clean(o.RootsFile)) // #nosec G304 -- the reviewer names the roots file
		if err != nil {
			return nil, fmt.Errorf("%w: --roots: %w", ErrInput, err)
		}
		if ao.roots, err = LoadRoots(data); err != nil {
			return nil, fmt.Errorf("%w: --roots %s: %w", ErrInput, o.RootsFile, err)
		}
		ao.rootsFrom = "the roots in " + o.RootsFile
	} else {
		ao.roots, ao.rootsFrom = systemRoots()
	}

	var userKeys []Key
	if o.KeysFile != "" {
		data, err := os.ReadFile(filepath.Clean(o.KeysFile)) // #nosec G304 -- the reviewer names the key list
		if err != nil {
			return nil, fmt.Errorf("%w: --keys: %w", ErrInput, err)
		}
		if userKeys, err = ParseKeys(data); err != nil {
			return nil, fmt.Errorf("%w: --keys %s: %w", ErrInput, o.KeysFile, err)
		}
	}

	if src.bundle() {
		verifyManifest(r, src)
	}
	var kr *keyring
	if src.kind != KindChain { // a chain export carries no signature
		kr = keysFor(r, src, o.KeysFile, userKeys)
	}

	// Reanchor receipts beside a chain export or a bundle, and those named, count as its anchors.
	var receipts []loadedReceipt
	if src.kind == KindChain || src.bundle() {
		paths, err := receiptPaths(o)
		if err != nil {
			return nil, err
		}
		receipts = loadReceipts(paths)
	} else if len(o.Receipts) > 0 {
		r.add(SectionAnchors, "reanchor receipts", NotChecked, "a %s carries no evidence chain to anchor: the receipts named were not read", src.kind)
	}

	var doc *reportDoc
	var lp *loadedPacks
	switch src.kind {
	case KindSpotCheck:
		verifySpotCheck(r, src.data, kr)
	case KindChain:
		if st := verifyChain(r, src.data); st != nil {
			verifyAnchors(r, src, st, ao, receipts)
		}
	case KindReport:
		doc, lp = verifyReport(ctx, r, src, src.data, src.file+".sig", kr, nil, o)
	default:
		var st *chainState
		if raw, ok, err := src.read(MemberChain); err != nil {
			r.add(SectionChain, MemberChain, Fail, "reading it: %v", err)
		} else if !ok {
			r.add(SectionChain, MemberChain, NotChecked, "the chain export is %s", NotPresent)
		} else if st = verifyChain(r, raw); st != nil {
			verifyAnchors(r, src, st, ao, receipts)
		}
		// Obligation record rows (docs/18 E2): custody.json's rows recompute to the record_sha256 the chain carries.
		checkRecordRows(r, src, st)
		if raw, ok, err := src.read(MemberReport); err != nil {
			r.add(SectionSignatures, MemberReport, Fail, "reading it: %v", err)
		} else if !ok {
			r.add(SectionReproducibility, MemberReport, NotChecked, "the Assurance Report is %s", NotPresent)
		} else {
			doc, lp = verifyReport(ctx, r, src, raw, MemberReportSig, kr, st, o)
		}
		if src.kind == KindBundleZip {
			checkBundleSignature(r, src, kr)
		}
		checkSampleSignature(r, src, kr)
		var oob map[string]string
		if o.ReviewerKeysFile != "" {
			if oob, err = readOutOfBandKeys(o.ReviewerKeysFile); err != nil {
				return nil, fmt.Errorf("%w: --reviewer-keys %s: %w", ErrInput, o.ReviewerKeysFile, err)
			}
		}
		checkReviewRecord(r, src, oob, o.ReviewerKeysFile, doc)
	}

	if src.kind != KindSpotCheck && src.kind != KindChain {
		if o.AdvisoriesFile == "" {
			r.add(SectionAdvisories, "advisories", NotChecked, "the advisory list is %s (pass --advisories advisories.json from the public rules repository)", NotPresent)
		} else {
			data, err := os.ReadFile(filepath.Clean(o.AdvisoriesFile)) // #nosec G304 -- the reviewer names the advisory list
			if err != nil {
				return nil, fmt.Errorf("%w: --advisories: %w", ErrInput, err)
			}
			checkAdvisories(r, data, o.AdvisoriesFile, doc, lp)
		}
	}
	if kr != nil {
		kr.custody(r)
	}
	r.finish()
	return r, nil
}

// keysFor builds the key list: --keys when given (a bundle's keys.json must agree with it), else
// the bundle's keys.json, else none.
func keysFor(r *Report, src *source, keysFile string, user []Key) *keyring {
	var bundled []Key
	if src.bundle() {
		if raw, ok, err := src.read(MemberKeys); err != nil {
			r.add(SectionKeys, MemberKeys, Fail, "reading it: %v", err)
		} else if ok {
			var perr error
			if bundled, perr = ParseKeys(raw); perr != nil {
				r.add(SectionKeys, MemberKeys, Fail, "%v", perr)
				bundled = nil
			}
		}
	}
	switch {
	case user != nil:
		if bundled != nil {
			mine := map[string]string{}
			for _, k := range user {
				mine[k.KeyID] = k.PublicKey
			}
			agree := true
			for _, k := range bundled {
				if pub, ok := mine[k.KeyID]; ok && pub != k.PublicKey {
					r.add(SectionKeys, MemberKeys, Fail, "the bundle lists key %s with another public key than %s", k.KeyID, keysFile)
					agree = false
				}
			}
			if agree {
				r.add(SectionKeys, MemberKeys, Pass, "the bundle's key list agrees with %s, which is the one used", keysFile)
			}
		}
		r.add(SectionKeys, "key list", Info, "%d key(s) from %s", len(user), keysFile)
		return newKeyring(keysFile, user)
	case bundled != nil:
		r.add(SectionKeys, "key list", Info, "%d key(s) from the bundle's own %s; for an independent check pass --keys with the organisation's published GET /evidence/keys",
			len(bundled), MemberKeys)
		return newKeyring("the bundle's "+MemberKeys, bundled)
	default:
		r.add(SectionKeys, "key list", NotChecked, "the key list is %s (pass --keys with a saved GET /evidence/keys): no signature can be checked against a key", NotPresent)
		return nil
	}
}

// verifyReport checks a JSON Assurance Report: its signature, its snapshot, its binding to the chain
// and the corpus, and re-runs the rules.
func verifyReport(ctx context.Context, r *Report, src *source, raw []byte, sigName string, kr *keyring, st *chainState, o Options) (*reportDoc, *loadedPacks) {
	var doc reportDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		r.add(SectionReproducibility, MemberReport, Fail, "not a JSON Assurance Report: %v", err)
		return nil, nil
	}
	r.add(SectionInput, "report", Info, "%s of %s v%d, generated %s (%s)", orNA(doc.Kind), orNA(doc.Architecture.ID), doc.Architecture.Version,
		orNA(doc.GeneratedAt), orNA(doc.Schema))

	sig, ok, err := src.read(sigName)
	switch {
	case err != nil:
		r.add(SectionSignatures, "report signature", Fail, "reading %s: %v", sigName, err)
	case ok:
		checkEnvelope(r, kr, "report", raw, sig, stated{snapshotHash: doc.SnapshotHash, packHash: doc.PackHash,
			corpusHash: doc.CorpusHash, chainHead: doc.chainHead(), keyID: doc.KeyID})
	case doc.SignatureState == "signed" && src.bundle():
		r.add(SectionSignatures, "report signature", Fail, "the report states it is signed by key %s; %s is missing from the bundle", orNA(doc.KeyID), sigName)
	case doc.SignatureState == "signed":
		r.add(SectionSignatures, "report signature", NotChecked, "the report states it is signed by key %s; %s is %s (save GET /exports/{id}/signature beside it)",
			orNA(doc.KeyID), sigName, NotPresent)
	case doc.SignatureState == "":
		r.add(SectionSignatures, "report signature", NotChecked, "the report's signature state is %s (a report from before signed exports)", NotPresent)
	default:
		r.add(SectionSignatures, "report signature", NotChecked, "the report is not signed by Sixi (signature_state %s)", oneLine(doc.SignatureState))
	}

	head := doc.chainHead()
	switch {
	case head == "":
		r.add(SectionChain, "report chain head", NotChecked, "the report's chain head is %s", NotPresent)
	case st == nil:
		r.add(SectionChain, "report chain head", NotChecked, "the report names chain head %s; the chain export is %s", short(head), NotPresent)
	default:
		if i, ok := st.hasHash(head); ok {
			r.add(SectionChain, "report chain head", Pass, "the report's chain head %s is event %s of the recomputed chain (position %d of %d)",
				short(head), st.exp.Events[i].ID, i+1, len(st.exp.Events))
		} else {
			r.add(SectionChain, "report chain head", Fail, "the report's chain head %s is not an intact event of this chain", short(head))
		}
	}

	if src.bundle() {
		checkCorpus(r, src, doc.CorpusHash)
	}
	snap := checkSnapshot(r, src, &doc)
	lp := reproduce(ctx, r, src, &doc, snap, reproOpts{rulesDir: o.RulesDir, policyFile: o.PolicyFile,
		defaultRules: o.DefaultRulesDir, allowMismatch: o.AllowPackMismatch})
	return &doc, lp
}

// checkCorpus compares the bundle's corpus records with the report's corpus release hash.
func checkCorpus(r *Report, src *source, want string) {
	raw, ok, err := src.read(MemberCorpus)
	switch {
	case err != nil:
		r.add(SectionReproducibility, "corpus", Fail, "reading %s: %v", MemberCorpus, err)
	case !ok:
		r.add(SectionReproducibility, "corpus", NotChecked, "%s is %s; the report names corpus release %s", MemberCorpus, NotPresent, short(orNA(want)))
	case want == "":
		r.add(SectionReproducibility, "corpus", NotChecked, "the report's corpus release hash is %s", NotPresent)
	default:
		canon, err := model.CanonicalJSON(bytes.TrimSpace(raw))
		switch {
		case err != nil:
			r.add(SectionReproducibility, "corpus", Fail, "%s is not valid JSON", MemberCorpus)
		case model.HashBytes(canon) != want:
			r.add(SectionReproducibility, "corpus", Fail, "%s hashes to %s, the report names corpus release %s", MemberCorpus, short(model.HashBytes(canon)), short(want))
		default:
			r.add(SectionReproducibility, "corpus", Pass, "%s hashes to the report's corpus release %s", MemberCorpus, short(want))
		}
	}
}

// checkBundleSignature verifies the zip's own detached signature (<bundle>.zip.sig beside it).
func checkBundleSignature(r *Report, src *source, kr *keyring) {
	sigPath := src.name + ".sig"
	sig, err := os.ReadFile(filepath.Clean(sigPath)) // #nosec G304 -- beside the bundle the reviewer named
	if errors.Is(err, os.ErrNotExist) {
		r.add(SectionSignatures, "bundle signature", NotChecked, "%s is %s: the zip as a whole is not checked against a signature", filepath.Base(sigPath), NotPresent)
		return
	}
	if err != nil {
		r.add(SectionSignatures, "bundle signature", Fail, "reading %s: %v", filepath.Base(sigPath), err)
		return
	}
	if st, err := os.Stat(src.name); err == nil && st.Size() > maxTotal {
		r.add(SectionSignatures, "bundle signature", Fail, "the bundle is larger than %d bytes", maxTotal)
		return
	}
	data, err := os.ReadFile(filepath.Clean(src.name)) // #nosec G304 -- the bundle the reviewer named
	if err != nil {
		r.add(SectionSignatures, "bundle signature", Fail, "reading the bundle: %v", err)
		return
	}
	checkEnvelope(r, kr, "bundle", data, sig, stated{})
}
