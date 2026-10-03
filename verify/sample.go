package verify

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Sampling with a recorded method (docs/18 WS-F F2, ADR-089 §5).
//
// A reviewer tests attestations and artefacts by sample: the rule results are re-testable at
// 100 % offline (`assure verify` re-runs the rules), the records and their artefacts are not. The
// reviewer supplies a seed (method random_seeded) or a list of clause ids (method list), and
// optional strata (regime, AI Act tier, worst finding severity, record provenance); the product
// emits sample.json from the bundle's own members (population.json, report.json, custody.json,
// patches.json, reviews.json, chain.json). SampleBundle is the one function that draws it: the
// server (POST /architectures/{id}/samples) runs it on the stored bundle, and `assure sample`
// runs it on the downloaded zip, so the two produce the same bytes for the same input.
//
// The draw is deterministic and documented: every candidate row's key is
// sha256(seed + "\n" + clause_id + "\n" + regime) in hex; the rows with the smallest keys are
// drawn. sample.json carries no time and no identity of who drew it, so a reproduction is a byte
// comparison; the server records who drew it and when beside the sheet (its signature envelope).

// SampleSchema names the shape of sample.json.
const SampleSchema = "sixi-assure/sample/v1"

// Sampling methods.
const (
	SampleRandomSeeded = "random_seeded"
	SampleList         = "list"
)

// Bounds of one sample.
const (
	MaxSampleSize   = 500
	maxSeedLength   = 200
	maxStratumValue = 100
)

// Bundle members the sample reads beside the verifier's own (the reviewer bundle writes them).
const (
	MemberPopulation = "population.json"
	MemberCustody    = "custody.json"
	MemberPatches    = "patches.json"
	MemberReviews    = "reviews.json"
	// MemberSample is the latest sample sheet a later bundle carries, with MemberSampleSig beside it.
	MemberSample    = "sample.json"
	MemberSampleSig = "sample.json.sig"
)

// Strata values that are not a declared value.
const (
	StratumNone        = "none"         // severity: no finding cites the clause; provenance: no record
	StratumNotDeclared = "not_declared" // tier: the architecture declares no AI Act tier
	ProvenanceDeclared = "declared"     // a person recorded it
	ProvenanceImported = "imported"     // an evidence import recorded it (a file another tool signed or not)
)

// ErrSample is a sample that cannot be drawn from this input with these parameters.
var ErrSample = errors.New("sample")

// SampleStrata restrict the population before the draw; an empty list does not restrict.
type SampleStrata struct {
	Regime     []string `json:"regime"`
	Tier       []string `json:"tier"`
	Severity   []string `json:"severity"`
	Provenance []string `json:"provenance"`
}

// SampleParams are what the reviewer supplies.
type SampleParams struct {
	Method string
	Seed   string
	List   []string
	Strata SampleStrata
	Size   int
}

// Normalise trims, sorts and de-duplicates the parameters and checks them.
func (p SampleParams) Normalise() (SampleParams, error) {
	out := SampleParams{Method: strings.TrimSpace(p.Method), Seed: p.Seed, Size: p.Size}
	clean := func(xs []string) []string {
		set := []string{}
		for _, x := range xs {
			if x = strings.TrimSpace(x); x != "" && !slices.Contains(set, x) {
				set = append(set, x)
			}
		}
		sort.Strings(set)
		return set
	}
	out.Strata = SampleStrata{Regime: clean(p.Strata.Regime), Tier: clean(p.Strata.Tier),
		Severity: clean(p.Strata.Severity), Provenance: clean(p.Strata.Provenance)}
	for _, xs := range [][]string{out.Strata.Regime, out.Strata.Tier, out.Strata.Severity, out.Strata.Provenance} {
		if len(xs) > maxStratumValue {
			return out, fmt.Errorf("%w: a stratum lists at most %d values", ErrSample, maxStratumValue)
		}
		for _, x := range xs {
			if len(x) > 200 || strings.ContainsAny(x, "\r\n") {
				return out, fmt.Errorf("%w: a stratum value is one line of at most 200 characters", ErrSample)
			}
		}
	}
	switch out.Method {
	case SampleRandomSeeded:
		if strings.TrimSpace(out.Seed) == "" || len(out.Seed) > maxSeedLength || strings.ContainsAny(out.Seed, "\r\n") {
			return out, fmt.Errorf("%w: random_seeded needs a seed of one line, at most %d characters", ErrSample, maxSeedLength)
		}
		if out.Size < 1 || out.Size > MaxSampleSize {
			return out, fmt.Errorf("%w: size is between 1 and %d", ErrSample, MaxSampleSize)
		}
		if len(p.List) > 0 {
			return out, fmt.Errorf("%w: random_seeded takes a seed, not a list", ErrSample)
		}
	case SampleList:
		out.Seed = ""
		out.List = clean(p.List)
		if len(out.List) == 0 || len(out.List) > MaxSampleSize {
			return out, fmt.Errorf("%w: list names between 1 and %d clause ids", ErrSample, MaxSampleSize)
		}
		for _, x := range out.List {
			if len(x) > 200 || strings.ContainsAny(x, "\r\n") {
				return out, fmt.Errorf("%w: a listed clause id is one line of at most 200 characters", ErrSample)
			}
		}
		if p.Seed != "" {
			return out, fmt.Errorf("%w: list takes clause ids, not a seed", ErrSample)
		}
		if out.Size != 0 && out.Size != len(out.List) {
			return out, fmt.Errorf("%w: the size of a list sample is the number of clause ids listed (%d)", ErrSample, len(out.List))
		}
		out.Size = len(out.List)
	default:
		return out, fmt.Errorf("%w: method is random_seeded or list", ErrSample)
	}
	return out, nil
}

// SampleDoc is sample.json.
type SampleDoc struct {
	Schema   string       `json:"schema"`
	BundleID string       `json:"bundle_id"`
	ArchID   string       `json:"arch_id"`
	Version  int          `json:"version"`
	Method   string       `json:"method"`
	Seed     string       `json:"seed,omitempty"`
	List     []string     `json:"list,omitempty"`
	Strata   SampleStrata `json:"strata"`
	// Size is what the reviewer asked for; Drawn is how many rows the stratum held up to it.
	Size           int           `json:"size"`
	Drawn          int           `json:"drawn"`
	PopulationHash string        `json:"population_hash"`
	PopulationSize int           `json:"population_size"`
	StratumSize    int           `json:"stratum_size"`
	Selection      string        `json:"selection"`
	Hashes         SampleHashes  `json:"hashes"`
	Rows           []SampleRow   `json:"rows"`
	NotInPop       []string      `json:"not_in_population"`
	Patches        []SamplePatch `json:"accepted_patches"`
	// PatchScope says whether the bundle lets rows be scoped to their elements: PatchScopeElement
	// (patches.json states element_ids on every record) or PatchScopeArchitecture (it does not, so
	// every row lists every accepted patch of the architecture). Each row states its own scope
	// (SampleRow.PatchScope): a row without elements is architecture-scoped on any sheet.
	PatchScope string      `json:"patch_scope"`
	Decisions  []SampleDec `json:"design_review_decisions"`
	Note       string      `json:"note"`
}

// Patch scopes of a sample sheet (SampleDoc.PatchScope).
const (
	PatchScopeElement      = "element"
	PatchScopeArchitecture = "architecture"
)

// SampleHashes are the hashes an independent review statement names (ADR-089 §5): the model, the
// chain head, the findings and the ledger (population) the sample was drawn from.
type SampleHashes struct {
	ModelHash    string `json:"model_hash"`
	SnapshotHash string `json:"snapshot_hash"`
	ChainHead    string `json:"chain_head"`
	FindingsHash string `json:"findings_hash"`
	LedgerHash   string `json:"ledger_hash"`
}

// SampleRow is one drawn obligation.
type SampleRow struct {
	ClauseID   string `json:"clause_id"`
	Regime     string `json:"regime"`
	Tier       string `json:"tier"`
	Severity   string `json:"severity"`
	Provenance string `json:"provenance"`
	// Key is the draw key (random_seeded) so the order can be checked by hand.
	Key        string         `json:"key,omitempty"`
	RuleResult SampleRule     `json:"rule_result"`
	Record     *SampleRecord  `json:"record"`
	Custody    *SampleCustody `json:"artefact_custody"`
	Recorder   string         `json:"recorder"`
	Patches    []int          `json:"accepted_patch_versions"`
	// PatchScope is how this row's accepted_patch_versions were chosen: PatchScopeElement (the
	// versions whose patch touched one of the row's elements) when the sheet is element-scoped and
	// the row names elements; PatchScopeArchitecture (every accepted patch) otherwise. A row names
	// elements only through the report's open findings and accepted risks, so a clause with none,
	// including one whose last finding a patch just fixed, would otherwise list no patch at all.
	PatchScope string          `json:"patch_scope"`
	Decisions  []string        `json:"design_review_decision_ids"`
	Elements   []string        `json:"element_ids"`
	Findings   []SampleFinding `json:"findings"`
}

// SampleRule is the rules' result for the obligation at the chain head.
type SampleRule struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// SampleFinding is one finding that cites the clause.
type SampleFinding struct {
	ID       string   `json:"id"`
	RuleID   string   `json:"rule_id"`
	Severity string   `json:"severity"`
	Status   string   `json:"status"`
	Elements []string `json:"element_ids"`
}

// SampleRecord is the obligation's latest evidence record.
type SampleRecord struct {
	ID         string `json:"id"`
	Hash       string `json:"hash"`
	Decision   string `json:"decision,omitempty"`
	RecordedAt string `json:"recorded_at,omitempty"`
	Signer     string `json:"external_signer,omitempty"`
	Signature  string `json:"signature,omitempty"`
	OnChain    bool   `json:"on_chain"`
}

// SampleCustody is where the record's artefact is kept, as recorded.
type SampleCustody struct {
	ArtefactHash   string `json:"artefact_hash"`
	Location       string `json:"location"`
	Custodian      string `json:"custodian"`
	SystemOfRecord string `json:"system_of_record"`
}

// SamplePatch is one accepted patch of the architecture.
type SamplePatch struct {
	Version    int    `json:"version"`
	ActorID    string `json:"actor_id"`
	ProposalID string `json:"proposal_id,omitempty"`
	BeforeHash string `json:"before_hash"`
	AfterHash  string `json:"after_hash"`
	AcceptedAt string `json:"accepted_at"`
	// ElementIDs are the elements the patch touched, when patches.json states them.
	ElementIDs []string `json:"element_ids,omitempty"`
}

// SampleDec is one design-review decision (ADR-082).
type SampleDec struct {
	ID        string `json:"id"`
	ReviewID  string `json:"review_id"`
	Version   int    `json:"version"`
	Decision  string `json:"decision"`
	Role      string `json:"role"`
	UserID    string `json:"user_id"`
	DecidedAt string `json:"decided_at"`
}

// sampleNote is sample.json's note.
const sampleNote = "A sample of the obligation population at the chain head, drawn by the method above from this bundle's " +
	"members. Rule results are re-testable at 100 % offline (assure verify re-runs the rules); sampling targets the records " +
	"and their artefacts, which stay with the customer. Selection: every row of the stratum gets the key " +
	"sha256(seed + \"\\n\" + clause_id + \"\\n\" + regime) and the rows with the smallest keys are drawn (random_seeded), or " +
	"the listed clause ids are taken (list). Each row names accepted patches by version and states its patch_scope: " +
	"\"element\", the versions whose patch touched an element of the row (patches.json element_ids); \"architecture\", every " +
	"accepted patch of the architecture. A row is element-scoped only when every patches.json record states its element_ids " +
	"and the row names elements; a row names elements only through the report's open findings and accepted risks, so a row " +
	"with none (a clause no open finding cites, including one whose last finding an accepted patch fixed) is " +
	"architecture-scoped. The sheet's patch_scope says whether patches.json states element_ids on every record. " +
	"Design-review decisions are of whole versions and are listed on every row. A status is what the rules and " +
	"records show, not a statement of compliance."

// SampleZip draws a sample from a bundle zip held in memory (the server's stored bundle).
func SampleZip(raw []byte, p SampleParams) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: not a readable zip: %w", ErrSample, err)
	}
	if len(zr.File) > maxMembers {
		return nil, fmt.Errorf("%w: the zip holds more than %d members", ErrSample, maxMembers)
	}
	return SampleBundle(bundleRoot(zr), p)
}

// SampleFile draws a sample from a bundle directory or zip on disk (`assure sample`).
func SampleFile(p string, params SampleParams) ([]byte, error) {
	src, err := open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	if !src.bundle() {
		return nil, fmt.Errorf("%w: %s is not a reviewer bundle (a directory or a .zip)", ErrInput, p)
	}
	return SampleBundle(src.fsys, params)
}

// sampleSource reads members, checking each against the manifest when there is one.
type sampleSource struct {
	fsys   fs.FS
	listed map[string]string
}

func (s sampleSource) read(name string, required bool) ([]byte, error) {
	f, err := s.fsys.Open(path.Clean(name))
	if errors.Is(err, fs.ErrNotExist) {
		if required {
			return nil, fmt.Errorf("%w: the bundle has no %s", ErrSample, name)
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxMember+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMember {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrSample, name, maxMember)
	}
	if s.listed != nil {
		want, ok := s.listed[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s is not listed in the bundle's manifest", ErrSample, name)
		}
		if got := model.HashBytes(data); got != want {
			return nil, fmt.Errorf("%w: %s hashes to %s, the manifest lists %s", ErrSample, name, short(got), short(want))
		}
	}
	return data, nil
}

// Shapes the sample reads (the reviewer bundle writes them; unknown fields are ignored).
type (
	samplePopulation struct {
		ArchID  string `json:"arch_id"`
		Version int    `json:"version"`
		Rows    []struct {
			ClauseID         string `json:"clause_id"`
			Regime           string `json:"regime"`
			Status           string `json:"status"`
			Reason           string `json:"reason"`
			LatestRecordID   string `json:"latest_record_id"`
			LatestRecordHash string `json:"latest_record_hash"`
			Decision         string `json:"decision"`
		} `json:"obligations"`
	}
	sampleReportFinding struct {
		ID       string `json:"id"`
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Status   string `json:"status"`
		Elements []struct {
			ID string `json:"id"`
		} `json:"elements"`
		Clauses []struct {
			ID string `json:"id"`
		} `json:"clauses"`
	}
	sampleReport struct {
		Architecture struct {
			ID      string `json:"id"`
			Version int    `json:"version"`
			Hash    string `json:"hash"`
			Tier    string `json:"ai_act_tier"`
		} `json:"architecture"`
		SnapshotHash  string                `json:"snapshot_hash"`
		ChainHead     string                `json:"chain_head"`
		EvidenceHead  string                `json:"evidence_head"`
		Findings      json.RawMessage       `json:"findings"`
		AcceptedRisks []sampleReportFinding `json:"accepted_risks"`
	}
	sampleCustodyDoc struct {
		Records []struct {
			RecordID       string `json:"record_id"`
			ArtefactHash   string `json:"artefact_hash"`
			Location       string `json:"location"`
			Custodian      string `json:"custodian"`
			SystemOfRecord string `json:"system_of_record"`
			// ExternalSigner is the record row's signer name (docs/18 E2: no longer on the chain payload).
			ExternalSigner *string `json:"external_signer"`
		} `json:"records"`
	}
	samplePatchesDoc struct {
		Patches []struct {
			Version    int       `json:"version"`
			ActorID    string    `json:"actor_id"`
			ProposalID string    `json:"proposal_id"`
			BeforeHash string    `json:"before_hash"`
			AfterHash  string    `json:"after_hash"`
			AcceptedAt time.Time `json:"accepted_at"`
			// ElementIDs are the elements the patch touched; nil when patches.json does not state
			// them (a bundle from before export/bundle.go wrote them, or a patch it could not read).
			ElementIDs *[]string `json:"element_ids"`
		} `json:"patches"`
	}
	sampleReviewsDoc struct {
		Reviews []struct {
			ID        string `json:"id"`
			Version   int    `json:"version"`
			Decisions []struct {
				ID        string `json:"id"`
				UserID    string `json:"user_id"`
				Role      string `json:"role"`
				Decision  string `json:"decision"`
				DecidedAt string `json:"decided_at"`
			} `json:"decisions"`
		} `json:"reviews"`
	}
	sampleChain struct {
		Events []struct {
			ID      string          `json:"id"`
			Type    string          `json:"type"`
			Actor   string          `json:"actor"`
			TS      time.Time       `json:"ts"`
			Payload json.RawMessage `json:"payload"`
		} `json:"events"`
	}
)

// severityRank orders finding severities, worst first.
var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

// SampleBundle draws a sample from a reviewer bundle's members (see the file comment).
func SampleBundle(fsys fs.FS, params SampleParams) ([]byte, error) {
	p, err := params.Normalise()
	if err != nil {
		return nil, err
	}
	src := sampleSource{fsys: fsys}
	var manifest struct {
		BundleID string `json:"bundle_id"`
		ArchID   string `json:"arch_id"`
		Version  int    `json:"version"`
		Items    []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"items"`
	}
	if raw, err := src.read(MemberManifest, false); err != nil {
		return nil, err
	} else if raw != nil {
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return nil, fmt.Errorf("%w: manifest.json: %w", ErrSample, err)
		}
		src.listed = map[string]string{}
		for _, it := range manifest.Items {
			src.listed[path.Clean(it.Path)] = it.SHA256
		}
	}

	popRaw, err := src.read(MemberPopulation, true)
	if err != nil {
		return nil, err
	}
	var pop samplePopulation
	if err := json.Unmarshal(popRaw, &pop); err != nil {
		return nil, fmt.Errorf("%w: population.json: %w", ErrSample, err)
	}
	repRaw, err := src.read(MemberReport, true)
	if err != nil {
		return nil, err
	}
	var rep sampleReport
	if err := json.Unmarshal(repRaw, &rep); err != nil {
		return nil, fmt.Errorf("%w: report.json: %w", ErrSample, err)
	}
	var findings []sampleReportFinding
	findingsHash := ""
	if len(rep.Findings) > 0 {
		if err := json.Unmarshal(rep.Findings, &findings); err != nil {
			return nil, fmt.Errorf("%w: report.json findings: %w", ErrSample, err)
		}
		canon, err := model.CanonicalJSON(rep.Findings)
		if err != nil {
			return nil, fmt.Errorf("%w: report.json findings: %w", ErrSample, err)
		}
		findingsHash = model.HashBytes(canon)
	}
	var custody sampleCustodyDoc
	var patches samplePatchesDoc
	var reviews sampleReviewsDoc
	var chain sampleChain
	for _, m := range []struct {
		name string
		into any
	}{{MemberCustody, &custody}, {MemberPatches, &patches}, {MemberReviews, &reviews}, {MemberChain, &chain}} {
		raw, err := src.read(m.name, false)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			continue
		}
		if err := json.Unmarshal(raw, m.into); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrSample, m.name, err)
		}
	}

	doc := SampleDoc{Schema: SampleSchema, BundleID: manifest.BundleID, ArchID: firstNonEmpty(manifest.ArchID, pop.ArchID, rep.Architecture.ID),
		Version: firstPositive(manifest.Version, pop.Version, rep.Architecture.Version), Method: p.Method, Seed: p.Seed, List: p.List,
		Strata: p.Strata, Size: p.Size, PopulationHash: model.HashBytes(popRaw), PopulationSize: len(pop.Rows),
		Rows: []SampleRow{}, NotInPop: []string{}, Patches: []SamplePatch{}, Decisions: []SampleDec{}, Note: sampleNote,
		Hashes: SampleHashes{ModelHash: rep.Architecture.Hash, SnapshotHash: rep.SnapshotHash,
			ChainHead: firstNonEmpty(rep.ChainHead, rep.EvidenceHead), FindingsHash: findingsHash, LedgerHash: model.HashBytes(popRaw)}}
	// docs/18 F2 asks, per row, for the accepted patches touching the row's elements. That needs the
	// elements each patch touched in patches.json (element_ids per record). Where every record
	// states them, a row lists only the versions that touched one of its elements; otherwise every
	// accepted patch of the architecture, and the sheet says so (patch_scope).
	// export/bundle.go writes element_ids per patchRecord from the stored ops (ADR-089 Action 4); a
	// bundle from before that, or with a patch it could not read, has patch_scope "architecture".
	versions := []int{}
	touched := map[int][]string{}
	doc.PatchScope = PatchScopeElement
	for _, pt := range patches.Patches {
		sp := SamplePatch{Version: pt.Version, ActorID: pt.ActorID, ProposalID: pt.ProposalID,
			BeforeHash: pt.BeforeHash, AfterHash: pt.AfterHash, AcceptedAt: rfc3339(pt.AcceptedAt)}
		if pt.ElementIDs == nil {
			doc.PatchScope = PatchScopeArchitecture
		} else {
			ids := slices.Clone(*pt.ElementIDs)
			sort.Strings(ids)
			ids = slices.Compact(ids)
			sp.ElementIDs, touched[pt.Version] = ids, ids
		}
		doc.Patches = append(doc.Patches, sp)
		versions = append(versions, pt.Version)
	}
	sort.Ints(versions)
	if len(patches.Patches) == 0 {
		doc.PatchScope = PatchScopeElement // no patch, so none touches any element
	}
	// patchesOf returns a row's accepted patch versions and their scope. A row without elements gets every
	// accepted patch (architecture): its elements come only from the report's open findings and accepted
	// risks, so element scope would silently drop the patch that fixed its last finding (review 3b).
	patchesOf := func(elements []string) ([]int, string) {
		if doc.PatchScope == PatchScopeArchitecture || len(elements) == 0 {
			return slices.Clone(versions), PatchScopeArchitecture
		}
		out := []int{}
		for _, v := range versions {
			for _, e := range touched[v] {
				if _, found := slices.BinarySearch(elements, e); found {
					out = append(out, v)
					break
				}
			}
		}
		return out, PatchScopeElement
	}
	decIDs := []string{}
	for _, rv := range reviews.Reviews {
		for _, d := range rv.Decisions {
			doc.Decisions = append(doc.Decisions, SampleDec{ID: d.ID, ReviewID: rv.ID, Version: rv.Version, Decision: d.Decision,
				Role: d.Role, UserID: d.UserID, DecidedAt: d.DecidedAt})
			decIDs = append(decIDs, d.ID)
		}
	}
	sort.Strings(decIDs)
	sort.SliceStable(doc.Decisions, func(i, j int) bool { return doc.Decisions[i].ID < doc.Decisions[j].ID })

	byClause := map[string][]SampleFinding{}
	for _, f := range append(slices.Clone(findings), rep.AcceptedRisks...) {
		sf := SampleFinding{ID: f.ID, RuleID: f.RuleID, Severity: f.Severity, Status: f.Status, Elements: []string{}}
		for _, e := range f.Elements {
			sf.Elements = append(sf.Elements, e.ID)
		}
		sort.Strings(sf.Elements)
		seen := map[string]bool{}
		for _, c := range f.Clauses {
			if !seen[c.ID] {
				seen[c.ID] = true
				byClause[c.ID] = append(byClause[c.ID], sf)
			}
		}
	}
	custodyOf := map[string]SampleCustody{}
	rowSigner := map[string]string{}
	for _, c := range custody.Records {
		if c.ArtefactHash != "" { // custody.json also lists records without an artefact, for their row (docs/18 E2)
			custodyOf[c.RecordID] = SampleCustody{ArtefactHash: c.ArtefactHash, Location: c.Location, Custodian: c.Custodian, SystemOfRecord: c.SystemOfRecord}
		}
		if c.ExternalSigner != nil {
			rowSigner[c.RecordID] = *c.ExternalSigner
		}
	}
	type chainRec struct {
		actor, at, signer, signature, sourceClass string
	}
	records := map[string]chainRec{}
	for _, e := range chain.Events {
		if e.Type != "evidence_record" {
			continue
		}
		var pl struct {
			Signer      string `json:"external_signer"`
			Signature   string `json:"signature"`
			SourceClass string `json:"source_class"`
		}
		_ = json.Unmarshal(e.Payload, &pl) // a payload that does not decode carries no provenance
		if pl.Signer == "" {
			// A record made since docs/18 E2 keeps the signer's name in its row, which custody.json carries.
			pl.Signer = rowSigner[e.ID]
		}
		records[e.ID] = chainRec{actor: e.Actor, at: rfc3339(e.TS), signer: pl.Signer, signature: pl.Signature, sourceClass: pl.SourceClass}
	}

	tier := strings.TrimSpace(rep.Architecture.Tier)
	if tier == "" {
		tier = StratumNotDeclared
	}
	type candidate struct {
		row SampleRow
		key string
	}
	var stratum []candidate
	inPop := map[string]bool{}
	for _, r := range pop.Rows {
		inPop[r.ClauseID] = true
		row := SampleRow{ClauseID: r.ClauseID, Regime: r.Regime, Tier: tier, Severity: StratumNone, Provenance: StratumNone,
			RuleResult: SampleRule{Status: r.Status, Reason: r.Reason}, Decisions: slices.Clone(decIDs),
			Elements: []string{}, Findings: []SampleFinding{}}
		elems := map[string]bool{}
		for _, f := range byClause[r.ClauseID] {
			row.Findings = append(row.Findings, f)
			if severityRank[f.Severity] > severityRank[row.Severity] {
				row.Severity = f.Severity
			}
			for _, e := range f.Elements {
				elems[e] = true
			}
		}
		for e := range elems {
			row.Elements = append(row.Elements, e)
		}
		sort.Strings(row.Elements)
		row.Patches, row.PatchScope = patchesOf(row.Elements)
		if r.LatestRecordID != "" {
			rec := &SampleRecord{ID: r.LatestRecordID, Hash: r.LatestRecordHash, Decision: r.Decision}
			if cr, ok := records[r.LatestRecordID]; ok {
				rec.OnChain, rec.RecordedAt, rec.Signer, rec.Signature = true, cr.at, cr.signer, cr.signature
				row.Recorder = cr.actor
				switch {
				case cr.sourceClass != "":
					row.Provenance = cr.sourceClass
				case cr.signer != "" || cr.signature != "":
					row.Provenance = ProvenanceImported
				default:
					row.Provenance = ProvenanceDeclared
				}
			} else {
				row.Provenance = ProvenanceDeclared
			}
			row.Record = rec
			if c, ok := custodyOf[r.LatestRecordID]; ok {
				cc := c
				row.Custody = &cc
			}
		}
		if !inStratum(p.Strata.Regime, row.Regime) || !inStratum(p.Strata.Tier, row.Tier) ||
			!inStratum(p.Strata.Severity, row.Severity) || !inStratum(p.Strata.Provenance, row.Provenance) {
			continue
		}
		stratum = append(stratum, candidate{row: row})
	}
	doc.StratumSize = len(stratum)

	var drawn []SampleRow
	switch p.Method {
	case SampleRandomSeeded:
		doc.Selection = "the rows of the stratum with the smallest sha256(seed + \"\\n\" + clause_id + \"\\n\" + regime), hex"
		for i := range stratum {
			stratum[i].key = drawKey(p.Seed, stratum[i].row.ClauseID, stratum[i].row.Regime)
			stratum[i].row.Key = stratum[i].key
		}
		sort.SliceStable(stratum, func(i, j int) bool { return stratum[i].key < stratum[j].key })
		for i := 0; i < len(stratum) && i < p.Size; i++ {
			drawn = append(drawn, stratum[i].row)
		}
	case SampleList:
		doc.Selection = "the rows of the stratum whose clause id is listed"
		for _, c := range stratum {
			if slices.Contains(p.List, c.row.ClauseID) {
				drawn = append(drawn, c.row)
			}
		}
		for _, id := range p.List {
			if !inPop[id] {
				doc.NotInPop = append(doc.NotInPop, id)
			}
		}
	}
	sort.SliceStable(drawn, func(i, j int) bool {
		if drawn[i].ClauseID != drawn[j].ClauseID {
			return drawn[i].ClauseID < drawn[j].ClauseID
		}
		return drawn[i].Regime < drawn[j].Regime
	})
	if drawn != nil {
		doc.Rows = drawn
	}
	doc.Drawn = len(doc.Rows)
	return marshalSample(doc)
}

// marshalSample is indented JSON with a trailing newline and no HTML escaping: the bytes the
// server signs and `assure sample` prints.
func marshalSample(doc SampleDoc) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawKey is a row's draw key.
func drawKey(seed, clause, regime string) string {
	sum := sha256.Sum256([]byte(seed + "\n" + clause + "\n" + regime))
	return hex.EncodeToString(sum[:])
}

func inStratum(allowed []string, v string) bool {
	return len(allowed) == 0 || slices.Contains(allowed, v)
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func firstPositive(xs ...int) int {
	for _, x := range xs {
		if x > 0 {
			return x
		}
	}
	return 0
}
