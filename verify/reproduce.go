package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/model/migrate"
	"github.com/sixi-ai/sixi-assure-rules/rules"
)

// reportDoc is the part of the JSON Assurance Report (sixi-assure/assurance-report/v1) the verifier
// reads. Fields added by signed exports (docs/18 A2) are absent from older reports: each check
// that needs one says "not present in this input".
type reportDoc struct {
	Schema       string `json:"schema"`
	Kind         string `json:"kind"`
	GeneratedAt  string `json:"generated_at"`
	Architecture struct {
		ID      string `json:"id"`
		Version int    `json:"version"`
		Hash    string `json:"hash"`
	} `json:"architecture"`
	EvidenceHead    string          `json:"evidence_head"`
	ChainHead       string          `json:"chain_head"`
	SnapshotHash    string          `json:"snapshot_hash"`
	PackHash        string          `json:"pack_hash"`
	PackHashFormat  string          `json:"pack_hash_format"`
	CorpusHash      string          `json:"corpus_hash"`
	KeyID           string          `json:"key_id"`
	Custody         string          `json:"custody"`
	SignatureState  string          `json:"signature_state"`
	SignatureFormat string          `json:"signature_format"`
	Regimes         []string        `json:"regimes"`
	RulePacks       []reportPack    `json:"rule_packs"`
	Summary         reportSummary   `json:"summary"`
	Findings        []reportFinding `json:"findings"`
	AcceptedRisks   []reportFinding `json:"accepted_risks"`
	Snapshot        json.RawMessage `json:"snapshot"`
}

type reportPack struct {
	Pack    string `json:"pack"`
	Version string `json:"version"`
	Hash    string `json:"hash"`
}

type reportSummary struct {
	AcceptedRisks int `json:"accepted_risks"`
}

type reportFinding struct {
	RuleID   string `json:"rule_id"`
	Pack     string `json:"pack"`
	Status   string `json:"status"`
	Elements []struct {
		ID string `json:"id"`
	} `json:"elements"`
}

func (d *reportDoc) chainHead() string {
	if d.ChainHead != "" {
		return d.ChainHead
	}
	return d.EvidenceHead
}

// reproOpts say where the rule packs and the policy table come from.
type reproOpts struct {
	rulesDir      string // --rules
	policyFile    string // --policy
	defaultRules  string
	allowMismatch bool
}

// loadedPacks is a catalog and where it came from.
type loadedPacks struct {
	cat        *rules.Catalog
	from       string
	table      *rules.PolicyTable
	policyFrom string
}

// packFiles returns the pack files of a directory: *.yaml and *.yml except the policy table and
// the cause taxonomy, which sit beside the packs in a bundle's rules/. allow (nil: every file)
// keeps a bundle's reads to the members its manifest verified.
func packFiles(fsys fs.FS, dir string, allow func(name string) bool) ([]rules.PackSource, []byte, string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, nil, "", err
	}
	var sources []rules.PackSource
	var policy []byte
	policyName := ""
	for _, e := range entries {
		name := e.Name()
		ext := strings.ToLower(path.Ext(name))
		if e.IsDir() || (ext != ".yaml" && ext != ".yml") || (allow != nil && !allow(path.Join(dir, name))) {
			continue
		}
		data, err := readFS(fsys, path.Join(dir, name))
		if err != nil {
			return nil, nil, "", err
		}
		switch strings.TrimSuffix(strings.ToLower(name), ext) {
		case "policy":
			policy, policyName = data, path.Join(dir, name)
			continue
		case "causes":
			continue
		}
		sources = append(sources, rules.PackSource{Name: name, Data: data, BaseDir: dir})
	}
	return sources, policy, policyName, nil
}

func readFS(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var b bytes.Buffer
	if _, err := b.ReadFrom(io.LimitReader(f, maxMember+1)); err != nil {
		return nil, err
	}
	if b.Len() > maxMember {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, maxMember)
	}
	return b.Bytes(), nil
}

// loadPacks finds the packs: the bundle's rules/, else --rules, else the default directory.
func loadPacks(r *Report, src *source, o reproOpts) (*loadedPacks, error) {
	var sources []rules.PackSource
	var policy []byte
	var from, policyFrom string
	switch {
	case src.bundle() && dirExists(src.fsys, MemberRules):
		dir := MemberRules
		if dirExists(src.fsys, MemberRules+"/packs") {
			dir = MemberRules + "/packs"
		}
		var allow func(string) bool
		if src.listed != nil {
			allow = func(name string) bool { _, ok := src.listed[name]; return ok }
		}
		var err error
		if sources, policy, policyFrom, err = packFiles(src.fsys, dir, allow); err != nil {
			return nil, err
		}
		if policy == nil && dir != MemberRules {
			if data, ok, _ := src.read(MemberRules + "/policy.yaml"); ok {
				policy, policyFrom = data, MemberRules+"/policy.yaml"
			}
		}
		from = "the bundle's " + dir + "/"
		if o.rulesDir != "" {
			r.add(SectionReproducibility, "rule packs", Info, "--rules %s is not used: the bundle carries its own packs (their hash is checked below)", o.rulesDir)
		}
	default:
		dir := o.rulesDir
		if dir == "" {
			dir = o.defaultRules
		}
		if dir == "" {
			return nil, nil
		}
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			if o.rulesDir != "" {
				return nil, fmt.Errorf("--rules %s is not a directory", dir)
			}
			return nil, nil
		}
		var err error
		if sources, _, _, err = packFiles(os.DirFS(dir), ".", nil); err != nil {
			return nil, err
		}
		from = dir
		for _, cand := range []string{filepath.Join(dir, "policy.yaml"), filepath.Join(dir, "..", "policy.yaml")} {
			if data, err := os.ReadFile(filepath.Clean(cand)); err == nil { // #nosec G304 -- beside the packs the reviewer named
				policy, policyFrom = data, cand
				break
			}
		}
	}
	if o.policyFile != "" {
		data, err := os.ReadFile(filepath.Clean(o.policyFile)) // #nosec G304 -- the reviewer names the policy table
		if err != nil {
			return nil, err
		}
		policy, policyFrom = data, o.policyFile
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("%s holds no pack file", from)
	}
	cat, err := rules.ParsePacks(sources, rules.LoadOptions{RequireFixtures: false, CostLimit: rules.DefaultCostLimit})
	if err != nil {
		return nil, err
	}
	lp := &loadedPacks{cat: cat, from: from, table: rules.DefaultPolicyTable(), policyFrom: "the built-in defaults (no policy.yaml beside the packs)"}
	if policy != nil {
		if lp.table, err = rules.ParsePolicyTable(policy); err != nil {
			return nil, fmt.Errorf("%s: %w", policyFrom, err)
		}
		sum := sha256.Sum256(policy)
		lp.policyFrom = fmt.Sprintf("%s (sha256 %s)", policyFrom, short(hex.EncodeToString(sum[:])))
	}
	return lp, nil
}

func dirExists(fsys fs.FS, name string) bool {
	st, err := fs.Stat(fsys, name)
	return err == nil && st.IsDir()
}

// checkSnapshot compares the embedded snapshot with the hash the report names and returns the
// snapshot to re-run the rules on.
func checkSnapshot(r *Report, src *source, doc *reportDoc) []byte {
	snap := []byte(doc.Snapshot)
	if src.bundle() {
		if file, ok, err := src.read(MemberSnapshot); err != nil {
			r.add(SectionReproducibility, "snapshot", Fail, "reading %s: %v", MemberSnapshot, err)
		} else if ok {
			file = bytes.TrimSpace(file)
			switch {
			case len(snap) == 0:
				snap = file
			case !sameJSON(snap, file):
				r.add(SectionReproducibility, "snapshot", Fail, "%s is not the snapshot the report embeds", MemberSnapshot)
				return nil
			}
		}
	}
	if len(snap) == 0 {
		r.add(SectionReproducibility, "snapshot", NotChecked, "the model snapshot is %s (a report from before signed exports embeds none)", NotPresent)
		return nil
	}
	exact := model.HashBytes(snap)
	canon, err := model.CanonicalJSON(snap)
	if err != nil {
		r.add(SectionReproducibility, "snapshot", Fail, "the snapshot is not valid JSON")
		return nil
	}
	canonical := model.HashBytes(canon)
	switch doc.SnapshotHash {
	case "":
		r.add(SectionReproducibility, "snapshot hash", NotChecked, "the report's snapshot_hash is %s; the snapshot hashes to %s", NotPresent, short(exact))
	case exact:
		r.add(SectionReproducibility, "snapshot hash", Pass, "sha256 of the embedded snapshot bytes is the report's snapshot_hash %s", short(exact))
	case canonical:
		r.add(SectionReproducibility, "snapshot hash", Pass, "sha256 of the canonical snapshot is the report's snapshot_hash %s (the copy read was re-formatted)", short(canonical))
	default:
		r.add(SectionReproducibility, "snapshot hash", Fail, "the snapshot hashes to %s, the report names %s", short(exact), short(doc.SnapshotHash))
		return nil
	}
	if h := doc.Architecture.Hash; h != "" && h != exact && h != canonical {
		r.add(SectionReproducibility, "architecture hash", Info, "the architecture's recorded hash %s is not the snapshot's: a version hashed before schema 1.0 keeps the hash it was recorded with (ADR-040)", short(h))
	}
	return canon
}

func sameJSON(a, b []byte) bool {
	ca, err1 := model.CanonicalJSON(a)
	cb, err2 := model.CanonicalJSON(b)
	return err1 == nil && err2 == nil && bytes.Equal(ca, cb)
}

// reproduce reloads the packs, compares their combined hash with the report's, and re-runs the
// rules on the snapshot. It returns the catalog it ran with (nil when it did not run).
func reproduce(ctx context.Context, r *Report, src *source, doc *reportDoc, snap []byte, o reproOpts) *loadedPacks {
	rep := &Reproduction{ReportPackHash: doc.PackHash, Matched: []RuleElement{}, Missing: []RuleElement{}, Extra: []RuleElement{}}
	r.Reproduction = rep
	lp, err := loadPacks(r, src, o)
	switch {
	case err != nil:
		r.add(SectionReproducibility, "rule packs", Fail, "the packs do not load: %v", err)
		return nil
	case lp == nil:
		r.add(SectionReproducibility, "rule packs", NotChecked, "rule packs %s (pass --rules with the packs at the report's version)", NotPresent)
		return nil
	}
	rep.PacksFrom, rep.PackHash, rep.PolicyFrom = lp.from, lp.cat.Hash(), lp.policyFrom
	rep.PackDiff = packDiff(doc, lp.cat)
	switch {
	case doc.PackHash == "":
		r.add(SectionReproducibility, "pack hash", NotChecked, "the report's pack_hash is %s; the packs from %s hash to %s, so the re-run below may use other packs than the report did",
			NotPresent, lp.from, short(rep.PackHash))
	case doc.PackHashFormat != "" && doc.PackHashFormat != rules.PackHashFormat:
		r.add(SectionReproducibility, "pack hash", NotChecked, "the report's pack hash format %q is not this verifier's %q", doc.PackHashFormat, rules.PackHashFormat)
	case doc.PackHash == rep.PackHash:
		r.add(SectionReproducibility, "pack hash", Pass, "the %d packs from %s hash to the report's pack_hash %s", len(lp.cat.Packs()), lp.from, short(rep.PackHash))
	case !o.allowMismatch:
		r.add(SectionReproducibility, "pack hash", Fail, "refused: the packs from %s hash to %s, the report pins %s (an unknown pack); %s; pass --allow-pack-mismatch to re-run anyway",
			lp.from, short(rep.PackHash), short(doc.PackHash), diffSummary(rep.PackDiff))
		addDiff(r, rep.PackDiff)
		return nil
	default:
		r.add(SectionReproducibility, "pack hash", Flag, "the packs from %s hash to %s, the report pins %s; re-run anyway (--allow-pack-mismatch); %s",
			lp.from, short(rep.PackHash), short(doc.PackHash), diffSummary(rep.PackDiff))
		addDiff(r, rep.PackDiff)
	}
	if snap == nil {
		return lp
	}
	// A snapshot recorded at an older schema is upgraded on read before the re-run, as the product
	// reads a stored version (ADR-040 §1): rules only ever see the current schema. The hash checks
	// above were made over the bytes as recorded.
	upgraded, from, _, err := migrate.Upgrade(snap)
	if err != nil {
		r.add(SectionReproducibility, "re-run", Fail, "the snapshot cannot be read at schema %s: %v", model.CurrentSchemaVersion, err)
		return lp
	}
	var arch model.Architecture
	if err := json.Unmarshal(upgraded, &arch); err != nil {
		r.add(SectionReproducibility, "re-run", Fail, "the snapshot is not a model: %v", err)
		return lp
	}
	if from != model.CurrentSchemaVersion {
		rep.Notes = append(rep.Notes, "model schema: the snapshot is at "+from+" and was upgraded on read to "+model.CurrentSchemaVersion+" before the re-run")
	}
	pol := rules.Policy{Regimes: regimesOf(&arch)}
	// ADR-086 §7: the `prov` clock is the bundle's, never the verifier's (asof.go).
	asOf, clockNote := evaluationClock(src, doc, &arch)
	pol.AsOf = asOf
	regionNote := "allowed regions: the organisation's setting is " + NotPresent + "; the policy table's default is used"
	regimeNote := "enabled regimes: the organisation's filter is " + NotPresent + "; the model's attrs.regimes are used"
	if bp := readBundlePolicy(r, src); bp != nil {
		regionNote, regimeNote = bp.apply(&pol)
	}
	rep.Regimes = pol.Regimes
	if rep.Regimes == nil {
		rep.Regimes = []string{}
	}
	rep.Notes = append(rep.Notes,
		"policy table: "+lp.policyFrom+"; the report does not pin it",
		regionNote,
		regimeNote,
		"knowledge facts: "+NotPresent+"; drift rules stay silent (kb.available is false)",
		clockNote)
	got, evalErr := rules.New(lp.cat, lp.table).Evaluate(ctx, &arch, pol)
	rep.Ran = true
	var ruleErrs []string
	if evalErr != nil {
		var re *rules.RuleError
		for _, e := range splitErrs(evalErr) {
			if errors.As(e, &re) {
				ruleErrs = append(ruleErrs, re.RuleID)
			} else {
				ruleErrs = append(ruleErrs, e.Error())
			}
		}
		slices.Sort(ruleErrs)
		ruleErrs = slices.Compact(ruleErrs)
	}
	compare(rep, doc, got)
	for _, n := range rep.Notes {
		r.add(SectionReproducibility, "re-run input", Info, "%s", n)
	}
	if len(ruleErrs) > 0 {
		r.add(SectionReproducibility, "rule errors", Info, "%d rule(s) did not evaluate on this snapshot and produced nothing: %s", len(ruleErrs), strings.Join(ruleErrs, ", "))
	}
	detail := fmt.Sprintf("rules re-run on the snapshot (regimes %s): %d matched, %d missing from the report, %d in the report but not produced",
		orNone(rep.Regimes), len(rep.Matched), len(rep.Missing), len(rep.Extra))
	if omitted := doc.Summary.AcceptedRisks - len(doc.AcceptedRisks); omitted > 0 {
		detail += fmt.Sprintf("; the report omits %d accepted risk(s), which read as missing", omitted)
	}
	if len(rep.Missing) == 0 && len(rep.Extra) == 0 {
		r.add(SectionReproducibility, "findings", Pass, "%s", detail)
	} else {
		r.add(SectionReproducibility, "findings", Fail, "%s: the report's findings are not reproduced", detail)
	}
	return lp
}

func splitErrs(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok { //nolint:errorlint // a joined error is unwrapped one level on purpose
		return j.Unwrap()
	}
	return []error{err}
}

func orNone(xs []string) string {
	if len(xs) == 0 {
		return "none declared, every pack applies"
	}
	return strings.Join(xs, ", ")
}

// regimesOf reads attrs.regimes as the server's policy does.
func regimesOf(a *model.Architecture) []string {
	raw, ok := a.Attrs["regimes"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func key(ruleID string, ids []string) string {
	s := slices.Clone(ids)
	sort.Strings(s)
	return ruleID + "\x00" + strings.Join(s, "\x00")
}

// compare matches the report's results (findings and accepted risks, whatever their status: the
// rules produced each one) with the re-run's, by rule id and element ids.
func compare(rep *Reproduction, doc *reportDoc, got []model.Finding) {
	want := map[string]RuleElement{}
	for _, f := range append(slices.Clone(doc.Findings), doc.AcceptedRisks...) {
		ids := make([]string, 0, len(f.Elements))
		for _, e := range f.Elements {
			ids = append(ids, e.ID)
		}
		sort.Strings(ids)
		want[key(f.RuleID, ids)] = RuleElement{RuleID: f.RuleID, Elements: ids}
	}
	have := map[string]RuleElement{}
	for _, f := range got {
		ids := slices.Clone(f.IDs)
		sort.Strings(ids)
		have[key(f.RuleID, ids)] = RuleElement{RuleID: f.RuleID, Elements: ids}
	}
	for k, v := range have {
		if _, ok := want[k]; ok {
			rep.Matched = append(rep.Matched, v)
		} else {
			rep.Missing = append(rep.Missing, v)
		}
	}
	for k, v := range want {
		if _, ok := have[k]; !ok {
			rep.Extra = append(rep.Extra, v)
		}
	}
	for _, s := range [][]RuleElement{rep.Matched, rep.Missing, rep.Extra} {
		sort.Slice(s, func(i, j int) bool { return s[i].String() < s[j].String() })
	}
}

// packDiff lists the packs whose presence, version or hash differ between the report and the
// loaded catalog. The report lists the packs that applied to its regimes; a loaded pack it does not
// list is a difference only when the report lists every pack it ran with.
func packDiff(doc *reportDoc, cat *rules.Catalog) []PackDiff {
	loaded := map[string]*rules.Pack{}
	for _, p := range cat.Packs() {
		loaded[p.Pack] = p
	}
	var out []PackDiff
	listed := map[string]bool{}
	for _, rp := range doc.RulePacks {
		listed[rp.Pack] = true
		p, ok := loaded[rp.Pack]
		switch {
		case !ok:
			out = append(out, PackDiff{Pack: rp.Pack, ReportHash: rp.Hash, ReportVer: rp.Version, Disagreement: "in the report, not loaded"})
		case rp.Hash != "" && rp.Hash != p.Hash():
			out = append(out, PackDiff{Pack: rp.Pack, ReportHash: rp.Hash, LoadedHash: p.Hash(), ReportVer: rp.Version, LoadedVer: p.Version, Disagreement: "content differs"})
		case rp.Version != "" && rp.Version != p.Version:
			out = append(out, PackDiff{Pack: rp.Pack, ReportVer: rp.Version, LoadedVer: p.Version, Disagreement: "version differs"})
		}
	}
	if len(doc.RulePacks) > 0 && len(doc.Regimes) == 0 {
		for name, p := range loaded {
			if !listed[name] {
				out = append(out, PackDiff{Pack: name, LoadedHash: p.Hash(), LoadedVer: p.Version, Disagreement: "loaded, not in the report"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pack < out[j].Pack })
	return out
}

func diffSummary(d []PackDiff) string {
	if len(d) == 0 {
		return "no per-pack difference is visible (the report lists only the packs of its regimes)"
	}
	parts := make([]string, 0, len(d))
	for _, p := range d {
		parts = append(parts, p.Pack+": "+p.Disagreement)
	}
	return "per pack: " + strings.Join(parts, "; ")
}

func addDiff(r *Report, d []PackDiff) {
	for _, p := range d {
		r.add(SectionReproducibility, "pack "+p.Pack, Info, "%s: report %s %s, loaded %s %s", p.Disagreement,
			orNA(p.ReportVer), short(orNA(p.ReportHash)), orNA(p.LoadedVer), short(orNA(p.LoadedHash)))
	}
}

// MemberPolicy is a bundle's policy.json: the organisation's policy at bundle time (docs/18
// A5) — its allowed regions and its enabled-regime filter — so a re-run uses the policy the bundle
// states. The report's findings were computed when the version was saved; policy.json's
// stored_findings says whether they agree with this policy, so a mismatch here can be a changed
// policy rather than a changed rule.
const MemberPolicy = "policy.json"

// bundlePolicy is the part of policy.json the re-run reads.
type bundlePolicy struct {
	AllowedRegions     []string `json:"allowed_regions"`
	AllowedRegionsFrom string   `json:"allowed_regions_from"`
	RegimeFilter       []string `json:"regime_filter"`
}

// readBundlePolicy reads a bundle's policy.json; nil when the input is not a bundle or carries
// none (the re-run then uses the defaults and says so). A policy.json that does not parse is a
// failed check, and the defaults are used.
func readBundlePolicy(r *Report, src *source) *bundlePolicy {
	if src == nil || !src.bundle() {
		return nil
	}
	raw, ok, err := src.read(MemberPolicy)
	switch {
	case err != nil:
		r.add(SectionReproducibility, MemberPolicy, Fail, "reading it: %v", err)
		return nil
	case !ok:
		return nil
	}
	var bp bundlePolicy
	if err := json.Unmarshal(raw, &bp); err != nil {
		r.add(SectionReproducibility, MemberPolicy, Fail, "not a bundle policy: %v; the defaults are used", err)
		return nil
	}
	return &bp
}

// apply sets the policy's allowed regions and filters its regimes as the server does (the
// organisation's enabled regimes, when it set any, filter the model's attrs.regimes), and returns
// the two notes the re-run prints.
func (bp *bundlePolicy) apply(pol *rules.Policy) (regionNote, regimeNote string) {
	if len(bp.AllowedRegions) > 0 {
		pol.AllowedRegions = slices.Clone(bp.AllowedRegions)
		regionNote = fmt.Sprintf("allowed regions: %s, from the bundle's %s (%s)", strings.Join(bp.AllowedRegions, ", "), MemberPolicy,
			orNA(oneLine(bp.AllowedRegionsFrom)))
	} else {
		regionNote = "allowed regions: the bundle's " + MemberPolicy + " names none; the policy table's default is used"
	}
	if len(bp.RegimeFilter) == 0 {
		return regionNote, "enabled regimes: the bundle's " + MemberPolicy + " names no filter; the model's attrs.regimes are used"
	}
	filtered := make([]string, 0, len(pol.Regimes))
	for _, reg := range pol.Regimes {
		if slices.Contains(bp.RegimeFilter, reg) {
			filtered = append(filtered, reg)
		}
	}
	pol.Regimes = filtered
	return regionNote, fmt.Sprintf("enabled regimes: the model's attrs.regimes filtered by the organisation's %s from the bundle's %s",
		strings.Join(bp.RegimeFilter, ", "), MemberPolicy)
}
