package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/goccy/go-yaml"

	"github.com/sixi-ai/sixi-assure-rules/model"
	modelschema "github.com/sixi-ai/sixi-assure-rules/schema"
)

// Pack format: rules/README.md. Every condition, message placeholder, severity override and
// patch-template placeholder is compiled once at load; evaluation never re-parses CEL.

var (
	ruleIDRe      = regexp.MustCompile(`^[A-Z]{2,5}-[0-9]{3}$`)
	packNameRe    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	placeholderRe = regexp.MustCompile(`\{\{(.*?)\}\}`)
	newIDRe       = regexp.MustCompile(`^new:([A-Za-z0-9_-]{1,16})$`)
)

// Scopes and severities accepted in packs.
var (
	Scopes = []string{ScopeNode, ScopeEdge, ScopeGraph}
)

// Rule is one compiled rule of a pack.
type Rule struct {
	ID                string
	Pack              string
	Title             string
	Scope             string
	Severity          string
	Condition         string
	Message           string
	Clauses           []string
	Remediation       string
	PatchTemplate     []PatchTemplateOp
	SeverityOverrides []SeverityOverride
	Fixtures          Fixtures
	Tags              []string
	// Requires lists the fact paths the condition needs to reach a decision (ADR-088 §4, docs/03 "requires and
	// not_checked"); Domain is the CEL guard naming the elements the rule decides ("" for a graph rule: the
	// architecture). An element of the domain the rule does not fire on, whose outcome depends on an undeclared
	// required path, is not checked (Engine.EvaluateCoverage). Neither ever changes a finding.
	Requires []string
	Domain   string
	// References are documentation citations beside the clauses (docs/18 D2, ADR-047 §4, ADR-030 style): a
	// specification that is not law (the MCP and A2A specifications) cited by url and the day it was fetched. They
	// never carry a regulatory statement — that is a clause id from corpus/ (CLAUDE.md §1.4) — and a rule without one
	// has an empty list.
	// The finding carries them as its structured `references` field (model.Finding.References, copied by the engine
	// and decorated on read by Catalog.Decorate), as does RuleSummary in openapi.yaml; the dock, every export format
	// and SARIF render them as documentation (ADR-095, accepted), so no message repeats them.
	References []Reference
	// RemediationByFramework is the framework-native remediation of the rule (ADR-093 decision 9, docs/18 WS-M M4):
	// per agent framework (the schema 1.2 `agent.framework` enum) one sentence naming the framework's own setting and
	// the repository file, pinned to a commit, it was read from. The finding shows the sentence for the framework of
	// its element's agent (RemediationFor, FrameworkOf) beside the generic Remediation, which stays the fallback; the
	// patch template stays a model operation. Empty for a rule that declares none.
	RemediationByFramework map[string]FrameworkRemediation

	prog       cel.Program
	msg        *tmpl
	overrides  []cel.Program
	patchExprs map[string]cel.Program // placeholder expression → program (patch templates)
	required   []requiredPath
	domain     cel.Program
}

// ReferenceKindDocument is the one reference kind a pack may declare: a published document (docs/18 D2).
const ReferenceKindDocument = "document"

// Reference is one documentation citation of a rule (`references:` in a pack, docs/03 "Documentation references"):
// what the document is, where it was read and when. FetchedAt is the day (YYYY-MM-DD) the cited text was read.
type Reference struct {
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	FetchedAt string `json:"fetched_at"`
}

// Limits of a `references:` list: a handful of documents per rule, each with a short title.
const (
	maxReferences     = 8
	maxReferenceTitle = 200
	maxReferenceURL   = 2000
)

// HasPatch reports whether the rule ships a patch template.
func (r *Rule) HasPatch() bool { return len(r.PatchTemplate) > 0 }

// PatchTemplateOp is a JSON Patch operation whose strings may contain placeholders.
type PatchTemplateOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	From  string `json:"from,omitempty"`
	Value any    `json:"value,omitempty"`
}

// SeverityOverride raises or lowers the severity when `When` holds (first match wins).
type SeverityOverride struct {
	When     string
	Severity string
}

// Fixtures are the resolved paths of the positive and negative fixture models and, for drift
// rules, of the knowledge facts (`kb`) both fixtures are evaluated with.
type Fixtures struct {
	Positive string
	Negative string
	KB       string
}

// LoadFixtureFacts reads a fixture's knowledge facts file ({"deprecated": {...}, "freshness": {...}});
// an empty path yields nil (kb.available == false).
func LoadFixtureFacts(path string) (*KnowledgeFacts, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- fixture path from the checked-in pack
	if err != nil {
		return nil, err
	}
	var facts KnowledgeFacts
	if err := json.Unmarshal(raw, &facts); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &facts, nil
}

// Offers a pack may be tagged with (docs/18 E5): the agentic offer is what Sixi sells; the industrial (machinery,
// OT) and pharma (GxP) packs stay in the product and the catalog, parked from the agentic offer's marketing.
const (
	OfferAgentic    = "agentic"
	OfferIndustrial = "industrial"
	OfferPharma     = "pharma"
)

// Offers lists the accepted `offer:` values, in display order.
var Offers = []string{OfferAgentic, OfferIndustrial, OfferPharma}

// Pack is a parsed and validated pack file.
type Pack struct {
	Pack    string
	Version string
	Regimes []string
	// Offer is the commercial offer the pack belongs to (docs/18 E5): agentic, industrial or pharma. A pack that
	// declares none belongs to the agentic offer (OfferOf); a value outside Offers fails the load.
	Offer string
	Rules []*Rule
	File  string

	hash string // content hash of the pack file (Hash), set by ParsePacks
}

// OfferOf is the pack's offer, agentic when the pack declares none.
func (p *Pack) OfferOf() string {
	if p == nil || p.Offer == "" {
		return OfferAgentic
	}
	return p.Offer
}

// AppliesTo reports pack applicability: enabled regimes empty, or intersecting the pack's regimes.
func (p *Pack) AppliesTo(regimes []string) bool {
	if len(regimes) == 0 || len(p.Regimes) == 0 {
		return true
	}
	enabled := regimeSet(regimes)
	for _, r := range p.Regimes {
		if enabled[CanonRegime(r)] {
			return true
		}
	}
	return false
}

// Catalog is the set of loaded packs with rule lookup.
type Catalog struct {
	packs       []*Pack
	byID        map[string]*Rule
	envs        *envSet
	causes      []Cause          // file order, nil when no causes file was loaded (causes.go)
	causeByRule map[string]Cause // rule id → its one cause
	hash        string           // combined hash of every loaded pack (Hash)
}

// Rule returns a rule by id.
func (c *Catalog) Rule(id string) (*Rule, bool) {
	r, ok := c.byID[id]
	return r, ok
}

// Rules returns all rules sorted by id.
func (c *Catalog) Rules() []*Rule {
	out := make([]*Rule, 0, len(c.byID))
	for _, r := range c.byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Packs returns the packs sorted by name.
func (c *Catalog) Packs() []*Pack {
	out := slices.Clone(c.packs)
	sort.Slice(out, func(i, j int) bool { return out[i].Pack < out[j].Pack })
	return out
}

// LoadOptions tune pack loading.
type LoadOptions struct {
	// RequireFixtures fails validation when a rule's fixture files are missing (LoadDir: true).
	RequireFixtures bool
	// CostLimit bounds the CEL runtime cost of one evaluation (0 → DefaultCostLimit).
	CostLimit uint64
}

// DefaultLoadOptions are strict: fixtures required, default cost limit.
func DefaultLoadOptions() LoadOptions {
	return LoadOptions{RequireFixtures: true, CostLimit: DefaultCostLimit}
}

// PackSource is an in-memory pack (tests, embedded packs).
type PackSource struct {
	Name    string // file name used in error messages
	Data    []byte
	BaseDir string // fixture paths resolve relative to this directory
}

// LoadDir loads every *.yaml/*.yml pack in dir with strict validation.
func LoadDir(dir string) (*Catalog, error) {
	return LoadDirWith(dir, DefaultLoadOptions())
}

// LoadDirWith loads every pack file in dir with the given options. Non-YAML files are ignored; a
// directory without any pack file is an error (a server without rules must not start silently).
func LoadDirWith(dir string, o LoadOptions) (*Catalog, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("rules dir: %w", err)
	}
	var sources []PackSource
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-controlled configuration (RULES_DIR)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		sources = append(sources, PackSource{Name: e.Name(), Data: b, BaseDir: dir})
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("rules dir %s: no pack files (*.yaml) found", dir)
	}
	c, err := ParsePacks(sources, o)
	if err != nil {
		return nil, err
	}
	// The curated cause taxonomy sits next to the packs directory (causes.yaml). It is
	// optional, but when it is there it must cover the catalog exactly (docs/03 §Causes).
	if err := c.attachCausesFrom(causesPathFor(dir)); err != nil {
		return nil, err
	}
	return c, nil
}

// ParsePacks parses and validates packs from memory and builds the catalog.
func ParsePacks(sources []PackSource, o LoadOptions) (*Catalog, error) {
	envs, err := newEnvs()
	if err != nil {
		return nil, err
	}
	c := &Catalog{byID: map[string]*Rule{}, envs: envs}
	var problems []error
	packNames := map[string]string{}
	sort.SliceStable(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
	for _, src := range sources {
		p, errs := parsePack(src, envs, o)
		if p != nil {
			if prev, dup := packNames[p.Pack]; dup {
				errs = append(errs, fmt.Errorf("%s: duplicate pack name %q (also in %s)", src.Name, p.Pack, prev))
			} else {
				packNames[p.Pack] = src.Name
			}
			for _, r := range p.Rules {
				if prev, dup := c.byID[r.ID]; dup {
					errs = append(errs, fmt.Errorf("%s: duplicate rule id %s (also in pack %s)", src.Name, r.ID, prev.Pack))
					continue
				}
				c.byID[r.ID] = r
			}
			c.packs = append(c.packs, p)
		}
		problems = append(problems, errs...)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("rule packs invalid: %w", errors.Join(problems...))
	}
	c.hash = CombinedHash(c.packs)
	return c, nil
}

// ---- YAML shapes ----------------------------------------------------------------------------------

type packFile struct {
	Pack    string     `yaml:"pack"`
	Version string     `yaml:"version"`
	Regimes []string   `yaml:"regimes"`
	Offer   string     `yaml:"offer"`
	Rules   []ruleFile `yaml:"rules"`
}

type ruleFile struct {
	ID               string           `yaml:"id"`
	Title            string           `yaml:"title"`
	Scope            string           `yaml:"scope"`
	Severity         string           `yaml:"severity"`
	Condition        string           `yaml:"condition"`
	Message          string           `yaml:"message"`
	Clauses          []string         `yaml:"clauses"`
	Remediation      string           `yaml:"remediation"`
	PatchTemplate    []map[string]any `yaml:"patch_template"`
	SeverityOverride []overrideFile   `yaml:"severity_override"`
	Fixtures         fixturesFile     `yaml:"fixtures"`
	Tags             []string         `yaml:"tags"`
	Requires         []string         `yaml:"requires"`
	Domain           string           `yaml:"domain"`
	References       []referenceFile  `yaml:"references"`
	// RemediationByFramework is `remediation_by_framework: {<framework>: {text, source}}` (ADR-093 decision 9).
	RemediationByFramework map[string]frameworkRemediationFile `yaml:"remediation_by_framework"`
}

type frameworkRemediationFile struct {
	Text   string `yaml:"text"`
	Source string `yaml:"source"`
}

type referenceFile struct {
	Kind      string `yaml:"kind"`
	Title     string `yaml:"title"`
	URL       string `yaml:"url"`
	FetchedAt string `yaml:"fetched_at"`
}

type overrideFile struct {
	When     string `yaml:"when"`
	Severity string `yaml:"severity"`
}

type fixturesFile struct {
	Positive string `yaml:"positive"`
	Negative string `yaml:"negative"`
	KB       string `yaml:"kb"`
}

func parsePack(src PackSource, envs *envSet, o LoadOptions) (*Pack, []error) {
	var pf packFile
	if err := yaml.UnmarshalWithOptions(src.Data, &pf, yaml.Strict()); err != nil {
		return nil, []error{fmt.Errorf("%s: %w", src.Name, err)}
	}
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", src.Name, fmt.Sprintf(format, args...)))
	}
	if !packNameRe.MatchString(pf.Pack) {
		fail("pack name %q invalid (expected %s)", pf.Pack, packNameRe)
	}
	if strings.TrimSpace(pf.Version) == "" {
		fail("version is required")
	}
	if len(pf.Rules) == 0 {
		fail("pack has no rules")
	}
	offer := strings.TrimSpace(pf.Offer)
	if offer != "" && !slices.Contains(Offers, offer) {
		fail("offer %q must be one of %s (docs/18 E5)", pf.Offer, strings.Join(Offers, "|"))
	}
	p := &Pack{Pack: pf.Pack, Version: pf.Version, Offer: offer, File: src.Name, Regimes: make([]string, 0, len(pf.Regimes))}
	if h, err := packContentHash(src.Data); err != nil {
		fail("content hash: %v", err)
	} else {
		p.hash = h
	}
	for _, r := range pf.Regimes {
		p.Regimes = append(p.Regimes, CanonRegime(r))
	}
	seen := map[string]bool{}
	for i, rf := range pf.Rules {
		where := rf.ID
		if where == "" {
			where = fmt.Sprintf("rules[%d]", i)
		}
		r, rerrs := compileRule(rf, pf.Pack, src.BaseDir, envs, o)
		for _, e := range rerrs {
			fail("rule %s: %v", where, e)
		}
		if seen[rf.ID] {
			fail("rule %s: duplicate id within pack", where)
		}
		seen[rf.ID] = true
		if r != nil {
			p.Rules = append(p.Rules, r)
		}
	}
	return p, errs
}

func compileRule(rf ruleFile, pack, baseDir string, envs *envSet, o LoadOptions) (*Rule, []error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if !ruleIDRe.MatchString(rf.ID) {
		fail("id %q must match %s", rf.ID, ruleIDRe)
	}
	if strings.TrimSpace(rf.Title) == "" {
		fail("title is required")
	}
	if !slices.Contains(Scopes, rf.Scope) {
		fail("scope %q must be one of %s", rf.Scope, strings.Join(Scopes, "|"))
	}
	if !slices.Contains(model.Severities, rf.Severity) {
		fail("severity %q must be one of %s", rf.Severity, strings.Join(model.Severities, "|"))
	}
	if len(rf.Clauses) == 0 {
		fail("clauses must not be empty (CLAUDE.md §1.4)")
	}
	for _, c := range rf.Clauses {
		if !strings.Contains(strings.Trim(c, ":"), ":") {
			fail("clause %q must have the form REGIME:DOC[:REF]", c)
		}
	}
	if strings.TrimSpace(rf.Condition) == "" {
		fail("condition is required")
	}
	if strings.TrimSpace(rf.Message) == "" {
		fail("message is required")
	}
	r := &Rule{
		ID: rf.ID, Pack: pack, Title: rf.Title, Scope: rf.Scope, Severity: rf.Severity, Condition: rf.Condition,
		Message: rf.Message, Clauses: slices.Clone(rf.Clauses), Remediation: rf.Remediation, Tags: slices.Clone(rf.Tags),
		patchExprs: map[string]cel.Program{},
	}
	if r.Clauses == nil {
		r.Clauses = []string{}
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
	scopeOK := slices.Contains(Scopes, rf.Scope)
	if scopeOK && strings.TrimSpace(rf.Condition) != "" {
		prog, typ, err := envs.compile(rf.Scope, rf.Condition, o.CostLimit)
		switch {
		case err != nil:
			fail("condition: %v", err)
		case typ != nil && !typ.IsEquivalentType(cel.BoolType) && !typ.IsEquivalentType(cel.DynType):
			fail("condition must evaluate to bool, got %s", typ)
		default:
			r.prog = prog
		}
	}
	if scopeOK && strings.TrimSpace(rf.Message) != "" {
		t, err := compileTemplate(rf.Scope, rf.Message, envs, o.CostLimit)
		if err != nil {
			fail("message: %v", err)
		}
		r.msg = t
	}
	for i, ov := range rf.SeverityOverride {
		if !slices.Contains(model.Severities, ov.Severity) {
			fail("severity_override[%d]: severity %q invalid", i, ov.Severity)
		}
		if strings.TrimSpace(ov.When) == "" {
			fail("severity_override[%d]: when is required", i)
			continue
		}
		r.SeverityOverrides = append(r.SeverityOverrides, SeverityOverride(ov))
		if !scopeOK {
			continue
		}
		prog, _, err := envs.compile(rf.Scope, ov.When, o.CostLimit)
		if err != nil {
			fail("severity_override[%d]: %v", i, err)
			continue
		}
		r.overrides = append(r.overrides, prog)
	}
	for i, raw := range rf.PatchTemplate {
		op, err := parsePatchOp(raw)
		if err != nil {
			fail("patch_template[%d]: %v", i, err)
			continue
		}
		r.PatchTemplate = append(r.PatchTemplate, op)
		if !scopeOK {
			continue
		}
		for _, expr := range placeholdersIn(op) {
			if newIDRe.MatchString(expr) {
				continue
			}
			if _, done := r.patchExprs[expr]; done {
				continue
			}
			prog, _, err := envs.compile(rf.Scope, expr, o.CostLimit)
			if err != nil {
				fail("patch_template[%d]: placeholder {{%s}}: %v", i, expr, err)
				continue
			}
			r.patchExprs[expr] = prog
		}
	}
	compileCoverage(r, rf, scopeOK, envs, o, fail)
	r.References = parseReferences(rf.References, fail)
	r.RemediationByFramework = parseFrameworkRemediation(rf.RemediationByFramework, fail)
	r.Fixtures = Fixtures{Positive: resolveFixture(baseDir, rf.Fixtures.Positive), Negative: resolveFixture(baseDir, rf.Fixtures.Negative), KB: resolveFixture(baseDir, rf.Fixtures.KB)}
	if o.RequireFixtures {
		for _, f := range []struct{ kind, rel, path string }{{"positive", rf.Fixtures.Positive, r.Fixtures.Positive}, {"negative", rf.Fixtures.Negative, r.Fixtures.Negative}} {
			if f.rel == "" {
				fail("fixtures.%s is required", f.kind)
				continue
			}
			if st, err := os.Stat(f.path); err != nil || st.IsDir() {
				fail("fixtures.%s: %s not found", f.kind, f.rel)
			}
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return r, nil
}

// parseReferences validates a rule's `references:` (docs/18 D2): kind document, a title, an absolute https url with a
// host and no credentials, and the day it was fetched as YYYY-MM-DD. A rule that declares none gets an empty list.
func parseReferences(in []referenceFile, fail func(string, ...any)) []Reference {
	out := make([]Reference, 0, len(in))
	if len(in) > maxReferences {
		fail("references: %d entries, at most %d", len(in), maxReferences)
		return out
	}
	seen := map[string]bool{}
	for i, rf := range in {
		ref := Reference{Kind: strings.TrimSpace(rf.Kind), Title: strings.TrimSpace(rf.Title), URL: strings.TrimSpace(rf.URL),
			FetchedAt: strings.TrimSpace(rf.FetchedAt)}
		ok := true
		bad := func(format string, args ...any) {
			fail("references[%d]: "+format, append([]any{i}, args...)...)
			ok = false
		}
		if ref.Kind != ReferenceKindDocument {
			bad("kind %q must be %q (a documentation citation; regulatory statements are clauses)", rf.Kind, ReferenceKindDocument)
		}
		if ref.Title == "" || len(ref.Title) > maxReferenceTitle {
			bad("title is required, at most %d characters", maxReferenceTitle)
		}
		if err := checkReferenceURL(ref.URL); err != nil {
			bad("url %q: %v", rf.URL, err)
		}
		if _, err := time.Parse(time.DateOnly, ref.FetchedAt); err != nil {
			bad("fetched_at %q must be the day the document was read, YYYY-MM-DD", rf.FetchedAt)
		}
		if seen[ref.URL] {
			bad("duplicate url %q", ref.URL)
		}
		seen[ref.URL] = true
		if ok {
			out = append(out, ref)
		}
	}
	return out
}

// checkReferenceURL accepts an absolute https url with a host, no user information and printable characters only.
func checkReferenceURL(raw string) error {
	if raw == "" || len(raw) > maxReferenceURL {
		return fmt.Errorf("required, at most %d characters", maxReferenceURL)
	}
	if strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("contains whitespace or a control character")
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return err
	case u.Scheme != "https":
		return errors.New("must be https")
	case u.Host == "":
		return errors.New("has no host")
	case u.User != nil:
		return errors.New("must not carry user information")
	}
	return nil
}

func resolveFixture(baseDir, rel string) string {
	if rel == "" {
		return ""
	}
	if filepath.IsAbs(rel) {
		return filepath.Clean(rel)
	}
	return filepath.Join(baseDir, rel)
}

func parsePatchOp(raw map[string]any) (PatchTemplateOp, error) {
	var op PatchTemplateOp
	for k := range raw {
		switch k {
		case "op", "path", "from", "value":
		default:
			return op, fmt.Errorf("unknown key %q", k)
		}
	}
	var ok bool
	if op.Op, ok = raw["op"].(string); !ok || op.Op == "" {
		return op, errors.New("op is required")
	}
	switch op.Op {
	case "add", "replace", "remove", "move", "copy", "test":
	default:
		return op, fmt.Errorf("unknown op %q", op.Op)
	}
	if op.Path, ok = raw["path"].(string); !ok || !strings.HasPrefix(op.Path, "/") {
		return op, errors.New("path must start with '/'")
	}
	if f, present := raw["from"]; present {
		if op.From, ok = f.(string); !ok {
			return op, errors.New("from must be a string")
		}
	}
	if (op.Op == "move" || op.Op == "copy") && op.From == "" {
		return op, fmt.Errorf("%s requires from", op.Op)
	}
	if v, present := raw["value"]; present {
		op.Value = normValue(v)
	} else if op.Op == "add" || op.Op == "replace" || op.Op == "test" {
		return op, fmt.Errorf("%s requires value", op.Op)
	}
	return op, nil
}

// placeholdersIn lists the distinct placeholder expressions of a patch op (path, from, value).
func placeholdersIn(op PatchTemplateOp) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		for _, m := range placeholderRe.FindAllStringSubmatch(s, -1) {
			expr := strings.TrimSpace(m[1])
			if !seen[expr] {
				seen[expr] = true
				out = append(out, expr)
			}
		}
	}
	add(op.Path)
	add(op.From)
	walkStrings(op.Value, add)
	return out
}

func walkStrings(v any, fn func(string)) {
	switch x := v.(type) {
	case string:
		fn(x)
	case map[string]any:
		for _, val := range x {
			walkStrings(val, fn)
		}
	case []any:
		for _, val := range x {
			walkStrings(val, fn)
		}
	}
}

// ---- message templates ----------------------------------------------------------------------------

type tmplPart struct {
	literal string
	expr    string
	prog    cel.Program
}

type tmpl struct {
	parts []tmplPart
}

func compileTemplate(scope, text string, envs *envSet, costLimit uint64) (*tmpl, error) {
	t := &tmpl{}
	last := 0
	for _, loc := range placeholderRe.FindAllStringSubmatchIndex(text, -1) {
		if loc[0] > last {
			t.parts = append(t.parts, tmplPart{literal: text[last:loc[0]]})
		}
		expr := strings.TrimSpace(text[loc[2]:loc[3]])
		if expr == "" {
			return nil, errors.New("empty placeholder")
		}
		if newIDRe.MatchString(expr) {
			return nil, fmt.Errorf("placeholder {{%s}} is only valid in patch templates", expr)
		}
		prog, _, err := envs.compile(scope, expr, costLimit)
		if err != nil {
			return nil, fmt.Errorf("placeholder {{%s}}: %w", expr, err)
		}
		t.parts = append(t.parts, tmplPart{expr: expr, prog: prog})
		last = loc[1]
	}
	if last < len(text) {
		t.parts = append(t.parts, tmplPart{literal: text[last:]})
	}
	return t, nil
}

// ---- content hashes (ADR-042 §4, docs/18 A2) ------------------------------------------------------

// PackHashFormat names the canonical serialisation Pack.Hash and Catalog.Hash are computed over.
// Exports record the hashes beside this name, so a verifier knows how to recompute them.
const PackHashFormat = "sixi-assure/rule-pack-hash/v1"

// Hash is the content hash of the pack (PackHashFormat, ADR-042 §4): the hex SHA-256 of
// CanonicalPack over the pack file. Every key a rule carries is covered — id, title, scope,
// severity, condition, message, clauses, remediation, patch template, severity overrides, tags,
// `requires` and `references` where a rule declares them — and so are the pack's id, version and regimes. Only a
// rule's `fixtures` (test inputs, not behaviour), comments, key order, rule order and YAML layout
// are not: two files that differ only in those hash the same. "" for a pack that was not parsed
// from a source (ParsePacks sets it).
func (p *Pack) Hash() string {
	if p == nil {
		return ""
	}
	return p.hash
}

// RuleCount is the number of rules in the pack.
func (p *Pack) RuleCount() int {
	if p == nil {
		return 0
	}
	return len(p.Rules)
}

// Hash is the combined hash of every loaded pack (CombinedHash): what an export pins as "findings
// are as of rule pack <hash>" and GET /rules/packs returns as combined_hash. "" for a nil catalog.
func (c *Catalog) Hash() string {
	if c == nil {
		return ""
	}
	return c.hash
}

// CombinedHash is the hex SHA-256 over one line per pack, sorted by pack id, each line
// "<pack id> <pack hash>\n". Pack ids carry no space (packNameRe), so the lines are unambiguous and
// the value is reproducible with standard tools from the per-pack hashes:
//
//	printf 'a2a %s\nagt %s\n' "$A2A_HASH" "$AGT_HASH" | sha256sum
func CombinedHash(packs []*Pack) string {
	sorted := slices.Clone(packs)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Pack < sorted[j].Pack })
	h := sha256.New()
	for _, p := range sorted {
		if p == nil {
			continue
		}
		_, _ = fmt.Fprintf(h, "%s %s\n", p.Pack, p.hash) // a hash.Hash never returns a write error
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalPack is the serialisation Pack.Hash is computed over (PackHashFormat): the YAML
// document read as JSON values, the `fixtures` key of every rule removed, the rules sorted by id,
// then canonical JSON (model.CanonicalJSON: object keys sorted, no insignificant whitespace, no
// HTML escaping, numbers as written).
func CanonicalPack(data []byte) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if rs, ok := doc["rules"].([]any); ok {
		out := make([]any, 0, len(rs))
		for _, r := range rs {
			if m, ok := r.(map[string]any); ok {
				m = maps.Clone(m)
				delete(m, "fixtures")
				r = m
			}
			out = append(out, r)
		}
		sort.SliceStable(out, func(i, j int) bool { return canonRuleID(out[i]) < canonRuleID(out[j]) })
		doc["rules"] = out
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return model.CanonicalJSON(raw)
}

// canonRuleID is the id of a rule as CanonicalPack sorts it ("" for anything that is not a rule
// mapping with a string id; such a file never passes validation, but the order stays defined).
func canonRuleID(r any) string {
	m, _ := r.(map[string]any)
	id, _ := m["id"].(string)
	return id
}

func packContentHash(data []byte) (string, error) {
	canon, err := CanonicalPack(data)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// ---- requires and domain (ADR-088 §4, docs/03 "requires and not_checked") ------------------------------------------

// requiredPath is one parsed `requires:` entry: a fact on the scope variable (n, e, e.from, e.to), on the architecture
// (g) or the knowledge facts (kb) the condition reads. attr is true for a path under `.attrs`; field then names the
// attribute, else a structural field (zone, layer, auth, encryption, data_class, protocol, label). identity is true for
// a schema 1.1 identity fact read through the scope node's resolved identity (n.identity.<member>,
// e.from.identity.<member>, e.to.identity.<member>; docs/03 CEL environment): field then names the member.
type requiredPath struct {
	raw      string
	root     string // n | e | e.from | e.to | g | kb
	attr     bool
	identity bool
	field    string
}

// Roots and structural fields a `requires:` path may name. Attributes are checked against the model schema.
var (
	nodeFieldPaths = []string{"zone", "layer"}
	edgeFieldPaths = []string{"auth", "encryption", "data_class", "protocol", "label"}
	// identityFieldPaths are the identity members (docs/02 §3a) a `requires:` path may name through n.identity,
	// e.from.identity or e.to.identity: the facts identityValue projects, without id (that is attrs.identity_id on the
	// node) and without the derived migrated flag.
	identityFieldPaths = []string{"name", "kind", "ref", "issuer", "credential_type", "credential_ttl", "rotation_days",
		"sponsor", "owner", "blueprint", "registry", "federation", "trust_domain"}
	attrNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	extAttrRe  = regexp.MustCompile(`^x_[A-Za-z0-9_]{1,60}$`)
)

// schemaAttrs are the attribute names the model schema declares (docs/02 §3): on nodes (the union of every type's
// attributes), on edges and on the architecture.
type schemaAttrs struct {
	node, edge, arch map[string]bool
}

var (
	schemaAttrsOnce sync.Once
	schemaAttrSet   schemaAttrs
)

func knownAttrs() schemaAttrs {
	schemaAttrsOnce.Do(func() {
		var doc struct {
			Defs struct {
				NodeAttrs struct {
					Properties map[string]json.RawMessage `json:"properties"`
				} `json:"nodeAttrs"`
				ArchitectureAttrs struct {
					Properties map[string]json.RawMessage `json:"properties"`
				} `json:"architectureAttrs"`
				Edge struct {
					Properties struct {
						Attrs struct {
							Properties map[string]json.RawMessage `json:"properties"`
						} `json:"attrs"`
					} `json:"properties"`
				} `json:"edge"`
			} `json:"$defs"`
		}
		schemaAttrSet = schemaAttrs{node: map[string]bool{}, edge: map[string]bool{}, arch: map[string]bool{}}
		if err := json.Unmarshal(modelschema.ModelSchema, &doc); err != nil {
			return // an unreadable schema leaves every set empty: every attribute path then fails validation
		}
		for k := range doc.Defs.NodeAttrs.Properties {
			schemaAttrSet.node[k] = true
		}
		for k := range doc.Defs.ArchitectureAttrs.Properties {
			schemaAttrSet.arch[k] = true
		}
		for k := range doc.Defs.Edge.Properties.Attrs.Properties {
			schemaAttrSet.edge[k] = true
		}
	})
	return schemaAttrSet
}

// parseRequired validates one `requires:` entry for a rule scope: the root must be a variable of that scope (or g, kb)
// and an attribute must exist in the model schema (or be an `x_` extension attribute).
func parseRequired(scope, raw string) (requiredPath, error) {
	p := requiredPath{raw: raw}
	if raw == "kb" {
		p.root = "kb"
		return p, nil
	}
	var roots []string
	switch scope {
	case ScopeNode:
		roots = []string{"n", "g"}
	case ScopeEdge:
		roots = []string{"e.from", "e.to", "e", "g"} // longest first: "e.from.x" is not "e" + "from.x"
	default:
		roots = []string{"g"}
	}
	for _, root := range roots {
		if rest, ok := strings.CutPrefix(raw, root+"."); ok {
			p.root = root
			if name, isAttr := strings.CutPrefix(rest, "attrs."); isAttr {
				p.attr, p.field = true, name
			} else if member, isIdentity := strings.CutPrefix(rest, "identity."); isIdentity && root != "e" && root != "g" {
				p.identity, p.field = true, member
			} else {
				p.field = rest
			}
			break
		}
	}
	if p.root == "" {
		return p, fmt.Errorf("requires %q: a path starts with %s or is kb", raw, strings.Join(roots, ", "))
	}
	known := knownAttrs()
	switch {
	case p.identity:
		if !slices.Contains(identityFieldPaths, p.field) {
			return p, fmt.Errorf("requires %q: an identity fact is one of %s", raw, strings.Join(identityFieldPaths, ", "))
		}
	case p.attr:
		if !attrNameRe.MatchString(p.field) && !extAttrRe.MatchString(p.field) {
			return p, fmt.Errorf("requires %q: %q is not an attribute name", raw, p.field)
		}
		set := known.node
		switch p.root {
		case "e":
			set = known.edge
		case "g":
			set = known.arch
		}
		if !set[p.field] && !extAttrRe.MatchString(p.field) {
			return p, fmt.Errorf("requires %q: the model schema declares no attribute %q there (docs/02 §3)", raw, p.field)
		}
	case p.root == "e":
		if !slices.Contains(edgeFieldPaths, p.field) {
			return p, fmt.Errorf("requires %q: an edge field is one of %s, or attrs.<name>", raw, strings.Join(edgeFieldPaths, ", "))
		}
	case p.root == "g":
		return p, fmt.Errorf("requires %q: the architecture's facts are g.attrs.<name>", raw)
	default:
		if !slices.Contains(nodeFieldPaths, p.field) {
			return p, fmt.Errorf("requires %q: a node field is one of %s, attrs.<name> or identity.<member>", raw, strings.Join(nodeFieldPaths, ", "))
		}
	}
	return p, nil
}

// compileCoverage parses `requires:` and compiles `domain:`. A node or edge rule that requires facts names its domain;
// a domain without requirements decides nothing and is refused.
func compileCoverage(r *Rule, rf ruleFile, scopeOK bool, envs *envSet, o LoadOptions, fail func(string, ...any)) {
	seen := map[string]bool{}
	for i, raw := range rf.Requires {
		raw = strings.TrimSpace(raw)
		if seen[raw] {
			fail("requires[%d]: duplicate path %q", i, raw)
			continue
		}
		seen[raw] = true
		if !scopeOK {
			continue
		}
		p, err := parseRequired(rf.Scope, raw)
		if err != nil {
			fail("requires[%d]: %v", i, err)
			continue
		}
		r.Requires = append(r.Requires, raw)
		r.required = append(r.required, p)
	}
	domain := strings.TrimSpace(rf.Domain)
	switch {
	case domain == "" && len(rf.Requires) > 0 && rf.Scope != ScopeGraph:
		fail("domain is required with requires on a %s rule (ADR-088 §4)", rf.Scope)
	case domain != "" && len(rf.Requires) == 0:
		fail("domain without requires decides nothing")
	case domain != "" && scopeOK:
		prog, typ, err := envs.compile(rf.Scope, domain, o.CostLimit)
		switch {
		case err != nil:
			fail("domain: %v", err)
		case typ != nil && !typ.IsEquivalentType(cel.BoolType) && !typ.IsEquivalentType(cel.DynType):
			fail("domain must evaluate to bool, got %s", typ)
		default:
			r.Domain, r.domain = domain, prog
		}
	}
}

// ---- framework-native remediation (ADR-093 decision 9, docs/18 WS-M M4) ------------------------------------------------

// FrameworkRemediation is one framework-native remediation sentence of a rule: the framework (a schema 1.2
// `agent.framework` value), the sentence naming the framework's own setting, and the source it was read from, a
// repository file URL pinned to a commit. It never carries a regulatory statement: the rule's clauses do.
type FrameworkRemediation struct {
	Framework string `json:"framework"`
	Text      string `json:"text"`
	Source    string `json:"source"`
}

// Limits of one remediation_by_framework entry.
const maxFrameworkRemediationText = 1200

// frameworkSourceRe is "a repository URL with a commit": a raw.githubusercontent.com file, or a github.com blob or
// tree, at a full 40-hex commit, never a branch name that moves.
var frameworkSourceRe = regexp.MustCompile(`^https://(raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/|github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(blob|tree)/[0-9a-f]{40}/)[^\s]+$`)

var (
	frameworksOnce sync.Once
	frameworkEnum  []string
)

// Frameworks are the agent frameworks a remediation_by_framework key may name: the schema 1.2 `framework` enum
// (docs/02 §10) without its empty value. A schema that cannot be read yields none, so every key then fails the load.
func Frameworks() []string {
	frameworksOnce.Do(func() {
		var doc struct {
			Defs struct {
				Framework struct {
					Enum []string `json:"enum"`
				} `json:"framework"`
			} `json:"$defs"`
		}
		if err := json.Unmarshal(modelschema.ModelSchema, &doc); err != nil {
			return
		}
		for _, v := range doc.Defs.Framework.Enum {
			if v != "" {
				frameworkEnum = append(frameworkEnum, v)
			}
		}
	})
	return slices.Clone(frameworkEnum)
}

// parseFrameworkRemediation validates `remediation_by_framework:` at load: every key is a schema 1.2 framework, every
// entry has a sentence and a source URL that pins a repository commit. A rule that declares none gets nil.
func parseFrameworkRemediation(in map[string]frameworkRemediationFile, fail func(string, ...any)) map[string]FrameworkRemediation {
	if len(in) == 0 {
		return nil
	}
	known := Frameworks()
	out := make(map[string]FrameworkRemediation, len(in))
	keys := slices.Sorted(maps.Keys(in))
	for _, fw := range keys {
		e := in[fw]
		ok := true
		bad := func(format string, args ...any) {
			fail("remediation_by_framework.%s: "+format, append([]any{fw}, args...)...)
			ok = false
		}
		if !slices.Contains(known, fw) {
			bad("unknown framework (one of %s, the schema 1.2 agent.framework enum)", strings.Join(known, "|"))
		}
		text, source := strings.TrimSpace(e.Text), strings.TrimSpace(e.Source)
		if text == "" || len(text) > maxFrameworkRemediationText {
			bad("text is required, at most %d characters", maxFrameworkRemediationText)
		}
		if err := checkReferenceURL(source); err != nil {
			bad("source %q: %v", e.Source, err)
		} else if !frameworkSourceRe.MatchString(source) {
			bad("source %q must be a repository file URL pinned to a 40-hex commit", e.Source)
		}
		if ok {
			out[fw] = FrameworkRemediation{Framework: fw, Text: text, Source: source}
		}
	}
	return out
}

// RemediationFor returns the rule's framework-native remediation for a framework, false when the rule declares none
// for it (the generic Remediation then applies).
func (r *Rule) RemediationFor(framework string) (FrameworkRemediation, bool) {
	if r == nil || framework == "" {
		return FrameworkRemediation{}, false
	}
	fr, ok := r.RemediationByFramework[framework]
	return fr, ok
}
