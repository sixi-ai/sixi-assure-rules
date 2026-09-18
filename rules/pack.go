package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"cel.dev/cel-go/cel"
	"github.com/goccy/go-yaml"

	"github.com/sixi-ai/sixi-assure-rules/model"
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

	prog       cel.Program
	msg        *tmpl
	overrides  []cel.Program
	patchExprs map[string]cel.Program // placeholder expression → program (patch templates)
}

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

// Pack is a parsed and validated pack file.
type Pack struct {
	Pack    string
	Version string
	Regimes []string
	Rules   []*Rule
	File    string
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
	return c, nil
}

// ---- YAML shapes ----------------------------------------------------------------------------------

type packFile struct {
	Pack    string     `yaml:"pack"`
	Version string     `yaml:"version"`
	Regimes []string   `yaml:"regimes"`
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
	p := &Pack{Pack: pf.Pack, Version: pf.Version, File: src.Name, Regimes: make([]string, 0, len(pf.Regimes))}
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
