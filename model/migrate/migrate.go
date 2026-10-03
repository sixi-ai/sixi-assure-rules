// Package migrate upgrades an architecture model document to the current schema version on read
// (ADR-040 §1, §4; docs/02 §Versions).
//
// A stored or submitted model is never rewritten on disk in bulk: every path where a model enters
// the engine (the store's read path, imports, A2A and MCP submissions, the CLI, all through
// model.ValidateJSON or the store's decoder) runs Upgrade first, so rules, exports and the SPA only
// ever see the current version, and the next save writes it.
//
// A document without `schema_version` is `0.9`: every model written before the field existed.
// Each schema change adds one Step to the ordered list below, keyed by the version it starts from,
// plus a golden pair under testdata (old JSON → expected new JSON). A step is pure: it is handed a
// private copy of the document, reads nothing else, writes nothing else, keeps no reference to it
// and returns the document at its To version. It never sees the database, the clock or the network.
//
// This package depends on the standard library only, so the model package, the store and the CLI
// can all call it without an import cycle.
package migrate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
)

// Current is the schema version this build reads, writes and evaluates.
const Current = "1.2"

// Unversioned is the version of a document that carries no `schema_version`: every model written
// before ADR-040 §1 shipped.
const Unversioned = "0.9"

// Field is the root member that carries the schema version.
const Field = "schema_version"

// Func is one migration step. It owns doc (Upgrade passes it a private copy) and returns the
// document at its Step's To version, with `schema_version` set to that version.
type Func func(doc map[string]any) (map[string]any, error)

// Step migrates a document from one schema version to the next.
type Step struct {
	From string
	To   string
	// Note is the one line docs/02 §Versions lists for the step.
	Note string
	Fn   Func
}

// steps is the ordered migration list, keyed by from-version: steps[i].To == steps[i+1].From and
// the last To is Current (TestStepsAreOrdered).
var steps = []Step{
	{From: "0.9", To: "1.0", Note: "sets schema_version to 1.0; nothing else changes", Fn: v09to10},
	{From: "1.0", To: "1.1", Note: "one identities[] entry per distinct agent.identity value, referenced by attrs.identity_id; " +
		"edge.protocol mapped to the enum (unknown and plaintext spellings → other with x_migrated_from); app/api authn becomes a list; " +
		"log_sink.purpose free text → x_purpose, agent.egress_policy boolean removed, mcp_server.exposure internal → private_network and unknown removed (each with x_migrated_from)", Fn: v10to11},
	{From: "1.1", To: "1.2", Note: "the framework vocabulary (ADR-093 M1) is additive: nothing changes on a model whose values are in the 1.2 type profiles; " +
		"the tolerant reading of the 1.0 shapes runs as on a current document; an agent.kind outside llm/orchestrator, a boolean tool.egress_policy, " +
		"and an agent or agent_memory hosted_on that names no node, the node itself or a note are removed (with x_migrated_from and their provenance entries)", Fn: v11to12},
}

// Steps returns a copy of the ordered migration list.
func Steps() []Step { return slices.Clone(steps) }

// Errors. A message never repeats a value from the document unless the value matched the
// MAJOR.MINOR pattern, so an error can be shown to a person and logged without carrying content.
var (
	// ErrNotObject: the document is not a JSON object.
	ErrNotObject = errors.New("the model is not a JSON object")
	// ErrInvalidVersion: schema_version is present but is not a "MAJOR.MINOR" string.
	ErrInvalidVersion = errors.New(`schema_version must be a "MAJOR.MINOR" string`)
	// ErrUnsupportedVersion: a well-formed version this build has no path from (newer than
	// Current, or older than the oldest step).
	ErrUnsupportedVersion = errors.New("unsupported schema_version")
)

// versionPattern bounds both parts so a version always parses and never carries free text.
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)

// Valid reports whether v is a well-formed MAJOR.MINOR version.
func Valid(v string) bool { return versionPattern.MatchString(v) }

// compare orders two well-formed versions numerically (-1, 0, +1). Callers rule out malformed
// input with Valid first; a malformed version sorts as 0.0.
func compare(a, b string) int {
	am, an := parts(a)
	bm, bn := parts(b)
	switch {
	case am != bm:
		return cmpInt(am, bm)
	default:
		return cmpInt(an, bn)
	}
}

func parts(v string) (major, minor int) {
	m := versionPattern.FindStringSubmatch(v)
	if m == nil {
		return 0, 0
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Version reads the schema version of a raw document without upgrading it: Unversioned when the
// field is absent.
func Version(raw []byte) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return "", ErrNotObject
	}
	v, present := top[Field]
	if !present {
		return Unversioned, nil
	}
	return versionOf(v)
}

func versionOf(v json.RawMessage) (string, error) {
	var s string
	if bytes.Equal(bytes.TrimSpace(v), []byte("null")) || json.Unmarshal(v, &s) != nil || !Valid(s) {
		return "", ErrInvalidVersion
	}
	return s, nil
}

// Upgrade brings a raw model document to Current. It returns the upgraded bytes and the versions
// it went from and to. A document already at Current is returned unchanged (the same bytes, so a
// stored model's hash is never disturbed by reading it); any other document is decoded with
// json.Number (numbers keep their exact text), migrated step by step and re-encoded.
func Upgrade(raw []byte) (upgraded []byte, from, to string, err error) {
	return upgradeWith(steps, Current, raw)
}

// UpgradeDoc is Upgrade for a document already decoded into a map (the CLI reads YAML that way).
// The caller's map is not modified.
func UpgradeDoc(doc map[string]any) (upgraded map[string]any, from, to string, err error) {
	return upgradeDocWith(steps, Current, doc)
}

func upgradeWith(list []Step, current string, raw []byte) ([]byte, string, string, error) {
	from, err := Version(raw)
	if err != nil {
		return nil, "", "", err
	}
	if from == current {
		return raw, from, current, nil
	}
	if _, err := pathFrom(list, current, from); err != nil {
		return nil, from, "", err
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return nil, from, "", ErrNotObject
	}
	out, _, to, err := run(list, current, from, doc)
	if err != nil {
		return nil, from, "", err
	}
	b, err := encode(out)
	if err != nil {
		return nil, from, "", err
	}
	return b, from, to, nil
}

func upgradeDocWith(list []Step, current string, doc map[string]any) (map[string]any, string, string, error) {
	if doc == nil {
		return nil, "", "", ErrNotObject
	}
	from := Unversioned
	if v, present := doc[Field]; present {
		s, ok := v.(string)
		if !ok || !Valid(s) {
			return nil, "", "", ErrInvalidVersion
		}
		from = s
	}
	if _, err := pathFrom(list, current, from); err != nil {
		return nil, from, "", err
	}
	copied, ok := deepCopy(doc).(map[string]any)
	if !ok {
		return nil, from, "", ErrNotObject
	}
	return run(list, current, from, copied)
}

// pathFrom returns the index of the first step to run from version v (len(list) when v is current).
func pathFrom(list []Step, current, v string) (int, error) {
	if v == current {
		return len(list), nil
	}
	for i, s := range list {
		if s.From == v {
			return i, nil
		}
	}
	if compare(v, current) > 0 {
		return 0, fmt.Errorf("%w: %s is newer than %s, the version this build reads", ErrUnsupportedVersion, v, current)
	}
	return 0, fmt.Errorf("%w: there is no migration from %s to %s", ErrUnsupportedVersion, v, current)
}

func run(list []Step, current, from string, doc map[string]any) (map[string]any, string, string, error) {
	start, err := pathFrom(list, current, from)
	if err != nil {
		return nil, from, "", err
	}
	at := from
	for _, s := range list[start:] {
		if s.From != at {
			return nil, from, "", fmt.Errorf("migrate: step list is out of order at %s → %s", s.From, s.To)
		}
		next, err := s.Fn(doc)
		if err != nil {
			return nil, from, "", fmt.Errorf("migrate %s → %s: %w", s.From, s.To, err)
		}
		if next == nil || next[Field] != s.To {
			return nil, from, "", fmt.Errorf("migrate %s → %s: the step did not set %s", s.From, s.To, Field)
		}
		doc, at = next, s.To
	}
	if at != current {
		return nil, from, "", fmt.Errorf("migrate: the step list ends at %s, not %s", at, current)
	}
	return doc, from, current, nil
}

func encode(doc map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// deepCopy copies a decoded JSON value (maps, slices and scalars).
func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = deepCopy(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepCopy(x)
		}
		return out
	default:
		return v
	}
}

// v09to10 is the 0.9 → 1.0 step: the schema of 1.0 is the schema every unversioned model was
// written against, so the step only records the version.
func v09to10(doc map[string]any) (map[string]any, error) {
	doc[Field] = "1.0"
	return doc, nil
}
