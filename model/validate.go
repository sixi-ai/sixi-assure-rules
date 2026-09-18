package model

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	modelschema "github.com/sixi-ai/sixi-assure-rules/schema"
	"github.com/sixi-ai/sixi-assure-rules/secretguard"
)

// ValidationError aggregates schema and invariant violations. Messages are safe to show to users
// (they contain JSON pointers and enum names, never free text from the model).
type ValidationError struct {
	Problems []Problem
}

// Problem is one violation.
type Problem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 0 {
		return "invalid model"
	}
	parts := make([]string, 0, len(e.Problems))
	for i, p := range e.Problems {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("… and %d more", len(e.Problems)-5))
			break
		}
		parts = append(parts, p.Path+": "+p.Message)
	}
	return "invalid model: " + strings.Join(parts, "; ")
}

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

func compiled() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(modelschema.ModelSchema))
		if err != nil {
			schemaErr = fmt.Errorf("parse model schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		if err := c.AddResource("model.schema.json", doc); err != nil {
			schemaErr = fmt.Errorf("add model schema: %w", err)
			return
		}
		schema, schemaErr = c.Compile("model.schema.json")
	})
	return schema, schemaErr
}

// ValidateJSON validates raw JSON against the schema and the invariants and returns the decoded
// architecture. It is the single entry point for untrusted model input (API, import, patches).
func ValidateJSON(raw []byte) (*Architecture, error) {
	s, err := compiled()
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, &ValidationError{Problems: []Problem{{Path: "/", Message: "malformed JSON"}}}
	}
	// The secret guard runs before anything else touches the document (ADR-041 §2): every string
	// leaf, every object key, including x_* extension values and patch operands after apply. This
	// is what makes every model write path — create, patch, import confirmation, rule fix, agent
	// and MCP proposals — covered by construction rather than per handler. The returned error
	// names the JSON pointer and the detector and never the value.
	if err := secretguard.CheckDocument(context.Background(), secretguard.SourceModel, doc); err != nil {
		return nil, err
	}
	if err := s.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return nil, &ValidationError{Problems: flatten(ve)}
		}
		return nil, err
	}
	var a Architecture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, &ValidationError{Problems: []Problem{{Path: "/", Message: "cannot decode: " + err.Error()}}}
	}
	normalize(&a)
	if err := Invariants(&a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Validate normalises nil collections, marshals the architecture and runs ValidateJSON.
func Validate(a *Architecture) error {
	normalize(a)
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = ValidateJSON(b)
	return err
}

var printer = message.NewPrinter(language.English)

func flatten(ve *jsonschema.ValidationError) []Problem {
	var out []Problem
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			out = append(out, Problem{Path: "/" + strings.Join(e.InstanceLocation, "/"), Message: e.ErrorKind.LocalizedString(printer)})
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func normalize(a *Architecture) {
	if a.Attrs == nil {
		a.Attrs = Attrs{}
	}
	if a.Groups == nil {
		a.Groups = []Group{}
	}
	if a.Nodes == nil {
		a.Nodes = []Node{}
	}
	if a.Edges == nil {
		a.Edges = []Edge{}
	}
	if a.Findings == nil {
		a.Findings = []Finding{}
	}
	if a.Evidence == nil {
		a.Evidence = []EvidenceRef{}
	}
	for i := range a.Nodes {
		if a.Nodes[i].Source == "" {
			a.Nodes[i].Source = SourceDesign
		}
		if a.Nodes[i].Attrs == nil {
			a.Nodes[i].Attrs = Attrs{}
		}
	}
	for i := range a.Edges {
		if a.Edges[i].Attrs == nil {
			a.Edges[i].Attrs = Attrs{}
		}
	}
	for i := range a.Groups {
		if a.Groups[i].NodeIDs == nil {
			a.Groups[i].NodeIDs = []string{}
		}
	}
}

// Invariants enforces docs/02 §4 on an already schema-valid architecture.
func Invariants(a *Architecture) error {
	var probs []Problem
	add := func(path, msg string) { probs = append(probs, Problem{Path: path, Message: msg}) }

	ids := map[string]string{}
	claim := func(id, what, path string) {
		if prev, dup := ids[id]; dup {
			add(path, fmt.Sprintf("duplicate id %q (already used by %s)", id, prev))
			return
		}
		ids[id] = what
	}
	nodeIdx := make(map[string]int, len(a.Nodes))
	for i, n := range a.Nodes {
		claim(n.ID, "node", fmt.Sprintf("/nodes/%d/id", i))
		nodeIdx[n.ID] = i
		for k, v := range n.Attrs {
			if k == "region" {
				if s, _ := v.(string); !ValidRegion(s) {
					add(fmt.Sprintf("/nodes/%d/attrs/region", i), fmt.Sprintf("unknown region %q", s))
				}
			}
		}
	}
	for i, e := range a.Edges {
		claim(e.ID, "edge", fmt.Sprintf("/edges/%d/id", i))
		fi, okF := nodeIdx[e.From]
		ti, okT := nodeIdx[e.To]
		if !okF {
			add(fmt.Sprintf("/edges/%d/from", i), fmt.Sprintf("unknown node %q", e.From))
		}
		if !okT {
			add(fmt.Sprintf("/edges/%d/to", i), fmt.Sprintf("unknown node %q", e.To))
		}
		if okF && okT && e.From == e.To {
			n := a.Nodes[fi]
			_ = ti
			if n.Type != "agent" || e.Kind != "delegates" || e.Auth != "obo" {
				add(fmt.Sprintf("/edges/%d", i), "self-loop not allowed (only agent→agent delegates with auth=obo)")
			}
		}
	}
	zoneOf := map[string]string{}
	for i, g := range a.Groups {
		claim(g.ID, "group", fmt.Sprintf("/groups/%d/id", i))
		for j, nid := range g.NodeIDs {
			if _, ok := nodeIdx[nid]; !ok {
				add(fmt.Sprintf("/groups/%d/node_ids/%d", i, j), fmt.Sprintf("unknown node %q", nid))
				continue
			}
			if g.Kind == "zone" {
				if prev, ok := zoneOf[nid]; ok && prev != g.ID {
					add(fmt.Sprintf("/groups/%d/node_ids/%d", i, j), fmt.Sprintf("node %q already belongs to zone %q", nid, prev))
				}
				zoneOf[nid] = g.ID
			}
		}
	}
	for i, g := range a.Groups {
		if g.Parent != "" {
			if a.Group(g.Parent) == nil {
				add(fmt.Sprintf("/groups/%d/parent", i), fmt.Sprintf("unknown group %q", g.Parent))
			} else if g.Parent == g.ID {
				add(fmt.Sprintf("/groups/%d/parent", i), "group cannot be its own parent")
			}
		}
	}
	for i, n := range a.Nodes {
		if n.Zone != "" {
			g := a.Group(n.Zone)
			switch {
			case g == nil:
				add(fmt.Sprintf("/nodes/%d/zone", i), fmt.Sprintf("unknown group %q", n.Zone))
			case g.Kind != "zone":
				add(fmt.Sprintf("/nodes/%d/zone", i), fmt.Sprintf("group %q is not a zone", n.Zone))
			case zoneOf[n.ID] != n.Zone:
				add(fmt.Sprintf("/nodes/%d/zone", i), fmt.Sprintf("zone %q does not list this node", n.Zone))
			}
		}
	}
	for i, f := range a.Findings {
		claim(f.ID, "finding", fmt.Sprintf("/findings/%d/id", i))
		for j, id := range f.IDs {
			if _, ok := ids[id]; !ok && id != a.ID {
				add(fmt.Sprintf("/findings/%d/ids/%d", i, j), fmt.Sprintf("unknown element %q", id))
			}
		}
	}
	if len(probs) > 0 {
		return &ValidationError{Problems: probs}
	}
	return nil
}

// RequiredAttrs returns the inventory-required attribute names for a node type (schema x-required-attrs).
func RequiredAttrs(nodeType string) []string {
	return attrCatalog()[catalogKey(nodeType)]
}

var (
	catalogOnce sync.Once
	catalog     map[string][]string
)

func attrCatalog() map[string][]string {
	catalogOnce.Do(func() {
		var doc struct {
			Defs struct {
				Attrs map[string]struct {
					Required []string `json:"x-required-attrs"`
				} `json:"attrs"`
			} `json:"$defs"`
		}
		catalog = map[string][]string{}
		if err := json.Unmarshal(modelschema.ModelSchema, &doc); err == nil {
			for k, v := range doc.Defs.Attrs {
				catalog[k] = v.Required
			}
		}
	})
	return catalog
}

func catalogKey(nodeType string) string {
	switch nodeType {
	case "mcp_server":
		return "tool"
	case "edge_device", "edge_gateway":
		return "edge"
	case "api":
		return "app"
	}
	return nodeType
}
