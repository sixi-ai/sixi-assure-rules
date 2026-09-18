package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
)

// collections whose array elements may be addressed by id in patch paths.
var idCollections = map[string]bool{"nodes": true, "edges": true, "groups": true, "findings": true}

// PatchError reports a failed patch operation.
type PatchError struct {
	Index int
	Op    PatchOp
	Err   error
}

func (e *PatchError) Error() string {
	return fmt.Sprintf("patch op %d (%s %s): %v", e.Index, e.Op.Op, e.Op.Path, e.Err)
}

func (e *PatchError) Unwrap() error { return e.Err }

// Apply applies ops to a (immutable input) and returns the validated result. Paths under
// /nodes, /edges, /groups and /findings may use the element id as the array segment; ids are
// resolved against the current document before each op, so later ops see earlier changes.
// Ops targeting /findings or /evidence are rejected for proposed_by=agent|user patches — those
// arrays are owned by the rules engine and the evidence chain (docs/02 §4).
func Apply(a *Architecture, ops []PatchOp, allowSystemPaths bool) (*Architecture, error) {
	if len(ops) == 0 {
		return nil, &PatchError{Index: 0, Err: fmt.Errorf("empty patch")}
	}
	doc, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	for i, op := range ops {
		if !allowSystemPaths && isSystemPath(op.Path) {
			return nil, &PatchError{Index: i, Op: op, Err: fmt.Errorf("path is managed by the server")}
		}
		if !allowSystemPaths && isSystemPath(op.From) {
			return nil, &PatchError{Index: i, Op: op, Err: fmt.Errorf("from path is managed by the server")}
		}
		if isProtectedRootField(op.Path) {
			return nil, &PatchError{Index: i, Op: op, Err: fmt.Errorf("field is immutable")}
		}
		resolved, err := resolveOp(doc, op)
		if err != nil {
			return nil, &PatchError{Index: i, Op: op, Err: err}
		}
		single, err := json.Marshal([]PatchOp{resolved})
		if err != nil {
			return nil, err
		}
		p, err := jsonpatch.DecodePatch(single)
		if err != nil {
			return nil, &PatchError{Index: i, Op: op, Err: err}
		}
		doc, err = p.ApplyWithOptions(doc, &jsonpatch.ApplyOptions{
			SupportNegativeIndices: false, AccumulatedCopySizeLimit: 1 << 20,
			EnsurePathExistsOnAdd: false, AllowMissingPathOnRemove: false,
		})
		if err != nil {
			return nil, &PatchError{Index: i, Op: op, Err: err}
		}
	}
	out, err := ValidateJSON(doc)
	if err != nil {
		return nil, err
	}
	// Observed nodes are read-only in v0 (docs/02 §4).
	for i := range out.Nodes {
		if out.Nodes[i].Source == SourceObserved {
			if before := a.Node(out.Nodes[i].ID); before == nil || !sameNode(before, &out.Nodes[i]) {
				return nil, &PatchError{Index: -1, Err: fmt.Errorf("node %q has source=observed and is read-only", out.Nodes[i].ID)}
			}
		}
	}
	for i := range a.Nodes {
		if a.Nodes[i].Source == SourceObserved && out.Node(a.Nodes[i].ID) == nil {
			return nil, &PatchError{Index: -1, Err: fmt.Errorf("node %q has source=observed and cannot be removed", a.Nodes[i].ID)}
		}
	}
	return out, nil
}

func sameNode(x, y *Node) bool {
	bx, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return string(bx) == string(by)
}

func isSystemPath(p string) bool {
	return p == "/findings" || strings.HasPrefix(p, "/findings/") || p == "/evidence" || strings.HasPrefix(p, "/evidence/")
}

func isProtectedRootField(p string) bool {
	switch p {
	case "/id", "/tenant_id", "/version", "/created_at", "/updated_at", "":
		return true
	}
	return false
}

// resolveOp rewrites id-addressed segments to numeric indexes for the current document.
func resolveOp(doc []byte, op PatchOp) (PatchOp, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(doc, &root); err != nil {
		return op, err
	}
	var err error
	if op.Path, err = resolvePath(root, op.Path); err != nil {
		return op, err
	}
	if op.From != "" {
		if op.From, err = resolvePath(root, op.From); err != nil {
			return op, err
		}
	}
	return op, nil
}

func resolvePath(root map[string]json.RawMessage, path string) (string, error) {
	if path == "" || path[0] != '/' {
		return "", fmt.Errorf("path must start with '/'")
	}
	segs := strings.Split(path[1:], "/")
	if len(segs) < 2 || !idCollections[segs[0]] {
		return path, nil
	}
	key := unescape(segs[1])
	if key == "-" {
		return path, nil
	}
	if _, err := strconv.Atoi(key); err == nil && !looksLikeID(root, segs[0], key) {
		return path, nil
	}
	var items []struct {
		ID string `json:"id"`
	}
	if raw, ok := root[segs[0]]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &items); err != nil {
			return "", fmt.Errorf("collection %q is not an array", segs[0])
		}
	}
	for i, it := range items {
		if it.ID == key {
			segs[1] = strconv.Itoa(i)
			return "/" + strings.Join(segs, "/"), nil
		}
	}
	return "", fmt.Errorf("no %s with id %q", strings.TrimSuffix(segs[0], "s"), key)
}

// looksLikeID reports whether a numeric-looking key matches an existing element id (ids win over indexes).
func looksLikeID(root map[string]json.RawMessage, coll, key string) bool {
	var items []struct {
		ID string `json:"id"`
	}
	if raw, ok := root[coll]; ok {
		_ = json.Unmarshal(raw, &items)
	}
	for _, it := range items {
		if it.ID == key {
			return true
		}
	}
	return false
}

func unescape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
}
