package c4

import (
	"encoding/json"
	"fmt"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// CanvasOp vocabulary of the prompt (§5) expressed as RFC 6902 patch ops on the graph model.
// Every helper returns ops that model.Apply accepts; the assistant packages them into a Proposal
// and nothing changes until the user accepts (CLAUDE.md §1.3).

// AddElement adds a node.
func AddElement(n model.Node) model.PatchOp {
	return model.PatchOp{Op: "add", Path: "/nodes/-", Value: raw(n)}
}

// RemoveElement removes a node by id (the server rejects it while edges still reference it).
func RemoveElement(id string) model.PatchOp {
	return model.PatchOp{Op: "remove", Path: "/nodes/" + id}
}

// UpdateElement replaces a node wholesale.
func UpdateElement(n model.Node) model.PatchOp {
	return model.PatchOp{Op: "replace", Path: "/nodes/" + n.ID, Value: raw(n)}
}

// SetProperty sets one typed attribute of a node (add works as upsert on object keys).
func SetProperty(nodeID, attr string, value any) model.PatchOp {
	return model.PatchOp{Op: "add", Path: "/nodes/" + nodeID + "/attrs/" + attr, Value: raw(value)}
}

// Annotate sets the description of a node.
func Annotate(nodeID, description string) model.PatchOp {
	return model.PatchOp{Op: "add", Path: "/nodes/" + nodeID + "/description", Value: raw(description)}
}

// Move sets the position of a node at a canvas level ("" = the primary position). The node is
// needed because RFC 6902 cannot create the `positions` object on the way.
func Move(n *model.Node, level string, x, y float64) model.PatchOp {
	pos := model.Position{X: x, Y: y}
	if level == "" {
		return model.PatchOp{Op: "add", Path: "/nodes/" + n.ID + "/position", Value: raw(pos)}
	}
	if n.Positions == nil {
		return model.PatchOp{Op: "add", Path: "/nodes/" + n.ID + "/positions", Value: raw(map[string]model.Position{level: pos})}
	}
	return model.PatchOp{Op: "add", Path: "/nodes/" + n.ID + "/positions/" + level, Value: raw(pos)}
}

// AddRelationship adds an edge.
func AddRelationship(e model.Edge) model.PatchOp {
	return model.PatchOp{Op: "add", Path: "/edges/-", Value: raw(e)}
}

// RemoveRelationship removes an edge by id.
func RemoveRelationship(id string) model.PatchOp {
	return model.PatchOp{Op: "remove", Path: "/edges/" + id}
}

// GroupIntoBoundary replaces the member list of a boundary (group) with the union of its current
// members and the given node ids.
func GroupIntoBoundary(g model.Group, nodeIDs ...string) model.PatchOp {
	seen := map[string]bool{}
	members := make([]string, 0, len(g.NodeIDs)+len(nodeIDs))
	for _, id := range append(append([]string{}, g.NodeIDs...), nodeIDs...) {
		if !seen[id] {
			seen[id] = true
			members = append(members, id)
		}
	}
	return model.PatchOp{Op: "replace", Path: "/groups/" + g.ID + "/node_ids", Value: raw(members)}
}

// AddBoundary adds a group.
func AddBoundary(g model.Group) model.PatchOp {
	return model.PatchOp{Op: "add", Path: "/groups/-", Value: raw(g)}
}

// SetParent declares the C4 parent of an element.
func SetParent(nodeID, parentID string) model.PatchOp {
	return SetProperty(nodeID, "c4_parent", parentID)
}

// AddDecision appends a decision record to the architecture attrs (creating the list).
func AddDecision(a *model.Architecture, d Decision) []model.PatchOp {
	if _, ok := a.Attrs["decisions"]; !ok {
		return []model.PatchOp{{Op: "add", Path: "/attrs/decisions", Value: raw([]Decision{d})}}
	}
	return []model.PatchOp{{Op: "add", Path: "/attrs/decisions/-", Value: raw(d)}}
}

// Diff computes the patch that turns `from` into `to`: removed edges, nodes and groups, then added
// groups, nodes and edges, then wholesale replacements of changed ones, then root attrs. Applying
// the result with model.Apply yields `to` (canonically equal); the tests prove it on every fixture.
func Diff(from, to *model.Architecture) ([]model.PatchOp, error) {
	var ops []model.PatchOp
	fromNodes, toNodes := map[string]model.Node{}, map[string]model.Node{}
	for _, n := range from.Nodes {
		fromNodes[n.ID] = n
	}
	for _, n := range to.Nodes {
		toNodes[n.ID] = n
	}
	fromEdges, toEdges := map[string]model.Edge{}, map[string]model.Edge{}
	for _, e := range from.Edges {
		fromEdges[e.ID] = e
	}
	for _, e := range to.Edges {
		toEdges[e.ID] = e
	}
	fromGroups, toGroups := map[string]model.Group{}, map[string]model.Group{}
	for _, g := range from.Groups {
		fromGroups[g.ID] = g
	}
	for _, g := range to.Groups {
		toGroups[g.ID] = g
	}
	// removals: edges first (they reference nodes), then nodes, then groups
	for _, e := range from.Edges {
		if _, ok := toEdges[e.ID]; !ok {
			ops = append(ops, RemoveRelationship(e.ID))
		}
	}
	for _, n := range from.Nodes {
		if _, ok := toNodes[n.ID]; !ok {
			ops = append(ops, RemoveElement(n.ID))
		}
	}
	for _, g := range from.Groups {
		if _, ok := toGroups[g.ID]; !ok {
			ops = append(ops, model.PatchOp{Op: "remove", Path: "/groups/" + g.ID})
		}
	}
	// additions: groups, nodes, edges
	for _, g := range to.Groups {
		if _, ok := fromGroups[g.ID]; !ok {
			ops = append(ops, AddBoundary(g))
		}
	}
	for _, n := range to.Nodes {
		if _, ok := fromNodes[n.ID]; !ok {
			ops = append(ops, AddElement(n))
		}
	}
	for _, e := range to.Edges {
		if _, ok := fromEdges[e.ID]; !ok {
			ops = append(ops, AddRelationship(e))
		}
	}
	// replacements
	for _, g := range to.Groups {
		if old, ok := fromGroups[g.ID]; ok {
			same, err := equalJSON(old, g)
			if err != nil {
				return nil, err
			}
			if !same {
				ops = append(ops, model.PatchOp{Op: "replace", Path: "/groups/" + g.ID, Value: raw(g)})
			}
		}
	}
	for _, n := range to.Nodes {
		if old, ok := fromNodes[n.ID]; ok {
			same, err := equalJSON(old, n)
			if err != nil {
				return nil, err
			}
			if !same {
				ops = append(ops, UpdateElement(n))
			}
		}
	}
	for _, e := range to.Edges {
		if old, ok := fromEdges[e.ID]; ok {
			same, err := equalJSON(old, e)
			if err != nil {
				return nil, err
			}
			if !same {
				ops = append(ops, model.PatchOp{Op: "replace", Path: "/edges/" + e.ID, Value: raw(e)})
			}
		}
	}
	same, err := equalJSON(from.Attrs, to.Attrs)
	if err != nil {
		return nil, err
	}
	if !same {
		ops = append(ops, model.PatchOp{Op: "replace", Path: "/attrs", Value: raw(to.Attrs)})
	}
	if from.Name != to.Name {
		ops = append(ops, model.PatchOp{Op: "replace", Path: "/name", Value: raw(to.Name)})
	}
	return ops, nil
}

// raw marshals a value into the patch op's JSON slot; the inputs are our own structs, so a
// marshal error is a programming error and the op becomes `null` (which model.Apply rejects).
func raw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

func equalJSON(a, b any) (bool, error) {
	ab, err := json.Marshal(a)
	if err != nil {
		return false, fmt.Errorf("c4 diff: %w", err)
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false, fmt.Errorf("c4 diff: %w", err)
	}
	ca, err := model.CanonicalJSON(ab)
	if err != nil {
		return false, err
	}
	cb, err := model.CanonicalJSON(bb)
	if err != nil {
		return false, err
	}
	return string(ca) == string(cb), nil
}
