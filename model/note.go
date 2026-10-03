package model

// ADR-081: a note is an annotation the architect draws on the map. It is part of the model version
// but outside assessment by construction: the rules engine, the C4 projection, the inventories, the
// spot check and the posture skip it, and it carries no flows.

// NodeTypeNote is the node type of an annotation.
const NodeTypeNote = "note"

// NoteTextMax is the rune limit of a note's text (the schema's longText).
const NoteTextMax = 2000

// IsNote reports whether a node type is the annotation type.
func IsNote(nodeType string) bool { return nodeType == NodeTypeNote }

// NoteTone returns the tone of a note, neutral when absent or unknown.
func NoteTone(n *Node) string {
	t := n.Attrs.String("tone", "")
	for _, v := range NoteTones {
		if v == t {
			return t
		}
	}
	return "neutral"
}

// AssessedNodes returns the nodes every assessment reads: all but notes. The slice aliases the
// architecture's nodes when there is no note, so the common path does not allocate.
func AssessedNodes(a *Architecture) []Node {
	has := false
	for i := range a.Nodes {
		if IsNote(a.Nodes[i].Type) {
			has = true
			break
		}
	}
	if !has {
		return a.Nodes
	}
	out := make([]Node, 0, len(a.Nodes))
	for i := range a.Nodes {
		if !IsNote(a.Nodes[i].Type) {
			out = append(out, a.Nodes[i])
		}
	}
	return out
}
