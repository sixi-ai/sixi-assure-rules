package model

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compactProvenance's second step (ADR-086 §2): over the schema's limit, keys below an element fold into the element's
// key with the weaker claim winning, and root attribute keys go, so the sidecar never exceeds one key per element.
func TestCompactProvenanceFoldsOverTheLimit(t *testing.T) {
	old := provenanceKeyLimit
	t.Cleanup(func() { provenanceKeyLimit = old })
	provenanceKeyLimit = 3

	at := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	a := Empty("arch_c", "t", "C")
	a.Attrs = Attrs{"x_a": "1", "x_b": "2"}
	for _, id := range []string{"n1", "n2"} {
		a.Nodes = append(a.Nodes, Node{ID: id, Type: "app", Name: id, Layer: "app", Attrs: Attrs{"x_1": "a", "x_2": "b"}})
	}
	a.Provenance = Provenance{
		"/nodes/n1":           {Kind: ProvenanceImported, Identifier: "terraform_plan:main", LastSeenImport: "v1"},
		"/nodes/n2":           {Kind: ProvenanceImported, Identifier: "terraform_plan:main", LastSeenImport: "v1"},
		"/nodes/n1/attrs/x_1": {Kind: ProvenanceDeclared, DeclaredBy: "usr_a", DeclaredAt: &at},
		"/nodes/n2/attrs/x_2": {Kind: ProvenanceImported, Identifier: "terraform_plan:other", LastSeenImport: "v9"},
		"/attrs/x_a":          {Kind: ProvenanceDeclared, DeclaredBy: "usr_a", DeclaredAt: &at},
		"/attrs/x_b":          {Kind: ProvenanceDeclared, DeclaredBy: "usr_b", DeclaredAt: &at},
	}
	a.compactProvenance()
	assert.LessOrEqual(t, len(a.Provenance), provenanceKeyLimit, fmt.Sprint(a.Provenance))
	assert.Equal(t, ProvenanceDeclared, a.Provenance["/nodes/n1"].Kind, "a declared attribute makes its imported element declared")
	assert.Equal(t, ProvenanceImported, a.Provenance["/nodes/n2"].Kind, "an imported attribute under an imported element keeps it imported")
	assert.Equal(t, "terraform_plan:main", a.Provenance["/nodes/n2"].Identifier)
	require.NoError(t, Validate(a))
}
