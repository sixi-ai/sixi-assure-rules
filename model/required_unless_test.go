package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRequiredAttrsOf (integration 2 item 10): an agent that declares identity_id (schema 1.1) no longer needs the
// deprecated identity string for its inventory; without identity_id it still does, and types without an
// x-required-unless keep their list.
func TestRequiredAttrsOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		node *Node
		want []string
	}{
		{"agent without identity_id", &Node{Type: "agent", Attrs: Attrs{"identity": "unknown"}},
			[]string{"identity", "autonomy", "purpose", "owner"}},
		{"agent with identity_id", &Node{Type: "agent", Attrs: Attrs{"identity_id": "id_1"}},
			[]string{"autonomy", "purpose", "owner"}},
		{"agent with an empty identity_id", &Node{Type: "agent", Attrs: Attrs{"identity_id": ""}},
			[]string{"identity", "autonomy", "purpose", "owner"}},
		{"api", &Node{Type: "api", Attrs: Attrs{"identity_id": "id_1"}}, []string{"exposure"}},
		{"queue", &Node{Type: "queue"}, nil},
		{"nil", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := RequiredAttrsOf(tc.node)
			if tc.want == nil {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tc.want, got)
		})
	}
	// The list of the type is unchanged: x-required-unless narrows it per node only.
	assert.Equal(t, []string{"identity", "autonomy", "purpose", "owner"}, RequiredAttrs("agent"))
}
