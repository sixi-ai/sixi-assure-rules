package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// The loader-derived credential_brokerage boolean (final polish item 3, ADR-088 D1, WIS-005's second branch): a node
// whose functions[] declares credential_brokerage carries attrs.credential_brokerage = true, so
// g.pathAvoidingAttr(agent, store, "credential_brokerage") walks around a brokering gateway as g.pathAvoiding walks
// around a credential_broker node. No functions, no attribute (the schema has no such node attribute to declare).
func TestCredentialBrokerageIsDerivedFromFunctions(t *testing.T) {
	t.Parallel()
	load := func(t *testing.T, name string) *model.Architecture {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("testdata", "credential-brokerage", name))
		require.NoError(t, err)
		a, err := model.ValidateJSON(raw)
		require.NoError(t, err, name)
		return a
	}
	tests := []struct {
		fixture string
		// derived is attr(n_gw, "credential_brokerage", "absent"); avoids is whether some path from the agent to the
		// store avoids every node that brokers credentials (what WIS-005's second branch reports).
		derived any
		avoids  bool
	}{
		{"gateway-brokers.json", true, false},
		{"gateway-without.json", "absent", true},
		{"gateway-brokers-bypassed.json", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			t.Parallel()
			a := load(t, tc.fixture)
			got, err := evalExpr(t, ScopeNode, `attr(n, "credential_brokerage", "absent")`, a, Policy{}, "n_gw")
			require.NoError(t, err)
			assert.Equal(t, tc.derived, got)
			got, err = evalExpr(t, ScopeGraph, `g.pathAvoidingAttr("n_agent", "n_kv", "credential_brokerage")`, a, Policy{}, "")
			require.NoError(t, err)
			assert.Equal(t, tc.avoids, got)
			// The model itself is not changed: the boolean exists only in the rules' projection.
			for _, n := range a.Nodes {
				if n.ID == "n_gw" {
					_, declared := n.Attrs["credential_brokerage"]
					assert.False(t, declared, "the loader never writes to the model")
				}
			}
		})
	}
}
