package rules

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// ADR-093 FS-23 (schema 1.2): `sas`, a shared access signature, is a static bearer secret. The enum value was held
// back until every shared-secret rule named it (adr/proposals/ADR-093-M1-schema-12-narrowing-on-read.md §4): a sas hop
// raises what its api_key twin raises, rule for rule and element for element, so drawing the credential as it is never
// hides a finding.

// sharedSecretRules: each rule that reads an edge's auth as a shared secret, by its positive fixture.
var sharedSecretRules = []string{"ZT-001", "ZT-006", "WIS-001", "WIS-010", "STR-006", "RAG-001", "ATA-002"}

// withSharedSecret returns a copy of a whose every shared-secret hop (api_key, password, connection_string) is drawn
// with auth.
func withSharedSecret(a *model.Architecture, auth string) *model.Architecture {
	c := *a
	c.Edges = make([]model.Edge, len(a.Edges))
	copy(c.Edges, a.Edges)
	for i := range c.Edges {
		switch c.Edges[i].Auth {
		case "api_key", "password", "connection_string", "sas":
			c.Edges[i].Auth = auth
		}
	}
	return &c
}

func TestSASReadsAsAnAPIKey(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	for _, id := range sharedSecretRules {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			_, ok := c.Rule(id)
			require.True(t, ok, id)
			base := loadModel(t, filepath.Join(repoPath("packs"), "fixtures", id+".pos.json"))
			got := map[string]map[string][]string{}
			for _, auth := range []string{"api_key", "sas"} {
				a := withSharedSecret(base, auth)
				fs, err := eng.Evaluate(context.Background(), a, policyFromAttrs(a))
				require.NoError(t, err)
				got[auth] = findingsByRule(fs)
				assert.NotEmpty(t, got[auth][id], "%s fires on the %s twin of its positive fixture", id, auth)
			}
			assert.Equal(t, got["api_key"], got["sas"], "an api_key hop and its sas twin raise the same rule ids on the same elements")
		})
	}
}

// The committed <RULE>.sas.pos.json fixtures are the sas twins, validated against the schema like any model (loadModel)
// and pinned in pathFixtureCases; this checks each draws sas and no other shared secret.
func TestSASFixturesDrawSAS(t *testing.T) {
	t.Parallel()
	for _, id := range sharedSecretRules {
		a := loadModel(t, filepath.Join(repoPath("packs"), "fixtures", id+".sas.pos.json"))
		n := 0
		for _, e := range a.Edges {
			assert.NotContains(t, []string{"api_key", "password", "connection_string"}, e.Auth, "%s: %s", id, e.ID)
			if e.Auth == "sas" {
				n++
			}
		}
		assert.Positive(t, n, "%s.sas.pos.json draws a sas hop", id)
	}
}
