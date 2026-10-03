package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The offer tag (docs/18 E5): a pack names the offer it belongs to — agentic, industrial or pharma — and nothing else
// loads; a pack without the key is agentic.
func TestPackOffer(t *testing.T) {
	t.Parallel()
	withOffer := func(offer string) string {
		return strings.Replace(minimalPack, "regimes: [FINMA]\n", "regimes: [FINMA]\noffer: "+offer+"\n", 1)
	}
	tests := []struct {
		name string
		yaml string
		want string
		err  string
	}{
		{"no offer reads agentic", minimalPack, OfferAgentic, ""},
		{"agentic", withOffer("agentic"), OfferAgentic, ""},
		{"industrial", withOffer("industrial"), OfferIndustrial, ""},
		{"pharma", withOffer("pharma"), OfferPharma, ""},
		{"unknown offer", withOffer("defence"), "", `offer "defence" must be one of agentic|industrial|pharma`},
		{"case matters", withOffer("Agentic"), "", "must be one of"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := parseInline(t, tc.yaml)
			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, c.Packs()[0].OfferOf())
		})
	}
	var nilPack *Pack
	assert.Equal(t, OfferAgentic, nilPack.OfferOf())
}

// Every shipped pack declares its offer: the sector packs are parked from the agentic offer (gxp pharma; mr and ot
// industrial), every other pack is agentic. No pack is deleted.
func TestShippedPackOffers(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	sector := map[string]string{"gxp": OfferPharma, "mr": OfferIndustrial, "ot": OfferIndustrial}
	for _, p := range c.Packs() {
		assert.NotEmpty(t, p.Offer, "pack %s declares no offer", p.Pack)
		want := OfferAgentic
		if o, ok := sector[p.Pack]; ok {
			want = o
		}
		assert.Equal(t, want, p.OfferOf(), p.Pack)
	}
	for name := range sector {
		found := false
		for _, p := range c.Packs() {
			found = found || p.Pack == name
		}
		assert.True(t, found, "sector pack %s is still shipped", name)
	}
}
