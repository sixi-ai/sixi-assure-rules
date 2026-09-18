package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// PolicyTable is the parsed policy.yaml: numeric requirements per regime plus the default
// allowed regions. required("<key>") in CEL resolves through Required.
//
//	retention_days: { default: 365, FINMA: 3650, CH-CO: 3650, AIACT_deployer: 180 }
//	regions: { allowed_default: [switzerlandnorth, switzerlandwest] }
//
// A table key of the form "<REGIME>" or "<REGIME>_<role>" is the minimum for that regime.
type PolicyTable struct {
	tables         map[string]map[string]int
	regionsDefault []string
}

// DefaultPolicyTable mirrors policy.yaml (used when the file is unavailable, e.g. tests).
func DefaultPolicyTable() *PolicyTable {
	return &PolicyTable{
		tables:         map[string]map[string]int{"retention_days": {"default": 365, "FINMA": 3650, "CH-CO": 3650, "AIACT_deployer": 180}},
		regionsDefault: []string{"switzerlandnorth", "switzerlandwest"},
	}
}

// LoadPolicyTable reads and parses a policy.yaml.
func LoadPolicyTable(path string) (*PolicyTable, error) {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-controlled configuration (RULES_DIR)
	if err != nil {
		return nil, fmt.Errorf("policy table: %w", err)
	}
	t, err := ParsePolicyTable(b)
	if err != nil {
		return nil, fmt.Errorf("policy table %s: %w", filepath.Base(path), err)
	}
	return t, nil
}

// ParsePolicyTable parses policy YAML.
func ParsePolicyTable(data []byte) (*PolicyTable, error) {
	var raw map[string]any
	if err := yaml.UnmarshalWithOptions(data, &raw); err != nil {
		return nil, err
	}
	t := &PolicyTable{tables: map[string]map[string]int{}}
	for key, val := range raw {
		if key == "regions" {
			m, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("regions must be a mapping")
			}
			list, _ := m["allowed_default"].([]any)
			for _, r := range list {
				s, ok := r.(string)
				if !ok {
					return nil, fmt.Errorf("regions.allowed_default must be a list of strings")
				}
				t.regionsDefault = append(t.regionsDefault, s)
			}
			continue
		}
		m, ok := val.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be a mapping of regime → number", key)
		}
		table := map[string]int{}
		for k, v := range m {
			n, ok := toInt(v)
			if !ok {
				return nil, fmt.Errorf("%s.%s must be an integer", key, k)
			}
			table[k] = n
		}
		t.tables[key] = table
	}
	return t, nil
}

func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case uint64:
		return int(x), true // #nosec G115 -- policy values are small
	case float64:
		if x == float64(int(x)) {
			return int(x), true
		}
	}
	return 0, false
}

// AllowedRegionsDefault returns regions.allowed_default.
func (t *PolicyTable) AllowedRegionsDefault() []string {
	return append([]string(nil), t.regionsDefault...)
}

// Keys lists the numeric requirement keys (sorted).
func (t *PolicyTable) Keys() []string {
	out := make([]string, 0, len(t.tables))
	for k := range t.tables {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Required returns the effective requirement for code under the policy: the maximum of the
// minima of the enabled regimes (else the table default), raised by a tenant override if larger.
// Tenants may raise, never lower below a regime minimum. Unknown codes return 0.
func (t *PolicyTable) Required(code string, p Policy) int {
	table, ok := t.tables[code]
	if !ok {
		return maxInt(0, p.Requirements[code])
	}
	enabled := regimeSet(p.Regimes)
	best, found := 0, false
	for key, v := range table {
		if key == "default" {
			continue
		}
		regime := key
		if i := strings.Index(key, "_"); i > 0 {
			regime = key[:i]
		}
		if enabled[CanonRegime(regime)] {
			if !found || v > best {
				best, found = v, true
			}
		}
	}
	if !found {
		best = table["default"]
	}
	return maxInt(best, p.Requirements[code])
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
