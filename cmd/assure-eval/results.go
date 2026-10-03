package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// resultsSchema names the format of the published result (docs/18 B4): by_pack (pack, version, hash, precision,
// recall, rules, unexercised_rules), the same pack shape as `-json`. A bundle's LIMITATIONS.md reads a copy of it from
// <RULES_DIR>/golden-set-result.json (server/internal/http/strict_bundle.go); the release must put latest.json there
// (TODO(decision), owner of deploy/ and internal/export: copy it, and state a pack's numbers only when its hash equals
// the loaded pack's). Until then a deployed bundle states the thresholds and no measured value.
const resultsSchema = "sixi-assure/golden-set-result/v1"

// publishedPack is one pack of the published result: the measured numbers and what they are about.
type publishedPack struct {
	Pack      string  `json:"pack"`
	Version   string  `json:"version"`
	Hash      string  `json:"hash"`
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	// Rules is the pack's rule count; UnexercisedRules the rules of it no expected entry names, which these numbers
	// do not measure.
	Rules            int      `json:"rules"`
	UnexercisedRules []string `json:"unexercised_rules"`
}

// published is golden-set/results/latest.json.
type published struct {
	Schema      string          `json:"schema"`
	RunDate     string          `json:"run_date"`
	CatalogHash string          `json:"catalog_hash"`
	Thresholds  map[string]any  `json:"thresholds"`
	Models      int             `json:"models"`
	Rules       int             `json:"rules"`
	Authors     map[string]int  `json:"authors"`
	ByPack      []publishedPack `json:"by_pack"`
	// UnexercisedRules lists every loaded rule no expected entry names (by_pack splits it per pack).
	UnexercisedRules []string `json:"unexercised_rules"`
	Note             string   `json:"note"`
}

// resultsPath resolves the -results flag: "auto" is results/latest.json beside the expected directory
// (golden-set/results/latest.json), and only when that results directory exists — the product keeps one, a checkout
// without it (the public mirror, whose synced golden-set has none) is not written into; "off" or "" writes nothing;
// anything else is the path to write.
func resultsPath(flagValue, expectedDir string) string {
	switch flagValue {
	case "", "off":
		return ""
	case "auto":
		dir := filepath.Join(filepath.Dir(filepath.Clean(expectedDir)), "results")
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return ""
		}
		return filepath.Join(dir, "latest.json")
	}
	return flagValue
}

// publishedOf builds the published result of a passing run at the given time.
func publishedOf(rep *report, now time.Time) published {
	meta := map[string]packMeta{}
	for _, m := range rep.PackMeta {
		meta[m.Pack] = m
	}
	out := published{
		Schema: resultsSchema, RunDate: now.UTC().Format(time.DateOnly), CatalogHash: rep.CatalogHash,
		Thresholds: map[string]any{"precision": minPrecision, "recall": minRecall},
		Rules:      rep.Rules, Authors: rep.Authors, ByPack: []publishedPack{}, UnexercisedRules: rep.UnexercisedRules,
		Note: "Measured against the golden set's own expectations (golden-set/AUTHORS.md says who wrote them). " +
			"A pack hash names exactly the rules these numbers are about; a different hash is a different measurement. " +
			"A rule under unexercised_rules has no golden expectation: its pack's precision and recall do not measure it.",
	}
	if out.UnexercisedRules == nil {
		out.UnexercisedRules = []string{}
	}
	if out.Authors == nil {
		out.Authors = map[string]int{}
	}
	for _, m := range rep.Models {
		if m.Status == "evaluated" {
			out.Models++
		}
	}
	for _, p := range rep.ByPack {
		m, ok := meta[p.Pack]
		if !ok {
			continue // an expected rule outside every loaded pack ("xyz?") is no published pack
		}
		unexercised := p.UnexercisedRules
		if unexercised == nil {
			unexercised = []string{}
		}
		out.ByPack = append(out.ByPack, publishedPack{Pack: p.Pack, Version: m.Version, Hash: m.Hash,
			TP: p.TP, FP: p.FP, FN: p.FN, Precision: p.Precision, Recall: p.Recall, Rules: m.Rules, UnexercisedRules: unexercised})
	}
	return out
}

// writeResults writes the published result of a passing run to path. When the file already states the same
// packs and numbers, it is left as it is (its run date included) and written is false.
func writeResults(path string, rep *report, now time.Time) (written bool, err error) {
	if rep == nil || !rep.Pass {
		return false, fmt.Errorf("a failing run publishes no result")
	}
	next := publishedOf(rep, now)
	if raw, err := os.ReadFile(filepath.Clean(path)); err == nil { // #nosec G304 -- CLI-supplied repository path
		var prev published
		if json.Unmarshal(raw, &prev) == nil {
			prev.RunDate = next.RunDate
			a, _ := json.Marshal(prev)
			b, _ := json.Marshal(next)
			if bytes.Equal(a, b) {
				return false, nil
			}
		}
	}
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
