package verify

import (
	"encoding/json"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// evaluationClock is the clock the re-run pins the rules' `prov` variable to (ADR-086 §7, docs/18 C5): the bundle's
// produced_at (manifest.json), else the report's generated_at, else the snapshot's updated_at. An imported fact whose
// cadence elapses after the bundle was produced is therefore as fresh in the re-run as it was in the report, and a
// valid bundle reproduces whenever it is verified. The zero time (none of the three) leaves the verifier's own clock,
// which the note says.
func evaluationClock(src *source, doc *reportDoc, arch *model.Architecture) (time.Time, string) {
	if src != nil && src.bundle() {
		if raw, ok, err := src.read(MemberManifest); err == nil && ok {
			var m manifest
			if json.Unmarshal(raw, &m) == nil && !m.ProducedAt.IsZero() {
				return m.ProducedAt.UTC(), "provenance clock: the bundle's produced_at " + m.ProducedAt.UTC().Format(time.RFC3339) +
					" (import freshness is computed as of that time)"
			}
		}
	}
	if doc != nil && doc.GeneratedAt != "" {
		if t, err := time.Parse(time.RFC3339, doc.GeneratedAt); err == nil {
			return t.UTC(), "provenance clock: the report's generated_at " + t.UTC().Format(time.RFC3339) +
				" (import freshness is computed as of that time)"
		}
	}
	if arch != nil && arch.UpdatedAt != nil && !arch.UpdatedAt.IsZero() {
		return arch.UpdatedAt.UTC(), "provenance clock: the snapshot's updated_at " + arch.UpdatedAt.UTC().Format(time.RFC3339) +
			" (no produced_at or generated_at)"
	}
	return time.Time{}, "provenance clock: no produced_at, generated_at or updated_at; import freshness is computed as of now and may differ from the report's"
}
