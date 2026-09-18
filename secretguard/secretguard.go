// Package secretguard is the credential detector every input path runs before anything is
// persisted, logged or sent to a model (ADR-041; brief §6 "ingestion guard on every path").
//
// The API is fixed so callers (model validation, importers, agent and assistant handlers,
// knowledge ingestion, MCP propose_change) compile against it. Scan never returns the matched
// value — only the detector name, the JSON pointer or byte span of the hit, and a confidence.
//
// The package is pure Go: no network, no dependencies, no state. Detectors live in detectors.go
// with their false-positive profile in a doc comment each; the documented limits are in
// docs/08-security.md §Secret guard.
package secretguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Source names the input path a scan protects; it is recorded on the secret_rejected
// evidence event and lets tests enumerate coverage per path.
type Source string

const (
	SourceModel     Source = "model"     // model create/patch (via model.ValidateJSON)
	SourceImport    Source = "import"    // draw.io, Structurizr, registry uploads (raw bytes, before parsing)
	SourceMessage   Source = "message"   // agent and assistant messages
	SourceBrief     Source = "brief"     // Architect-mode briefs
	SourceKnowledge Source = "knowledge" // knowledge documents at ingestion
	SourcePack      Source = "pack"      // tenant-authored rule packs (ADR-042)
	SourceComment   Source = "comment"   // review comments (ADR-050)
	SourceProposal  Source = "proposal"  // MCP / rule / agent proposals (via model.Apply)
)

// Finding is one credential-shaped hit. It carries no secret material.
type Finding struct {
	Detector   string  `json:"detector"`   // e.g. "pem_private_key", "jwt", "aws_access_key", "connection_string", "terraform_state"
	Path       string  `json:"path"`       // JSON pointer for structured input, "bytes[off:len]" for raw input
	Confidence float64 `json:"confidence"` // 0..1; entropy-only hits never reach the reject threshold on their own
	Reject     bool    `json:"reject"`     // false = warn-only (certificates, entropy-only)
}

// Result is the outcome of one scan.
type Result struct {
	Source   Source    `json:"source"`
	Findings []Finding `json:"findings,omitempty"`
}

// Rejects reports whether any finding must refuse the input.
func (r Result) Rejects() bool {
	for _, f := range r.Findings {
		if f.Reject {
			return true
		}
	}
	return false
}

// ErrSecretDetected is returned by helpers that turn a rejecting Result into an error; HTTP
// maps it to 422 with problem type "secret_detected" and the offending path.
var ErrSecretDetected = errors.New("secret_detected")

// Violation is the typed error a rejecting Result becomes. It names the place (JSON pointer or
// byte span) and the detector, never the value, and unwraps to ErrSecretDetected.
type Violation struct {
	Source  Source  `json:"source"`
	Finding Finding `json:"finding"`
	More    int     `json:"more,omitempty"` // further rejecting findings not reported individually
}

// Error is safe to log and to show a user: pointer + detector only.
func (v *Violation) Error() string {
	if v.More > 0 {
		return fmt.Sprintf("secret_detected: %s (and %d more)", v.Detail(), v.More)
	}
	return "secret_detected: " + v.Detail()
}

// Unwrap lets callers use errors.Is(err, ErrSecretDetected).
func (v *Violation) Unwrap() error { return ErrSecretDetected }

// Detail is the problem+json detail: "<pointer>: <detector>".
func (v *Violation) Detail() string { return v.Finding.Path + ": " + v.Finding.Detector }

// PathHash is the sha256 hex of a JSON pointer, for the secret_rejected evidence payload
// (the pointer itself can name a user-authored extension key, so only its hash is stored).
func PathHash(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// Err turns a rejecting Result into a *Violation; a Result with only warnings returns nil.
func (r Result) Err() error {
	var first *Finding
	more := 0
	for i := range r.Findings {
		if !r.Findings[i].Reject {
			continue
		}
		if first == nil {
			first = &r.Findings[i]
			continue
		}
		more++
	}
	if first == nil {
		return nil
	}
	return &Violation{Source: r.Source, Finding: *first, More: more}
}

// Scan inspects text that has no structural path of its own (raw uploads, message bodies).
// Finding.Path is "bytes[off:len]".
func Scan(_ context.Context, src Source, text string) Result {
	r := Result{Source: src}
	scanInto(&r, nil, false, text)
	return r
}

// ScanBytes inspects raw input before parsing (importers, uploads).
func ScanBytes(ctx context.Context, src Source, data []byte) Result {
	return Scan(ctx, src, string(data))
}

// ScanValue inspects one string leaf and reports hits at the given JSON pointer.
func ScanValue(_ context.Context, src Source, pointer, text string) Result {
	r := Result{Source: src}
	scanInto(&r, []byte(pointer), true, text)
	return r
}

// ScanDocument walks every string leaf (and every object key, because an x_* extension key is
// user-authored too) of a decoded JSON document and scans it at its JSON pointer. The walk stops
// at the first rejecting leaf: the input is refused whole, so further hits add nothing but cost.
// Object keys are visited in sorted order so the reported pointer is deterministic.
func ScanDocument(_ context.Context, src Source, doc any) Result {
	r := Result{Source: src}
	walk(&r, make([]byte, 0, 64), doc)
	return r
}

// Check* return a *Violation error instead of a Result, for callers that only refuse.

// Check scans free text and returns an error when it must be refused.
func Check(ctx context.Context, src Source, text string) error { return Scan(ctx, src, text).Err() }

// CheckBytes scans raw input and returns an error when it must be refused.
func CheckBytes(ctx context.Context, src Source, data []byte) error {
	return ScanBytes(ctx, src, data).Err()
}

// CheckValue scans one string leaf at a JSON pointer and returns an error when it must be refused.
func CheckValue(ctx context.Context, src Source, pointer, text string) error {
	return ScanValue(ctx, src, pointer, text).Err()
}

// CheckDocument scans every string leaf of a decoded JSON document.
func CheckDocument(ctx context.Context, src Source, doc any) error {
	return ScanDocument(ctx, src, doc).Err()
}

// walk visits doc depth-first, appending JSON pointer tokens to ptr. It returns false once a
// rejecting finding has been recorded so the caller stops descending.
func walk(r *Result, ptr []byte, v any) bool {
	switch t := v.(type) {
	case string:
		scanInto(r, ptr, true, t)
		return !r.Rejects()
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := appendToken(ptr, k)
			// The key itself is untrusted (x_<60 chars> is user-authored, ADR-041 §Context).
			// The schema's x_ prefix is stripped first: it is a word character, so it would
			// swallow the word boundary the prefixed detectors (AKIA…, ghp_…) anchor on.
			keyText := k
			if rest, cut := strings.CutPrefix(k, "x_"); cut {
				keyText = rest
			}
			scanInto(r, child, true, keyText)
			if r.Rejects() {
				return false
			}
			if !walk(r, child, t[k]) {
				return false
			}
		}
		return true
	case []any:
		for i, e := range t {
			if !walk(r, appendToken(ptr, strconv.Itoa(i)), e) {
				return false
			}
		}
		return true
	default:
		// numbers, booleans, null: no free text, nothing to scan.
		return true
	}
}

// appendToken appends one RFC 6901 escaped pointer token to ptr. The buffer is reused across
// siblings (a finding copies it into a string), so the walk allocates once per depth, not per leaf.
func appendToken(ptr []byte, token string) []byte {
	out := append(ptr, '/') //nolint:gocritic // deliberate: the caller keeps its own slice header
	for i := 0; i < len(token); i++ {
		switch token[i] {
		case '~':
			out = append(out, '~', '0')
		case '/':
			out = append(out, '~', '1')
		default:
			out = append(out, token[i])
		}
	}
	return out
}

// minScanLen is the shortest string that can hold any detected shape; below it the scan is a
// no-op, which is what keeps a 500-node model (~5 000 leaves, most of them short) cheap.
const minScanLen = 12

// scanInto runs every detector over one string and appends its findings to r. ptr is the JSON
// pointer of the leaf when structured is true, otherwise the byte span of the hit is reported.
// The pointer is turned into a string only when a finding is recorded, so a clean model never
// allocates one.
func scanInto(r *Result, ptr []byte, structured bool, s string) {
	if len(s) < minScanLen {
		return
	}
	rejected := -1
	entropy := false
	for _, d := range detectors {
		if !d.hinted(s) {
			continue
		}
		off, n, ok := d.match(s)
		if !ok {
			continue
		}
		path := "bytes[" + strconv.Itoa(off) + ":" + strconv.Itoa(n) + "]"
		if structured {
			path = string(ptr)
		}
		r.Findings = append(r.Findings, Finding{Detector: d.name, Path: path, Confidence: d.confidence, Reject: d.reject})
		switch {
		case d.name == detectorEntropy:
			entropy = true
		case d.reject && rejected < 0:
			rejected = len(r.Findings) - 1
		}
	}
	// Entropy never rejects on its own; it only raises the confidence of a detector that does
	// (ADR-041 §1), which keeps ordinary prose and ids out of the reject path.
	if entropy && rejected >= 0 {
		r.Findings[rejected].Confidence = min(1, r.Findings[rejected].Confidence+0.05)
	}
}
