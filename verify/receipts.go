package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Reanchor receipts (docs/18 WS-A A8, ADR-087 §5). `assure reanchor` writes its receipt beside the input it
// timestamped, never into it: <input>.reanchor-<UTC time>.json, with the token and the authority's certificates
// inline, in the shape of a chain export's `anchors` entry. The verifier reads every such receipt beside a chain
// export or a bundle, plus the files --receipts names, and checks each one like an anchor of the export: its position
// in the recomputed chain, its token over that head, the authority's chain, and the long-term rule, where a receipt
// valid today carries an earlier anchor whose authority's chain has expired. A receipt has no chain_anchored record:
// reanchoring changes nothing in the exported chain.

// ReceiptSchema names the receipt document `assure reanchor` writes.
const ReceiptSchema = "sixi.assure.reanchor.v1"

// maxReceipt bounds one receipt file (a token and a certificate chain, inline).
const maxReceipt = 1 << 20

// receiptFile is the part of a receipt the verifier reads: the anchors entry, the schema and the architecture.
type receiptFile struct {
	chainAnchor
	Schema string `json:"schema"`
	ArchID string `json:"arch_id"`
}

// loadedReceipt is one receipt file: its anchor, or why it is not a usable receipt.
type loadedReceipt struct {
	path   string
	archID string
	a      chainAnchor
	err    error
}

// ReceiptsBeside lists the reanchor receipts written beside input (<input>.reanchor-*.json), sorted by name, which
// sorts them by time. A directory without any lists none.
func ReceiptsBeside(input string) ([]string, error) {
	base := strings.TrimRight(filepath.Clean(input), string(filepath.Separator))
	dir, name := filepath.Dir(base), filepath.Base(base)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, name+".reanchor-") || !strings.HasSuffix(n, ".json") {
			continue
		}
		out = append(out, filepath.Join(dir, n))
	}
	sort.Strings(out)
	return out, nil
}

// receiptPaths is every receipt of a verification: those beside the input, then those named, once each. A named
// receipt that does not exist is an input error.
func receiptPaths(o Options) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = filepath.Clean(p)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	beside, err := ReceiptsBeside(o.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: receipts beside the input: %w", ErrInput, err)
	}
	for _, p := range beside {
		add(p)
	}
	for _, p := range o.Receipts {
		if _, err := os.Stat(filepath.Clean(p)); err != nil {
			return nil, fmt.Errorf("%w: --receipts: %w", ErrInput, err)
		}
		add(p)
	}
	return out, nil
}

// loadReceipts reads each receipt. A file that is not a receipt is kept with its error, to be reported as a failed
// check: a receipt the reviewer was handed and that does not read is not silently dropped.
func loadReceipts(paths []string) []loadedReceipt {
	out := make([]loadedReceipt, 0, len(paths))
	for _, p := range paths {
		rc := loadedReceipt{path: p}
		rc.archID, rc.a, rc.err = readReceipt(p)
		out = append(out, rc)
	}
	return out
}

func readReceipt(p string) (string, chainAnchor, error) {
	f, err := os.Open(filepath.Clean(p)) // #nosec G304 -- a receipt beside the input or named by the reviewer
	if err != nil {
		return "", chainAnchor{}, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxReceipt+1))
	if err != nil {
		return "", chainAnchor{}, err
	}
	if len(raw) > maxReceipt {
		return "", chainAnchor{}, fmt.Errorf("larger than %d bytes", maxReceipt)
	}
	var doc receiptFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", chainAnchor{}, fmt.Errorf("not a receipt: %w", err)
	}
	a := doc.chainAnchor
	switch {
	case doc.Schema != ReceiptSchema:
		return "", a, fmt.Errorf("schema %q is not %s", doc.Schema, ReceiptSchema)
	case a.Status != "ok":
		return "", a, fmt.Errorf("status %q: only an ok receipt anchors", a.Status)
	case a.ID == "" || a.HeadHash == "" || a.HeadEventID == "":
		return "", a, errors.New("id, head_hash and head_event_id are required")
	case len(a.Token) == 0:
		return "", a, errors.New("the RFC 3161 token is not inline")
	}
	// A receipt is never a chain_anchored record of the export, whatever the file says.
	a.EventID = ""
	return doc.ArchID, a, nil
}
