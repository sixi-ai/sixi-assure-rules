package verify

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The record rows of custody.json (docs/18 E2, ADR-090 §1) recompute to the record_sha256 the chain carries: a row
// edited after the chain recorded it, or one no chain event names, fails; a bundle without rows gets no check.
func TestCheckRecordRows(t *testing.T) {
	t.Parallel()
	custody := map[string]string{"location": "DMS", "custodian": "Compliance office"}
	sum, err := RecordRowSHA256("Marking checked.", "DMS-42", "", custody)
	require.NoError(t, err)
	row := func(statement string) map[string]any {
		return map[string]any{"record_id": "ev_1", "record_row_id": "er_1", "record_sha256": sum, "statement": statement,
			"artefact_ref": "DMS-42", "external_signer": "", "custody": custody}
	}
	chainWith := func(rowID, hash string) *chainState {
		payload, err := json.Marshal(map[string]any{"record_id": rowID, "record_sha256": hash})
		require.NoError(t, err)
		return &chainState{exp: &chainExport{Events: []chainEvent{{ID: "ev_1", Type: "evidence_record", Payload: payload}}}}
	}
	tests := []struct {
		name    string
		records []map[string]any
		chain   *chainState
		want    Status
		checks  int
	}{
		{"the row recomputes and the chain names it", []map[string]any{row("Marking checked.")}, chainWith("er_1", sum), Pass, 1},
		{"the statement was edited", []map[string]any{row("Marking checked, all good.")}, chainWith("er_1", sum), Fail, 1},
		{"the chain names another row", []map[string]any{row("Marking checked.")}, chainWith("er_2", sum), Fail, 1},
		{"no chain event names it", []map[string]any{row("Marking checked.")}, &chainState{exp: &chainExport{}}, Fail, 1},
		{"no chain in the bundle", []map[string]any{row("Marking checked.")}, nil, NotChecked, 1},
		{"a bundle before E2 lists no row", []map[string]any{{"record_id": "ev_1", "artefact_hash": "aa"}}, chainWith("er_1", sum), Pass, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeJSON(t, filepath.Join(dir, MemberCustody), map[string]any{"records": tc.records})
			src, err := open(dir)
			require.NoError(t, err)
			r := &Report{}
			checkRecordRows(r, src, tc.chain)
			require.Len(t, r.Checks, tc.checks)
			if tc.checks > 0 {
				assert.Equal(t, tc.want, r.Checks[0].Status, r.Checks[0].Detail)
				assert.Equal(t, SectionChain, r.Checks[0].Section)
			}
		})
	}
}
