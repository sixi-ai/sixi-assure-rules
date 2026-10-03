package verify

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Obligation record rows (docs/18 WS-E E2, ADR-090 §1).
//
// Since E2 the chain payload of an obligation record names its row by id and `record_sha256`; the row's free text
// (statement, artefact reference, external signer) and its custody block travel in the bundle's custody.json. The
// check below recomputes each row's hash from those fields and compares it with the record_sha256 of the chain event
// that recorded it: a row edited after the chain recorded it, or one the chain never recorded, fails.

// RecordRowSHA256 is the hash a record's chain payload carries for its row: sha256 (hex) of the canonical JSON
// (RFC 8785) of {statement, artefact_ref, external_signer, custody}, custody with unset fields absent and
// retrieved_at in RFC 3339 UTC (store.EvidenceRecordSHA256 computes the same; a test pins the two together).
func RecordRowSHA256(statement, artefactRef, externalSigner string, custody map[string]string) (string, error) {
	c := map[string]string{}
	for k, v := range custody {
		if v != "" {
			c[k] = v
		}
	}
	raw, err := json.Marshal(map[string]any{"statement": statement, "artefact_ref": artefactRef,
		"external_signer": externalSigner, "custody": c})
	if err != nil {
		return "", err
	}
	canon, err := model.CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	return model.HashBytes(canon), nil
}

// custodyRecordRows is the part of custody.json this check reads.
type custodyRecordRows struct {
	Records []struct {
		RecordID       string            `json:"record_id"`
		RecordRowID    string            `json:"record_row_id"`
		RecordSHA256   string            `json:"record_sha256"`
		Statement      *string           `json:"statement"`
		ArtefactRef    *string           `json:"artefact_ref"`
		ExternalSigner *string           `json:"external_signer"`
		Custody        map[string]string `json:"custody"`
	} `json:"records"`
}

// checkRecordRows adds one chain check when custody.json lists record rows; a bundle made before E2 lists none and
// gets no check.
func checkRecordRows(r *Report, src *source, st *chainState) {
	raw, ok, err := src.read(MemberCustody)
	if err != nil {
		r.add(SectionChain, "record rows", Fail, "reading %s: %v", MemberCustody, err)
		return
	}
	if !ok {
		return
	}
	var doc custodyRecordRows
	if err := json.Unmarshal(raw, &doc); err != nil {
		r.add(SectionChain, "record rows", Fail, "%s does not decode: %v", MemberCustody, err)
		return
	}
	payloads := map[string]string{}
	if st != nil && st.exp != nil {
		for _, e := range st.exp.Events {
			if e.Type != "evidence_record" {
				continue
			}
			var p struct {
				RecordID     string `json:"record_id"`
				RecordSHA256 string `json:"record_sha256"`
			}
			if json.Unmarshal(e.Payload, &p) == nil && p.RecordID != "" {
				payloads[e.ID] = p.RecordID + "\x00" + p.RecordSHA256
			}
		}
	}
	rows, matched := 0, 0
	var bad []string
	for _, c := range doc.Records {
		if c.RecordRowID == "" {
			continue
		}
		rows++
		if c.Statement == nil || c.ArtefactRef == nil || c.ExternalSigner == nil {
			bad = append(bad, oneLine(c.RecordRowID)+" (its text is missing)")
			continue
		}
		sum, err := RecordRowSHA256(*c.Statement, *c.ArtefactRef, *c.ExternalSigner, c.Custody)
		if err != nil || sum != c.RecordSHA256 {
			bad = append(bad, oneLine(c.RecordRowID)+" (its fields do not hash to its record_sha256)")
			continue
		}
		onChain, found := payloads[c.RecordID]
		switch {
		case st == nil:
			continue // no chain to compare with: the row recomputes, that is all that is known
		case !found:
			bad = append(bad, oneLine(c.RecordRowID)+" (no evidence_record event "+oneLine(c.RecordID)+" names it)")
			continue
		case onChain != c.RecordRowID+"\x00"+c.RecordSHA256:
			bad = append(bad, oneLine(c.RecordRowID)+" (the chain event names another row or hash)")
			continue
		}
		matched++
	}
	switch {
	case rows == 0:
		return
	case len(bad) > 0:
		r.add(SectionChain, "record rows", Fail, "%d of %d record row(s) in %s do not match the chain: %s", len(bad), rows,
			MemberCustody, strings.Join(bad, "; "))
	case st == nil:
		r.add(SectionChain, "record rows", NotChecked, "%d record row(s) recompute to their record_sha256; the chain is %s, so "+
			"nothing says the chain recorded them", rows, NotPresent)
	default:
		r.add(SectionChain, "record rows", Pass, "%s", fmt.Sprintf("%d record row(s) in %s recompute to the record_sha256 "+
			"of the evidence_record event that names them", matched, MemberCustody))
	}
}
