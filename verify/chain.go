package verify

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// chainEvent is one event of a chain export (GET /audit/{arch_id}, a bundle's chain.json).
type chainEvent struct {
	ID          string          `json:"id"`
	ArchID      string          `json:"arch_id"`
	Version     int             `json:"version"`
	Type        string          `json:"type"`
	Payload     json.RawMessage `json:"payload"`
	PayloadHash string          `json:"payload_hash"`
	PrevHash    string          `json:"prev_hash"`
	Hash        string          `json:"hash"`
	Actor       string          `json:"actor"`
	TS          time.Time       `json:"ts"`
	Seq         *int64          `json:"seq"`
	// AnchoredBy is the raw anchored_by: absent (nil), null, or an anchor id.
	AnchoredBy json.RawMessage `json:"anchored_by,omitempty"`
}

// chainAnchor is one receipt as a chain export lists it. A bundle adds the token and its
// certificates as files (anchors/<id>.tsr, anchors/<id>.certs.pem); an export may carry them inline.
type chainAnchor struct {
	ID            string     `json:"id"`
	HeadHash      string     `json:"head_hash"`
	HeadSeq       int64      `json:"head_seq"`
	HeadEventID   string     `json:"head_event_id"`
	EventID       string     `json:"event_id"`
	ReceiptSHA256 string     `json:"receipt_sha256"`
	SignedAt      *time.Time `json:"signed_at"`
	TSAHost       string     `json:"tsa_host"`
	Status        string     `json:"status"`
	Token         []byte     `json:"token,omitempty"`
	CertChain     []byte     `json:"cert_chain,omitempty"`
}

type chainExport struct {
	ArchID   string        `json:"arch_id"`
	Events   []chainEvent  `json:"events"`
	HeadHash string        `json:"head_hash"`
	Count    *int          `json:"count"`
	Anchors  []chainAnchor `json:"anchors"`
}

// chainState is what the chain checks established, for the anchor and report checks after them.
type chainState struct {
	exp *chainExport
	// recomputed is each event's hash recomputed from its fields (index = position).
	recomputed []string
	// intact is the number of leading events whose links all recompute.
	intact  int
	seqOK   bool // every event carries a seq
	bySeq   map[int64]int
	byID    map[string]int
	head    string
	linksOK bool
}

// PayloadHash is the hash of an event payload as the store computes it: sha256 of the canonical
// JSON (sorted keys, no insignificant whitespace).
func PayloadHash(payload []byte) (string, error) {
	canon, err := model.CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	return model.HashBytes(canon), nil
}

// verifyChain recomputes every hash from genesis (ChainHash, mirrored from the store) and checks
// the head and the anchored_by marks.
func verifyChain(r *Report, raw []byte) *chainState {
	var exp chainExport
	if err := json.Unmarshal(raw, &exp); err != nil {
		r.add(SectionChain, "chain export", Fail, "not a chain export: %v", err)
		return nil
	}
	st := &chainState{exp: &exp, bySeq: map[int64]int{}, byID: map[string]int{}, seqOK: true, linksOK: true}
	name := "chain " + exp.ArchID
	if len(exp.Events) == 0 {
		r.add(SectionChain, name, Fail, "the export holds no events")
		return nil
	}
	if exp.Count != nil && *exp.Count != len(exp.Events) {
		r.add(SectionChain, name, Fail, "the export holds %d of the chain's %d events (an export with limit); verify the whole chain", len(exp.Events), *exp.Count)
		st.linksOK = false
	}
	prev := GenesisHash
	broken := ""
	for i, e := range exp.Events {
		st.byID[e.ID] = i
		if e.Seq == nil {
			st.seqOK = false
		} else {
			st.bySeq[*e.Seq] = i
		}
		ph, perr := PayloadHash(e.Payload)
		hash := ChainHash(e.PrevHash, ph, e.Type, e.Actor, e.Version, e.TS)
		st.recomputed = append(st.recomputed, hash)
		if broken != "" {
			continue
		}
		switch {
		case exp.ArchID != "" && e.ArchID != "" && e.ArchID != exp.ArchID:
			broken = fmt.Sprintf("event %s belongs to %s, not %s", e.ID, e.ArchID, exp.ArchID)
		case perr != nil:
			broken = fmt.Sprintf("the payload of event %s is not valid JSON", e.ID)
		case ph != e.PayloadHash:
			broken = fmt.Sprintf("the payload of event %s hashes to %s, not its payload_hash %s (payload changed)", e.ID, short(ph), short(e.PayloadHash))
		case e.PrevHash != prev:
			if i == 0 {
				broken = fmt.Sprintf("the first event %s does not start at genesis (prev_hash %s)", e.ID, short(e.PrevHash))
			} else {
				broken = fmt.Sprintf("event %s does not link to the event before it (prev_hash %s, previous hash %s)", e.ID, short(e.PrevHash), short(prev))
			}
		case hash != e.Hash:
			broken = fmt.Sprintf("event %s recomputes to %s, not its stored hash %s (type, actor, version or time changed)", e.ID, short(hash), short(e.Hash))
		default:
			st.intact = i + 1
		}
		prev = e.Hash
	}
	last := exp.Events[len(exp.Events)-1]
	st.head = last.Hash
	if broken != "" {
		st.linksOK = false
		r.add(SectionChain, name, Fail, "%d event(s); the links break: %s", len(exp.Events), broken)
	} else if st.linksOK {
		r.add(SectionChain, name, Pass, "%d event(s) recomputed from genesis with the store's chain hash; every payload, link and hash matches", len(exp.Events))
	}
	switch {
	case exp.HeadHash == "":
		r.add(SectionChain, "head", NotChecked, "the export's head_hash is %s; the last event's hash is %s", NotPresent, short(st.head))
	case exp.HeadHash != st.head:
		r.add(SectionChain, "head", Fail, "the export names head %s, its last event is %s", short(exp.HeadHash), short(st.head))
	case st.linksOK:
		r.add(SectionChain, "head", Pass, "head %s is the last event %s, recomputed", short(st.head), last.ID)
	default:
		r.add(SectionChain, "head", Fail, "head %s is the last stored event, but the chain before it does not recompute", short(st.head))
	}
	checkAnchoredBy(r, st)
	return st
}

// checkAnchoredBy recomputes, for every event, the first ok receipt whose head_seq is at or after
// the event's seq (store.CoverEvents) and compares it with the export's anchored_by mark.
func checkAnchoredBy(r *Report, st *chainState) {
	present := 0
	for _, e := range st.exp.Events {
		if e.AnchoredBy != nil {
			present++
		}
	}
	if present == 0 {
		r.add(SectionChain, "anchored_by", NotChecked, "the events' anchored_by marks are %s", NotPresent)
		return
	}
	if !st.seqOK {
		r.add(SectionChain, "anchored_by", NotChecked, "the events' seq is %s, so the anchor each event falls under cannot be recomputed", NotPresent)
		return
	}
	anchors := okAnchors(st.exp.Anchors)
	for i, e := range st.exp.Events {
		want := ""
		for _, a := range anchors {
			if a.HeadSeq >= *e.Seq {
				want = a.ID
				break
			}
		}
		var got *string
		if e.AnchoredBy != nil {
			if err := json.Unmarshal(e.AnchoredBy, &got); err != nil {
				r.add(SectionChain, "anchored_by", Fail, "event %s: anchored_by is neither null nor an anchor id", e.ID)
				return
			}
		}
		gotID := ""
		if got != nil {
			gotID = *got
		}
		if e.AnchoredBy == nil || gotID != want {
			r.add(SectionChain, "anchored_by", Fail, "event %s (position %d) is marked %q; the receipts place it under %q", e.ID, i+1, gotID, want)
			return
		}
	}
	r.add(SectionChain, "anchored_by", Pass, "every event's anchored_by mark is the first receipt whose head is at or after it")
}

// okAnchors are the receipts of an export in head order (a missing status reads as ok: the export
// lists ok receipts only).
func okAnchors(in []chainAnchor) []chainAnchor {
	out := make([]chainAnchor, 0, len(in))
	for _, a := range in {
		if a.Status == "" || a.Status == "ok" {
			out = append(out, a)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].HeadSeq < out[j-1].HeadSeq; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// eventAt finds the event an anchor names: by seq when the export carries it, else by id.
func (st *chainState) eventAt(a chainAnchor) (int, bool) {
	if st.seqOK {
		i, ok := st.bySeq[a.HeadSeq]
		return i, ok
	}
	i, ok := st.byID[a.HeadEventID]
	return i, ok
}

// hasHash reports the position of the event with this stored hash, among the events that recompute.
func (st *chainState) hasHash(h string) (int, bool) {
	for i := 0; i < st.intact; i++ {
		if st.exp.Events[i].Hash == h {
			return i, true
		}
	}
	return 0, false
}
