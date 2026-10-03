// Package verify is the offline verifier of Sixi Assure evidence (docs/18 WS-A A4, ADR-087 §5 and
// §6): `assure verify` in the product and `assure-check verify` in the public rules repository are
// thin wrappers over Main.
//
// It reads one of four inputs, all as files, never from a network:
//
//	a JSON Assurance Report     report.json (with report.json.sig beside it when present)
//	a spot-check receipt        {"snapshot": …, "receipt": …} (ADR-028)
//	a chain export              GET /audit/{arch_id}: events, head_hash, anchors
//	a reviewer bundle           a directory or a .zip with manifest.json, report.json, report.json.sig,
//	                            snapshot.json, chain.json, keys.json, anchors/<id>.tsr and
//	                            anchors/<id>.certs.pem, rules/ (packs and policy.yaml), corpus/records.json
//
// and checks what the input carries: every chain hash recomputed from genesis with the store's own
// function (mirrored, see mirror_test.go), the head, each signature against the key it names and that
// key's validity window, each RFC 3161 anchor against the head hash it signs and its certificate chain
// (with the long-term rule: an expired authority chain is accepted when a later valid anchor signs the
// same or a later head), the rule packs' combined hash against the report's, and the rules re-run on
// the embedded snapshot. A check whose input is absent is reported as not checked, "not present in
// this input", never as passed.
//
// Imports are the standard library, internal/model and internal/rules only (the guard in
// scripts/sync-public-rules.sh copies this package verbatim). What verification does not establish is
// printed on every run (DoesNotEstablish).
package verify

// Version is the verifier's own version: the bundle manifest names it (verifier_version) and the
// report prints it. It changes when what the verifier checks, or how, changes.
const Version = "1.0.0"
