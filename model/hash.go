package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Canonical returns deterministic JSON (sorted keys, no insignificant whitespace) for hashing.
// Findings and evidence are excluded: the hash identifies the designed model at a version.
//
// `schema_version` is inside the hash from schema 1.0 (ADR-040 §1, docs/02 §Versions): the same
// content means different things under different schemas, so the hash names both. A Go value that
// left the field empty is hashed at CurrentSchemaVersion, which is what it is by construction. A
// document read at 0.9 is hashed after its upgrade; hashes already recorded in the evidence chain
// and in architecture_versions are never recomputed, and the store returns them as stored.
//
// The provenance sidecar (ADR-086 §6) is inside the hash from schema 1.1: it is an omitempty member, so a model
// that carries none hashes exactly as before, and a stored 1.0 version is hashed as stored.
func Canonical(a *Architecture) ([]byte, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	var generic map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	if _, ok := generic["schema_version"]; !ok {
		generic["schema_version"] = CurrentSchemaVersion
	}
	delete(generic, "findings")
	delete(generic, "evidence")
	delete(generic, "created_at")
	delete(generic, "updated_at")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Hash returns the hex SHA-256 of the canonical model.
func Hash(a *Architecture) (string, error) {
	c, err := Canonical(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// HashBytes hashes arbitrary canonical bytes (used for patch and payload hashes).
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// CanonicalJSON re-encodes any JSON value with sorted keys.
func CanonicalJSON(raw []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
