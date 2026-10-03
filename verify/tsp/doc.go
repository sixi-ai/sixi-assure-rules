// Package tsp verifies RFC 3161 time-stamp tokens offline: the CMS SignedData over a TSTInfo, the
// imprint, the signed attributes, the signing-certificate binding, the time-stamping usage and the
// chain to the roots a verifier gives, at the token's own genTime.
//
// The code is the product's own (internal/anchor, docs/18 A3), mirrored file by file by
// TestMirrorsMatchTheirSources in the parent package so the offline verifier carries no database,
// configuration or network code (docs/18 A4, ADR-087 §5). Edit the source in internal/anchor and
// regenerate; never edit the zz_ files here.
package tsp
