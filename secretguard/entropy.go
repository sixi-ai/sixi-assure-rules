package secretguard

import (
	"math"
)

// entropyThreshold is the Shannon entropy in bits per character above which a token of at least
// entropyMinLen characters is called "high entropy" (ADR-041 §1). Random base64 sits near 5.3,
// hex digests near 4.0 and English prose near 4.0, so 4.5 separates opaque material from text.
const (
	entropyThreshold = 4.5
	entropyMinLen    = 32
)

// matchEntropy finds the first opaque high-entropy token that is not a known identifier shape.
// It is warn-only: see the detector table.
func matchEntropy(s string) (int, int, bool) {
	if len(s) < entropyMinLen {
		return 0, 0, false
	}
	// base64 image or font payloads are legitimate and enormous; they are excluded wholesale.
	if containsFold(s, ";base64,") || containsFold(s, "data:image/") {
		return 0, 0, false
	}
	// Candidate runs are found with a byte loop rather than a regexp: this detector has no hint
	// to skip on, so it runs over every string leaf of every model.
	for i := 0; i < len(s); {
		if !isTokenByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isTokenByte(s[j]) {
			j++
		}
		if tok := s[i:j]; len(tok) >= entropyMinLen && !knownIDShape(tok) && shannon(tok) > entropyThreshold {
			return i, j - i, true
		}
		i = j
	}
	return 0, 0, false
}

// isTokenByte reports the alphabet of an opaque token: base64 (standard and URL-safe) plus "=".
func isTokenByte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '=', c == '_', c == '-':
		return true
	}
	return false
}

// knownIDShape reports identifier shapes that are high-entropy by construction but carry no
// secret: UUIDs (with or without dashes) and hex digests (md5/sha1/sha256/sha512).
func knownIDShape(tok string) bool {
	if reUUID.MatchString(tok) {
		return true
	}
	if isHex(tok) {
		return true
	}
	return false
}

func isHex(tok string) bool {
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F', c == '-':
		default:
			return false
		}
	}
	return true
}

// shannon returns the Shannon entropy of tok in bits per character over its byte distribution.
func shannon(tok string) float64 {
	if tok == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(tok); i++ {
		counts[tok[i]]++
	}
	n := float64(len(tok))
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
