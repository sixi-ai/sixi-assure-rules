package main

import (
	"bytes"
	"testing"

	"github.com/sixi-ai/sixi-assure-rules/verify"
)

// TestVerifySubcommand runs the verifier on the published hash-chain test vectors: every hash
// recomputes, and the limits of what verification establishes are printed.
func TestVerifySubcommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := verify.Main("assure-check verify", []string{"../../verify/testdata/chain-vectors.json"}, &out, &errOut)
	if code != verify.ExitVerified {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"recomputed from genesis", "What this verification does not establish:"} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Fatalf("%q is not in the output: %s", want, out.String())
		}
	}
}
