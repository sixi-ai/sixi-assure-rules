package main

import (
	"os"

	"github.com/sixi-ai/sixi-assure-rules/verify"
)

// `assure-check verify <path>` is the offline verifier of a Sixi Assure bundle, report, spot-check
// receipt or chain export (VERIFY.md): the same code as the product's `assure verify`, synced into
// verify/. It is dispatched before main parses its flags, so the model check's command line
// (`assure-check [flags] <model.json>…`) is unchanged. It needs no account and opens no network
// connection.
func init() {
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		os.Exit(verify.Main("assure-check verify", os.Args[2:], os.Stdout, os.Stderr))
	}
}
