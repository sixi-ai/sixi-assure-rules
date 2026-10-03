package verify

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

// DefaultRulesDir is where the packs are looked for when neither the bundle nor --rules gives them:
// the product's layout seen from server/ (the public repository's sync rewrites it to "packs").
var DefaultRulesDir = "packs"

// Exit codes of the verify command.
const (
	ExitVerified = 0 // no check failed (some may not have been made: see --strict)
	ExitFailed   = 1 // a check failed, or --strict and a check was not made
	ExitUsage    = 2 // usage, or an input that cannot be read at all
)

// Main is the command: `assure verify` and `assure-check verify` call it with their arguments
// after "verify". It opens no network connection: every input is a file.
func Main(tool string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(tool, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o Options
	var asJSON, strict bool
	var now string
	fs.StringVar(&o.KeysFile, "keys", "", "saved GET /evidence/keys (JSON); used instead of, and checked against, a bundle's keys.json")
	fs.StringVar(&o.RootsFile, "roots", "", "PEM roots of the time-stamp authorities (default: the system roots on Linux and BSD)")
	fs.StringVar(&o.RulesDir, "rules", "", "rule packs to re-run when the bundle carries none (default "+DefaultRulesDir+")")
	fs.StringVar(&o.PolicyFile, "policy", "", "policy table (default: policy.yaml beside the packs, else the built-in defaults)")
	fs.StringVar(&o.AdvisoriesFile, "advisories", "", "rule-pack advisory list (advisories.json) to flag affected packs")
	fs.StringVar(&o.ReviewerKeysFile, "reviewer-keys", "", "the organisation's reviewer key registry obtained out of band (saved GET /settings/reviewer-keys); the bundle's registry is checked against it")
	fs.Func("receipts", "reanchor receipt (assure reanchor .json) to count as an anchor; repeatable or comma-separated "+
		"(receipts named <input>.reanchor-*.json beside the input are read without it)", func(v string) error {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				o.Receipts = append(o.Receipts, p)
			}
		}
		return nil
	})
	fs.BoolVar(&o.AllowPackMismatch, "allow-pack-mismatch", false, "re-run the rules even when the packs' combined hash is not the report's; prints the per-pack diff")
	fs.BoolVar(&strict, "strict", false, "exit 1 when a check could not be made because its input is not present")
	fs.BoolVar(&asJSON, "json", false, "print the verification as JSON")
	fs.StringVar(&now, "at", "", "verification time, RFC 3339 (default now): the long-term rule checks the authorities' chains at it")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s [flags] <report.json | spot-check.json | chain.json | bundle directory | bundle.zip>\n\n"+
			"Verifies offline, with no account and no network: chain hashes from genesis, signatures against their key and its\n"+
			"validity window, RFC 3161 anchors and their certificate chains, the rule packs' hash, and the findings re-run on\n"+
			"the embedded snapshot. Exit 0: no check failed; 1: a check failed; 2: usage or unreadable input.\n\n", tool)
		fs.PrintDefaults()
	}
	// Flags may come before or after the path.
	var paths []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return ExitVerified
			}
			return ExitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		paths = append(paths, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(paths) != 1 {
		fs.Usage()
		return ExitUsage
	}
	o.Path, o.Tool, o.DefaultRulesDir = paths[0], tool, DefaultRulesDir
	if now != "" {
		t, err := time.Parse(time.RFC3339, now)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%s: -at: %v\n", tool, err)
			return ExitUsage
		}
		o.Now = t
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rep, err := Run(ctx, o)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %s\n", tool, oneLine(strings.TrimPrefix(err.Error(), ErrInput.Error()+": ")))
		return ExitUsage
	}
	if asJSON {
		err = rep.WriteJSON(stdout)
	} else {
		err = rep.WriteText(stdout)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", tool, err)
		return ExitUsage
	}
	if !rep.OK() || (strict && rep.NotChecked > 0) {
		return ExitFailed
	}
	return ExitVerified
}
