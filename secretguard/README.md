# secretguard

The detector that runs before anything else touches an architecture model. Every string leaf and
every object key of an incoming document is checked; a document carrying something that looks like
a credential is refused, and the error names the JSON pointer and the detector — **never the value**.

It is here because an architecture model is a document people paste into: a connection string ends
up in a node attribute, a token in a description, a key in an imported diagram. The guard makes
every write path — create, patch, import, rule fix, agent proposal — covered by construction
instead of handler by handler.

## The fixtures look like credentials, and that is the point

`testdata/positives/*.txt` holds strings shaped like AWS access keys, Google API keys, GitHub and
Slack tokens, Entra client secrets, Azure storage keys and SAS tokens, Stripe keys, JWTs, PEM
private keys and certificates, kubeconfigs, Terraform state and database connection strings.
`testdata/negatives/*.txt` holds the near-misses that must **not** trip it: hashes, UUIDs, data
URIs, prose that happens to contain `sk-`, ordinary model text.

Every positive fixture is **synthetic**. The key bodies read `EXAMPLE`, `notarealgcpkey`,
`not-a-real-key-body-for-tests-only`, `example-only`; the AWS key is the published
`AKIAIOSFODNN7EXAMPLE` documentation value. None of them is, or ever was, a real credential, and
none of them is derived from one.

A secret scanner will still flag them, because that is exactly what they are designed to trigger.
`.gitleaks.toml` at the repository root allowlists this directory, `detectors.go` (which contains
the detection patterns themselves, including prefixes such as `AIza` and `AKIA`) and the tests that
use them. If you run a different scanner, allowlist the same paths.

If you believe a fixture here is a real credential, please report it to contact@sixi.ai rather than
opening a public issue (`SECURITY.md`).
