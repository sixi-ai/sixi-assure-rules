# Contributing

Thank you for looking. This repository holds the deterministic part of Sixi Assure: rule packs, the
regulatory corpus and the typed-model schema. Anyone may read it, run it against their own
architecture models and propose changes.

## How to contribute

**Issues** are the right place for: a rule that fires when it should not (or stays silent when it
should not), a clause reference that is wrong, superseded or mis-numbered, a helper the CEL
environment is missing, or a model your architecture cannot express. A small model that reproduces
the behaviour is worth more than a description.

**Pull requests** are welcome for the same things. Keep one change per pull request.

## Developer Certificate of Origin

Every commit must be signed off:

```bash
git commit -s -m "fix(ai): AI-002 no longer fires on an internal-only agent"
```

The `Signed-off-by` line certifies the [Developer Certificate of Origin](https://developercertificate.org/):
you wrote the contribution, or you have the right to submit it under this repository's licence.
Contributions are accepted under **Apache-2.0** (`LICENSE`).

## Before you open a pull request

```bash
make test   # go vet + go test ./...
make eval   # the golden set: per-rule and per-pack precision and recall
gofmt -l .  # must print nothing
```

The CI workflow runs exactly these.

## Changing a rule

A rule is a CEL condition in `packs/<pack>.yaml`. The rules that apply to it:

1. **Both fixtures.** Every rule declares `fixtures: { positive: …, negative: … }`. The positive
   model must make the rule fire, the negative must not. A rule without working fixtures fails the
   eval, and a rule whose fixtures both pass by accident proves nothing — make the negative a
   near-miss of the positive.
2. **Real clauses only.** `clauses:` may only name ids that exist in `corpus/`. Never invent a
   clause, never cite a clause that does not say what the rule claims. If no clause fits, ship the
   rule with no citation rather than a wrong one.
3. **Exactly one cause.** Add the rule id to a cause in `causes.yaml`. Loading fails otherwise.
4. **Deterministic.** No network, no time-dependence, no randomness. The same model must always
   produce the same findings.
5. **Message and remediation.** The message says what the drawing shows, in one line, naming the
   elements. The remediation says what to change. Both follow the wording rule below.
6. **Thresholds.** `make eval` must stay at or above 0.90 precision and 0.85 recall per pack. If a
   new rule costs recall elsewhere, fix the golden set's expectations only when they were wrong.

## Changing the corpus

- The record format and the rules on it are in `README.md` ("How to add a clause").
- `summary` is **our** paraphrase. Do not paste the source's sentences into it.
- `excerpt` may hold a short verbatim quotation **only** where the source licence permits
  redistribution. `NOTICE.md` has the table. For every other source the sync marks the record
  `"redacted": "licence"` and empties the excerpt; do not re-add it by hand.
- A provision that changed is a **new record with a new `version`**, not an edit of a released one.
- Set `verified: true` only if you fetched the official source, and say so in `note` with the date.

## The wording rule

Sixi Assure **assesses**, **evidences** and **proposes**. It never **certifies**, **confirms** or
**guarantees**, and nothing it produces calls a system **compliant**. This holds in rule messages,
remediations, summaries, command output and documentation. A finding describes a design and points
at a clause; the compliance judgement belongs to the organisation and its regulator.

## Security

Do not open a public issue for a vulnerability. See `SECURITY.md` — report to **contact@sixi.ai**.

## Code of conduct

By participating you agree to the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Where things come from

This repository is a synced snapshot: the rule packs, the corpus and the Go packages are maintained
in the private Sixi Assure product repository and mirrored here after each release. Your pull
request is reviewed here and merged upstream, then reappears in the next sync. That is also why a
merged change may land with a different commit hash.

Questions: **contact@sixi.ai**.
