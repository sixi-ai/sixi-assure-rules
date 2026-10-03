# Sixi Assure Rules

The deterministic rule packs, the regulatory corpus and the typed-model schema behind
[Sixi Assure](https://sixi.ai), extracted so they can be read, checked and argued with.

An architecture is a typed graph: nodes (users, apps, agents, LLM endpoints, tools, datastores,
gateways, edge devices, machines, log sinks …), edges with a kind, an auth mode and an encryption
mode, and groups (zones, trust boundaries). A **rule** is a CEL condition over that graph. When it
holds, the engine emits a **finding** that names the elements involved, a severity, a remediation
and the **clause ids** the rule cites.

Three properties hold throughout, and they are the reason this repository exists:

1. **Findings come only from rules.** No model, no heuristic and no language model creates a
   finding. The condition is in the YAML, in front of you.
2. **Every regulatory statement cites a clause.** A citation is `REGIME:DOC:REF` — for example
   `AIACT:2024/1689:Art14` — and resolves to a record in `corpus/` with the instrument, the
   reference, a paraphrase and the official URL. Unknown id → "no clause found", never an invention.
3. **It assesses and evidences; it never certifies.** No output of this engine says *compliant*,
   *certified*, *guaranteed* or *confirmed*.

The product at https://sixi.ai runs this same engine: the canvas, the exports and the assistant are
projections of the same typed model, and the assistant may only *propose* patches a person accepts.
This repository is a synced snapshot of the engine and its data; the product repository is the
source of truth.

**Today: 88 rules in 16 packs, grouped into 19 causes · 383 clause records across 23 regimes ·
14 golden models with expected findings · 180 rule fixtures.**

## Quick start

Go ≥ 1.27, no other dependency.

```bash
git clone https://github.com/sixi-ai/sixi-assure-rules && cd sixi-assure-rules

# Validate a model and list its findings, each with the clause it cites.
go run ./cmd/assure-check examples/agentic-ai-on-azure-bad-twin.json
```

```
OK   examples/agentic-ai-on-azure-bad-twin.json  nodes=12 edges=14 groups=4 hash=ee7a221b7f93
     18 findings (7 high, 8 medium, 3 low)

  [high    ] AI-003   e_agent_ledger
             Operations agent (Foundry Agent Service) performs a high-consequence writes on
             Core ledger SQL with no human approval step.
             cites AIACT:2024/1689:Art14 — Regulation (EU) 2024/1689 (AI Act), Art. 14 — Human oversight
             cites FINMA:08/2024:Governance — FINMA Guidance 08/2024 …, Section 2.1 Governance
             fix:   Insert a human approval step before the action; make the action reversible; add a kill switch.
  …
```

Its clean twin, `examples/agentic-ai-on-azure.json`, is the same architecture with the weaknesses
designed out. `make check MODEL=…` does the same thing; `-json` gives machine-readable output and
`-fail-on high` makes it a gate in CI.

```bash
make test    # go vet + go test ./...
make eval    # the golden set: precision and recall per rule and per pack
```

## In CI: SARIF for code scanning and a job summary

`assure-check` writes its findings as **SARIF 2.1.0** (`-sarif <file>`) and as a Markdown summary
(`-summary-md <file>`, `-` for stdout; `-step-summary` appends it to `$GITHUB_STEP_SUMMARY`). Each
result points at the model file and the line that declares the first element it names, lists the
element ids as logical locations, cites the rule's clause ids (an id the corpus does not know is
marked "no clause found") and carries a fingerprint built from the rule id and the sorted element
ids, so re-ordering a model never re-opens an alert. Critical and high map to `error`, medium to
`warning`, low and info to `note`. Both files are written before the exit status is decided, so a
failing `-fail-on` still leaves them behind. No account and no network are needed.

```bash
go run ./cmd/assure-check -fail-on high -sarif sixi-assure.sarif -summary-md - examples/*.json
```

The repository is also a **GitHub Action** (`action.yml`, composite): it sets up Go, builds
`assure-check` from the action's own checkout, assesses the models your glob matches against the
packs of the ref you pinned, appends the summary to the job summary and outputs the SARIF path.
It runs on **Linux runners** (`ubuntu-latest`; it needs bash 4 or later, which macOS runners do not
ship). Symlinked model files are skipped, and workflow commands are switched off while the report
is printed, so text inside a model cannot become one.

| Input | Default | Meaning |
|---|---|---|
| `models` | `**/*.sixi.json` | space-separated globs, relative to the repository root (hidden directories are skipped) |
| `fail-on` | `high` | fail the step at this severity or above: `critical`, `high`, `medium`, `low`, `info`, or `none` |
| `sarif` | `sixi-assure.sarif` | where the SARIF file is written; also the `sarif` output |

```yaml
name: architecture
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  assess:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload-sarif
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false   # the check needs no token in .git/config
      - id: assure
        # Pin the action by a commit SHA of this repository (tags can move).
        uses: sixi-ai/sixi-assure-rules@<commit-sha>
        with:
          models: "architecture/**/*.sixi.json"
          fail-on: high
      - name: Upload findings to code scanning
        if: ${{ !cancelled() }}           # also when the gate failed the previous step
        uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
        with:
          sarif_file: ${{ steps.assure.outputs.sarif }}
          category: sixi-assure
```

Findings then appear under *Security → Code scanning* and as annotations on the model file in the
pull request. A reviewer who dismisses an alert there dismisses the alert, not the rule: the
finding stays in the SARIF until the design changes. The summary and the alerts assess and
evidence a design; they never certify anything.

## Layout

| Path | What it is |
|---|---|
| `packs/*.yaml` | the 16 rule packs — ai, agt, a2a, zt, net, data, log, res, gov, tpr, ot, mr, gxp, c4, imp, drift |
| `packs/fixtures/` | one positive and one negative model per rule; the eval asserts both behave |
| `causes.yaml` | the 19 design invariants; every rule belongs to exactly one |
| `policy.yaml` | which regimes raise or lower a severity |
| `lenses/` | rule id → MITRE ATLAS technique / STRIDE category; re-labels findings, never creates one |
| `corpus/regimes/*.json` | the clause records every citation resolves to (`corpus/` is also a Go package) |
| `corpus/disclaimers.json` | the one-sentence disclaimer shown with any statement about a regime |
| `golden-set/` | 14 architectures with their expected findings — the precision/recall gate |
| `examples/` | four demo architectures: two Azure agentic-AI twins, two OT edge-to-cloud twins |
| `schema/model.schema.json` | the typed graph model as JSON Schema 2020-12 |
| `model/` | Go: the model types, validation, invariants, JSON Patch, the C4 projection |
| `rules/` | Go: the pack loader, the CEL environment, the engine, causes, policy; `rules/sarif` renders findings as SARIF 2.1.0 and a Markdown summary |
| `secretguard/` | Go: the detector that refuses a model carrying a credential |
| `cmd/assure-check`, `cmd/assure-eval` | the two commands |
| `action.yml` | the GitHub Action: `assure-check` over your models, SARIF for code scanning, a job summary |

## How a pack is written

A pack is YAML. A rule has a scope (`node`, `edge` or `graph`), a severity, a **CEL condition** over
that scope, a message template, the clauses it cites, a remediation, optionally a JSON Patch
template that fixes it, and two fixtures.

```yaml
pack: ai
version: 0.2.0
regimes: [AIACT, FINMA, OWASP, ISO, MAESTRO, DORA, MSFT]
rules:
  - id: AI-001
    title: LLM called without an AI gateway
    scope: edge
    severity: high
    condition: |
      e.from.type in ["agent","app"] && e.to.type == "llm_endpoint" &&
      !g.pathThrough(e.from.id, e.to.id, "gateway")
    message: "{{e.from.name}} calls {{e.to.name}} directly: no token limits, content safety or prompt/response logging."
    clauses: [MSFT:APIM-GenAI, FINMA:08/2024:Monitoring]
    remediation: "Route through an AI gateway (token limits, content safety, logging); private networking."
    fixtures: { positive: fixtures/AI-001.pos.json, negative: fixtures/AI-001.neg.json }
    tags: [ai, gateway, logging]
```

`e` is the edge (`e.from`, `e.to` are its nodes), `n` the node, `g` the graph. Helpers such as
`g.pathThrough`, `g.has`, `attr(x, "name", default)` and `p.regimes` are declared in
`rules/cel.go`; the environment is closed, every rule is cost-limited and time-limited, and a rule
that cannot be compiled fails the load rather than being skipped.

**Adding a rule**: put it in the right pack with a new id, write both fixtures (`.pos.json` must
fire it, `.neg.json` must not), cite clauses that exist, add the id to a cause in `causes.yaml`,
then run `make eval`. The eval fails if a fixture is missing or misbehaves, if a rule has no cause,
or if a pack drops below 0.90 precision / 0.85 recall on the golden set.

## How to add a clause

Add a record to `corpus/regimes/<REGIME>.json`:

```json
{
  "id": "AIACT:2024/1689:Art14",
  "regime": "AIACT",
  "doc": "Regulation (EU) 2024/1689 (AI Act)",
  "ref": "Art. 14",
  "title": "Human oversight",
  "summary": "Our own one- or two-sentence paraphrase. Never the source's wording.",
  "excerpt": "A short verbatim quotation — only where the source licence permits it.",
  "version": "2024-06-13",
  "effective": "2026-08-02",
  "applies_to": ["high_risk", "provider"],
  "source_url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
  "tags": ["oversight", "human-in-the-loop"],
  "licence": "eu-law",
  "verified": true,
  "note": "Checked against the ELI text on 2026-09-16."
}
```

Rules on a record: the id is stable and never re-used; `summary` is ours, not the source's; `excerpt`
is filled **only** when the `licence` permits redistribution (see NOTICE.md — the sync applies
`scripts/redact_corpus.py`, which empties it and sets `"redacted": "licence"` otherwise); a new
version of a provision is a new record, never an edit of a released one; `verified: true` means
someone fetched the official source. `corpus/` is also a Go package, so
`corpus.Lookup("AIACT:2024/1689:Art14")` resolves the citation from the embedded data, and the
tests fail if a rule cites a clause that does not exist.

## The wording rule

In this engine, in its messages and in anything built on it: **assesses, evidences, proposes.**
Never *certifies*, *confirms*, *guarantees*, or calls a system *compliant*. A finding says what the
drawing shows and which clause is relevant; whether an organisation complies is a judgement for
that organisation and its regulator, on the real system, not on a diagram. The corpus ships a
disclaimer per regime (`corpus/disclaimers.json`) for exactly this reason.

## Licence and corpus notice

Apache-2.0 — see `LICENSE`. Copyright 2026 Sixi AI.

The corpus is a special case and `NOTICE.md` is not optional reading: verbatim text is republished
only for EU law, Swiss federal texts, FINMA publications, US federal works and OWASP (CC BY-SA,
attributed). For ISO, IEC, ISPE/GAMP, CSA, CIS, OSFI and Microsoft documentation the records carry
**references only** and are marked `"redacted": "licence"` — the ids, the headings and our own
paraphrase, with a link to the official text. 136 of the 383 records are in that state.

Comments in the Go code cite the product specification (`docs/NN`) and its decision records
(`ADR-NNN`); those documents live in the private product repository, and the citations are kept so
the two trees stay diffable.

## Contributing

Issues and pull requests are welcome — a rule that fires when it should not, a clause reference
that is wrong or out of date, a missing helper, a fixture that proves a gap. Please read
`CONTRIBUTING.md` first: contributions are made under Apache-2.0 with a
[DCO](https://developercertificate.org/) sign-off (`git commit -s`), rules must ship both fixtures,
and clause text is only ever added where its licence permits.

Security reports: `SECURITY.md`, or contact@sixi.ai — please do not open a public issue.

Contact: **contact@sixi.ai** · https://sixi.ai
