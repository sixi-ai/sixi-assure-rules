# NOTICE

Sixi Assure Rules
Copyright 2026 Sixi AI

This product includes software developed at Sixi AI (https://sixi.ai).
Licensed under the Apache License, Version 2.0 — see `LICENSE`.

The code, the rule packs, the cause taxonomy, the lenses, the golden set, the examples and every
`summary` and `note` field in the corpus are our own work and are covered by that licence. This
file records what is not: the third-party sources the corpus references, and the upstream projects
that informed two rule patterns.

---

## 1. Regulatory corpus (`corpus/`)

Each clause record in `corpus/regimes/*.json` names its source in the `licence` field. A record
always carries the citation id, the instrument, the reference, the heading, **our own paraphrase**
(`summary`), our verification `note` and the official `source_url`. A short **verbatim** quotation
(`excerpt`) is published **only** where the source permits redistribution. Every other record is
marked `"redacted": "licence"`, carries an empty `excerpt`, and points at the official text through
`source_url`, where you can read the wording under the source's own terms.

The policy is executed by `scripts/redact_corpus.py`, which is run on every sync from the product
repository, and it is enforced by `TestRedactedClausesCarryNoVerbatimText` in `corpus/`.

| `licence` | Source | Terms as we understand them | Verbatim text here | Records |
|---|---|---|---|---:|
| `eu-law` | EU legislation and RTS on EUR-Lex (AI Act, DORA, CRA, NIS2, GDPR, Machinery Regulation, EudraLex Vol. 4 Annex 11) | Reuse permitted with acknowledgement of the source — Commission Decision 2011/833/EU. Only the [Official Journal](https://eur-lex.europa.eu) is authentic. | **included** | 147 |
| `admin.ch` | Swiss federal texts on [Fedlex](https://www.fedlex.admin.ch) (FADP/SR 235.1, ISA/SR 128) | Official publications of the Swiss Confederation; reproduction with the source is permitted. | **included** | 13 |
| `ch-law` | Swiss federal act text (Fedlex) | as above | **included** | 3 |
| `finma` | [FINMA](https://www.finma.ch) circulars and guidance (Circ. 2023/1, Circ. 2018/3, Guidance 08/2024) | Published supervisory documents of the Swiss supervisory authority. | **included** | 18 |
| `public` (FDA) | 21 CFR Part 11 via [eCFR](https://www.ecfr.gov) | Work of the US federal government — public domain. | **included** | 22 |
| `nist-public` | NIST SP 800-207, NIST AI 100-1 | Work of the US federal government — public domain. | included (no excerpt held) | 10 |
| `owasp` | OWASP LLM Top 10 (2025), OWASP Top 10 for Agentic Applications (2026), OWASP ASVS 5.0.0 | **CC BY-SA 4.0** — attribution required, share-alike on derived text. | included (no excerpt held) | 34 |
| `public` (OSFI) | OSFI Guideline E-23 (Canada) | Crown copyright; redistribution terms not confirmed. | **references only** | 21 |
| `iso` | ISO/IEC 27001:2022 and ISO/IEC 42001:2023, Annex A | Copyright-protected standards sold by ISO/IEC. | **references only** | 22 |
| `iec` | IEC 62443-3-2, 3-3, 4-2 | Copyright-protected standards sold by the IEC. | **references only** | 5 |
| `ispe` | ISPE GAMP 5 (2nd ed.) and the ISPE GAMP Guide: Artificial Intelligence | Licensed to the purchaser. | **references only** | 27 |
| `csa` | Cloud Security Alliance — MAESTRO agentic threat-modelling framework | **CC BY-NC-SA 4.0** — non-commercial only, so not republished here. | **references only** | 13 |
| `cis-benchmark` | CIS Microsoft Azure Foundations Benchmark | **CC BY-NC-SA 4.0** — non-commercial only, so not republished here. | **references only** | 1 |
| `microsoft-docs` | Microsoft cloud security benchmark, Microsoft Learn product guidance | Terms vary by page and are not confirmed for redistribution. | **references only** | 47 |

383 clause records across 23 regimes; **136 carry references only**. No record in this repository
reproduces text from ISO, IEC, ISPE, CSA, CIS, OSFI or Microsoft.

**Attributions required by the sources above**

- **OWASP** — OWASP Top 10 for Large Language Model Applications and OWASP Top 10 for Agentic
  Applications, © OWASP Foundation, licensed CC BY-SA 4.0. Control ids and headings are used for
  citation; the descriptions in `summary` are ours.
- **European Union** — © European Union, https://eur-lex.europa.eu, 1998–2026. Only the European
  Union law published in the printed Official Journal is deemed authentic.
- **Swiss Confederation** — texts from Fedlex; only the versions published there are authoritative.
- **FINMA** — circulars and guidance published by the Swiss Financial Market Supervisory Authority.
- **NIST** — NIST SP 800-207 and the NIST AI Risk Management Framework (AI 100-1), US Department of
  Commerce, public domain.

Regime names, standard numbers and the names of the bodies above are used nominatively, to cite
their documents. This repository is not endorsed by, affiliated with or certified by any of them.

## 2. Rule packs (`packs/`)

The packs are our own work. Two of them derive a detection *pattern* — not code and not text —
from Apache-2.0 projects, and `packs/NOTICE.md` records exactly what was taken and what was
changed: **MCP Scanner** (Cisco AI Defense) for the hidden-secondary-behaviour vocabulary of
`AGT-002`, and **Agentic Radar** (SplxAI) as an editorial cross-reference for tool-capability
classes. No text or code from either project is reproduced here.

## 3. Lenses (`lenses/`)

- `lenses/atlas.yaml` maps rule ids to **MITRE ATLAS** technique ids. ATLAS is © The MITRE
  Corporation 2021–2026 and is published under Apache-2.0; technique ids and names are used for
  reference. The `why` sentence beside each entry is ours.
- `lenses/stride.yaml` is our own classification. STRIDE is a taxonomy, not a licensed artefact.

## 4. Dependencies

All runtime and test dependencies are permissively licensed:

| Module | Licence |
|---|---|
| `cel.dev/cel-go`, `cel.dev/expr` | Apache-2.0 |
| `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 |
| `github.com/goccy/go-yaml` | MIT |
| `github.com/evanphx/json-patch/v5` | BSD-3-Clause |
| `github.com/stretchr/testify` | MIT |
| `github.com/antlr4-go/antlr/v4` | BSD-3-Clause |
| `golang.org/x/text`, `golang.org/x/exp` | BSD-3-Clause |
| `google.golang.org/protobuf`, `google.golang.org/genproto/...` | BSD-3-Clause |
| `go.yaml.in/yaml/v3` | MIT / Apache-2.0 |

No AGPL or SSPL dependency is used.

## 5. Test fixtures that look like credentials

`secretguard/testdata/` contains **synthetic** strings shaped like API keys, tokens, connection
strings and private keys. They are the test vectors of the secret detector and none of them is, or
ever was, a real credential; see `secretguard/README.md`. `.gitleaks.toml` allowlists that
directory so secret scanners do not report them.
