# Who authored the golden-set expectations

docs/18 WS-B B4. An expectation (`expected/<model>.json`) says which rule must fire on which element of a golden model.
Precision and recall are only as independent as the person who wrote the expectation: an expectation written by the
author of the rule measures the rule against its own author's reading.

**Status (2026-10-02): every expectation in this set is authored by the rule authors. None is independently authored.**
Externally authored expectations, at least one per rule, by a person independent of the rule's author, are pending a
named external author. That is a programme acceptance item (docs/18 B4 merge gate: the external author's sign-off),
owned by Rad; until it is met, the published precision and recall (`results/latest.json`, LIMITATIONS.md in a bundle)
state agreement with the rule authors' own reading, not an independent measurement.

**Decided (D-048, 2026-10-02):** the expectations stay authored by the rule authors for now, and are labelled so (this
file, `rule-authors` in `results/latest.json`). No external author is paid before a pilot. Each pilot's architects
write the expectations for their own model as part of the pilot, with `author` naming them and their organisation;
those become the first externally authored expectations and get their rows here.

## How authorship is recorded

- Per entry: an expectation may carry `author` (one line, at most 200 characters, no control character: a name and,
  for an external author, the organisation) and `authored_at` (`YYYY-MM-DD`). `cmd/eval` and `assure eval` both refuse
  an `authored_at` without an `author`, a date that is not `YYYY-MM-DD`, and an author longer than 200 characters or
  carrying a line break, a tab or a terminal escape; the refused file fails its model and the run exits 1. The same
  cases drive both commands (`server/cmd/eval/testdata/conformance/cases.json`).
- An entry without `author` is counted under `rule-authors`. `cmd/eval` prints the count per author
  (`expectations by author: …`) and writes it to `results/latest.json` (`authors`).
- When a rule's condition changes, its externally authored expectations are redone by their author (docs/18 B4); the
  rule author does not edit them, and the change is recorded here.
- Nobody's e-mail address or other contact detail goes into an expectation or this file.

## By file

"Rule authors" is the Sixi Assure product team: rule packs and expectations drafted with coding agents and reviewed by
the product owner. Dates: when the file entered the repository and when it last changed.

| Expectation file | Author | Independent of the rule author | Entered · last changed | Note |
|---|---|---|---|---|
| `rag-chatbot.json`, `rag-chatbot-bad.json` | rule authors | no | 2026-09-20 · 2026-10-02 | re-expected for docs/18 B1 (LOG-004 retired into AI-001); 2026-10-02: the template's evaluation scope declares `prompt_injection`, so AEI-001 is silent on it (`[]`) |
| `foundry-agent-tools.json`, `foundry-agent-tools-bad.json` | rule authors | no | 2026-09-20 · 2026-10-02 | 2026-10-02: the template declares `prompt_injection` in its evaluation scope; AEI-001 and AEI-002 silent (`[]`) |
| `webapp-sql-keyvault.json`, `webapp-sql-keyvault-bad.json` | rule authors | no | 2026-09-20 · 2026-10-01 | re-expected for docs/18 B3 (one credential, one finding) |
| `edge-iot-glassbox.json`, `edge-iot-glassbox-bad.json` | rule authors | no | 2026-09-20 · 2026-09-20 | |
| `multi-agent-fleet.json`, `multi-agent-fleet-bad.json` | rule authors | no | 2026-09-20 · 2026-10-02 | re-expected for docs/18 B1; 2026-10-02 as rag-chatbot (AEI-001) |
| `glassbox-ot-agent.json`, `glassbox-ot-agent-bad.json` | rule authors | no | 2026-09-20 · 2026-10-01 | re-expected for docs/18 B1 (AI-003 all paths) |
| `a2a-agent-mesh.json`, `a2a-agent-mesh-bad.json` | rule authors | no | 2026-09-20 · 2026-10-02 | the A2A pair (ADR-062), exercises the a2a pack; 2026-10-02 as rag-chatbot (AEI-001) |
| `dora-third-party`, `cra-agent-product`, `nis2-ledger`, `swiss-ledger` pairs | rule authors (swarm team 06 increment) | no | 2026-10-01 | regulatory-mapper rules (docs/18 WS-I I2) |
| `team05-records-resilience` pair | rule authors (swarm team 05 increment) | no | 2026-10-01 | |
| `team09-learning-guard-gmp` pair | rule authors (swarm team 09 increment) | no | 2026-10-01 | |
| `machinery-learning-guard` pair | rule authors (swarm team 09 increment, review fix) | no | 2026-10-01 | the machinery spec's MR + AIACT pair: MR-001, MR-006, MR-007, MR-008 on the bad twin |
| `mcp-agent-platform` pair | rule authors (docs/18 D2 increment) | no | 2026-10-01 | the mcp pack |
| `team01-import-provenance` pair | rule authors (swarm team 01 increment) | no | 2026-10-01 | the scp, cmp, imp and prov packs |
| `team02-identity-zero-trust` pair | rule authors (swarm team 02 increment) | no | 2026-10-01 | the lpv pack and the team 02 rules |
| `team03-agentic-runtime` pair | rule authors (swarm team 03 increment) | no | 2026-10-01 | the arh, tsc, ing, hov, mem and blr packs |
| `team04-gateways-network-data` pair | rule authors (swarm team 04 increment) | no | 2026-10-01 | the rag pack, AGW, APX, SEG, TLS, DCR |
| `team07-attack-testing` pair | rule authors (swarm team 07 increment) | no | 2026-10-02 | the aei pack |
| `fw-langgraph`, `fw-ms-agent-framework`, `fw-foundry-agent-service`, `fw-google-adk`, `fw-openai-agents` pairs | rule authors (docs/18 WS-M M3 increment) | no | 2026-10-02 | the fw pack |

A pair added after this table counts under `rule-authors` until its row is added here.

## Rules no expectation exercises

`cmd/eval` and `assure eval` list every loaded rule that no expected entry names (`unexercised_rules`, overall and per
pack, also in `results/latest.json`). Their packs' precision and recall do not measure them: a pack's 1.000 is about
its exercised rules only. On 2026-10-02 there are fifteen: AGT-006, AI-015, the eight drift rules DRF-001 … DRF-008
(the golden set is evaluated without knowledge facts, so every drift rule is silent by design), EVD-004, SCP-001,
SEG-005, STR-008 and WIS-006. AGW-003 and APX-004 left the list with the team 04 pair. The TPR-001 managed-service
branch (E6) is also unexercised although TPR-001 itself is expected on its `llm_endpoint` and `saas` branch.

## Re-expected for B2b and E6 (2026-10-01)

The gateway-functions rules (AI-001, NET-003 and STR-005 read `gateway.functions[]`; AGW-003 and APX-004 take the hop
out of a gateway of another kind) and the E6 rules (TPR-001 by function, SEG-005, WIS-006) changed no expectation: only
the `mcp-agent-platform` pair declares `functions[]`, and each of its gateways declares the functions the path rules
need; no golden model declares `environment` or `secrets_delivery`; no model hop leaves an api or waf gateway; and
the managed services the a2a pair names (`provider_service` on its identity provider, gateway and log sink) leave their
register status undeclared, which TPR-001 reports `not_checked`, not as a finding.
