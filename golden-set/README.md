# Golden set

`models/<name>.json` — a full model (docs/02). `expected/<name>.json` — expected findings
`[{ "rule_id": "AI-001", "ids": ["e3"] }]`, sorted by rule id, ids sorted. `make eval` evaluates every
model with the packs in `packs/` (pack applicability = pack `regimes` ∩ model `attrs.regimes`) and
reports TP/FP/FN per rule; thresholds: precision ≥ 0.90, recall ≥ 0.85 per pack (docs/09 §2).
Never add real customer diagrams; create anonymised twins instead.

## Fifty models, fifty expectation files

`models/` holds 51 files: the 50 models listed in this file (the core fourteen just below, then the pairs of each
increment in their own sections) and `README-templates.md`. `expected/` holds 50 files, one per model. Counts as of
2026-10-02, read from the files ("rules (findings)" is the number of distinct rule ids and of entries in
`expected/<name>.json`); `server/cmd/eval` pins the total (`goldenModelCount`, docs/09 §2).

| Model | id | Tenant | Regimes | Nodes | Edges | Expected rules (findings) |
|---|---|---|---|---|---|---|
| `rag-chatbot.json` | `arch_tpl_rag_chatbot` | templates | FINMA AIACT FADP MCSB | 13 | 17 | 0 (0) |
| `foundry-agent-tools.json` | `arch_tpl_foundry_agent` | templates | FINMA AIACT DORA | 14 | 17 | 0 (0) |
| `webapp-sql-keyvault.json` | `arch_tpl_webapp_sql` | templates | FINMA FADP MCSB DORA | 8 | 11 | 0 (0) |
| `edge-iot-glassbox.json` | `arch_tpl_edge_iot` | templates | CRA CH-ISG IEC DORA | 12 | 11 | 0 (0) |
| `multi-agent-fleet.json` | `arch_tpl_multi_agent` | templates | FINMA AIACT OWASP MSFT | 16 | 23 | 0 (0) |
| `glassbox-ot-agent.json` | `arch_tpl_glassbox_ot_agent` | templates | AIACT CRA NIS2 IEC ISO FADP FDA EU-GMP MR GAMP | 32 | 43 | 1 (1) |
| `a2a-agent-mesh.json` | `arch_gs_a2a_mesh` | templates | AIACT OWASP FINMA MSFT MCSB NIST | 10 | 12 | 0 (0) |
| `rag-chatbot-bad.json` | `arch_demo_rag_bad` | demo | FINMA AIACT FADP MCSB | 8 | 6 | 32 (32) |
| `foundry-agent-tools-bad.json` | `arch_demo_foundry_agent_bad` | demo | FINMA AIACT DORA | 12 | 14 | 21 (21) |
| `webapp-sql-keyvault-bad.json` | `arch_demo_webapp_sql_bad` | demo | FINMA FADP MCSB DORA | 7 | 9 | 16 (16) |
| `edge-iot-glassbox-bad.json` | `arch_demo_edge_iot_bad` | demo | CRA CH-ISG IEC DORA | 11 | 10 | 14 (14) |
| `multi-agent-fleet-bad.json` | `arch_demo_multi_agent_bad` | demo | FINMA AIACT OWASP MSFT | 14 | 16 | 26 (28) |
| `glassbox-ot-agent-bad.json` | `arch_demo_glassbox_ot_agent_bad` | demo | AIACT CRA NIS2 IEC ISO FADP FDA EU-GMP MR GAMP | 30 | 42 | 29 (29) |
| `a2a-agent-mesh-bad.json` | `arch_gs_a2a_mesh_bad` | templates | AIACT OWASP FINMA MSFT MCSB NIST | 10 | 12 | 6 (6) |

### Re-expected on 2026-10-01 (docs/18 B1, B2a, B3; ADR-088)

The path rules now read all paths and the duplicate rule is gone; these rows changed, and nothing else:

| Model | Change | Why |
|---|---|---|
| `rag-chatbot-bad` | LOG-004 on `e_agent_llm` removed | LOG-004 is retired into AI-001 (one finding per fact); AI-001 on the same edge stays |
| `multi-agent-fleet-bad` | LOG-004 on `e_research_llm` removed | the same; AI-001 on the same edge stays |
| `glassbox-ot-agent-bad` | LOG-004 on `e_agent_foundry` removed | the same; AI-001 on the same edge stays |
| `glassbox-ot-agent-bad` | AI-003 added on `e_jetson_a_plc_b`, `e_jetson_plc_b`, `e_validator_plc_a` | all paths: the agent reaches each high-consequence PLC write through the MCP `execute_command` bypass (`n_mcp → n_broker → n_hub → Jetson`) with no human step on that walk; before, AI-003 read only hops leaving an agent, so a consequential write further down a walk from the agent was not asked. OT-002 still reports the two unvalidated line-B writes (a different control); the good twin has no bypass and stays silent |
| `webapp-sql-keyvault-bad` | ZT-001 on `e_api_sql_w` removed, `e_api_sql_r` stays | one credential, one finding (B3): the API reads and writes the same database with the same connection string, which is one shared secret; the read hop, lowest edge id into the database, carries it |

The seven rewritten path rules (AI-001, AI-003, NET-003, NET-005, STR-005, AGT-003, AGT-006) raise no other new row on
any model: every good twin stays silent, and the gated routes of the good twins pass a gateway of the kind each rule
needs (B2a). A hop out of a human step is the person's, not the agent's, so `glassbox-ot-agent`'s `e_interrupt_mcp`
(the interrupt writing the pending-approval row) is not an STR-005 finding on either twin.

The expectations are written by the rule authors; the golden set measures the packs against their own authors'
reading, not against an external one (docs/18 §1 row 7, WS-B).

### Re-expected on 2026-10-02 (Reconcile A)

Swarm team 07's AEI-001 and AEI-002 fired on four clean templates, whose evaluation scope named no
`prompt_injection`; the templates are the designs the gallery offers as clean, so their declarations were completed,
not their expectations (the C2 handover: fix the template's declarations, preferred):

| Model | Change | Why |
|---|---|---|
| `rag-chatbot`, `multi-agent-fleet`, `a2a-agent-mesh` | `n_eval.evaluates` gains `prompt_injection`; AEI-001 on the user-facing agent removed (`[]`) | a clean design keeps its user-facing agent inside an adversarial evaluation scope |
| `foundry-agent-tools` | the same; AEI-001 and AEI-002 on `n_agent` removed (`[]`) | the acting agent is inside the same scope |
| `team03-agentic-runtime` | `n_tool_exec` declares `egress_policy: disabled`; FW-008 on it removed (`[]`) | the M3 rule fired on the clean twin's code-executing tool, which declared no egress policy; a clean design turns network access off for executed code |

The frozen migration inputs of the first four (`server/internal/model/migrate/testdata/pairs`) carry the same value,
which the 1.0 schema already listed; `team03-agentic-runtime` is born at 1.1 and has none. The gateway path rules' exact walk (any chain length), ATA-010 reading integrity
only, DATA-003/004 reading `data_classes[]`, OT-009's machine-write condition, the `sas` additions and the new
citations changed no other expectation; precision and recall stay 1.000 for every pack (`results/latest.json`).

## Authorship and the published result (docs/18 B4)

[`AUTHORS.md`](AUTHORS.md) states who authored which expectation file (the a2a pair included). Today every expectation
is the rule authors'; externally authored expectations are pending a named external author (programme acceptance,
Rad). An expectation entry may carry `author` and `authored_at` (`YYYY-MM-DD`); an entry without `author` counts under
`rule-authors`, and `make eval` prints the count per author.

A passing `make eval` writes [`results/latest.json`](results/latest.json): per pack its version, content hash, TP, FP,
FN, precision and recall, its rule count and the rules no expectation exercises (`unexercised_rules`: the pack's
numbers do not measure them), the combined hash of the packs, the expectation count per author and the run date. The
file keeps its run date while the packs and the numbers are unchanged; `go test ./cmd/eval`
(`TestPublishedResultIsCurrent`) fails when it is stale. A customer re-measures the public packs offline with
`assure eval` (or `go run ./cmd/assure-eval` in the public rules repository).

A reviewer bundle's LIMITATIONS.md reads a recorded result from `<RULES_DIR>/golden-set-result.json`, not from this
file, and no release step copies `results/latest.json` there yet (the image copies `rules/` and `golden-set/models`
only): a deployed bundle therefore states the thresholds and "No recorded golden-set result is available". Wiring it
(copy at release, and print a pack's numbers only when the recorded hash equals the loaded pack's) is pending with the
owners of `deploy/` and `internal/export` (TODO(decision), B2b/B4 review).

The B2b and E6 rules (gateway functions, AGW-003, APX-004, TPR-001 by function, SEG-005, WIS-006; 2026-10-01) changed
no expectation; the reasons are in `AUTHORS.md` §Re-expected.

Templates are the "good" versions (docs/05 §9, design notes in `models/README-templates.md`) and are
expected to be silent under every rule of docs/03. Each bad twin seeds violations across several packs;
`expected/*-bad.json` lists every hit including incidental ones, because `make eval` scores precision.

Seeded themes per twin:
- **rag-chatbot-bad** (demo model): shared agent identity, connection string + unknown encryption to SQL,
  public SQL, PII in West Europe, unredacted PII indexed, no ACL trimming, direct LLM call with PII prompts,
  no log sink / evaluation / owner / AI Act tier, missing inventory fields, no backup or geo-redundancy.
- **foundry-agent-tools-bad**: autonomous agent without kill switch, standing subscription contributor,
  payment release without human approval, unvetted third-party MCP server called unauthenticated with
  wildcard scopes, unlogged tool calls, connection string to the ledger, PMK, no exit strategy for the LLM.
- **webapp-sql-keyvault-bad**: no WAF, no MFA, secrets in code/config, public SQL with connection strings over
  none/unknown transport, no backup / geo-redundancy / RTO-RPO, PMK, 90-day mutable logs, no incident path, no DR test.
- **edge-iot-glassbox-bad**: gateway without egress policy, shadow sensor writing straight to the lake
  (no broker/DMZ), unencrypted PLC traffic, devices without secure boot / signed OTA / SBOM, camera PII in
  West Europe with PMK and no backup/geo-redundancy/RTO-RPO, 30-day logs, no incident path, no DR test.
  The zt pack does not apply (no zt regime enabled), so the api_key on the shadow uplink is intentionally not expected.
- **glassbox-ot-agent-bad** (GlassBox Edge, Governed Agents playbook v4.1): the demo configuration plus the command-path gaps
  a first version has — an MCP `execute_command` tool calls the command broker (so the agent reaches the machine and the
  signing key: OT-001, OT-003), Jetson B writes its PLC from cloud-to-device messages without validation and Jetson A
  bridges line B (OT-002, OT-004; neither write leaves a tracing log: MR-002), alarm text reaches the model unscreened (OT-005), approvals under a shared identity
  (OT-006; under Part 11 and Annex 11 also GXP-002), one SQL for both lines without row-level security (OT-007); and the demo's shortcuts — direct public Foundry
  call (AI-001, NET-002), agent → MCP without gateway (STR-005), public SQL with PMK (NET-001, DATA-004), no WAF
  or MFA (NET-003, ZT-009), no secure boot (CRA-002), 90-day traces (LOG-002), no output marking (AI-012), no reporting
  path under NIS2/CRA (GOV-002), no substantial-modification assessment under the Machinery Regulation (MR-004), and no supplier assessment behind the custom agent or the configured database (GXP-004). The template is the production path of the playbook's §6.4 table; its calls inside a
  Jetson are `hosted_on` the node, so NET-006 does not read them as transport.
- **a2a-agent-mesh-bad** (ADR-062, `packs/a2a.yaml`): the orchestrator delegates a research sub-task to a partner's
  agent over A2A (`e_orch_partner`) whose agent card is never verified (ATA-001), authenticated with an API key across
  the trust boundary (ATA-002, and STR-006 for the shared secret on a service hop), with the partner's credential in
  the task payload (ATA-003). The template verifies the signed card and uses an OAuth client.
- **multi-agent-fleet-bad**: users talk to the orchestrator without content safety or disclosure, non-OBO and
  untraced delegation, autonomous worker without kill switch calling the LLM directly, drafting agent
  impersonating users with no owner, unauthenticated/unscoped/unlogged MCP call, no log sink, no evaluation,
  LLM not in the outsourcing register.

## The regulatory-mapper pairs (docs/18 WS-I I2, team 06)

Four golden-set-only pairs (ids `arch_gs_*`, so `internal/templates` ignores them and the gallery still offers six
templates and six examples) exercise the DORA, FINMA, CRA, NIS2 and Swiss rules of `agents/swarm/06-regulatory-mappers/`,
which no template reaches. They add eight models to the golden set, whose size is pinned in `server/cmd/eval`
`goldenModelCount` and docs/09 §2.

| Model | id | Tenant | Regimes | Nodes | Edges | Expected rules (findings) |
|---|---|---|---|---|---|---|
| `dora-third-party.json` | `arch_gs_dora_third_party` | templates | DORA FINMA | 8 | 8 | 0 (0) |
| `dora-third-party-bad.json` | `arch_gs_dora_third_party_bad` | templates | DORA FINMA | 8 | 8 | 8 (8) |
| `cra-agent-product.json` | `arch_gs_cra_agent_product` | templates | CRA AIACT | 9 | 10 | 0 (0) |
| `cra-agent-product-bad.json` | `arch_gs_cra_agent_product_bad` | templates | CRA AIACT | 9 | 7 | 9 (9) |
| `nis2-ledger.json` | `arch_gs_nis2_ledger` | templates | NIS2 | 3 | 2 | 0 (0) |
| `nis2-ledger-bad.json` | `arch_gs_nis2_ledger_bad` | templates | NIS2 | 3 | 2 | 3 (3) |
| `swiss-ledger.json` | `arch_gs_swiss_ledger` | templates | FADP CH-ISG CH-CO | 9 | 8 | 0 (0) |
| `swiss-ledger-bad.json` | `arch_gs_swiss_ledger_bad` | templates | FADP CH-ISG CH-CO | 9 | 8 | 4 (4) |

Seeded themes per twin:
- **dora-third-party-bad**: the core payments SaaS moves to the model's provider (`azure`) and loses its region (DOR-002
  on both critical services, DOR-001), its card-network subcontractor is not registered (DOR-003 on the core SaaS,
  TPR-001 on the subcontractor), the KYC service a critical app calls is unclassified (DOR-004), the model is rated
  above the application it belongs to (FIN-001), and the material CRM has no exit arrangement (FIN-003).
- **cra-agent-product-bad**: the appliance has no SBOM, unsigned updates and no version (CRA-001, CRA-002, CRA-006),
  embeds an unpinned third-party MCP server (CRA-003, AGT-004), accepts the partner's calls unauthenticated (CRA-004),
  its agent and MCP server reach no log sink (CRA-005), and the architecture declares the GPAI tier while it runs an
  agent (AIA-003).
- **nis2-ledger-bad**: no decision names the national transposition act (NIS-001), the reporting path is declared
  with no criticality (NIS-003), and the partner's SaaS sits in the data zone (NIS-004).
- **swiss-ledger-bad**: health records reach the agent and the model with no accepted impact-assessment decision
  (CHE-001), the autonomous customer-facing agent writes cases directly instead of through the case handler (CHE-002),
  the cases store keeps two years where the CO keeps ten (CHE-003), and the public portal writes no log sink (CHE-004).

## The agent platform pair (docs/18 D2, ADR-047 §4)

A golden-set-only pair at schema 1.1 (ids `arch_gs_*`) that exercises the `mcp` pack and the D2 rules of the `zt`, `a2a`
and `net` packs: an orchestrator and an autonomous research worker reach MCP servers through an MCP gateway
(`gateway{kind: mcp}` with `functions[]`), credentials come from a token vault (`credential_broker`), agents and MCP
servers are listed in a registry (`agent_registry` with a `trust_anchor`), the worker keeps notes in an `agent_memory`,
and two partner agents (`external_agent`) are reached over A2A through an A2A gateway. Every identity is a native 1.1
entity (issuer, federation, sponsor, registry), so none of the migrated-identity exemptions applies. Regimes are the
non-regulatory ones only, so the pair does not move the regulatory mappers' ledgers.

Migration pairs: the two models have no frozen 0.9 or 1.0 inputs in `server/internal/model/migrate/testdata/pairs`.
They are native at schema 1.1 (native identity entities, and the 1.1-only node types `agent_registry`,
`credential_broker`, `external_agent`, `agent_memory`), so no older version can express them and no upgrade could
equal the golden file: a 1.0 copy would upgrade to migrated identities (`x_migrated_from`), not to these. They are
listed with that reason in `nativeAtCurrent` (`golden_test.go`); `TestEveryGoldenModelHasAPair` still asserts they are
stored at `migrate.Current`, that they have no pair (a model that gains one leaves the list) and that every listed
name is a golden model.

| Model | id | Tenant | Regimes | Nodes | Edges | Expected rules (findings) |
|---|---|---|---|---|---|---|
| `mcp-agent-platform.json` | `arch_gs_mcp_platform` | templates | OWASP MSFT MCSB NIST MAESTRO | 22 | 31 | 0 (0) |
| `mcp-agent-platform-bad.json` | `arch_gs_mcp_platform_bad` | templates | OWASP MSFT MCSB NIST MAESTRO | 22 | 33 | 30 (32) |

Seeded themes:
- **mcp-agent-platform-bad**: the MCP gateway forwards the analyst's token to the vendor's market-data server across the
  vendor boundary (`token_passthrough`: MCP-003, the ADR-047 acceptance) and rides a blanket consent to the documents
  server (MCP-009), which accepts API keys on the private network (MCP-002) and holds a client secret on a platform that
  offers managed identity (WIS-004); the vendor server registers clients only by DCR (MCP-005) and has no registry entry
  (TSC-001); the autonomous worker updates tickets directly beside the analyst's approval step (HOV-003, and STR-005 on
  the same ungated hop), runs with `sandbox: none` (ARH-001) and default-allow egress (SEG-010), writes its memory
  unvalidated (MEM-001) and calls the AI gateway with an API key (WIS-010, and STR-006 on the shared secret), its
  gateway hop carries authority two hops deep without an exchange (DLG-010); the orchestrator lets the worker re-delegate
  its token three hops deep, beyond the policy's one (DLG-001); the orchestrator's identity has no sponsor
  and no registry (AID-001, AID-010); the report agent shares the worker's identity, which names no issuer (AID-002 and
  AID-011 on both); the delegation to the report agent's tenant is an unbound bearer (DLG-003); the A2A gateway's token
  to the research partner is unbound (ATA-006) and that partner's card is neither signed nor pinned (ATA-010), its
  callback identity is a static key across the boundary (WIS-011); the pricing partner's signed card names no anchor
  (ATA-011), and the orchestrator also asks it directly beside the A2A gateway (SEG-011).

## The swarm-team and framework pairs (docs/18 WS-I I2, WS-M M3)

Golden-set-only pairs (ids `arch_gs_*` or `arch_team0*_*`; the five framework clean twins are `arch_tpl_fw_*`, the
blueprint templates of the gallery) that each exercise one swarm team's rules or the fw pack. All are stored at schema
1.2. They were authored at 1.1 or later, so `server/internal/model/migrate` keeps no frozen 0.9/1.0/1.1 inputs for them
(`nativeAtCurrent` in `golden_test.go`, "born at 1.1 or later"); `TestNativeModelsAreTheirOwn11Upgrade` checks the
1.1 → 1.2 step on each. Added to this file on 2026-10-02 (Reconcile A).

| Model | id | Tenant | Regimes | Nodes | Edges | Expected rules (findings) |
|---|---|---|---|---|---|---|
| `team01-import-provenance.json` | `arch_gs_team01_import_provenance` | templates | FINMA FADP NIST | 12 | 10 | 0 (0) |
| `team01-import-provenance-bad.json` | `arch_gs_team01_import_provenance_bad` | templates | FINMA FADP NIST | 13 | 8 | 24 (26) |
| `team02-identity-zero-trust.json` | `arch_gs_team02_identity` | templates | NIST | 12 | 17 | 0 (0) |
| `team02-identity-zero-trust-bad.json` | `arch_gs_team02_identity_bad` | templates | NIST | 12 | 15 | 24 (24) |
| `team03-agentic-runtime.json` | `arch_gs_team03_agentic_runtime` | templates | OWASP AIACT | 31 | 37 | 0 (0) |
| `team03-agentic-runtime-bad.json` | `arch_gs_team03_agentic_runtime_bad` | templates | OWASP AIACT | 30 | 36 | 20 (22) |
| `team04-gateways-network-data.json` | `arch_team04_gateways` | templates | AIACT GDPR IEC MSFT | 44 | 39 | 0 (0) |
| `team04-gateways-network-data-bad.json` | `arch_team04_gateways_bad` | templates | AIACT GDPR IEC MSFT | 42 | 40 | 22 (22) |
| `team05-records-resilience.json` | `arch_gs_team05_records_resilience` | templates | FINMA AIACT | 13 | 17 | 0 (0) |
| `team05-records-resilience-bad.json` | `arch_gs_team05_records_resilience_bad` | templates | FINMA AIACT | 13 | 14 | 17 (21) |
| `team07-attack-testing.json` | `arch_team07_attack_testing` | templates | FINMA AIACT DORA | 14 | 17 | 0 (0) |
| `team07-attack-testing-bad.json` | `arch_team07_attack_testing_bad` | templates | FINMA AIACT DORA | 14 | 17 | 2 (2) |
| `team09-learning-guard-gmp.json` | `arch_gs_team09_learning_guard_gmp` | templates | MR FDA EU-GMP | 14 | 13 | 0 (0) |
| `team09-learning-guard-gmp-bad.json` | `arch_gs_team09_learning_guard_gmp_bad` | templates | MR FDA EU-GMP | 14 | 13 | 14 (14) |
| `machinery-learning-guard.json` | `arch_gs_machinery_learning_guard` | templates | MR AIACT | 6 | 5 | 0 (0) |
| `machinery-learning-guard-bad.json` | `arch_gs_machinery_learning_guard_bad` | templates | MR AIACT | 5 | 4 | 4 (4) |
| `fw-langgraph.json` | `arch_tpl_fw_langgraph` | templates | OWASP AIACT | 22 | 25 | 0 (0) |
| `fw-langgraph-bad.json` | `arch_gs_fw_langgraph_bad` | templates | OWASP AIACT | 22 | 27 | 8 (8) |
| `fw-ms-agent-framework.json` | `arch_tpl_fw_ms_agent_framework` | templates | OWASP AIACT | 26 | 30 | 0 (0) |
| `fw-ms-agent-framework-bad.json` | `arch_gs_fw_ms_agent_framework_bad` | templates | OWASP AIACT | 27 | 31 | 5 (5) |
| `fw-foundry-agent-service.json` | `arch_tpl_fw_foundry_agent_service` | templates | OWASP AIACT | 23 | 25 | 0 (0) |
| `fw-foundry-agent-service-bad.json` | `arch_gs_fw_foundry_agent_service_bad` | templates | OWASP AIACT | 23 | 26 | 5 (5) |
| `fw-google-adk.json` | `arch_tpl_fw_google_adk` | templates | OWASP AIACT | 25 | 27 | 0 (0) |
| `fw-google-adk-bad.json` | `arch_gs_fw_google_adk_bad` | templates | OWASP AIACT | 25 | 27 | 5 (5) |
| `fw-openai-agents.json` | `arch_tpl_fw_openai_agents` | templates | OWASP AIACT | 23 | 26 | 0 (0) |
| `fw-openai-agents-bad.json` | `arch_gs_fw_openai_agents_bad` | templates | OWASP AIACT | 25 | 28 | 7 (7) |

What each pair exercises, and the rules its bad twin raises:
- **team01-import-provenance**: swarm team 01 (intake and model): scp, cmp, imp and prov packs, STR-001/007/009..012; the one pair with a stored provenance sidecar (imported from a Terraform plan). `team01-import-provenance-bad` raises CMP-001, CMP-003, CMP-004, IMP-001, IMP-002, IMP-003, IMP-004, IMP-005, IMP-006, PRV-001, PRV-002, PRV-004, PRV-005, PRV-006, SCP-002, SCP-003, SCP-004, SCP-005, STR-001, STR-007, STR-009, STR-010, STR-011, STR-012.
- **team02-identity-zero-trust**: swarm team 02 (identity and zero trust): the lpv pack and the team 02 rules of zt and a2a. `team02-identity-zero-trust-bad` raises AID-003, AID-004, ATA-004, ATA-005, ATA-007, DLG-002, DLG-004, HAC-001, HAC-002, HAC-003, HAC-004, LPV-001, LPV-002, LPV-003, LPV-004, STR-002, STR-004, STR-006, WIS-001, WIS-002, WIS-003, ZT-003, ZT-005, ZT-006.
- **team03-agentic-runtime**: swarm team 03 (agentic runtime and supply chain): arh, tsc, ing, hov, mem and blr packs, MCP-004. `team03-agentic-runtime-bad` raises AGT-003, AGT-005, AI-009, ARH-003, BLR-002, BLR-004, CMP-002, FW-008, HOV-001, HOV-002, ING-001, ING-003, ING-004, MCP-004, MEM-002, MEM-003, MEM-005, TSC-002, TSC-003, TSC-004.
- **team04-gateways-network-data**: swarm team 04 (gateways, network and data): the rag pack, AGW, APX, SEG-001..004, TLS and DCR. `team04-gateways-network-data-bad` raises AGW-002, AGW-003, AGW-004, AGW-005, APX-001, APX-002, APX-003, APX-004, DCR-001, DCR-002, DCR-003, RAG-001, RAG-003, RAG-004, SEG-001, SEG-002, SEG-003, SEG-004, STR-006, TLS-001, TLS-002, TLS-003.
- **team05-records-resilience**: swarm team 05 (logging, evidence and resilience): evd, evl and irr packs, LOG-006/007/009, RES-004/005/007. `team05-records-resilience-bad` raises CMP-005, EVD-001, EVD-003, EVL-001, EVL-002, EVL-003, EVL-004, IRR-002, IRR-003, IRR-004, LOG-003, LOG-006, LOG-007, LOG-009, RES-004, RES-005, RES-007.
- **team07-attack-testing**: swarm team 07 (verification and audit): the aei pack. `team07-attack-testing-bad` raises AEI-001, AEI-002.
- **team09-learning-guard-gmp**: swarm team 09 (sector packs): MR, GXP, OT-008/010/011. `team09-learning-guard-gmp-bad` raises GXP-001, GXP-003, GXP-005, GXP-006, GXP-007, GXP-008, MR-001, MR-003, MR-005, MR-006, MR-007, OT-008, OT-010, OT-011.
- **machinery-learning-guard**: swarm team 09 review fix: the machinery spec's MR + AIACT pair, so MR-008 is measured. `machinery-learning-guard-bad` raises MR-001, MR-006, MR-007, MR-008.
- **fw-langgraph**: docs/18 WS-M M3: the fw pack on LangGraph; the clean twin is a blueprint template. `fw-langgraph-bad` raises FW-001, FW-002, FW-003, FW-004, FW-005, FW-006, FW-009, FW-011.
- **fw-ms-agent-framework**: docs/18 WS-M M3: the fw pack on the Microsoft Agent Framework. `fw-ms-agent-framework-bad` raises FW-005, FW-008, FW-010, FW-011, FW-013.
- **fw-foundry-agent-service**: docs/18 WS-M M3: the fw pack on Azure AI Foundry Agent Service. `fw-foundry-agent-service-bad` raises FW-002, FW-004, FW-008, FW-009, FW-011.
- **fw-google-adk**: docs/18 WS-M M3: the fw pack on Google ADK. `fw-google-adk-bad` raises FW-001, FW-005, FW-006, FW-009, FW-010.
- **fw-openai-agents**: docs/18 WS-M M3: the fw pack on the OpenAI Agents SDK. `fw-openai-agents-bad` raises ATA-010, FW-003, FW-005, FW-006, FW-007, FW-012, STR-006.
