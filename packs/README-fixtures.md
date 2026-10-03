# Rule fixtures

`fixtures/<RULE>.pos.json` fires exactly that rule on exactly one element (model id `arch_fx_<rule>_pos`,
tenant `tenant_fixtures`); `fixtures/<RULE>.neg.json` (`arch_fx_<rule>_neg`) is the same model with the
single attribute/edge changed so the rule is silent. Conventions:

- 2–4 nodes, ≤ 3 edges, no groups/positions. `attrs.regimes` make the owning pack apply and `regime()`
  guards hold: zt MCSB+NIST · net MCSB+IEC · data FADP+FINMA · log FINMA+AIACT · ai AIACT+OWASP · agt AIACT+OWASP · a2a AIACT+OWASP ·
  res DORA · gov FINMA+DORA+CH-ISG+CRA · c4 MCSB+NIST · drift MCSB+NIST · aia AIACT · fin FINMA. The regulatory-mapper rules
  (AIA, FIN, DOR, CRA-004, NIS-004, CHE) declare only the one regime their `regime()` guard reads. `allowed_regions` = switzerlandnorth/west.
- Boundary rules (STR-002, STR-006, ATA-001, ATA-002) need groups, because "across a boundary" means the endpoints
  share none: the ATA fixtures put the caller in a `zone` and the peer in its own zone plus a `trust_boundary`, and the
  negative changes the declared attribute (`integrity`, `auth`), never the grouping.
- Drift rules (DRF-*) read knowledge facts: `fixtures/<RULE>.kb.json` (`{"deprecated": {...}, "freshness": {...}}`)
  is declared as `fixtures.kb` and applied to **both** fixtures, so the negative changes the model (e.g. names
  the replacement service or the fresh url), never the facts. Without a kb file `kb.available` is false.
- Graph-scope rules (LOG-001, AI-004, AI-006, RES-003, GOV-001, GOV-002, STR-003, DRF-002) report the architecture id.
- Path rules (AI-001, AI-003, NET-003, NET-005, STR-005, AGT-003, AGT-006) read all paths (docs/03 "Path rules",
  ADR-088): the positive is a "parallel gateway" pair — the direct edge `e1` beside the gated route (gateway, broker or
  human step) fires on `e1` — and the negative keeps only the gated route. Variant fixtures
  `fixtures/<RULE>.<variant>.{pos,neg}.json` (not declared in the pack; asserted element by element by
  `TestPathRuleFixtures` in `rules/allpaths_test.go`, which also fails on an unasserted variant) pin
  the rest: `chain` (the finding lands on the last ungated hop), gateway kinds (B2a: `AI-001.apigw.pos`,
  `NET-003.aigw.pos`, `NET-003.apigw.neg`, `STR-005.aigw.neg`, `STR-005.mcpgw.neg` (a schema 1.1 `mcp` gateway),
  `STR-005.waf.pos`), `STR-005.human.neg` (a hop out of a human step is the person's), `NET-005.edgebroker.neg` (a
  broker in the edge layer is the conduit, not edge traffic), `AGT-003.safety.neg` (the agent's own content safety),
  `AGT-003.screened.neg` (an agent with content safety between the unscreened agent and the third-party tool), and B3's
  `hosted_on` cases (`ZT-001.hosted.pos` and `STR-006.hosted.pos`: one credential, one finding, on the hop into the
  host; `ZT-001.lowestid.pos` and `STR-006.lowestid.pos`: no hop into the host, so the lowest edge id;
  `ZT-001.twosecrets.pos` and `STR-006.twosecrets.pos`: two different secrets into one host, two findings;
  `ZT-001.colocated.neg` and `STR-006.colocated.neg`: co-located hops are exempt as in NET-006).
  `TestPathRulePatchesEvaluateClean` applies each rewritten rule's patch to its positive (and chain) fixture and pins
  what the rule still fires on afterwards — nothing, except two documented limits: AGT-003's chain (its template sets
  `content_safety` on `e.from`) and the `hosted` fixtures of ZT-001 and STR-006 (the patch fixes the reported hop, the
  finding moves to the sibling hop that shares the secret; one acceptance per hop).
- Other rules may fire incidentally in a fixture (e.g. AI-004 in most ai fixtures); tests assert only the
  fixture's own rule. All files validate with `cd server && go run ./cmd/modelcheck fixtures/*.json`.

Matrix — rule → element the positive fixture fires on (fixture ids follow the pattern above):

| Pack | Rule → fires on |
|---|---|
| zt | ZT-001→`e1` · ZT-002→`n_agent` · ZT-003→`e1` · ZT-004→`n_app` · ZT-005→`e1` · ZT-006→`e3` · ZT-007→`n_app` · ZT-008→`e1` · ZT-009→`e3` |
| net | NET-001→`n_db` · NET-002→`e1` · NET-003→`e1` · NET-004→`e1` · NET-005→`e1` · NET-006→`e1` |
| data | DATA-001→`e1` · DATA-002→`e1` · DATA-003→`n_db` · DATA-004→`n_db` · DATA-005→`n_db` · DATA-006→`e1` · CHE-002→`n_agent` (FADP) |
| log | LOG-001→`arch_fx_log_001_pos` · LOG-002→`n_logs` · LOG-003→`n_logs` · LOG-005→`e1` (LOG-004 retired into AI-001) |
| ai | AI-001→`e1` · AI-002→`e1` · AI-003→`e1` · AI-004→`arch_fx_ai_004_pos` · AI-005→`n_agent` · AI-006→`arch_fx_ai_006_pos` · AI-007→`n_agent` · AI-008→`e1` · AI-009→`n_mcp` · AI-010→`n_agent` · AI-011→`e1` · AI-012→`n_agent` · AI-013→`n_llm` · AI-014→`n_eval` · AI-015→`n_eval` |
| res | RES-001→`n_db` · RES-002→`n_db` · RES-003→`arch_fx_res_003_pos` |
| agt | AGT-001→`n_tool_tp` · AGT-002→`n_tool` · AGT-003→`e1` · AGT-004→`n_tool_tp` · AGT-005→`n_agent` · AGT-006→`e1` · AGT-007→`n_tool_tp` |
| a2a | ATA-001→`e1` · ATA-002→`e1` · ATA-003→`e1` (ATA-003 keeps both agents in one zone, so 001/002 stay silent) |
| gov | CRA-001→`n_dev` · CRA-002→`n_prod` · CRA-004→`e1` (CRA) · GOV-001→`arch_fx_gov_001_pos` · GOV-002→`arch_fx_gov_002_pos` · NIS-004→`n_saas` (NIS2; a `zone` group holds the store and, on the positive, the SaaS) · CHE-004→`n_app` (CH-ISG) |
| tpr | TPR-001→`n_llm` · TPR-002→`n_saas` · DOR-001→`n_saas` (DORA) |
| aia | AIA-001→`n_agent` (user → app → agent; AI-007 silent) · AIA-002→`arch_fx_aia_002_pos` |
| fin | FIN-002→`n_crm` · FIN-003→`n_llm` |
| c4 | STR-001→`n_comp` · STR-002→`e1` · STR-003→`arch_fx_c4_003.pos` · STR-004→`n_app` · STR-005→`e1` · STR-006→`e1` · STR-007→`n_user` · STR-008→`n_comp` |
| drift | DRF-001→`n_llm` · DRF-002→`arch_fx_drf_002_pos` · DRF-003→`n_gw` · DRF-004→`e1` (each with `DRF-00N.kb.json`) |
| ot | (IEC+AIACT; OT-009 IEC+ISO; OT-010 IEC+NIS2, `zone` groups) OT-001→`n_ag` · OT-002→`e_node_plc` · OT-003→`n_kv` · OT-004→`e_write` · OT-005→`n_ag` · OT-006→`n_appr` · OT-007→`n_db` · OT-008→`n_hs` · OT-009→`n_kv` · OT-010→`n_hs` · OT-011→`e_val_plc` |
| mr | (MR; MR-008 MR+AIACT) MR-001→`n_guard` · MR-002→`e_writer_plc` · MR-003→`n_guard` · MR-004→`arch_fx_mr_004_pos` · MR-005→`n_guard` · MR-006→`n_guard` · MR-007→`n_log` · MR-008→`n_guard` |
| gxp | (FDA+EU-GMP) GXP-001→`arch_fx_gxp_001_pos` · GXP-002→`n_release` · GXP-003→`n_db` · GXP-004→`n_lims` · GXP-005→`n_db` · GXP-006→`e_app_db` · GXP-007→`n_qa` · GXP-008→`e_mcp_db` |

Team 06 rules of docs/18 WS-I I2 (each fixture declares only the regime its `regime()` guard reads):

| Pack | Rule → fires on |
|---|---|
| aia | AIA-003→`arch_fx_aia_003_pos` (tier `gpai`, one agent; the negative declares `high_risk`) |
| fin | FIN-001→`n_agent` (architecture `materiality: low`, agent `high`; the negative raises the architecture to `high`) |
| tpr | DOR-002→`n_llm` and `n_saas` (both `azure`, both `critical`: the pair is reported on both nodes) · DOR-003→`n_saas` (TPR-001 fires on the unregistered `n_sub` incidentally, as for AI-004; `n_sub` is classified `high`, so DOR-004 stays quiet) · DOR-004→`e1` (the edge rule names the call from the `critical` app into `n_saas`, which has no `criticality`; the negative classifies the app `high`, so the edge is in the domain and decided quiet) |
| gov | CRA-003→`n_prod` (a third-party MCP server with `c4_parent` the product and no `integrity`; it writes the product's sink, so CRA-005 stays quiet) · CRA-005→`n_agent` (the product's API writes the sink, the agent reaches none; CRA-004's fixtures draw no sink, so CRA-005 also fires there on `n_api` incidentally) · CRA-006→`n_prod` · NIS-001→`arch_fx_nis_001_pos` · NIS-003→`arch_fx_nis_003_pos` (both NIS-003 fixtures carry the Art41 decision, so NIS-001 stays quiet; NIS-004's fixtures carry none, so NIS-001 fires there incidentally) |
| data | CHE-001→`n_agent` and `n_llm` (a `phi` store the agent reads reaches both; the negative carries the accepted FADP Art22 decision) |
| log | CHE-003→`n_store` (CH-CO, retention 1825 days; the negative 3650) |

Team 05 rules of docs/18 WS-I I2 (logging, evidence and resilience). Regimes per pack: log AIACT+MCSB (the pack applies
through AIACT) · evd FINMA+AIACT · evl AIACT+FINMA (EVL-003 adds `ai_act_tier: high_risk`) · res DORA (RES-006
FINMA, because it reads `!regime("DORA")`) · irr the one regime each rule reads (IRR-004 DORA, IRR-005 GDPR) · drift MCSB+NIST. The
schema 1.1 rules (LOG-009, EVD-001, EVD-004, RES-007, IRR-004, DRF-005, DRF-006) declare `purpose`, `spec_version` or
`retention_statement`, and stay silent on a model that declares none.

| Pack | Rule → fires on |
|---|---|
| log | LOG-006→`n_agent` (the gateway writes the sink, the agent reaches neither) · LOG-007→`n_agent` · LOG-008→`n_logs` (`westeurope`) · LOG-009→`n_agent` (reaches the `operational` sink; the `evidence` sink is drawn, not reached) |
| evd | EVD-001→`n_sink` · EVD-003→`e1` (`auth: none`; `unknown` lowers the severity to medium) · EVD-004→`arch_fx_evd_004_pos` (LOG-003 stays silent: the sinks are immutable) |
| evl | EVL-001→`n_eval` · EVL-002→`n_agent_b` · EVL-003→`n_eval` · EVL-004→`n_eval` (an agent `materiality: high` under FINMA) |
| res | RES-004→`n_app` · RES-005→`n_app` · RES-006→`arch_fx_res_006_pos` · RES-007→`n_logs` |
| irr | IRR-001→`arch_fx_irr_001_pos` (FADP, a `pii` store) · IRR-002→`arch_fx_irr_002_pos` · IRR-003→`arch_fx_irr_003_pos` · IRR-004→`arch_fx_irr_004_pos` · IRR-005→`arch_fx_irr_005_pos` (GDPR, a `pii` store) |
| drift | DRF-005→`n_mcp` · DRF-006→`n_llm` · DRF-007→`arch_fx_drf_007_pos` · DRF-008→`n_gw` (each with `DRF-00N.kb.json`) |

### Gateway functions and the E6 rules (docs/18 B2b and E6, 2026-10-01)

Declared fixtures: AGW-003→`e_gw_llm` (agent → WAF → model; negative: the gateway is `kind: ai`) · APX-004→`e2` (user →
AI gateway → public app; negative: `kind: waf`) · SEG-005→`n_db` (a staging service reads a production store;
negative: the service is production) · WIS-006→`n_app` (`secrets_delivery: env` from a secret store; negative:
`mounted_file`). Path-rule variants, pinned in `TestPathRuleFixtures`: `AI-001.functions.neg` (an API gateway that
declares `observability` and `policy` counts, and AGW-003 is silent), `AI-001.nofunc.pos` (an AI gateway whose functions
lack them), `AI-001.series.pos` (two such gateways in series, the finding on the hop into the model),
`AI-001.credited.neg` (a sufficient AI gateway further up is credited), `NET-003.functions.neg` / `NET-003.nofunc.pos`
(a WAF with and without `policy`), `APX-004.functions.neg` (an AI gateway that declares `policy`),
`STR-005.functions.neg` / `STR-005.nofunc.pos` (with and without `identity_termination`). `AI-001.apigw.pos` and
`NET-003.aigw.pos` now fire AGW-003 and APX-004 on `e2` (one finding per hop). The `not_checked` side (a gateway of the
right kind that declares no functions, an absent `kind`) and the TPR-001, SEG-005 and WIS-006 mutations are asserted
in `server/cmd/eval/rules_b2b_e6_test.go`.

Swarm team 02 (docs/18 WS-I I2, `agents/swarm/02-identity-and-zero-trust`): fixture regimes zt MCSB+NIST, lpv
MCSB+OWASP, a2a AIACT+OWASP; schema 1.1 where the rule reads a 1.1 declaration (WIS-003, DLG-002, LPV-003, HAC-002,
HAC-004, ATA-005, ATA-007), else 1.0; 2 to 4 nodes; groups only on the ATA fixtures (our side in a `zone`, the peer in a
`trust_boundary`, as the D2 ATA fixtures). Every fixture user declares `mfa: true`, so ZT-009 stays silent where it is
not the rule under test. The negative changes the one declaration the rule reads, except AID-003 and HAC-003 (the
negative adds the `authenticates` edge) and WIS-002 (the negative adds the `reads` hop to the drawn store).

| Pack | Rule → fires on |
|---|---|
| zt | AID-003→`n_agent` · AID-004→`n_agent` · WIS-001→`n_kv` (STR-006 fires incidentally on `e1`) · WIS-002→`n_app` · WIS-003→`arch_fx_wis_003_pos` · DLG-002→`e1` · DLG-004→`n_tool` (ZT-003 fires incidentally on `e2`) · HAC-001→`n_api` · HAC-002→`e1` · HAC-003→`n_app` · HAC-004→`e1` |
| lpv | LPV-001→`n_agent` · LPV-002→`e1` · LPV-003→`e1` · LPV-004→`n_agent` |
| a2a | ATA-004→`e1` (STR-002 fires incidentally on the same hop: its source is an external party's service, not a person) · ATA-005→`n_orch` · ATA-007→`e1` |

Swarm team 03 (docs/18 WS-I I2, `agents/swarm/03-agentic-runtime-and-supply-chain`): fixture regimes AIACT+OWASP
(MCP-004 OWASP+MCSB, as the D2 mcp fixtures), schema 1.1, 2 to 5 nodes, no groups; the negative changes the one
declaration the rule reads, except MEM-002 (the second agent reads its own memory), BLR-001 and BLR-003 (the hop passes
a human step) and BLR-002 (the egress tool is reached through an API gateway), as the specs state.

| Pack | Rule → fires on |
|---|---|
| arh | ARH-003→`n_agent` (semi, writes a store) · ARH-004→`n_agent` (`n_aigw.token_limits: false`) |
| tsc | TSC-002→`n_tool_tp` (`document_search_tool` beside `Document search tool`) · TSC-003→`n_mcp_tp` · TSC-004→`n_registry` |
| mcp | MCP-004→`n_mcp` |
| ing | ING-001→`n_agent` · ING-002→`n_web` · ING-003→`n_index` · ING-004→`e1` (the `subscribes` edge) |
| hov | HOV-001→`n_human` · HOV-002→`n_human` · HOV-004→`n_agent` (HOV-003 fires incidentally on both HOV-004 fixtures) |
| mem | MEM-002→`n_mem` · MEM-003→`n_state` · MEM-004→`n_mem` · MEM-005→`e1` |
| blr | BLR-001→`n_orch` · BLR-002→`n_agent` · BLR-003→`n_agent` · BLR-004→`n_writer` |

Swarm team 01 (docs/18 WS-I I2, `agents/swarm/01-intake-and-model`): fixture regimes scp the one regime each rule reads
(SCP-001 none on the positive, NIST on the negative; SCP-002 AIACT; SCP-003 FINMA, the negative adds AIACT; SCP-004 FADP
with `allowed_regions: []` on the positive; SCP-005 FINMA) · cmp AIACT+OWASP · prov AIACT+NIST · imp MCSB+DORA (IMP-002
to IMP-004 set `x_import_source`, since they decide only on an imported architecture) · c4 MCSB+NIST; schema 1.1 on
CMP-005 and PRV-003 (gateway `functions[]`, MCP `registry_entry`), else 1.0; 1 to 3 nodes; one `zone` group on STR-009.

| Pack | Rule → fires on |
|---|---|
| scp | SCP-001→`arch_fx_scp_001_pos` (AI-006 fires incidentally: an agent and no tier) · SCP-002→`arch_fx_scp_002_pos` · SCP-003→`arch_fx_scp_003_pos` · SCP-004→`arch_fx_scp_004_pos` · SCP-005→`arch_fx_scp_005_pos` |
| cmp | CMP-001→`n_db` · CMP-002→`n_agent` · CMP-003→`n_tool` · CMP-004→`n_api` · CMP-005→`n_gw` |
| prov | PRV-001→`n_gw` (the negative imports the gateway: `source: declared` with an `x_iac_address`) · PRV-002→`arch_fx_prv_002_pos` · PRV-003→`n_mcp` · PRV-004→`n_api` |
| imp | IMP-002→`n_db` · IMP-003→`n_db` (CMP-001 fires incidentally: the class is only in `x_data_class`) · IMP-004→`n_app` · IMP-005→`n_pe` (the negative's endpoint `flows` to the store) · IMP-006→`arch_fx_imp_006_pos` |
| c4 | STR-009→`n_app2` · STR-010→`e_comp_db` · STR-011→`arch_fx_str_011_pos` · STR-012→`n_db1` and `n_db2` (the pair is reported on both nodes) |

### Team 04 rules of docs/18 WS-I I2 (gateways, network and data)

Regimes per rule family: AGW AIACT+OWASP (AGW-004 at schema 1.1, the only fixture pair with `functions[]`) · APX and
TLS MCSB+IEC · SEG-001 … SEG-003 IEC+NIS2 (SEG-001, SEG-003 with `zone` groups `g_a`/`g_b`) · SEG-004 OWASP+MCSB ·
DCR FADP+FINMA · RAG ISO+OWASP (RAG-004 with `zone` groups `g1`/`g2`). TLS-001 is a boundary rule: both fixtures hold
groups, the positive puts the host in a second zone.

| Pack | Rule → fires on |
|---|---|
| ai | AGW-002→`n_agent` (AI gateway `logging: false`) · AGW-004→`n_gw` (`functions: [identity_termination]` with logging and token limits; AI-001 fires on `e_gw_llm` incidentally, the gateway's functions lack observability and policy) · AGW-005→`e_gw_llm` (`semantic_cache: true`, `prompt_contains: cid`) |
| net | APX-001→`e1` (partner → public API direct) · APX-002→`n_kv` · APX-003→`e1` (SaaS reads the store; the negative's API is internal, so APX-001 stays quiet) · SEG-001→`e_api_store` · SEG-002→`n_egw` (edge gateway → API → queue) · SEG-003→`n_dmz` · SEG-004→`n_mcp` · TLS-001→`e1` · TLS-002→`e1` (shared host `n_ghost` not drawn) · TLS-003→`e1` (`mcp_stdio`, `encryption: tls`) |
| data | DCR-001→`n_llm` (`eastus`) · DCR-002→`n_kv` (`eastus`, `key_use: data_encryption`) · DCR-003→`e1` (`pii` CRM flows into an `internal` lake) |
| rag | RAG-001→`e1` (`api_key` on a trimmed index) · RAG-002→`e1` (medium: the reader only reads) · RAG-003→`n_idx` · RAG-004→`n_idx` |

The NET-006 sensitive-data severity row and RAG-002's acting-reader row are asserted on mutated positive fixtures in
`server/internal/agent/assistant/swarm/gateways-network-and-data/agents_test.go` (`TestSeverityOverrides`).

### Team 07 rules of docs/18 WS-I I2 (verification and audit)

Regimes: aei AIACT+FINMA with `ai_act_tier: limited` (the FINMA branch of the guard holds; the AI Act branch alone
needs an empty or high-risk tier). Four nodes, three edges, no groups; the negative changes only the evaluation's
`evaluates` (it adds `prompt_injection`).

| Pack | Rule → fires on |
|---|---|
| aei | AEI-001→`n_agent` (a `user` calls it; `evaluates: [accuracy, drift]`) · AEI-002→`n_agent` (`autonomy: autonomous`, `executes` a first-party tool with `capabilities: [modifies_state]`; `evaluates: [accuracy]`) |

AEI-002's `semi` → medium override is asserted in
`server/internal/agent/assistant/swarm/verification-and-audit/agents_test.go` (`TestAEI002SemiIsMedium`).

### D2 rules (docs/18 D2, ADR-047 §4) and the rows the earlier matrices left out

Regimes: zt MCSB+NIST · mcp OWASP+MCSB · a2a AIACT+OWASP (groups as the team 02 ATA fixtures) · net MCSB+IEC · prov
DORA+NIST · imp MCSB; schema 1.1 declarations (`identities[]`, edge `audience`, `scopes`, `delegation_depth`, MCP
`auth_mode`, `transport`, `registry_entry`), read at 1.2 after the migration. Added to the matrix 2026-10-02
(Reconcile A, the D2 handover).

| Pack | Rule → fires on |
|---|---|
| zt | AID-001→`n_agent` · AID-002→`n_agent_a` and `n_agent_b` (one identity, two agents: the pair is reported on both) · AID-010→`n_agent` · AID-011→`n_agent` · WIS-004→`n_api` · WIS-010→`e1` · WIS-011→`e1` · DLG-001→`e1` · DLG-003→`e1` · DLG-010→`e1` |
| mcp | MCP-002→`n_mcp` · MCP-003→`e1` · MCP-005→`n_mcp` · MCP-009→`e1` · TSC-001→`n_mcp` · MEM-001→`n_mem` · ARH-001→`n_agent` · HOV-003→`e1` |
| a2a | ATA-006→`e1` · ATA-010→`e1` · ATA-011→`n_peer` |
| net | SEG-010→`n_agent` · SEG-011→`e1` |
| prov | PRV-005→`n_app` and `n_db` (both imported facts past their cadence) · PRV-006→`n_old` (left behind by a later import) |
| imp | IMP-001→`n_legacy` |

### FW rules (docs/18 WS-M M3, ADR-093)

Regimes AIACT+OWASP, schema 1.2 (`agent.framework` and the 1.2 attributes each rule reads); the amendment fixtures in
`fixtures/amendments/` are asserted by `rules/fw_test.go`.

| Pack | Rule → fires on |
|---|---|
| fw | FW-001→`n_mem` · FW-002→`n_mem` · FW-003→`n_mem` · FW-004→`n_mem` · FW-005→`n_agent` · FW-006→`e1` · FW-007→`e1` · FW-008→`n_tool` · FW-009→`n_app` · FW-010→`n_agent` · FW-011→`n_app` · FW-012→`e1` · FW-013→`e1` |

### Variant fixtures added 2026-10-02 (Reconcile A)

All pinned element by element in `TestPathRuleFixtures` (`rules/allpaths_test.go`):
`AI-001.deepseries.pos` (five gateways in series, none crediting the hop: the function-aware walk is exact at any
length, `e6`); `ATA-010.cardsigned.pos` (`card_signed: true` with `integrity: none` fires: a present signature is not a
verified one); `DATA-003.classes.pos` and `DATA-004.classes.pos` (`data_class: internal` with a sensitive class in
`data_classes[]`, `n_db`); `DATA-003.classesonly.pos` and `DATA-004.classesonly.pos` (no `data_class`, a sensitive class
in `data_classes[]` only: fires and is decided, `data_classes_test.go`); `OT-009.nomachine.neg` (a public command-signing store in a model with no machine write is
silent); `LPV-002.imported.neg` and `LPV-003.imported.neg` (the tool's `scopes: []` on an element whose provenance is
`imported`: silent, and `not_checked` in `lpv_imported_test.go`); and the `sas` twins `ZT-001.sas.pos`,
`ZT-006.sas.pos`, `WIS-001.sas.pos`, `WIS-010.sas.pos`, `STR-006.sas.pos`, `RAG-001.sas.pos`, `ATA-002.sas.pos` (each
positive fixture with its shared secret drawn as `auth: sas`, firing on the same element; `sas_test.go` compares every
rule id of the `api_key` and `sas` twins).
