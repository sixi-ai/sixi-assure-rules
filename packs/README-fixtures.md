# Rule fixtures

`fixtures/<RULE>.pos.json` fires exactly that rule on exactly one element (model id `arch_fx_<rule>_pos`,
tenant `tenant_fixtures`); `fixtures/<RULE>.neg.json` (`arch_fx_<rule>_neg`) is the same model with the
single attribute/edge changed so the rule is silent. Conventions:

- 2–4 nodes, ≤ 3 edges, no groups/positions. `attrs.regimes` make the owning pack apply and `regime()`
  guards hold: zt MCSB+NIST · net MCSB+IEC · data FADP+FINMA · log FINMA+AIACT · ai AIACT+OWASP · agt AIACT+OWASP · a2a AIACT+OWASP ·
  res DORA · gov FINMA+DORA+CH-ISG+CRA · c4 MCSB+NIST · drift MCSB+NIST. `allowed_regions` = switzerlandnorth/west.
- Boundary rules (STR-002, STR-006, ATA-001, ATA-002) need groups, because "across a boundary" means the endpoints
  share none: the ATA fixtures put the caller in a `zone` and the peer in its own zone plus a `trust_boundary`, and the
  negative changes the declared attribute (`integrity`, `auth`), never the grouping.
- Drift rules (DRF-*) read knowledge facts: `fixtures/<RULE>.kb.json` (`{"deprecated": {...}, "freshness": {...}}`)
  is declared as `fixtures.kb` and applied to **both** fixtures, so the negative changes the model (e.g. names
  the replacement service or the fresh url), never the facts. Without a kb file `kb.available` is false.
- Graph-scope rules (LOG-001, AI-004, AI-006, RES-003, GOV-001, GOV-002, STR-003, DRF-002) report the architecture id.
- Path rules (NET-003, NET-005, LOG-004, AI-001, AI-003, AGT-006, STR-005) keep the direct edge in the negative and add the
  gateway / broker / human-step path, so they exercise `g.pathThrough` (endpoints count).
- Other rules may fire incidentally in a fixture (e.g. AI-004 in most ai fixtures); tests assert only the
  fixture's own rule. All files validate with `cd server && go run ./cmd/modelcheck fixtures/*.json`.

Matrix — rule → element the positive fixture fires on (fixture ids follow the pattern above):

| Pack | Rule → fires on |
|---|---|
| zt | ZT-001→`e1` · ZT-002→`n_agent` · ZT-003→`e1` · ZT-004→`n_app` · ZT-005→`e1` · ZT-006→`e3` · ZT-007→`n_app` · ZT-008→`e1` · ZT-009→`e3` |
| net | NET-001→`n_db` · NET-002→`e1` · NET-003→`e1` · NET-004→`e1` · NET-005→`e1` · NET-006→`e1` |
| data | DATA-001→`e1` · DATA-002→`e1` · DATA-003→`n_db` · DATA-004→`n_db` · DATA-005→`n_db` · DATA-006→`e1` |
| log | LOG-001→`arch_fx_log_001_pos` · LOG-002→`n_logs` · LOG-003→`n_logs` · LOG-004→`e1` · LOG-005→`e1` |
| ai | AI-001→`e1` · AI-002→`e1` · AI-003→`e1` · AI-004→`arch_fx_ai_004_pos` · AI-005→`n_agent` · AI-006→`arch_fx_ai_006_pos` · AI-007→`n_agent` · AI-008→`e1` · AI-009→`n_mcp` · AI-010→`n_agent` · AI-011→`e1` · AI-012→`n_agent` · AI-013→`n_llm` · AI-014→`n_eval` · AI-015→`n_eval` |
| res | RES-001→`n_db` · RES-002→`n_db` · RES-003→`arch_fx_res_003_pos` |
| agt | AGT-001→`n_tool_tp` · AGT-002→`n_tool` · AGT-003→`e1` · AGT-004→`n_tool_tp` · AGT-005→`n_agent` · AGT-006→`e1` · AGT-007→`n_tool_tp` |
| a2a | ATA-001→`e1` · ATA-002→`e1` · ATA-003→`e1` (ATA-003 keeps both agents in one zone, so 001/002 stay silent) |
| gov | CRA-001→`n_dev` · CRA-002→`n_prod` · GOV-001→`arch_fx_gov_001_pos` · GOV-002→`arch_fx_gov_002_pos` · TPR-001→`n_llm` · TPR-002→`n_saas` |
| c4 | STR-001→`n_comp` · STR-002→`e1` · STR-003→`arch_fx_c4_003.pos` · STR-004→`n_app` · STR-005→`e1` · STR-006→`e1` · STR-007→`n_user` · STR-008→`n_comp` |
| drift | DRF-001→`n_llm` · DRF-002→`arch_fx_drf_002_pos` · DRF-003→`n_gw` · DRF-004→`e1` (each with `DRF-00N.kb.json`) |
