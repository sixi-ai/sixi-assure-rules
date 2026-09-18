# Golden set

`models/<name>.json` — a full model (docs/02). `expected/<name>.json` — expected findings
`[{ "rule_id": "AI-001", "ids": ["e3"] }]`, sorted by rule id, ids sorted. `make eval` evaluates every
model with the packs in `packs/` (pack applicability = pack `regimes` ∩ model `attrs.regimes`) and
reports TP/FP/FN per rule; thresholds: precision ≥ 0.90, recall ≥ 0.85 per pack (docs/09 §2).
Never add real customer diagrams; create anonymised twins instead.

## Twelve models (v0)

| Model | id | Tenant | Regimes | Nodes | Edges | Expected rules (findings) |
|---|---|---|---|---|---|---|
| `rag-chatbot.json` | `arch_tpl_rag_chatbot` | templates | FINMA AIACT FADP MCSB | 13 | 17 | 0 (0) |
| `foundry-agent-tools.json` | `arch_tpl_foundry_agent` | templates | FINMA AIACT DORA | 14 | 17 | 0 (0) |
| `webapp-sql-keyvault.json` | `arch_tpl_webapp_sql` | templates | FINMA FADP MCSB DORA | 8 | 11 | 0 (0) |
| `edge-iot-glassbox.json` | `arch_tpl_edge_iot` | templates | CRA CH-ISG IEC DORA | 12 | 11 | 0 (0) |
| `multi-agent-fleet.json` | `arch_tpl_multi_agent` | templates | FINMA AIACT OWASP MSFT | 16 | 23 | 0 (0) |
| `glassbox-ot-agent.json` | `arch_tpl_glassbox_ot_agent` | templates | AIACT CRA NIS2 IEC ISO FADP FDA EU-GMP MR GAMP | 32 | 43 | 0 (0) |
| `rag-chatbot-bad.json` | `arch_demo_rag_bad` | demo | FINMA AIACT FADP MCSB | 8 | 6 | 22 (25) |
| `foundry-agent-tools-bad.json` | `arch_demo_foundry_agent_bad` | demo | FINMA AIACT DORA | 12 | 14 | 10 (12) |
| `webapp-sql-keyvault-bad.json` | `arch_demo_webapp_sql_bad` | demo | FINMA FADP MCSB DORA | 7 | 9 | 14 (17) |
| `edge-iot-glassbox-bad.json` | `arch_demo_edge_iot_bad` | demo | CRA CH-ISG IEC DORA | 11 | 10 | 13 (17) |
| `multi-agent-fleet-bad.json` | `arch_demo_multi_agent_bad` | demo | FINMA AIACT OWASP MSFT | 13 | 15 | 15 (16) |
| `glassbox-ot-agent-bad.json` | `arch_demo_glassbox_ot_agent_bad` | demo | AIACT CRA NIS2 IEC ISO FADP FDA EU-GMP MR GAMP | 30 | 42 | 23 (34) |

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
  call (AI-001, LOG-004, NET-002), agent → MCP without gateway (STR-005), public SQL with PMK (NET-001, DATA-004), no WAF
  or MFA (NET-003, ZT-009), no secure boot (CRA-002), 90-day traces (LOG-002), no output marking (AI-012), no reporting
  path under NIS2/CRA (GOV-002), no substantial-modification assessment under the Machinery Regulation (MR-004), and no supplier assessment behind the custom agent or the configured database (GXP-004). The template is the production path of the playbook's §6.4 table; its calls inside a
  Jetson are `hosted_on` the node, so NET-006 does not read them as transport.
- **multi-agent-fleet-bad**: users talk to the orchestrator without content safety or disclosure, non-OBO and
  untraced delegation, autonomous worker without kill switch calling the LLM directly, drafting agent
  impersonating users with no owner, unauthenticated/unscoped/unlogged MCP call, no log sink, no evaluation,
  LLM not in the outsourcing register.
