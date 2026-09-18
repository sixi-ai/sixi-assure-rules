# Third-party attribution for rule content

Rule packs in this directory are our own work except where noted here. Code is not vendored from
any of these projects; what is reused is described per entry, as Apache-2.0 §4 requires for a
derivative work.

## AGT-002 — hidden secondary behaviour (`packs/agt.yaml`)

The vocabulary of the detection pattern (the adverb and verb sets that mark a declared secondary
action, and the idea of pairing them with an exemption term to hold the false-positive rate down)
is derived from the YARA rules `tool_poisoning.yara` and `prompt_injection.yara` in:

> **MCP Scanner** — Cisco AI Defense. Apache License 2.0.
> https://github.com/cisco-ai-defense/mcp-scanner

Changes we made: the patterns were rewritten as RE2 (no YARA, no back-references), narrowed to the
subset that can appear in an architect's declared description, expressed as a single CEL condition
with an explicit audit-logging exemption, and given a severity and two clause citations from
`corpus/` rather than the upstream threat table.

## Editorial cross-references

The judgement of which tool capability classes map to which OWASP clause was informed by the
category-to-vulnerability table in:

> **Agentic Radar** — SplxAI. Apache License 2.0.
> https://github.com/splx-ai/agentic-radar

No text from that table is reproduced. Our clause IDs, wording and remediation are sourced from
`corpus/` and written by us; see `docs/upstream-analysis-2026-09.md` for the full account of what
was taken and what was deliberately refused.
