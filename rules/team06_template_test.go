package rules

// glassboxTemplateBaseline is what the GlassBox Edge template (golden-set/models/glassbox-ot-agent.json) raises as
// shipped: NIS-001 only. The template declares NIS2 and ships no accepted decision citing NIS2:2022/2555:Art41,
// because that acceptance (which national act transposes NIS2 for the organisation) is the customer's own evidence
// (ADR-032), never a template default (docs/18 WS-I I2 review fix). Every other rule is silent on it, which is the
// baseline the GlassBox mutation tests break one control against. Its gateways declare functions[] (schema 1.1), so
// CMP-005 is silent on it too (docs/18 WS-I I2 swarm team 01 review fix, adr/proposals/ADR-102-team01-golden-twin-gaps.md).
var glassboxTemplateBaseline = map[string][]string{"NIS-001": {"arch_tpl_glassbox_ot_agent"}}
