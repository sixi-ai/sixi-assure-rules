package migrate

// Schema 1.3 (ADR-105, docs/research/09-agent-swarms-2026.md): the containment and continuity
// vocabulary. Every addition is a node type (model_artifact), a group kind (isolation), an enum value
// (five capabilities) or an optional attribute (agent max_instances, kill_switch_identity and
// agent_role; edge-device default_credentials, debug_interface, debug_auth, accelerator and
// network_exposure; architecture max_blast_radius and degraded_mode_tested_at). None of them existed
// at 1.2 under any spelling (nodeAttrs admits no unknown member but x_*), so a 1.2 model is a 1.3
// model once it says so: the step changes schema_version and nothing else, which the golden pairs
// check.
//
// The tolerant reading of the 1.0 shapes that ADR-040 §4 promised until 1.3 is kept: Normalize runs
// here as in v11to12, so a stored document that still carries a 1.0 shape reads as it did at 1.2.

// v12to13 is the 1.2 → 1.3 step.
func v12to13(doc map[string]any) (map[string]any, error) {
	Normalize(doc)
	doc[Field] = "1.3"
	return doc, nil
}
