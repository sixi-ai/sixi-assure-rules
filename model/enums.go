package model

// Enumerations mirror schema/model.schema.json; TestEnumsMatchSchema guards drift.

// NodeTypes lists every node.type (docs/02 §2).
var NodeTypes = []string{"user", "external_party", "edge_device", "edge_gateway", "edge_model", "broker", "dmz",
	"data_diode", "network", "identity_provider", "app", "api", "agent", "tool", "mcp_server", "llm_endpoint",
	"gateway", "vector_index", "datastore", "queue", "log_sink", "secret_store", "human_step", "saas",
	"evaluation", "product"}

// Layers lists node.layer values.
var Layers = []string{"edge", "network", "platform", "app", "data", "ai", "identity", "human"}

// Sources lists node.source values.
var Sources = []string{"design", "declared", "observed"}

// EdgeKinds lists edge.kind values.
var EdgeKinds = []string{"calls", "reads", "writes", "publishes", "subscribes", "delegates", "authenticates", "flows", "executes"}

// EdgeAuths lists edge.auth values.
var EdgeAuths = []string{"managed_identity", "agent_id", "obo", "oauth_client", "mtls", "api_key", "password", "connection_string", "none", "unknown"}

// Encryptions lists edge.encryption values.
var Encryptions = []string{"tls", "mtls", "none", "unknown"}

// Capabilities lists the declared capability classes of a tool or mcp_server node
// (docs/02 §3). They are what the architect states the component is able to do, which is
// what the agentic rule pack reasons over; nothing here is observed from a running system.
var Capabilities = []string{"executes_code", "reads_filesystem", "queries_database", "network_egress",
	"sends_message", "modifies_state", "reads_secrets", "deserializes_input"}

// Integrities lists node.attrs.integrity values: how a tool or MCP server definition is fixed
// against later change (docs/03 AGT-004).
var Integrities = []string{"", "none", "pinned", "signed"}

// EvaluationScopes lists node.attrs.evaluates values: what an evaluation node is declared to
// cover (docs/02 §3). A declaration of scope only; no result is ever recorded in the model.
var EvaluationScopes = []string{"accuracy", "robustness", "bias", "fairness", "toxicity", "prompt_injection", "calibration", "drift"}

// DataClasses lists data_class values.
var DataClasses = []string{"public", "internal", "confidential", "pii", "phi", "cid", "secret"}

// Severities lists finding.severity values, most severe first.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// FindingStatuses lists finding.status values.
var FindingStatuses = []string{"open", "fixed", "accepted", "false_positive"}

// GroupKinds lists group.kind values.
var GroupKinds = []string{"zone", "trust_boundary", "region", "subscription", "site"}

// Regimes lists regime pack codes (docs/04).
var Regimes = []string{"FINMA", "CH-CO", "FADP", "CH-ISG", "DORA", "AIACT", "CRA", "NIS2", "ISO", "MCSB", "NIST", "IEC", "OWASP", "MAESTRO", "MSFT", "FDA", "EU-GMP", "MR", "GAMP", "GDPR", "OSFI", "CSA"}

// EvidenceTypes lists evidence event types (docs/02 §6).
var EvidenceTypes = []string{"model_created", "patch_accepted", "finding_status", "export_generated", "share_created", "llm_call",
	// ADR-028: the two notary events. evidence_record deposits evidence against one obligation;
	// spot_check records the signed receipt of a snapshot of obligations and components.
	"evidence_record", "spot_check",
	// ADR-034: one Architect-mode run (ids, hashes and counts only; proposals and decisions are
	// evidenced by their own accepted patches).
	"assistant_architect_run",
	// ADR-041: an input path refused a credential-shaped value (path hash + detector only, never the value).
	"secret_rejected"}

// Evidence types added by ADR-028 and ADR-034.
const (
	EvidenceRecord         = "evidence_record"
	EvidenceSpotCheck      = "spot_check"
	EvidenceArchitectRun   = "assistant_architect_run"
	EvidenceSecretRejected = "secret_rejected"
)

// Finding status constants.
const (
	StatusOpen          = "open"
	StatusFixed         = "fixed"
	StatusAccepted      = "accepted"
	StatusFalsePositive = "false_positive"
)

// Source constants.
const (
	SourceDesign   = "design"
	SourceDeclared = "declared"
	SourceObserved = "observed"
)

// SeverityRank returns 0 for critical … 4 for info (5 for unknown).
func SeverityRank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return len(Severities)
}
