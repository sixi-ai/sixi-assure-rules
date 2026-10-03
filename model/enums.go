package model

import "github.com/sixi-ai/sixi-assure-rules/model/migrate"

// Enumerations mirror schema/model.schema.json; TestEnumsMatchSchema guards drift.

// NodeTypes lists every node.type (docs/02 §2).
var NodeTypes = []string{"user", "external_party", "edge_device", "edge_gateway", "edge_model", "broker", "dmz",
	"data_diode", "network", "identity_provider", "app", "api", "agent", "tool", "mcp_server", "llm_endpoint",
	"gateway", "vector_index", "datastore", "queue", "log_sink", "secret_store", "human_step", "saas",
	"evaluation", "product",
	// ADR-047 §3 (schema 1.1): agent memory, a registry of agents or servers, a credential broker
	// (token vault) and an A2A peer outside the organisation's control.
	"agent_memory", "agent_registry", "credential_broker", "external_agent",
	"note"}

// NoteTones lists the attrs.tone values of a note (ADR-081); absent means neutral.
var NoteTones = []string{"neutral", "decision", "question", "warning"}

// Layers lists node.layer values.
var Layers = []string{"edge", "network", "platform", "app", "data", "ai", "identity", "human"}

// Sources lists node.source values.
var Sources = []string{"design", "declared", "observed"}

// EdgeKinds lists edge.kind values.
var EdgeKinds = []string{"calls", "reads", "writes", "publishes", "subscribes", "delegates", "authenticates", "flows", "executes"}

// EdgeAuths lists edge.auth values.
var EdgeAuths = []string{"managed_identity", "agent_id", "obo", "oauth_client", "mtls", "api_key", "password", "connection_string",
	// ADR-047 §1 (schema 1.1); token_passthrough is drawable so a rule can flag it. ADR-047 §3b:
	// public_client_id is an identifier published by design (limitation 21).
	"token_exchange", "workload_identity", "agent_user", "jwt_assertion", "federated_credential", "token_passthrough", "public_client_id",
	// ADR-093 FS-23 (schema 1.2): sas, a shared access signature, is a static bearer secret. Every
	// shared-secret rule (zt ZT-001, ZT-006, WIS-001, WIS-010; c4 STR-006; rag RAG-001; a2a ATA-002)
	// names it beside api_key, and rules TestSASReadsAsAnAPIKey pins that a sas hop raises what its
	// api_key twin raises (adr/proposals/ADR-093-M1-schema-12-narrowing-on-read.md §4, closed).
	"sas",
	"none", "unknown"}

// SharedSecretAuths lists the edge.auth values that are a static shared secret: replayable by anyone who
// holds it and not attributable to a caller. The rules name them (ZT-001, STR-006, RAG-001, ATA-002), and the
// Go code that classifies a hop reads this one list, so a value added here reaches every site at once: the
// assistant and swarm critics (a proposal setting one is an unsafe change), the architect planners (the
// workload-identity candidate and the elevation threat), the swarm's retrieval-security mirror of RAG-001 and
// the Annex IV export's weak-authentication list. TestSharedSecretAuthsAreEdgeAuths pins it to EdgeAuths.
var SharedSecretAuths = []string{"api_key", "sas", "password", "connection_string"}

// IsSharedSecretAuth reports whether an edge.auth value is a static shared secret (SharedSecretAuths).
func IsSharedSecretAuth(auth string) bool {
	for _, s := range SharedSecretAuths {
		if s == auth {
			return true
		}
	}
	return false
}

// Protocols lists edge.protocol values (ADR-047 §2, schema 1.1): an enum with an `other` escape and
// the empty value for "not declared". Free text from 1.0 is mapped by model/migrate.
var Protocols = append([]string{""}, migrate.Protocols...)

// IdentityKinds lists identities[].kind values (ADR-047 §1).
var IdentityKinds = []string{"", "user_account", "service_principal", "workload_identity", "agent_identity", "agent_user_account", "shared", "none"}

// CredentialTypes lists identities[].credential_type values (ADR-047 §1).
var CredentialTypes = []string{"", "federated", "managed_identity", "certificate", "client_secret", "api_key", "sidecar", "none"}

// Federations lists identities[].federation values (docs/18 D1).
var Federations = []string{"", "workload_identity_federation", "spiffe", "entra_agent_id", "oidc_client", "static_key", "none"}

// Sandboxes lists the sandbox values of an agent, MCP server or tool (ADR-047 §3, amended by docs/18
// D3 with managed and by ADR-093 FS-08 with wasm, vm and model_hosted for a tool; an MCP server
// accepts the first five and an agent the first six, see x-attr-values).
var Sandboxes = []string{"", "none", "process", "container", "os_sandbox", "managed", "wasm", "vm", "model_hosted"}

// Frameworks lists agent.framework values (ADR-093 FS-01, schema 1.2): the agent framework an agent
// is built with. Framework-native remediation (WS-M M4) is chosen by it.
var Frameworks = []string{"", "langgraph", "ms_agent_framework", "foundry_agent_service", "google_adk", "openai_agents", "crewai", "other"}

// Orchestrations lists agent.orchestration values (ADR-093 FS-03, schema 1.2): the multi-agent
// pattern an orchestrating agent runs.
var Orchestrations = []string{"", "supervisor", "swarm", "handoff", "sequential", "parallel", "loop", "graph", "group_chat", "magentic", "hierarchical"} //nolint:misspell // MAF's Magentic orchestration (Magentic-One), not "magnetic"

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
var FindingStatuses = []string{"open", "fixed", "accepted", "false_positive", "superseded"}

// GroupKinds lists group.kind values.
var GroupKinds = []string{"zone", "trust_boundary", "region", "subscription", "site",
	// ADR-047 §2 (schema 1.1): a tenant boundary and a legal jurisdiction, beside the cloud region.
	"tenant", "jurisdiction",
	// ADR-093 FS-06 (schema 1.2): the executors of one workflow (MAF, ADK, CrewAI flows), with its
	// loop bound and checkpointing as group attributes.
	"workflow"}

// Regimes lists regime pack codes (docs/04).
var Regimes = []string{"FINMA", "CH-CO", "FADP", "CH-ISG", "DORA", "AIACT", "CRA", "NIS2", "ISO", "MCSB", "NIST", "IEC", "OWASP", "MAESTRO", "MSFT", "FDA", "EU-GMP", "MR", "GAMP", "GDPR", "OSFI", "CSA"}

// EvidenceTypes lists evidence event types (docs/02 §6).
var EvidenceTypes = []string{"model_created", "patch_accepted", "finding_status", "export_generated", "share_created", "llm_call",
	// ADR-028: the two notary events. evidence_record deposits evidence against one obligation;
	// spot_check records the signed receipt of a snapshot of obligations and components.
	"evidence_record", "spot_check",
	// ADR-046 §5: one pipeline gate run recorded by the CLI or a pipeline (docs/17 round 21).
	"ci_gate",
	// ADR-034: one Architect-mode run (ids, hashes and counts only; proposals and decisions are
	// evidenced by their own accepted patches).
	"assistant_architect_run",
	// ADR-041: an input path refused a credential-shaped value (path hash + detector only, never the value).
	"secret_rejected",
	// ADR-060: a person decided a draft session an agent drew (draft id, agent key, batch count,
	// batch hashes, rationale hash — never the ops or the rationale text).
	"draft_accepted", "draft_rejected",
	// ADR-082 proposal (docs/17 DP-5): the design review object. A review was requested on one
	// version, a person recorded a decision about the design review, the review closed (approved,
	// rejected, stale because a new version was saved, or withdrawn). Ids, roles, counts and the
	// sha256 of a note — never the note or the title. They record a design review, never a
	// compliance statement.
	"design_review_requested", "design_review_decision", "design_review_closed",
	// docs/18 V2 (ADR-087, ADR-089, ADR-090, ADR-084, WS-J): a tenant signing key was rotated or a key
	// ceremony recorded (key ids, custody and the record hash only); a chain head was anchored at an
	// external timestamp authority (head hash, authority, receipt hash); a scanner trusted key was
	// registered for the organisation (key id and fingerprint); a bundle was downloaded (bundle hash,
	// downloader identity); a rule-pack advisory was applied (pack hash, advisory id); a management
	// assertion or an independent review record was signed (hashes only); a read-only reviewer scope
	// was granted or changed (ids only).
	"signing_key_rotated", "signing_key_ceremony", "chain_anchored", "trusted_key_registered",
	"bundle_downloaded", "pack_advisory_applied", "management_assertion", "independent_review",
	"auditor_scope_granted", "auditor_scope_changed",
	// ADR-085 (docs/18 WS-I I1): one assurance swarm run (run and session ids, agents run and not
	// run, candidate, proposal, not-checked and evidence-request counts, the critic score, the
	// guard's counters; hashes and counts only).
	"assistant_swarm_run"}

// Evidence types added by ADR-028 and ADR-034.
const (
	EvidenceRecord         = "evidence_record"
	EvidenceSpotCheck      = "spot_check"
	EvidenceArchitectRun   = "assistant_architect_run"
	EvidenceSecretRejected = "secret_rejected"
)

// Evidence types added by ADR-060 (draft sessions).
const (
	EvidenceDraftAccepted = "draft_accepted"
	EvidenceDraftRejected = "draft_rejected"
)

// Evidence types added by docs/18 V2 (ADR-084, ADR-087, ADR-089, ADR-090, WS-J).
const (
	EvidenceSigningKeyRotated    = "signing_key_rotated"
	EvidenceSigningKeyCeremony   = "signing_key_ceremony"
	EvidenceChainAnchored        = "chain_anchored"
	EvidenceTrustedKeyRegistered = "trusted_key_registered"
	EvidenceBundleDownloaded     = "bundle_downloaded"
	EvidencePackAdvisoryApplied  = "pack_advisory_applied"
	EvidenceManagementAssertion  = "management_assertion"
	EvidenceIndependentReview    = "independent_review"
	EvidenceAuditorScopeGranted  = "auditor_scope_granted"
	EvidenceAuditorScopeChanged  = "auditor_scope_changed"
)

// Evidence type added by ADR-085 (the assurance swarm, docs/18 WS-I I1).
const EvidenceSwarmRun = "assistant_swarm_run"

// Evidence types added by ADR-082 (design reviews, docs/17 DP-5).
const (
	EvidenceReviewRequested = "design_review_requested"
	EvidenceReviewDecision  = "design_review_decision"
	EvidenceReviewClosed    = "design_review_closed"
)

// Finding status constants.
const (
	StatusOpen          = "open"
	StatusFixed         = "fixed"
	StatusAccepted      = "accepted"
	StatusFalsePositive = "false_positive"
	// StatusSuperseded is set by the system only (ADR-088 Amendments "Stored findings"): the rule was retired or
	// its pack changed and the finding no longer fires on the model it was raised on, so the design did not fix it.
	StatusSuperseded = "superseded"
)

// GroupKindWorkflow is the group kind of a workflow's executors (ADR-093 FS-06, schema 1.2).
const GroupKindWorkflow = "workflow"

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
