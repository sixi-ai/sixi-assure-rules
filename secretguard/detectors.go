package secretguard

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// detectorEntropy is the one soft detector that never rejects on its own (ADR-041 §1).
const detectorEntropy = "high_entropy_token"

// detector is one credential shape. Every detector documents its false-positive profile in the
// comment above its entry in the table below.
//
//	name       stable identifier reported to the user and stored on the evidence event
//	reject     true = refuse the input; false = warn only (certificates, entropy)
//	confidence 0..1, reported on the finding; never used as a threshold on its own
//	hints      lowercase substrings; when none of them occurs the detector is skipped without
//	           running its regex, which is what keeps a 5 000-leaf model scan in single-digit ms
//	match      returns (offset, length, found) and never the matched text
type detector struct {
	name       string
	reject     bool
	confidence float64
	hints      []string
	match      func(s string) (int, int, bool)
}

// hinted reports whether the detector can possibly match; a detector without hints always runs.
// The comparison is case-insensitive over ASCII and allocation-free, which matters because it
// runs once per detector per string leaf.
func (d detector) hinted(s string) bool {
	if len(d.hints) == 0 {
		return true
	}
	for _, h := range d.hints {
		if containsFold(s, h) {
			return true
		}
	}
	return false
}

// containsFold reports whether s contains sub, which must be lowercase ASCII, ignoring case.
func containsFold(s, sub string) bool {
	n, m := len(s), len(sub)
	if m == 0 || n < m {
		return false
	}
	first := sub[0]
	upper := first
	if first >= 'a' && first <= 'z' {
		upper = first - 'a' + 'A'
	}
	for i := 0; i+m <= n; i++ {
		if s[i] != first && s[i] != upper {
			continue
		}
		j := 1
		for ; j < m; j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != sub[j] {
				break
			}
		}
		if j == m {
			return true
		}
	}
	return false
}

// reMatch adapts a regexp to the detector match signature.
func reMatch(re *regexp.Regexp) func(s string) (int, int, bool) {
	return func(s string) (int, int, bool) {
		if loc := re.FindStringIndex(s); loc != nil {
			return loc[0], loc[1] - loc[0], true
		}
		return 0, 0, false
	}
}

var (
	rePEMPrivate = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	rePEMPublic  = regexp.MustCompile(`-----BEGIN (?:CERTIFICATE|PUBLIC KEY|CERTIFICATE REQUEST|PGP PUBLIC KEY BLOCK)-----`)
	reJWT        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*`)
	reAWSID      = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}`)
	reAzureSAS   = regexp.MustCompile(`(?i)[?&]sig=[A-Za-z0-9%+/=_-]{20,}`)
	reAzureStore = regexp.MustCompile(`(?i)\b(?:accountkey|sharedaccesskey)\s*=\s*[A-Za-z0-9+/]{24,}={0,2}`)
	reGoogleAPI  = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)
	reGoogleSA   = regexp.MustCompile(`"type"\s*:\s*"service_account"|"private_key"\s*:\s*"`)
	reGitHub     = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|\bgithub_pat_[A-Za-z0-9_]{22,}`)
	reSlack      = regexp.MustCompile(`\bxox[abprse]-[A-Za-z0-9-]{10,}`)
	reModelAPI   = regexp.MustCompile(`\bsk-(?:ant-|proj-|svcacct-)?([A-Za-z0-9_-]{20,})`)
	reStripeLive = regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{10,}`)
	reEntraShape = regexp.MustCompile(`\b[A-Za-z0-9~._-]{3}[0-9]Q~[A-Za-z0-9~._-]{31,34}\b`)
	reDSNCreds   = regexp.MustCompile(`(?i)\b(?:postgresql|postgres|mysql|mariadb|mongodb\+srv|mongodb|amqps|amqp|rediss|redis|sqlserver|mssql|jdbc:[a-z0-9]+)://[^\s/:@"'<>]{1,100}:[^\s/@"'<>]{1,200}@`)
	reADOPass    = regexp.MustCompile(`(?i)\b(?:password|pwd)\s*=\s*[^;\s"'<>]{4,}`)
	reADOLocator = regexp.MustCompile(`(?i)\b(?:server|data source|host|initial catalog|database|user id|uid)\s*=\s*[^;\n]{1,200};`)
	reBasicAuth  = regexp.MustCompile(`(?i)\bhttps?://[^\s/:@"'<>]{1,100}:[^\s/@"'<>]{1,200}@[^\s"'<>]{1,255}`)
	reKubeClient = regexp.MustCompile(`(?i)\bclient-key-data\s*:\s*\S`)
	reUUID       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// detectors is the ordered detector table (ADR-041 §1). Order matters only for which finding is
// reported first when a value trips several: the most specific shapes come first.
var detectors = []detector{
	// PEM private keys. A private key block has one shape and no legitimate reason to appear in a
	// design document. False positives: documentation that quotes the armour header without a key
	// body is refused too — intended, the header alone is a "paste your key here" instruction.
	{name: "pem_private_key", reject: true, confidence: 0.99, hints: []string{"-----begin"}, match: reMatch(rePEMPrivate)},

	// Certificates and public keys are public material: warn only, never refuse (ADR-041 §3).
	// False positives: none of consequence; the finding exists so a reviewer sees the paste.
	{name: "pem_certificate", reject: false, confidence: 0.40, hints: []string{"-----begin"}, match: reMatch(rePEMPublic)},

	// JWT: three base64url segments whose header decodes to JSON carrying "alg". The decode step
	// is what keeps ordinary dotted identifiers out. False positives: an *expired sample* token
	// from documentation is indistinguishable from a live one and is refused.
	{name: "jwt", reject: true, confidence: 0.90, hints: []string{"eyj"}, match: matchJWT},

	// AWS access key ids (AKIA long-term, ASIA temporary). False positives: a 20-character
	// upper-case identifier that happens to start with AKIA/ASIA; not observed in practice.
	{name: "aws_access_key", reject: true, confidence: 0.95, hints: []string{"akia", "asia"}, match: reMatch(reAWSID)},

	// Azure shared-access-signature: the sig= component of a SAS URL. False positives: a query
	// parameter genuinely called "sig" holding 20+ opaque characters (rare; refused by design,
	// since a signed URL is a bearer credential whatever it signs).
	{name: "azure_sas_token", reject: true, confidence: 0.85, hints: []string{"sig="}, match: reMatch(reAzureSAS)},

	// Azure storage account key, in a connection string or on its own line. Also covers the
	// Service Bus / Event Hubs SharedAccessKey. False positives: an attribute literally named
	// AccountKey holding a long base64 value that is not a key.
	{name: "azure_storage_key", reject: true, confidence: 0.95, hints: []string{"accountkey", "sharedaccesskey"}, match: reMatch(reAzureStore)},

	// Google API key (AIza + 35). False positives: none known; the prefix is registered.
	{name: "gcp_api_key", reject: true, confidence: 0.95, hints: []string{"aiza"}, match: reMatch(reGoogleAPI)},

	// Google service-account JSON, recognised by its account-type marker (the JSON key `type` with the service-account value) or by
	// "private_key" member. False positives: a model that *describes* a service account in JSON
	// prose using the same keys.
	{name: "gcp_service_account", reject: true, confidence: 0.90, hints: []string{"service_account", "private_key"}, match: reMatch(reGoogleSA)},

	// GitHub tokens: classic (ghp_/gho_/ghu_/ghs_/ghr_ + 36) and fine-grained (github_pat_).
	// False positives: none known.
	{name: "github_token", reject: true, confidence: 0.95, hints: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, match: reMatch(reGitHub)},

	// Slack tokens (xoxb/xoxp/xoxa/xoxr/xoxs/xoxe). False positives: none known.
	{name: "slack_token", reject: true, confidence: 0.90, hints: []string{"xox"}, match: reMatch(reSlack)},

	// OpenAI and Anthropic keys: sk-, sk-ant-, sk-proj-, sk-svcacct-. The body must be base64-ish
	// material (mixed case with a digit) or at least 40 characters, which is what every issued key
	// is and what a hyphenated slug ("sk-eu-west-payments-gateway-v2") is not. False positives: a
	// mixed-case opaque identifier of 20+ characters behind an "sk-" prefix. Prose that merely
	// mentions "sk-" is not matched: a token body is required.
	{name: "llm_api_key", reject: true, confidence: 0.85, hints: []string{"sk-"}, match: matchModelAPIKey},

	// Stripe live secret and restricted keys. Test keys (sk_test_) are deliberately not matched.
	// False positives: none known.
	{name: "stripe_secret_key", reject: true, confidence: 0.95, hints: []string{"sk_live_", "rk_live_"}, match: reMatch(reStripeLive)},

	// Microsoft Entra application secrets, recognised by shape (xxx<digit>Q~ + 31-34). False
	// positives: a 38-40 character opaque string that contains "<digit>Q~" at offset 3; rare.
	{name: "entra_client_secret", reject: true, confidence: 0.80, hints: []string{"q~"}, match: reMatch(reEntraShape)},

	// Connection strings: a DSN carrying user:password@ (postgres, mysql, mongodb+srv, amqp,
	// redis, sqlserver, jdbc:*) or an ADO/ODBC keyword string that pairs a locator keyword
	// (Server=, Data Source=, Initial Catalog=, User ID=) with Password=/Pwd=. Azure
	// AccountKey=/SharedAccessKey= is reported by azure_storage_key instead.
	// False positives: a *placeholder* DSN such as postgres://user:password@host is refused —
	// intended: security is a claim on the edge, a DSN never belongs in the model.
	{name: "connection_string", reject: true, confidence: 0.90, hints: []string{"://", "password", "pwd="}, match: matchConnectionString},

	// http(s) URLs carrying credentials in the authority. False positives: a documentation URL of
	// the form https://user:pass@example.com; refused by design (same reasoning as above).
	{name: "basic_auth_url", reject: true, confidence: 0.85, hints: []string{"://"}, match: reMatch(reBasicAuth)},

	// kubeconfig client certificates. client-key-data holds a base64 private key; its presence is
	// enough. False positives: none known.
	{name: "kubeconfig", reject: true, confidence: 0.90, hints: []string{"client-key-data"}, match: reMatch(reKubeClient)},

	// Terraform state: the three state markers together, or the sensitive_attributes member of a
	// plan/state resource (ADR-041 §4). False positives: a document that quotes all three JSON
	// keys while discussing state files.
	{name: "terraform_state", reject: true, confidence: 0.85, hints: []string{"terraform_version", "sensitive_attributes"}, match: matchTerraformState},

	// High-entropy token: Shannon entropy > 4.5 bits/character over 32+ characters, excluding
	// UUIDs, hex digests and base64 data URIs. Warn only: on its own it says nothing, it raises
	// the confidence of a detector that does reject (ADR-041 §1). False positives by design —
	// hashes, ids and minified payloads all trip it, which is why it cannot refuse an input.
	{name: detectorEntropy, reject: false, confidence: 0.30, match: matchEntropy},
}

// Detectors returns the detector names in table order (used by the seeded-secret suites).
func Detectors() []string {
	out := make([]string, 0, len(detectors))
	for _, d := range detectors {
		out = append(out, d.name)
	}
	return out
}

// Rejecting reports whether a detector name refuses its input (false = warn-only).
func Rejecting(name string) bool {
	for _, d := range detectors {
		if d.name == name {
			return d.reject
		}
	}
	return false
}

// matchJWT finds a three-segment base64url token whose header decodes to a JSON object with an
// "alg" member. Everything else (dotted ids, version strings, file names) is skipped.
func matchJWT(s string) (int, int, bool) {
	for from := 0; from < len(s); {
		loc := reJWT.FindStringIndex(s[from:])
		if loc == nil {
			return 0, 0, false
		}
		tok := s[from+loc[0] : from+loc[1]]
		if header, _, ok := strings.Cut(tok, "."); ok && jwtHeader(header) {
			return from + loc[0], loc[1] - loc[0], true
		}
		from += loc[1]
	}
	return 0, 0, false
}

// jwtHeader reports whether seg is a base64url JOSE header (a JSON object carrying "alg").
func jwtHeader(seg string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return false
	}
	var hdr map[string]json.RawMessage
	if json.Unmarshal(raw, &hdr) != nil {
		return false
	}
	_, ok := hdr["alg"]
	return ok
}

// matchModelAPIKey finds an OpenAI/Anthropic-shaped key. The body test keeps human-readable
// hyphenated slugs (and the red-team canaries that imitate one) out of the reject path while
// every issued key — 48 to 100 characters of base64url — stays in it.
func matchModelAPIKey(s string) (int, int, bool) {
	for from := 0; from < len(s); {
		loc := reModelAPI.FindStringSubmatchIndex(s[from:])
		if loc == nil {
			return 0, 0, false
		}
		if body := s[from+loc[2] : from+loc[3]]; len(body) >= 40 || looksGenerated(body) {
			return from + loc[0], loc[1] - loc[0], true
		}
		from += loc[1]
	}
	return 0, 0, false
}

// looksGenerated reports the base64-ish mix (upper + lower + digit) every issued key has.
func looksGenerated(body string) bool {
	var upper, lower, digit bool
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

// matchConnectionString reports a DSN with inline credentials or an ADO keyword string that pairs
// a locator with a password.
func matchConnectionString(s string) (int, int, bool) {
	if loc := reDSNCreds.FindStringIndex(s); loc != nil {
		return loc[0], loc[1] - loc[0], true
	}
	pass := reADOPass.FindStringIndex(s)
	if pass == nil || reADOLocator.FindStringIndex(s) == nil {
		return 0, 0, false
	}
	return pass[0], pass[1] - pass[0], true
}

// matchTerraformState reports state/plan markers: the trio terraform_version + serial + lineage,
// or sensitive_attributes on its own (ADR-041 §4 refuses .tfstate outright).
func matchTerraformState(s string) (int, int, bool) {
	if i := strings.Index(s, `"sensitive_attributes"`); i >= 0 {
		return i, len(`"sensitive_attributes"`), true
	}
	i := strings.Index(s, `"terraform_version"`)
	if i < 0 || !strings.Contains(s, `"serial"`) || !strings.Contains(s, `"lineage"`) {
		return 0, 0, false
	}
	return i, len(`"terraform_version"`), true
}
