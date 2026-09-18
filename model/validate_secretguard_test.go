package model_test

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sixi-ai/sixi-assure-rules/model"
	"github.com/sixi-ai/sixi-assure-rules/secretguard"
)

// ADR-041 §2: the guard is structural. Every model write path goes through ValidateJSON, so a
// credential-shaped value is refused wherever it is put, with the JSON pointer that holds it.

func baseArch(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"id": "arch_sg", "tenant_id": "t1", "version": 1, "name": "Guarded",
		"attrs": map[string]any{},
		"nodes": []any{
			map[string]any{"id": "n_api", "type": "api", "name": "Gateway", "layer": "app", "source": "design",
				"attrs": map[string]any{"owner": "platform"}},
			map[string]any{"id": "n_db", "type": "datastore", "name": "Records", "layer": "data", "source": "design",
				"attrs": map[string]any{}},
		},
		"edges": []any{
			map[string]any{"id": "e1", "from": "n_api", "to": "n_db", "kind": "reads",
				"auth": "managed_identity", "encryption": "tls", "attrs": map[string]any{}},
		},
		"groups": []any{}, "findings": []any{}, "evidence": []any{},
	}
}

func raw(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	return b
}

func TestValidateJSONRefusesSecretsInEveryFreeTextLeaf(t *testing.T) {
	const awsKey = "AKIAIOSFODNN7EXAMPLE"
	tests := []struct {
		name     string
		mutate   func(doc map[string]any)
		pointer  string
		detector string
	}{
		{"architecture description", func(d map[string]any) {
			d["attrs"] = map[string]any{"description": "Deploy with " + awsKey}
		}, "/attrs/description", "aws_access_key"},
		{"architecture x_ extension", func(d map[string]any) {
			d["attrs"] = map[string]any{"x_handover": "sk-ant-api03-EXAMPLEnotarealkey0123456789abcdef"}
		}, "/attrs/x_handover", "llm_api_key"},
		{"node name", func(d map[string]any) {
			d["nodes"].([]any)[0].(map[string]any)["name"] = "Gateway " + awsKey
		}, "/nodes/0/name", "aws_access_key"},
		{"node external_ref", func(d map[string]any) {
			d["nodes"].([]any)[1].(map[string]any)["external_ref"] = "https://u:EXAMPLEnotarealpassword@cmdb.example.test/x"
		}, "/nodes/1/external_ref", "basic_auth_url"},
		{"node attrs purpose", func(d map[string]any) {
			d["nodes"].([]any)[0].(map[string]any)["attrs"].(map[string]any)["purpose"] =
				"reads postgres://app:EXAMPLEnotarealpassword@db.example.test:5432/records"
		}, "/nodes/0/attrs/purpose", "connection_string"},
		{"node x_ extension value", func(d map[string]any) {
			d["nodes"].([]any)[0].(map[string]any)["attrs"].(map[string]any)["x_note"] = "ghp_EXAMPLEnotarealtoken0123456789abcdef"
		}, "/nodes/0/attrs/x_note", "github_token"},
		{"edge label", func(d map[string]any) {
			d["edges"].([]any)[0].(map[string]any)["label"] = "auth header eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJleGFtcGxlIn0.EXAMPLEnotarealsignature"
		}, "/edges/0/label", "jwt"},
		{"edge attrs description", func(d map[string]any) {
			d["edges"].([]any)[0].(map[string]any)["attrs"].(map[string]any)["description"] =
				"uses AccountKey=RXhhbXBsZU5vdEFSZWFsQWNjb3VudEtleUZvclRlc3RzT25seTAxMjM0NTY3OA=="
		}, "/edges/0/attrs/description", "azure_storage_key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseArch(t)
			tc.mutate(doc)
			_, err := model.ValidateJSON(raw(t, doc))
			require.Error(t, err)
			var v *secretguard.Violation
			require.ErrorAs(t, err, &v)
			assert.ErrorIs(t, err, secretguard.ErrSecretDetected)
			assert.Equal(t, tc.pointer, v.Finding.Path)
			assert.Equal(t, tc.detector, v.Finding.Detector)
			assert.NotContains(t, err.Error(), "EXAMPLE", "the error must never carry the value")
		})
	}
}

func TestValidateJSONAcceptsOrdinaryModelText(t *testing.T) {
	doc := baseArch(t)
	doc["attrs"] = map[string]any{
		"description": "Retail payments platform. Security is expressed as a claim: set auth: api_key on the edge, never paste the key.",
		"x_runbook":   "https://wiki.example.test/runbooks/gateway?view=current",
		"x_ref":       "550e8400-e29b-41d4-a716-446655440000",
	}
	_, err := model.ValidateJSON(raw(t, doc))
	assert.NoError(t, err)
}

// The patch path reaches the guard through Apply → ValidateJSON (ADR-041 §2).
func TestApplyRefusesSecretOperands(t *testing.T) {
	a, err := model.ValidateJSON(raw(t, baseArch(t)))
	require.NoError(t, err)

	_, err = model.Apply(a, []model.PatchOp{{Op: "add", Path: "/nodes/n_db/attrs/x_dsn",
		Value: json.RawMessage(`"Server=tcp:db.example.test,1433;Initial Catalog=records;User ID=app;Password=EXAMPLEnotarealpassword;"`)}}, false)
	require.Error(t, err)
	var v *secretguard.Violation
	require.ErrorAs(t, err, &v)
	assert.Equal(t, "connection_string", v.Finding.Detector)
	assert.Equal(t, "/nodes/1/attrs/x_dsn", v.Finding.Path)

	// A patch that adds an ordinary value still applies.
	next, err := model.Apply(a, []model.PatchOp{{Op: "add", Path: "/nodes/n_db/attrs/x_dsn",
		Value: json.RawMessage(`"managed identity, no secret in the model"`)}}, false)
	require.NoError(t, err)
	assert.Equal(t, "managed identity, no secret in the model", next.Nodes[1].Attrs["x_dsn"])
}

func TestValidateJSONSecretGuardCostOnA500NodeModel(t *testing.T) {
	doc := baseArch(t)
	nodes := make([]any, 0, 500)
	edges := make([]any, 0, 499)
	for i := 0; i < 500; i++ {
		id := "n_" + strconv.Itoa(i)
		nodes = append(nodes, map[string]any{"id": id, "type": "app", "name": "Service " + id, "layer": "app", "source": "design",
			"description": "Handles part " + id + " of the payments platform and reports to the control plane.",
			"attrs": map[string]any{"owner": "platform-team", "external_ref": "CMDB-" + strconv.Itoa(100000+i),
				"purpose": "serves the retail channel", "x_runbook": "https://wiki.example.test/runbooks/" + id}})
		if i > 0 {
			edges = append(edges, map[string]any{"id": "e_" + strconv.Itoa(i), "from": id, "to": "n_0", "kind": "calls",
				"auth": "managed_identity", "encryption": "mtls", "label": "synchronous call over mTLS",
				"attrs": map[string]any{"description": "carries customer records"}})
		}
	}
	doc["nodes"], doc["edges"] = nodes, edges
	body := raw(t, doc)
	_, err := model.ValidateJSON(body)
	require.NoError(t, err)

	var parsed any
	require.NoError(t, json.Unmarshal(body, &parsed))
	start := time.Now()
	for i := 0; i < 5; i++ {
		require.NoError(t, secretguard.CheckDocument(t.Context(), secretguard.SourceModel, parsed))
	}
	per := time.Since(start) / 5
	t.Logf("secret guard over a 500-node model: %s", per)
	// ADR-041: under 50 ms in production; the test budget is 250 ms, and 4 s under the race
	// detector with every package running in parallel (the measurement is logged either way).
	budget := 250 * time.Millisecond
	if raceEnabled {
		budget = 4 * time.Second
	}
	assert.Less(t, per, budget)
}

func TestValidationErrorTypesStaySeparate(t *testing.T) {
	doc := baseArch(t)
	doc["nodes"].([]any)[0].(map[string]any)["type"] = "not_a_type"
	_, err := model.ValidateJSON(raw(t, doc))
	require.Error(t, err)
	var ve *model.ValidationError
	assert.True(t, errors.As(err, &ve), "a schema problem stays a ValidationError")
	assert.False(t, errors.Is(err, secretguard.ErrSecretDetected))
	assert.True(t, strings.Contains(err.Error(), "/nodes/0/type"))
}
