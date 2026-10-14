package model

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Schema 1.3 (ADR-105, docs/research/09-agent-swarms-2026.md): the containment and continuity
// vocabulary. Every addition is optional; the server checks what JSON Schema cannot say (the kill
// switch is operated by a declared identity that is not the agent's own).

// containment13 is a small valid 1.3 model using every new construct once.
func containment13() map[string]any {
	return map[string]any{
		"schema_version": CurrentSchemaVersion, "id": "arch_13", "tenant_id": "t", "name": "1.3", "version": 1,
		"attrs": map[string]any{"max_blast_radius": 3, "degraded_mode_tested_at": "2026-09-30"},
		"identities": []any{
			map[string]any{"id": "id_soc", "kind": "agent_identity", "credential_type": "federated", "federation": "entra_agent_id"},
			map[string]any{"id": "id_oncall", "kind": "user_account"},
		},
		"groups": []any{
			map[string]any{"id": "g_quarantine", "kind": "isolation", "name": "Quarantine segment", "node_ids": []any{"n_cam"}},
		},
		"nodes": []any{
			map[string]any{"id": "n_soc", "type": "agent", "name": "Triage agent", "layer": "ai", "attrs": map[string]any{
				"identity_id": "id_soc", "autonomy": "semi", "purpose": "triage alerts", "owner": "SOC",
				"agent_role": "security_operations", "max_instances": 4, "kill_switch_identity": "id_oncall",
				"kill_switch": true, "rate_limit": true}},
			map[string]any{"id": "n_spawn", "type": "tool", "name": "Spawn worker", "layer": "app", "attrs": map[string]any{
				"origin": "first_party", "scopes": []any{"spawn"},
				"capabilities": []any{"spawns_agents", "provisions_compute", "deploys_code", "creates_identity", "transfers_model_artifact"}}},
			map[string]any{"id": "n_weights", "type": "model_artifact", "name": "Fine-tuned weights", "layer": "data", "attrs": map[string]any{
				"integrity": "signed", "network_exposure": "private", "data_class": "confidential", "owner": "ML", "version": "3"}},
			map[string]any{"id": "n_cam", "type": "edge_device", "name": "Camera fleet", "layer": "edge", "attrs": map[string]any{
				"site": "plant", "attestation": "tpm", "default_credentials": false, "debug_interface": "adb", "debug_auth": true,
				"accelerator": true, "network_exposure": "private", "ota_signed": true}},
		},
		"edges": []any{
			map[string]any{"id": "e_spawn", "from": "n_soc", "to": "n_spawn", "kind": "calls", "auth": "agent_id", "encryption": "tls", "attrs": map[string]any{}},
		},
		"findings": []any{}, "evidence": []any{},
	}
}

func TestSchema13ModelValidates(t *testing.T) {
	t.Parallel()
	a, err := ValidateJSON(marshal(t, containment13()))
	require.NoError(t, err)
	assert.Equal(t, CurrentSchemaVersion, a.SchemaVersion)
	assert.Equal(t, "model_artifact", a.Node("n_weights").Type)
	assert.Equal(t, "id_oncall", a.Node("n_soc").Attrs["kill_switch_identity"])
	assert.Equal(t, "adb", a.Node("n_cam").Attrs["debug_interface"])
}

func TestSchema13Refuses(t *testing.T) {
	t.Parallel()
	nodeAttrs := func(m map[string]any, id string) map[string]any {
		for _, n := range m["nodes"].([]any) {
			if n.(map[string]any)["id"] == id {
				return n.(map[string]any)["attrs"].(map[string]any)
			}
		}
		t.Fatalf("no node %s", id)
		return nil
	}
	for _, tc := range []struct {
		name   string
		mutate func(m map[string]any)
		path   string
		msg    string
	}{
		{"kill switch held by the agent itself", func(m map[string]any) { nodeAttrs(m, "n_soc")["kill_switch_identity"] = "id_soc" },
			"/nodes/0/attrs/kill_switch_identity", "own identity_id"},
		{"kill switch held by an undeclared identity", func(m map[string]any) { nodeAttrs(m, "n_soc")["kill_switch_identity"] = "id_gone" },
			"/nodes/0/attrs/kill_switch_identity", "unknown identity"},
		{"negative instance bound", func(m map[string]any) { nodeAttrs(m, "n_soc")["max_instances"] = -1 }, "/nodes/0/attrs/max_instances", ""},
		{"unknown agent role", func(m map[string]any) { nodeAttrs(m, "n_soc")["agent_role"] = "red_team" }, "/nodes/0/attrs/agent_role", ""},
		{"unknown capability", func(m map[string]any) { nodeAttrs(m, "n_spawn")["capabilities"] = []any{"replicates"} }, "/nodes/1/attrs/capabilities/0", ""},
		{"unknown debug interface", func(m map[string]any) { nodeAttrs(m, "n_cam")["debug_interface"] = "bluetooth" }, "/nodes/3/attrs/debug_interface", ""},
		{"blast radius of zero", func(m map[string]any) { m["attrs"].(map[string]any)["max_blast_radius"] = 0 }, "/attrs/max_blast_radius", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := containment13()
			tc.mutate(m)
			_, err := ValidateJSON(marshal(t, m))
			var ve *ValidationError
			require.True(t, errors.As(err, &ve), "%v", err)
			paths := make([]string, 0, len(ve.Problems))
			found := false
			for _, p := range ve.Problems {
				paths = append(paths, p.Path)
				if p.Path == tc.path {
					found = true
					if tc.msg != "" {
						assert.Contains(t, p.Message, tc.msg)
					}
				}
			}
			assert.True(t, found, "want a problem at %s, got %v", tc.path, paths)
		})
	}
}

// TestSchema13Enums: the Go mirrors carry the 1.3 values the rules name.
func TestSchema13Enums(t *testing.T) {
	t.Parallel()
	assert.Contains(t, NodeTypes, "model_artifact")
	assert.Contains(t, GroupKinds, "isolation")
	for _, c := range SelfPropagationCapabilities {
		assert.Contains(t, Capabilities, c)
	}
	assert.Contains(t, Capabilities, "transfers_model_artifact")
	assert.Contains(t, AgentRoles, "security_operations")
	assert.Contains(t, DebugInterfaces, "adb")
}
