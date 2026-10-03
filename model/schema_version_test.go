package model

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	modelschema "github.com/sixi-ai/sixi-assure-rules/schema"
	"github.com/sixi-ai/sixi-assure-rules/schema/schemas"
)

// Schema versioning (ADR-040 §1, §2; docs/02 §Versions).

func TestSchemaFileNamesTheCurrentVersion(t *testing.T) {
	t.Parallel()
	var doc struct {
		ID         string   `json:"$id"`
		Required   []string `json:"required"`
		Properties map[string]struct {
			Type  string `json:"type"`
			Const string `json:"const"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(modelschema.ModelSchema, &doc))
	assert.Equal(t, "https://schema.sixi.ai/model/1.2/model.schema.json", doc.ID)
	assert.Equal(t, SchemaID(CurrentSchemaVersion), doc.ID, "the file's $id is the published URL of the current version")
	sv, ok := doc.Properties["schema_version"]
	require.True(t, ok, "schema_version is a root member")
	assert.Equal(t, "string", sv.Type)
	assert.Equal(t, CurrentSchemaVersion, sv.Const, "the schema file describes the current version only")
	assert.NotContains(t, doc.Required, "schema_version", "optional on input: absent means 0.9")

	// The published 1.0 file stays as it was served (ADR-040 §2): its own $id and const.
	var v10 struct {
		ID         string `json:"$id"`
		Properties map[string]struct {
			Const string `json:"const"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(modelschema.ModelSchemaV10, &v10))
	assert.Equal(t, "https://schema.sixi.ai/model/1.0/model.schema.json", v10.ID)
	assert.Equal(t, "1.0", v10.Properties["schema_version"].Const)
	assert.NotContains(t, v10.Properties, "identities", "the 1.0 file is the one 1.0 published, not a copy of 1.1")

	// The published 1.1 file stays as it was served too: its own $id and const, without the 1.2
	// framework vocabulary (ADR-093 M1).
	var v11 struct {
		ID         string `json:"$id"`
		Properties map[string]struct {
			Const string `json:"const"`
		} `json:"properties"`
		Defs struct {
			GroupKind struct {
				Enum []string `json:"enum"`
			} `json:"groupKind"`
			NodeAttrs struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"nodeAttrs"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(schemas.ModelV11, &v11))
	assert.Equal(t, "https://schema.sixi.ai/model/1.1/model.schema.json", v11.ID)
	assert.Equal(t, "1.1", v11.Properties["schema_version"].Const)
	assert.Contains(t, v11.Properties, "identities")
	assert.NotContains(t, v11.Defs.GroupKind.Enum, "workflow", "the 1.1 file is the one 1.1 published, not a copy of 1.2")
	assert.NotContains(t, v11.Defs.NodeAttrs.Properties, "framework")
}

func TestSchemaIDsAndDocuments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		id   string
		want string
		ok   bool
	}{
		{"https://schema.sixi.ai/model/1.0/model.schema.json", "1.0", true},
		{"https://sixi.ai/schemas/model.schema.json", "1.0", true}, // the pre-1.0 id, an alias of 1.0
		{"https://schema.sixi.ai/model/1.1/model.schema.json", "1.1", true},
		{"https://schema.sixi.ai/model/1.2/model.schema.json", "1.2", true},
		{"https://schema.sixi.ai/model/0.9/model.schema.json", "", false},
		{"https://schema.sixi.ai/model/1.3/model.schema.json", "", false},
		{"", "", false},
	} {
		got, ok := SchemaVersionOfID(tc.id)
		assert.Equal(t, tc.ok, ok, tc.id)
		assert.Equal(t, tc.want, got, tc.id)
	}
	b, ok := SchemaDocument(CurrentSchemaVersion)
	require.True(t, ok)
	assert.Equal(t, modelschema.ModelSchema, b, "served byte for byte as validated")
	b, ok = SchemaDocument("1.0")
	require.True(t, ok)
	assert.Equal(t, modelschema.ModelSchemaV10, b, "the 1.0 file is still served")
	b, ok = SchemaDocument("1.1")
	require.True(t, ok)
	assert.Equal(t, schemas.ModelV11, b, "the 1.1 file is still served")
	assert.NotEqual(t, modelschema.ModelSchema, b, "not the current file")
	assert.Equal(t, []string{"1.0", "1.1", "1.2"}, PublishedSchemaVersions())
	for _, v := range PublishedSchemaVersions() {
		doc, ok := SchemaDocument(v)
		require.True(t, ok, v)
		var head struct {
			ID string `json:"$id"`
		}
		require.NoError(t, json.Unmarshal(doc, &head))
		assert.Equal(t, SchemaID(v), head.ID, "the file served at %s carries its own $id", v)
	}
	for _, v := range []string{"0.9", "1.3", "2.0", "", "latest"} {
		_, ok := SchemaDocument(v)
		assert.False(t, ok, v)
	}
}

func TestValidateJSONUpgradesOnRead(t *testing.T) {
	t.Parallel()
	golden := string(loadGolden(t, "rag-chatbot-bad.json"))
	current := `"schema_version": "` + CurrentSchemaVersion + `"`
	without := strings.Replace(golden, current+",", "", 1)
	require.NotEqual(t, golden, without, "the golden model carries schema_version")
	with := func(v string) string {
		return strings.Replace(golden, current, `"schema_version": `+v, 1)
	}
	for _, tc := range []struct {
		name string
		raw  string
		path string // ValidationError path; empty means valid
	}{
		{"current", golden, ""},
		{"absent means 0.9 and upgrades", without, ""},
		{"explicit 0.9 upgrades", with(`"0.9"`), ""},
		{"explicit 1.0 upgrades", with(`"1.0"`), ""},
		{"explicit 1.1 upgrades", with(`"1.1"`), ""},
		{"newer is refused", with(`"1.3"`), "/schema_version"},
		{"unknown older is refused", with(`"0.1"`), "/schema_version"},
		{"free text is refused", with(`"one"`), "/schema_version"},
		{"a number is refused", with(`1.0`), "/schema_version"},
		{"not an object", `["nodes"]`, "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := ValidateJSON([]byte(tc.raw))
			if tc.path != "" {
				var ve *ValidationError
				require.True(t, errors.As(err, &ve), "%v", err)
				require.NotEmpty(t, ve.Problems)
				assert.Equal(t, tc.path, ve.Problems[0].Path)
				assert.NotContains(t, err.Error(), "one", "a malformed version is not echoed")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, CurrentSchemaVersion, a.SchemaVersion, "rules, exports and the SPA see the current version only")
		})
	}
}

func TestGoValuesAreAtTheCurrentVersion(t *testing.T) {
	t.Parallel()
	assert.Equal(t, CurrentSchemaVersion, Empty("arch_x", "t", "x").SchemaVersion)

	built := &Architecture{ID: "arch_x", TenantID: "t", Name: "x"}
	require.NoError(t, Validate(built))
	assert.Equal(t, CurrentSchemaVersion, built.SchemaVersion, "Validate writes the version a builder left empty")

	stale := Empty("arch_x", "t", "x")
	stale.SchemaVersion = "0.9"
	err := Validate(stale)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, "/schema_version", ve.Problems[0].Path, "a decoded value at another version was never upgraded")
}

func TestHashIncludesTheSchemaVersion(t *testing.T) {
	t.Parallel()
	a, err := ValidateJSON(loadGolden(t, "rag-chatbot-bad.json"))
	require.NoError(t, err)
	canon, err := Canonical(a)
	require.NoError(t, err)
	assert.Contains(t, string(canon), `"schema_version":"`+CurrentSchemaVersion+`"`)

	h, err := Hash(a)
	require.NoError(t, err)
	unset, err := a.Clone()
	require.NoError(t, err)
	unset.SchemaVersion = ""
	hUnset, err := Hash(unset)
	require.NoError(t, err)
	assert.Equal(t, h, hUnset, "a Go value that left the field empty hashes at the current version")

	other, err := a.Clone()
	require.NoError(t, err)
	other.SchemaVersion = "9.9"
	hOther, err := Hash(other)
	require.NoError(t, err)
	assert.NotEqual(t, h, hOther, "the version is inside the hash")
}
