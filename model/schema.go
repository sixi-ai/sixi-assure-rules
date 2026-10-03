package model

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/sixi-ai/sixi-assure-rules/model/migrate"
	modelschema "github.com/sixi-ai/sixi-assure-rules/schema"
	"github.com/sixi-ai/sixi-assure-rules/schema/schemas"
)

// CurrentSchemaVersion is the model schema version this build reads, writes and evaluates
// (ADR-040 §1, docs/02 §Versions). Every model is upgraded to it on read and saved at it.
const CurrentSchemaVersion = migrate.Current

// schemaIDPrefix and schemaIDFile frame the published URL of a schema version (ADR-040 §2).
const (
	schemaIDPrefix = "https://schema.sixi.ai/model/"
	schemaIDFile   = "/model.schema.json"
)

// LegacySchemaID is the `$id` the schema carried before it was versioned. The file it named is
// the 1.0 schema without the `schema_version` member (the identity migration is all that separates
// the two), so it stays an alias of 1.0 for anyone who stored the old URL.
const LegacySchemaID = "https://sixi.ai/schemas/model.schema.json"

// publishedSchemas are the schema files this build serves, by version (ADR-040 §2): the current
// one (the file the server validates with) and every earlier published version, byte for byte as
// it was served. An earlier version's file is documentation for clients that still name it: a
// model at that version is upgraded on read (model/migrate), never validated against it.
var publishedSchemas = map[string][]byte{
	CurrentSchemaVersion: modelschema.ModelSchema,
	"1.0":                modelschema.ModelSchemaV10,
	"1.1":                schemas.ModelV11,
}

// PublishedSchemaVersions lists the versions SchemaDocument serves, oldest first.
func PublishedSchemaVersions() []string {
	out := make([]string, 0, len(publishedSchemas))
	for v := range publishedSchemas {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b string) int {
		var am, an, bm, bn int
		_, _ = fmt.Sscanf(a, "%d.%d", &am, &an)
		_, _ = fmt.Sscanf(b, "%d.%d", &bm, &bn)
		return cmp.Or(cmp.Compare(am, bm), cmp.Compare(an, bn))
	})
	return out
}

// SchemaID is the published `$id` of the schema at a version:
// https://schema.sixi.ai/model/<version>/model.schema.json.
func SchemaID(version string) string { return schemaIDPrefix + version + schemaIDFile }

// SchemaVersionOfID names the schema version a `$id` identifies, the legacy alias included; false
// for an id this build does not publish.
func SchemaVersionOfID(id string) (string, bool) {
	if id == LegacySchemaID {
		return "1.0", true
	}
	for v := range publishedSchemas {
		if id == SchemaID(v) {
			return v, true
		}
	}
	return "", false
}

// SchemaDocument returns the JSON Schema file of a published version byte for byte (for the current
// version, the file the server validates with), and false for a version this build does not serve:
// 0.9 was never published (it is "no schema_version"), and a version newer than this build is
// unknown to it.
func SchemaDocument(version string) ([]byte, bool) {
	b, ok := publishedSchemas[version]
	return b, ok
}
