// Package schema holds the machine-readable contract of the architecture model: the JSON Schema
// (2020-12) that `model.ValidateJSON` compiles. The file is copied unchanged from the Sixi Assure
// product repository, where the typed graph model is specified (docs/02).
package schema

import _ "embed"

// ModelSchema is the JSON Schema (2020-12) of the architecture model.
//
//go:embed model.schema.json
var ModelSchema []byte

// ModelSchemaV10 is the published 1.0 schema, still served at its version (ADR-040 §2).
//
//go:embed model-1.0.schema.json
var ModelSchemaV10 []byte
