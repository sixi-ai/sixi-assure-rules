// Package schema holds the machine-readable contract of the architecture model: the JSON Schema
// (2020-12) that `model.ValidateJSON` compiles. It defines the typed graph model validated by this package (docs/02).
package schema

import _ "embed"

// ModelSchema is the JSON Schema (2020-12) of the architecture model.
//
//go:embed model.schema.json
var ModelSchema []byte
