// Package schemas holds the model schema files of earlier published versions, each byte for byte as
// it was served (ADR-040 §2, docs/02 §Versions). The 1.0 file is embedded by package api, where it
// was first published; every later one is embedded here, beside the file.
package schemas

import _ "embed"

// ModelV11 is the published schema of model version 1.1, kept byte for byte as it was served:
// GET /schema/model/1.1 still answers with it after 1.2 became current. A 1.1 model is upgraded on
// read and never validated against this file.
//
//go:embed model-1.1.schema.json
var ModelV11 []byte
