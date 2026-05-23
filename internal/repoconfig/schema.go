package repoconfig

import _ "embed"

//go:embed hibou-config.schema.json
var schemaBytes []byte

func SchemaBytes() []byte {
	return append([]byte(nil), schemaBytes...)
}
