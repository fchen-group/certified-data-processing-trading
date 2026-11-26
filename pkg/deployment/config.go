// Package deployment embeds the node trust anchor into the measured executable.
package deployment

import _ "embed"

//go:embed runtime.json
var Runtime []byte
