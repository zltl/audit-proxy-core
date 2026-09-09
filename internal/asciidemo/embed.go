package asciidemo

import _ "embed"

// DemoCast is the pre-generated asciicast used by the Web live drip and download.
//
//go:embed demo.cast
var DemoCast []byte
