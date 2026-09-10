package main

import (
	"encoding/json"
	"io"
)

// writeJSON encodes v to w as indented JSON without HTML-escaping "<",
// ">", or "&". json.Marshal/json.Encoder escape those by default (safe
// for embedding in <script> tags, which nothing in this CLI does), which
// would silently corrupt content this codebase needs verbatim - FedRAMP
// rule text (rulesdiff.go's JSON output) and Terraform attribute values
// (compile.go's) can both contain those characters legitimately.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
