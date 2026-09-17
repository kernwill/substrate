package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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

// readArtifact reads and decodes the JSON object at path into a *T -
// writeArtifact's read-side counterpart, used by compile.go's --runtime
// ingestion to read collect.go's own aws_s3.json/aws_iam.json output
// back in. A missing or malformed file fails loudly here rather than
// being treated as "nothing collected": --runtime is only ever passed
// when the caller expects real Observed evidence to be there.
func readArtifact[T any](path string) (*T, error) {
	// os.Open's own *PathError already renders as "open <path>: <cause>"
	// - no extra "open %s: %w" wrapper here, which would otherwise
	// double up on both the verb and the path in the final message.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var v T
	if err := json.NewDecoder(f).Decode(&v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &v, nil
}
