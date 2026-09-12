// Package rego embeds this directory's own Rego source into the substrate
// binary, so the compiled binary carries its rule modules with it rather
// than reading them from disk at runtime (NFR-1's single static binary,
// no runtime dependencies).
//
// This is a loader, not a policy: it holds no evaluation logic of its
// own. internal/backends/fedramp20x imports FS and runs the embedded
// modules through OPA.
package rego

import "embed"

//go:embed ksi
var FS embed.FS
