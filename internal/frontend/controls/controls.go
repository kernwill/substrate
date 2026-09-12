// Package controls holds control assignments shared by more than one
// frontend collector, so two collectors that evidence the same
// underlying fact - one Declared (static config), one Observed (a live
// API read) - reference the exact same reviewed ir.Control value rather
// than each carrying its own copy of the same literal.
//
// A duplicated literal is a real risk here, not a style nitpick: control
// assignments require explicit review (CLAUDE.md's compliance-content
// discipline), and a future correction applied to one copy with no
// compiler-enforced link to the other would silently leave the Declared
// and Observed halves of one fact mapped to two different controls with
// no error anywhere. This package exists so "the same fact, two
// collectors" has exactly one place to correct.
//
// A control used by only one collector belongs in that collector's own
// ir.go as a local value, not here - this package is for reuse that
// actually exists, not anticipated reuse.
package controls

import "github.com/kernwill/substrate/internal/ir"

// S3Encryption is the control assignment for an S3 bucket's default
// server-side encryption algorithm being present and resolved (SC-28(1)):
// there is no "off" state to distinguish an algorithm from, so presence
// with a resolved value is itself sufficient evidence. Shared by
// internal/frontend/terraform's mapEncryption (Declared, from
// aws_s3_bucket_server_side_encryption_configuration) and
// internal/frontend/collectors/aws's mapBucketEncryption (Observed, from
// GetBucketEncryption).
var S3Encryption = ir.Control{Family: "SC", Base: 28, Enhancement: 1}

// S3PublicAccessBlock is the control assignment for an S3 bucket's four
// Block Public Access flags (AC-3). Unlike S3Encryption, this control
// genuinely has an "off" state (all four flags false) as well as an
// "on" one - each flag's actual value is recorded verbatim; whether a
// given combination counts as AC-3 being satisfied is a backend
// predicate, not either mapper's call. Shared by
// internal/frontend/terraform's mapPublicAccessBlock (Declared, from
// aws_s3_bucket_public_access_block) and
// internal/frontend/collectors/aws's mapBucketPublicAccessBlock
// (Observed, from GetPublicAccessBlock).
var S3PublicAccessBlock = ir.Control{Family: "AC", Base: 3}
