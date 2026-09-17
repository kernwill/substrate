package aws

import (
	"fmt"
	"strconv"

	"github.com/kernwill/substrate/internal/frontend/controls"
	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// ToIR converts g's buckets into IR nodes, reusing exactly the two
// control assignments internal/frontend/terraform/ir.go's mapEncryption
// and mapPublicAccessBlock already carry for the identical Declared
// measurements (controls.S3Encryption, controls.S3PublicAccessBlock) -
// this is the Observed half of the same two facts, not a new mapping
// decision, and both frontends reference the exact same ir.Control
// values rather than each carrying their own copy (see
// internal/frontend/controls's own doc comment for why that distinction
// matters). A bucket whose Encryption or PublicAccessBlock could not be
// resolved (Provenance.Confidence != Deterministic - see this package's
// s3.go for why an API error there is never treated as a negative
// measurement) produces no node for that field, the same "never guess"
// treatment an unmapped Terraform resource gets.
//
// Bucket.Logging is deliberately NOT mapped here yet. Unlike encryption
// and public access block, there is no already-reviewed control
// assignment to reuse for server access logging - it belongs somewhere
// in the AU (Audit and Accountability) family, but which specific
// control is a real compliance-content decision this file isn't making
// unreviewed. Collecting it now and mapping it later, once that's
// decided, costs nothing; guessing a control family today would be
// exactly the kind of unreviewed judgment CLAUDE.md's compliance-content
// discipline exists to prevent.
func ToIR(g *S3Graph) (ir.Graph, error) {
	var out ir.Graph
	for _, b := range g.Buckets {
		if node, ok := mapBucketEncryption(b); ok {
			out.Nodes = append(out.Nodes, node)
		}
		if node, ok := mapBucketPublicAccessBlock(b); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// awsNodeID builds the "aws:<service>:<resource>#<aspect>" IR node ID
// every collector in this package uses, so the ID grammar lives in one
// place rather than being re-spelled per service (s3.go's buckets,
// iam.go's users, and whatever comes next) - the same
// one-definition-only reasoning internal/frontend/controls applies to
// control assignments.
func awsNodeID(service, resource, aspect string) ir.NodeID {
	return ir.NodeID(fmt.Sprintf("aws:%s:%s#%s", service, resource, aspect))
}

func nodeID(bucket, suffix string) ir.NodeID {
	return awsNodeID("s3", bucket, suffix)
}

// mapBucketEncryption maps b's Observed encryption algorithm to
// controls.S3Encryption, mirroring
// internal/frontend/terraform/ir.go's mapEncryption exactly - same
// control, same "presence with a resolved algorithm is sufficient"
// reasoning (there is no "off" state to distinguish an algorithm from).
func mapBucketEncryption(b Bucket) (ir.Node, bool) {
	if b.Encryption == nil || b.Encryption.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}
	return ir.Node{
		ID:            nodeID(b.Name, "encryption"),
		ControlFamily: controls.S3Encryption.Family,
		Controls:      []ir.Control{controls.S3Encryption},
		Kind:          "s3_bucket_encryption",
		Attributes:    map[string]string{"sse_algorithm": b.Encryption.Algorithm},
		Provenance:    b.Encryption.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}

// mapBucketPublicAccessBlock maps b's Observed Block Public Access flags
// to controls.S3PublicAccessBlock, mirroring
// internal/frontend/terraform/ir.go's mapPublicAccessBlock exactly - same
// control, same verbatim four-flag recording. Whether a given
// combination counts as AC-3 being satisfied remains a backend predicate
// (FR-5.9), not this mapper's call.
func mapBucketPublicAccessBlock(b Bucket) (ir.Node, bool) {
	if b.PublicAccessBlock == nil || b.PublicAccessBlock.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}
	pab := b.PublicAccessBlock
	return ir.Node{
		ID:            nodeID(b.Name, "public-access-block"),
		ControlFamily: controls.S3PublicAccessBlock.Family,
		Controls:      []ir.Control{controls.S3PublicAccessBlock},
		Kind:          "s3_bucket_public_access_block",
		Attributes: map[string]string{
			"block_public_acls":       strconv.FormatBool(pab.BlockPublicACLs),
			"block_public_policy":     strconv.FormatBool(pab.BlockPublicPolicy),
			"ignore_public_acls":      strconv.FormatBool(pab.IgnorePublicACLs),
			"restrict_public_buckets": strconv.FormatBool(pab.RestrictPublicBuckets),
		},
		Provenance:    pab.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
