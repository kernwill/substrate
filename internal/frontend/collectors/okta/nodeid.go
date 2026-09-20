package okta

import (
	"fmt"

	"github.com/kernwill/substrate/internal/ir"
)

// oktaNodeID builds a stable ir.NodeID for one collected Okta fact,
// mirroring aws.awsNodeID's shape ("aws:%s:%s#%s") - collector names
// substrate's own name for the sub-collector (e.g.
// "mfa-enrollment-policy"), resource is the Okta object's own ID
// (opaque, but stable across collection runs), and aspect distinguishes
// more than one fact about the same resource, when a later collector
// needs it.
func oktaNodeID(collector, resource, aspect string) ir.NodeID {
	return ir.NodeID(fmt.Sprintf("okta:%s:%s#%s", collector, resource, aspect))
}
