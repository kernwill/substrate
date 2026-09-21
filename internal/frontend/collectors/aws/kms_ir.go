package aws

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// kmsKeyManagement is the control assignment for a customer-managed KMS
// key's rotation status: base SC-12 (Cryptographic Key Establishment
// and Management), not an enhancement. Confirmed against the vendored
// FedRAMP dataset (internal/rules/data/fedramp-consolidated-rules.json)
// before proposing: sc-12 is cited by KSI-SVC-ASM ("Automating Secret
// Management" - "management, protection, and regular rotation of
// digital keys... is automated and persistently reviewed"), close to a
// verbatim description of what this collector evidences. Base, not an
// enhancement: this collector resolves only whether rotation is
// enabled, not key policy content (FR-3.3's separate, deferred half) -
// the same "don't claim more than the collected fact supports"
// discipline every prior collector's control choice in this package
// follows. Proposed and approved 2026-09-21 alongside this collector's
// first implementation.
var kmsKeyManagement = ir.Control{Family: "SC", Base: 12}

// KMSToIR converts g's keys into IR nodes, one per key whose rotation
// status actually resolved. A key whose rotation status could not be
// resolved (Provenance.Confidence != Deterministic - see buildKey's own
// doc comment on why that's genuinely ambiguous, not guessed at)
// produces no node - the same "never guess" treatment every other
// mapper in this codebase applies.
func KMSToIR(g *KMSGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, k := range g.Keys {
		if node, ok := mapKey(k); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapKey records k's rotation status verbatim (FR-5.9's
// measurement-not-verdict split: this mapper records whether rotation
// is enabled, never whether that's sufficient - a customer's own key
// rotation policy is out of this collector's scope to judge).
func mapKey(k Key) (ir.Node, bool) {
	if k.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	return ir.Node{
		ID:            awsNodeID("kms-key", k.KeyID, "rotation"),
		ControlFamily: kmsKeyManagement.Family,
		Controls:      []ir.Control{kmsKeyManagement},
		Kind:          "aws_kms_key_rotation",
		Attributes: map[string]string{
			"key_state":        k.KeyState,
			"rotation_enabled": strconv.FormatBool(k.RotationEnabled),
		},
		Provenance:    k.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
