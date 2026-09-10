package terraform

import (
	"fmt"
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
)

// ToIR converts g's resources into IR nodes and edges, using a small,
// explicit, human-reviewed table of which Terraform resource types
// evidence which NIST 800-53 controls - see this file's mapping
// functions for the reasoning behind each one. A resource type
// with no entry here (including a bare "aws_s3_bucket" with no
// encryption/versioning/access-block configuration attached) produces
// no node at all: this package never guesses a control family nobody
// has reviewed, resolving graph.go's TODO(mapping) the same way
// FR-2.3 already resolves "never guess" for attribute values.
//
// A mapping function decides only WHICH CONTROL a resource's
// configuration is ABOUT, never whether that configuration is
// correctly (or incorrectly) set - it records the actual attribute
// values found, verbatim, as the node's measurement (FR-5.9). Whether
// e.g. all four aws_s3_bucket_public_access_block flags being true
// counts as AC-3 being satisfied is a backend predicate over that
// measurement, not a judgment this package makes.
//
// Node IDs are prefixed "terraform:" so they stay unique when merged
// with another frontend source's nodes into one shared ir.Graph
// downstream (cmd/substrate/compile.go does exactly this).
func ToIR(g *ResourceGraph) (ir.Graph, error) {
	var out ir.Graph
	hasNode := make(map[ResourceAddress]bool, len(g.Resources))
	for _, r := range g.Resources {
		node, ok, err := mapResource(r)
		if err != nil {
			return ir.Graph{}, fmt.Errorf("terraform: map %s to IR: %w", r.Address, err)
		}
		if !ok {
			continue
		}
		out.Nodes = append(out.Nodes, node)
		hasNode[r.Address] = true
	}

	for _, r := range g.Resources {
		if !hasNode[r.Address] {
			continue
		}
		for _, ref := range r.References {
			if !hasNode[ref.Target] {
				// The referenced resource has no IR node of its own
				// (e.g. a bare aws_s3_bucket) - nothing to link to.
				continue
			}
			out.Edges = append(out.Edges, ir.Edge{
				From:          nodeID(r.Address),
				To:            nodeID(ref.Target),
				Relationship:  "configures",
				Provenance:    r.Provenance,
				SchemaVersion: ir.SchemaVersion,
			})
		}
	}
	return out, nil
}

func nodeID(addr ResourceAddress) ir.NodeID {
	return ir.NodeID("terraform:" + addr.String())
}

// mapResource returns the IR node r's configuration evidences, if any
// mapping entry matches its resource type.
func mapResource(r Resource) (ir.Node, bool, error) {
	switch r.Address.Type {
	case "aws_s3_bucket_versioning":
		return mapVersioning(r)
	case "aws_s3_bucket_server_side_encryption_configuration":
		return mapEncryption(r)
	case "aws_s3_bucket_public_access_block":
		return mapPublicAccessBlock(r)
	default:
		return ir.Node{}, false, nil
	}
}

// mapVersioning maps aws_s3_bucket_versioning to CP-9 (System Backup):
// enabling object versioning lets a prior version of an object be
// recovered after an accidental or malicious overwrite or delete,
// functioning as an object-level backup mechanism. The status value
// (Enabled, Suspended, or Disabled) is recorded verbatim; whether a
// given status counts as CP-9 being met is a backend predicate.
func mapVersioning(r Resource) (ir.Node, bool, error) {
	nested, ok := r.Attributes["versioning_configuration"].Value.(map[string]AttributeValue)
	if !ok {
		return ir.Node{}, false, nil
	}
	status, ok := attrString(nested["status"])
	if !ok {
		return ir.Node{}, false, nil
	}
	return ir.Node{
		ID:            nodeID(r.Address),
		ControlFamily: "CP",
		Controls:      []ir.Control{{Family: "CP", Base: 9}},
		Kind:          "s3_bucket_versioning",
		Attributes:    map[string]string{"status": status},
		Provenance:    r.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true, nil
}

// mapEncryption maps aws_s3_bucket_server_side_encryption_configuration
// to SC-28(1) (Protection of Information at Rest - Cryptographic
// Protection). Every valid sse_algorithm value (AES256, aws:kms,
// aws:kms:dsse) is a cryptographic mechanism, so - unlike versioning's
// status or the public access block's flags - this resource's mere
// presence with a resolved algorithm is sufficient; there is no "off"
// state to distinguish it from.
func mapEncryption(r Resource) (ir.Node, bool, error) {
	rule, ok := r.Attributes["rule"].Value.(map[string]AttributeValue)
	if !ok {
		return ir.Node{}, false, nil
	}
	def, ok := rule["apply_server_side_encryption_by_default"].Value.(map[string]AttributeValue)
	if !ok {
		return ir.Node{}, false, nil
	}
	algorithm, ok := attrString(def["sse_algorithm"])
	if !ok {
		return ir.Node{}, false, nil
	}
	return ir.Node{
		ID:            nodeID(r.Address),
		ControlFamily: "SC",
		Controls:      []ir.Control{{Family: "SC", Base: 28, Enhancement: 1}},
		Kind:          "s3_bucket_encryption",
		Attributes:    map[string]string{"sse_algorithm": algorithm},
		Provenance:    r.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true, nil
}

// mapPublicAccessBlock maps aws_s3_bucket_public_access_block to AC-3
// (Access Enforcement). Unlike encryption, this resource genuinely can
// represent "off" (all four flags false, meaning public access stays
// permitted) as well as "on" - each flag's actual boolean value is
// recorded verbatim; whether a given combination counts as AC-3 being
// satisfied is a backend predicate, not this package's call.
func mapPublicAccessBlock(r Resource) (ir.Node, bool, error) {
	attrs := make(map[string]string, 4)
	for _, name := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
		s, ok := attrString(r.Attributes[name])
		if !ok {
			continue
		}
		attrs[name] = s
	}
	if len(attrs) == 0 {
		return ir.Node{}, false, nil
	}
	return ir.Node{
		ID:            nodeID(r.Address),
		ControlFamily: "AC",
		Controls:      []ir.Control{{Family: "AC", Base: 3}},
		Kind:          "s3_bucket_public_access_block",
		Attributes:    attrs,
		Provenance:    r.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true, nil
}

// attrString renders a resolved AttributeValue as the flat string
// ir.Node.Attributes requires (FR-5.9's "measurements, not verdicts" -
// see Node's own doc comment for why even a numeric measurement is
// stored as a string). An Unresolved or nil-valued attribute has
// nothing to measure, so it's simply absent from the result rather
// than represented some other way.
func attrString(v AttributeValue) (string, bool) {
	if v.Unresolved != "" || v.Value == nil {
		return "", false
	}
	switch val := v.Value.(type) {
	case string:
		return val, true
	case bool:
		return strconv.FormatBool(val), true
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64), true
	default:
		return "", false
	}
}
