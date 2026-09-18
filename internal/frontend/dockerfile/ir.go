package dockerfile

import (
	"fmt"
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// baseImageAuthenticity is the control assignment for whether a FROM
// instruction's external base image is pinned to an immutable digest:
// base SR-11 (Component Authenticity). The same control
// internal/frontend/githubactions' mapDependencyReview already assigns
// to a workflow's use of actions/dependency-review-action - both facts
// are "can this externally-sourced component's identity be verified,"
// just for a different kind of component (a container base image here,
// a declared dependency there). Deliberately NOT moved into the shared
// internal/frontend/controls package: that package is for the SAME
// underlying fact evidenced by two Bases (see its own doc comment,
// e.g. S3Encryption's Declared/Observed pair) - this is a genuinely
// different fact that happens to land on the same control, not a
// second Basis for an already-reviewed one, so it stays local here the
// same way iamUserMFA/iamUserAccessKeys stay local to
// internal/frontend/collectors/aws/iam_ir.go.
//
// Base control, no enhancement: the vendored dataset's SR-11 guidance
// does not split further in any way a single pinned/unpinned boolean
// could support.
var baseImageAuthenticity = ir.Control{Family: "SR", Base: 11}

// ToIR converts g's stages into IR nodes: whether each stage's external
// base image is pinned to a digest, mapped to baseImageAuthenticity. A
// stage that is not an external component at all (BaseImageScratch,
// BaseImageLocalStage - see this package's doc comment) or whose image
// reference could not be resolved (Provenance.Confidence !=
// Deterministic) produces no node, the same "never guess, and don't
// assert a control that doesn't apply" treatment every other mapper in
// this codebase applies.
func ToIR(g *DockerfileGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, s := range g.Stages {
		if node, ok := mapBaseImageAuthenticity(s); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

func nodeID(addr StageAddress) ir.NodeID {
	return ir.NodeID(fmt.Sprintf("dockerfile:%s", addr.String()))
}

// mapBaseImageAuthenticity records whether s's external base image is
// pinned to an immutable digest. pinned_to_digest is the authoritative
// signal - a tag's presence or absence (including the implicit
// ":latest" Docker itself assumes when neither tag nor digest is given)
// is recorded for context but is NOT what this control measures: a tag
// is a mutable pointer that can be re-pushed to point at a different
// image entirely, so only a digest reference is genuinely immutable and
// verifiable. Whether a given repository/tag combination is otherwise
// "trustworthy" is a backend predicate (FR-5.9), not this mapper's call.
func mapBaseImageAuthenticity(s Stage) (ir.Node, bool) {
	if s.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}
	if s.Image.Kind != BaseImageExternal {
		return ir.Node{}, false
	}
	attrs := map[string]string{
		"repository":       s.Image.Repository,
		"pinned_to_digest": strconv.FormatBool(s.Image.Digest != ""),
	}
	if s.Image.Tag != "" {
		attrs["tag"] = s.Image.Tag
	}
	if s.Image.Digest != "" {
		attrs["digest"] = s.Image.Digest
	}
	return ir.Node{
		ID:            nodeID(s.Address),
		ControlFamily: baseImageAuthenticity.Family,
		Controls:      []ir.Control{baseImageAuthenticity},
		Kind:          "dockerfile_base_image",
		Attributes:    attrs,
		Provenance:    s.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
