package githubactions

import (
	"fmt"
	"sort"

	"github.com/kernwill/substrate/internal/ir"
)

// dependencyReviewAction is the action mapPermissions's sibling mapper
// looks for in every job step, regardless of the job's own name -
// matching by which action runs, not by convention over job naming.
const dependencyReviewAction = "actions/dependency-review-action"

// ToIR converts g's workflows into IR nodes, using a small, explicit,
// human-reviewed table of which workflow fields evidence which NIST
// 800-53 controls - see mapPermissions and mapDependencyReview for the
// reasoning behind each one. A workflow with neither an explicit
// permissions block nor a dependency-review step produces no node -
// this package never guesses a control family nobody has reviewed, the
// same principle internal/frontend/terraform's and
// internal/frontend/kubernetes's ir.go apply.
//
// There are no edges: a workflow file has no cross-file references for
// this package to model.
func ToIR(g *WorkflowGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, w := range g.Workflows {
		if node, ok := mapPermissions(w); ok {
			out.Nodes = append(out.Nodes, node)
		}
		out.Nodes = append(out.Nodes, mapDependencyReview(w)...)
	}
	return out, nil
}

func nodeID(addr WorkflowAddress, suffix string) ir.NodeID {
	return ir.NodeID(fmt.Sprintf("github_actions:%s#%s", addr.String(), suffix))
}

// mapPermissions maps a workflow's top-level "permissions" block to
// AC-6 (Least Privilege): declaring it scopes the GITHUB_TOKEN's access
// down from its account/organization default. The actual granted
// scopes are recorded verbatim (e.g. "contents": "read") - whether a
// given set of scopes counts as sufficiently least-privileged is a
// backend predicate, not this package's call (FR-5.9). A workflow with
// no explicit permissions block at all - relying on whatever default the
// account or organization has configured - has nothing declared to
// measure, so it produces no node, the same treatment an unmapped
// Terraform or Kubernetes resource gets.
//
// An explicit but empty block ("permissions: {}") is different: GitHub
// documents that shape as explicitly setting every scope to no access,
// its own strictest possible declaration - not an absence of one. This
// mapper distinguishes the two by checking the key's presence in
// w.Attributes before the type assertion, rather than folding "map
// present but empty" into the same "nothing to measure" case as "no map
// at all" (an earlier version did exactly that, silently discarding the
// one workflow shape that most directly evidences AC-6).
func mapPermissions(w Workflow) (ir.Node, bool) {
	raw, exists := w.Attributes["permissions"]
	if !exists {
		return ir.Node{}, false
	}
	perms, ok := raw.(map[string]any)
	if !ok {
		// A shorthand string form ("permissions: read-all" or
		// "write-all") isn't the scope-map shape this mapper models;
		// left unmapped rather than guessed at, same as no permissions
		// block at all.
		return ir.Node{}, false
	}
	attrs := make(map[string]string, len(perms))
	for scope, level := range perms {
		s, ok := level.(string)
		if !ok {
			continue
		}
		attrs[scope] = s
	}
	return ir.Node{
		ID:            nodeID(w.Address, "permissions"),
		ControlFamily: "AC",
		Controls:      []ir.Control{{Family: "AC", Base: 6}},
		Kind:          "workflow_token_permissions",
		Attributes:    attrs,
		Provenance:    w.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}

// mapDependencyReview maps any job step using
// actions/dependency-review-action to SR-11 (Component Authenticity),
// matching the crosswalk analysis' own row 42 citation for supply-chain
// component scanning. One node per matching job, since a workflow can
// declare more than one.
//
// jobNames is sorted before iterating: "jobs" decodes to a Go map, whose
// iteration order is randomized per run, and a workflow with two or
// more matching jobs would otherwise produce this function's own output
// slice in a different order on different runs - the same class of
// non-reproducibility bug docs/adr/0006 found and fixed for Provenance
// timestamps, caught here before it ever reached a golden fixture.
func mapDependencyReview(w Workflow) []ir.Node {
	jobs, ok := w.Attributes["jobs"].(map[string]any)
	if !ok {
		return nil
	}
	jobNames := make([]string, 0, len(jobs))
	for name := range jobs {
		jobNames = append(jobNames, name)
	}
	sort.Strings(jobNames)

	var nodes []ir.Node
	for _, jobName := range jobNames {
		job, ok := jobs[jobName].(map[string]any)
		if !ok {
			continue
		}
		steps, ok := job["steps"].([]any)
		if !ok {
			continue
		}
		for _, s := range steps {
			step, ok := s.(map[string]any)
			if !ok {
				continue
			}
			uses, ok := step["uses"].(string)
			if !ok || !usesAction(uses, dependencyReviewAction) {
				continue
			}
			nodes = append(nodes, ir.Node{
				ID:            nodeID(w.Address, "dependency-review["+jobName+"]"),
				ControlFamily: "SR",
				Controls:      []ir.Control{{Family: "SR", Base: 11}},
				Kind:          "dependency_review",
				Attributes:    map[string]string{"job": jobName, "uses": uses},
				Provenance:    w.Provenance,
				SchemaVersion: ir.SchemaVersion,
			})
			break // one node per job is enough even if used in multiple steps
		}
	}
	return nodes
}

// usesAction reports whether uses (a step's "uses:" value, e.g.
// "actions/dependency-review-action@v4") runs action, ignoring the
// "@version" suffix.
func usesAction(uses, action string) bool {
	for i := 0; i < len(uses); i++ {
		if uses[i] == '@' {
			return uses[:i] == action
		}
	}
	return uses == action
}
