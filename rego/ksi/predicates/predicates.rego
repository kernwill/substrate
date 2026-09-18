# Shared, control-keyed predicates: is a covered control's actual
# collected value good, not just present. This is the first module in
# the tree to make that kind of judgment (docs/adr/0007's coverage-only
# modules never do) - see docs/adr/0013 for why this judgment lives
# here, shared and reviewed once per control, rather than duplicated
# inside every family module that happens to reference the same
# control (KSI-IAM-APM, -ELP, and -JIT all reference ac-3 today; more
# families will as coverage grows).
#
# A family module never calls ac3_ok (or any future per-control
# predicate) directly. It calls failing_nodes with its own indicator's
# controls and the graph's nodes; a nonempty result means the indicator
# must be not_satisfied, full stop, regardless of how much of the
# indicator's other, unjudged controls remain uncollected -
# docs/adr/0013's propagation rule, and CLAUDE.md's "fail visible,
# never fail silent": a proven bad value is real, actionable
# information today, not something to withhold until every other
# control is also covered.
#
# Tracked concern (docs/adr/0013, docs/REQUIREMENTS.md section 31 item
# 9): because one predicate failure overrides an entire indicator's
# status regardless of how many of its other controls remain
# uncollected, a single misconfigured resource can flip a
# multi-control indicator like KSI-IAM-ELP (34 controls) to
# not_satisfied in a way a PR comment might read as a much bigger
# regression than "one bucket." The underlying signal is correct - see
# docs/adr/0013 - but the messaging may need work once this is visible
# in a real gate run.
package fedramp20x.ksi.predicates

import rego.v1

# judged_controls is every control ID (OSCAL form) this module has an
# authored predicate for. A family module must never treat a control as
# judged unless it appears here.
judged_controls := {"ac-3"}

# ac3_ok is true if node is a properly-configured
# s3_bucket_public_access_block: all four Block Public Access flags are
# the literal string "true". ir.Node.Attributes is a flat string map,
# never a JSON boolean (FR-5.9 - "store measurements, not verdicts"),
# so this compares against a string - see
# internal/frontend/terraform/ir.go's mapPublicAccessBlock and
# internal/frontend/collectors/aws/ir.go's mapBucketPublicAccessBlock,
# both of which use Go's strconv.FormatBool to produce these four
# values, Declared and Observed alike.
ac3_ok(node) if {
	node.kind == "s3_bucket_public_access_block"
	node.attributes.block_public_acls == "true"
	node.attributes.block_public_policy == "true"
	node.attributes.ignore_public_acls == "true"
	node.attributes.restrict_public_buckets == "true"
}

# failing(control, node) is true if node is evidence for control and
# fails this module's predicate for that control. Only meaningful for
# control IDs in judged_controls - failing_nodes is the safe aggregate
# a family module should actually call, since it already restricts to
# judged_controls itself.
failing(control, node) if {
	control == "ac-3"
	not ac3_ok(node)
}

# failing_nodes returns the IDs of every node in nodes that is evidence
# for a control in indicator_controls this module judges, and fails
# that control's predicate. indicator_controls is normally one
# indicator's own referenced controls (input.indicators[name].controls
# in a family module) - a nonempty result is that indicator's
# not_satisfied signal.
failing_nodes(indicator_controls, nodes) := sort({node.id |
	some node in nodes
	some control in node.controls
	control in indicator_controls
	control in judged_controls
	failing(control, node)
})
