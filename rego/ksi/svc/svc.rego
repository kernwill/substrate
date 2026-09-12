# KSI-SVC: Service Configuration.
#
# results is FR-6.6's per-indicator status for every KSI-SVC indicator in
# input.indicators, decided purely from evidence coverage: an indicator's
# controls (input.indicators[name].controls, OSCAL-form control ID
# strings straight from the vendored dataset - see
# internal/backends/fedramp20x/input.go) are checked against
# evidenced_controls, the set of controls input.nodes actually names.
#
# This module makes no judgment about whether a given control's collected
# value is good or bad (FR-5.9's measurement/verdict split extends to this
# backend too, for now): a control counts as evidenced the moment any IR
# node names it, regardless of that node's own attributes. That is enough
# to classify an indicator as satisfied once every control it references
# has at least one such node - it is not enough, yet, to ever return
# not_satisfied, since that needs a per-control-type predicate over a
# node's actual attribute values (e.g. whether an
# s3_bucket_public_access_block's four flags are all true) that has not
# been authored for any control KSI-SVC references. Authoring those
# predicates is a separate, later increment; this module returns
# undetermined rather than guessing in the meantime, per CLAUDE.md's
# "never collapse undetermined into either satisfied or not_satisfied."
#
# Tested from internal/backends/fedramp20x's Go test suite (via OPA's Go
# SDK against this embedded module), not a colocated *_test.rego file -
# see evaluate_test.go.
package fedramp20x.ksi.svc

import rego.v1

results contains result if {
	some name, indicator in input.indicators
	count(indicator.controls) > 0
	missing := missing_controls(indicator)
	count(missing) == 0
	result := {
		"indicator": name,
		"status": "satisfied",
		"reason": sprintf("all %d referenced control(s) have IR evidence", [count(indicator.controls)]),
		"evidence": evidence_for(indicator),
	}
}

results contains result if {
	some name, indicator in input.indicators
	count(indicator.controls) > 0
	missing := missing_controls(indicator)
	count(missing) > 0
	count(missing) < count(indicator.controls)
	result := {
		"indicator": name,
		"status": "undetermined",
		"reason": sprintf("missing IR evidence for control(s): %v", [sort(missing)]),
		"remediation_hint": "add a frontend collector or IR mapping producing a node for the missing control(s)",
	}
}

results contains result if {
	some name, indicator in input.indicators
	count(indicator.controls) > 0
	missing := missing_controls(indicator)
	count(missing) == count(indicator.controls)
	result := {
		"indicator": name,
		"status": "undetermined",
		"reason": "no IR evidence collected for any control this indicator references",
		"remediation_hint": "add a frontend collector or IR mapping producing a node for at least one referenced control",
	}
}

results contains result if {
	some name, indicator in input.indicators
	count(indicator.controls) == 0
	result := {
		"indicator": name,
		"status": "not_applicable",
		"reason": "indicator has no associated controls in the vendored dataset",
	}
}

# evidenced_controls is every control ID string backed by at least one
# node in input.nodes (an ir.Node's Controls, rendered in OSCAL form - see
# input.go's buildInput).
evidenced_controls contains control if {
	some node in input.nodes
	some control in node.controls
}

missing_controls(indicator) := [c |
	some c in indicator.controls
	not c in evidenced_controls
]

# A set comprehension, not an array one: a node whose own controls
# overlap an indicator's controls on more than one control ID must still
# contribute its id to Evidence exactly once, not once per matching
# control. sort() dedupes-via-set and orders in one step.
evidence_for(indicator) := sort({id |
	some node in input.nodes
	some c in node.controls
	c in indicator.controls
	id := node.id
})
