# KSI-IAM: Identity and Access Management.
#
# results is FR-6.6's per-indicator status for every KSI-IAM indicator
# in input.indicators. Coverage-only checking (does the graph contain a
# node naming each referenced control) is rego/ksi/svc/svc.rego's
# original discipline (docs/adr/0007); this module additionally
# consults rego/ksi/predicates for controls that module has an authored
# "is this covered control's value actually good" check for (ac-3
# today) - docs/adr/0013 records why that judgment lives in a shared
# module rather than duplicated here, and the exact propagation rule
# below.
#
# Propagation, in priority order:
#   1. Any control this indicator references, with evidence, that
#      fails predicates.failing_nodes -> not_satisfied, regardless of
#      how many of the indicator's other controls remain uncollected
#      (docs/adr/0013 - a proven bad value is real information today,
#      not something to withhold pending full coverage. Tracked
#      concern: this means one bad resource can flip a whole
#      multi-control indicator's status - see docs/adr/0013's own
#      "Open" section).
#   2. Otherwise, every referenced control has evidence -> satisfied.
#   3. Otherwise, some but not all do -> undetermined, naming the
#      missing ones.
#   4. Otherwise, none do -> undetermined, "no evidence at all."
#   5. Zero referenced controls -> not_applicable.
#
# Three of KSI-IAM's six indicators (KSI-IAM-APM, KSI-IAM-ELP,
# KSI-IAM-JIT) reference ac-3, the one control predicates.rego judges
# today, alongside our other evidenced controls (AC-6, CM-7, IA-2,
# IA-5). The other three (AAM, SNU, SUS) still get the plain
# no-evidence-at-all outcome.
#
# Tested from internal/backends/fedramp20x's Go test suite (via OPA's Go
# SDK against this embedded module), not a colocated *_test.rego file -
# see evaluate_test.go.
package fedramp20x.ksi.iam

import data.fedramp20x.ksi.predicates
import rego.v1

results contains result if {
	some name, indicator in input.indicators
	count(indicator.controls) > 0
	failing := predicates.failing_nodes(indicator.controls, input.nodes)
	count(failing) > 0
	result := {
		"indicator": name,
		"status": "not_satisfied",
		"reason": sprintf("control(s) evidenced with a value that fails this indicator's predicate: %v", [failing]),
		"evidence": failing,
	}
}

results contains result if {
	some name, indicator in input.indicators
	count(indicator.controls) > 0
	count(predicates.failing_nodes(indicator.controls, input.nodes)) == 0
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
	count(predicates.failing_nodes(indicator.controls, input.nodes)) == 0
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
	count(predicates.failing_nodes(indicator.controls, input.nodes)) == 0
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
# node in input.nodes (an ir.Node's Controls, rendered in OSCAL form -
# see input.go's buildInput).
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
