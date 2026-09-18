# KSI-IAM: Identity and Access Management.
#
# Same discipline as rego/ksi/svc/svc.rego (docs/adr/0007), applied to a
# second family: results is FR-6.6's per-indicator status for every
# KSI-IAM indicator in input.indicators, decided purely from evidence
# coverage - does the graph contain at least one node naming each
# control the indicator references - never from whether a covered
# control's collected value is actually good. That is enough to reach
# satisfied once every referenced control has a node; it is not enough
# to ever return not_satisfied, which needs a per-control-type predicate
# (e.g. whether an IAM user's MFA device count is nonzero) this ticket
# did not author, same deferral svc.rego already made. requires_attestation
# is likewise not returned here - see docs/crosswalk-analysis.md section 9.
#
# Three of KSI-IAM's six indicators (KSI-IAM-APM, KSI-IAM-ELP,
# KSI-IAM-JIT) reference at least one control our current frontends and
# collectors evidence today (AC-3, AC-6, CM-7, IA-2, IA-5) - see
# docs/adr/0012's sibling proposal for the exact overlap. The other
# three (AAM, SNU, SUS) get the same "no evidence collected for any
# control" outcome every KSI-SVC indicator gets today; this module still
# names all six, per ADR 0007's "account for every indicator, never
# omit."
#
# Tested from internal/backends/fedramp20x's Go test suite (via OPA's Go
# SDK against this embedded module), not a colocated *_test.rego file -
# see evaluate_test.go.
package fedramp20x.ksi.iam

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
