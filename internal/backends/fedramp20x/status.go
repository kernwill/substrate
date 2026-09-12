package fedramp20x

// Status is FR-6.6's per-indicator evaluation result.
//
// Undetermined must never be collapsed into Satisfied or NotSatisfied -
// see CLAUDE.md's "fail visible, never fail silent" and Evaluate's own
// doc comment for how this package holds that line today (it can prove
// full evidence coverage, so it can return Satisfied; it cannot yet judge
// a covered control's actual value as good or bad, so it never returns
// NotSatisfied). RequiresAttestation is reserved for indicators whose
// controls are determinately outside anything a compiler can observe
// (docs/crosswalk-analysis.md section 9) - this package does not classify
// any indicator that way yet, since doing so is itself a compliance-
// content decision distinct from evidence-coverage checking.
type Status string

const (
	StatusSatisfied           Status = "satisfied"
	StatusNotSatisfied        Status = "not_satisfied"
	StatusUndetermined        Status = "undetermined"
	StatusNotApplicable       Status = "not_applicable"
	StatusRequiresAttestation Status = "requires_attestation"
)

// IndicatorResult is one KSI indicator's evaluated status. Reason is
// always set, not just when Status is Undetermined, so a caller never has
// to special-case which statuses come with an explanation.
type IndicatorResult struct {
	// Indicator is the full KSI indicator ID, e.g. "KSI-SVC-SIN".
	Indicator string `json:"indicator"`
	// Family is the three-letter KSI family code, e.g. "SVC".
	Family string `json:"family"`
	Status Status `json:"status"`
	Reason string `json:"reason"`
	// RemediationHint is set for Undetermined results pointing at a real
	// action (add a collector, add an IR mapping) - never a vague "fix
	// this."
	RemediationHint string `json:"remediation_hint,omitempty"`
	// Evidence lists the ir.NodeIDs backing a Satisfied or NotSatisfied
	// verdict, so any assertion this package makes traces back to the
	// facts it was computed from (FR-4.6).
	Evidence []string `json:"evidence,omitempty"`
}
