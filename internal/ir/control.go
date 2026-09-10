package ir

import (
	"fmt"
	"strings"
)

// ControlFamily is a NIST 800-53 control family code, e.g. "AC" (Access
// Control), "AU" (Audit and Accountability), "SC" (System and
// Communications Protection).
//
// This is this package's own minimal, generic notion of a control
// family - deliberately independent of any single framework's own
// control catalog or ingestion package. internal/rules already models
// one specific certification program's control identifiers, but this
// package must never import internal/rules or any other
// framework-specific package: the whole point of the evidence graph is
// that it's the one thing every framework backend maps from, so it
// can't itself depend on one framework's dataset (see
// scripts/check-boundaries.sh and CLAUDE.md's architectural invariants).
// The two types look similar because they describe the same underlying
// standard, not because either was derived from the other.
type ControlFamily string

// Control identifies a specific NIST 800-53 control or control
// enhancement within a family, e.g. family "AC", base 6, enhancement 1
// for AC-6(1). Enhancement is 0 for a base control.
type Control struct {
	Family      ControlFamily `json:"family"`
	Base        int           `json:"base"`
	Enhancement int           `json:"enhancement,omitempty"`
}

// HasEnhancement reports whether c identifies a control enhancement
// rather than a base control.
func (c Control) HasEnhancement() bool { return c.Enhancement > 0 }

// Validate checks that c is well-formed: Family is set, Base is a
// positive control number, and Enhancement (when present) is positive
// too. It does not check c against any actual control catalog - only
// that the numbers are the kind a real 800-53 control ID could have.
func (c Control) Validate() error {
	if c.Family == "" {
		return fmt.Errorf("ir: control: family is required")
	}
	if c.Base <= 0 {
		return fmt.Errorf("ir: control %s: base %d must be positive", c.Family, c.Base)
	}
	if c.Enhancement < 0 {
		return fmt.Errorf("ir: control %s-%d: enhancement %d must not be negative", c.Family, c.Base, c.Enhancement)
	}
	return nil
}

// String renders c in OSCAL's dotted-decimal notation, e.g. "ac-6.1".
func (c Control) String() string {
	family := strings.ToLower(string(c.Family))
	if c.HasEnhancement() {
		return fmt.Sprintf("%s-%d.%d", family, c.Base, c.Enhancement)
	}
	return fmt.Sprintf("%s-%d", family, c.Base)
}
