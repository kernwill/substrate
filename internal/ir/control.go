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

// String renders c in OSCAL's dotted-decimal notation, e.g. "ac-6.1".
func (c Control) String() string {
	family := strings.ToLower(string(c.Family))
	if c.HasEnhancement() {
		return fmt.Sprintf("%s-%d.%d", family, c.Base, c.Enhancement)
	}
	return fmt.Sprintf("%s-%d", family, c.Base)
}
