package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ControlID is the canonical, form-independent representation of a NIST
// 800-53 control or control enhancement. The dataset refers to the same
// control in three different surface notations depending on context:
//
//   - CTL key form: object keys in the CTL section, e.g. "AC-06-01" or "AC-20".
//   - OSCAL form: entries in FRR/KSI "controls" arrays, e.g. "ac-6.1" or "cp-3".
//   - FedRAMP prose form: narrative and rev5_controls_list text, e.g. "AC-06 (01)".
//
// ControlID lets code compare or look up a control regardless of which
// form it was read in.
type ControlID struct {
	Family      string // two-letter uppercase family code, e.g. "AC"
	Base        int    // base control number, e.g. 6
	Enhancement int    // enhancement number; 0 means the ID names the base control
}

// HasEnhancement reports whether c identifies a control enhancement rather
// than a base control.
func (c ControlID) HasEnhancement() bool { return c.Enhancement > 0 }

var (
	ctlKeyPattern       = regexp.MustCompile(`^([A-Z]{2})-(\d{2})(?:-(\d{2}))?$`)
	oscalPattern        = regexp.MustCompile(`^([a-z]{2})-(\d+)(?:\.(\d+))?$`)
	fedrampProsePattern = regexp.MustCompile(`^([A-Z]{2})-(\d{1,2})(?:\s*\((\d{1,2})\))?$`)
)

// ParseCTLKey parses the CTL section's object-key form, e.g. "AC-06-01" or "AC-20".
func ParseCTLKey(s string) (ControlID, error) {
	m := ctlKeyPattern.FindStringSubmatch(s)
	if m == nil {
		return ControlID{}, fmt.Errorf("rules: %q is not a valid CTL key control ID (want e.g. AC-06-01)", s)
	}
	return newControlID(m[1], m[2], m[3])
}

// ParseOSCAL parses OSCAL's dotted-decimal form, e.g. "ac-6.1" or "cp-3".
func ParseOSCAL(s string) (ControlID, error) {
	m := oscalPattern.FindStringSubmatch(s)
	if m == nil {
		return ControlID{}, fmt.Errorf("rules: %q is not a valid OSCAL control ID (want e.g. ac-6.1)", s)
	}
	return newControlID(strings.ToUpper(m[1]), m[2], m[3])
}

// ParseFedRAMPProse parses FedRAMP's narrative parenthetical form, e.g.
// "AC-6(1)", as well as the dataset's own zero-padded, spaced variant,
// e.g. "AC-06 (01)".
func ParseFedRAMPProse(s string) (ControlID, error) {
	m := fedrampProsePattern.FindStringSubmatch(s)
	if m == nil {
		return ControlID{}, fmt.Errorf("rules: %q is not a valid FedRAMP prose control ID (want e.g. AC-6(1))", s)
	}
	return newControlID(m[1], m[2], m[3])
}

// ParseControlID parses s using whichever of the three known notations
// matches. Prefer the form-specific parser when the source of s is known;
// use ParseControlID for input whose notation isn't known ahead of time.
func ParseControlID(s string) (ControlID, error) {
	if id, err := ParseCTLKey(s); err == nil {
		return id, nil
	}
	if id, err := ParseOSCAL(s); err == nil {
		return id, nil
	}
	if id, err := ParseFedRAMPProse(s); err == nil {
		return id, nil
	}
	return ControlID{}, fmt.Errorf("rules: %q does not match any known control ID notation (CTL key, OSCAL, or FedRAMP prose)", s)
}

func newControlID(family, base, enhancement string) (ControlID, error) {
	b, err := strconv.Atoi(base)
	if err != nil {
		return ControlID{}, fmt.Errorf("rules: invalid control base number %q: %w", base, err)
	}
	var e int
	if enhancement != "" {
		e, err = strconv.Atoi(enhancement)
		if err != nil {
			return ControlID{}, fmt.Errorf("rules: invalid control enhancement number %q: %w", enhancement, err)
		}
	}
	return ControlID{Family: family, Base: b, Enhancement: e}, nil
}

// CTLKey formats c in the CTL section's object-key form, e.g. "AC-06-01".
func (c ControlID) CTLKey() string {
	if c.HasEnhancement() {
		return fmt.Sprintf("%s-%02d-%02d", c.Family, c.Base, c.Enhancement)
	}
	return fmt.Sprintf("%s-%02d", c.Family, c.Base)
}

// OSCAL formats c in OSCAL's dotted-decimal form, e.g. "ac-6.1".
func (c ControlID) OSCAL() string {
	family := strings.ToLower(c.Family)
	if c.HasEnhancement() {
		return fmt.Sprintf("%s-%d.%d", family, c.Base, c.Enhancement)
	}
	return fmt.Sprintf("%s-%d", family, c.Base)
}

// FedRAMPProse formats c in FedRAMP's narrative parenthetical form, e.g.
// "AC-06 (01)", matching the dataset's own rev5_control_id pattern.
func (c ControlID) FedRAMPProse() string {
	if c.HasEnhancement() {
		return fmt.Sprintf("%s-%02d (%02d)", c.Family, c.Base, c.Enhancement)
	}
	return fmt.Sprintf("%s-%02d", c.Family, c.Base)
}

// String returns the OSCAL form, the notation most FRR/KSI cross-references use.
func (c ControlID) String() string { return c.OSCAL() }

// MarshalText renders c in CTL-key form. This is what makes ControlID
// usable as a map key or plain JSON string value, and CTL-key form is
// the one that actually matters there: ControlID's only real use as a
// map key today is CTL's own map[ControlID]ControlEntry (ctl.go), which
// is decoded from CTL-key strings like "AC-06-01" in the first place -
// UnmarshalText round-trips CTL-key form back to the same ControlID
// (ParseControlID tries ParseCTLKey first), so encoding it back out the
// same way keeps a Dataset's own re-marshal lossless in the one form
// that's ever exercised. (An earlier version of this method emitted
// OSCAL form here instead, which silently reformatted every CTL key -
// e.g. "SA-09-02" into "sa-9.2" - the moment anything re-marshaled a
// loaded Dataset, since nothing about the value remembers which of the
// three notations it was originally parsed from.)
func (c ControlID) MarshalText() ([]byte, error) { return []byte(c.CTLKey()), nil }

// UnmarshalText parses text using whichever known notation matches, so
// ControlID can be decoded transparently from any of the dataset's three
// surface forms.
func (c *ControlID) UnmarshalText(text []byte) error {
	id, err := ParseControlID(string(text))
	if err != nil {
		return err
	}
	*c = id
	return nil
}

// ParseControlIDs parses a slice of raw control ID strings (as found in an
// FRR or KSI "controls" array) into canonical ControlIDs. It fails on the
// first unparseable entry rather than skipping it.
func ParseControlIDs(raw []string) ([]ControlID, error) {
	if raw == nil {
		return nil, nil
	}
	ids := make([]ControlID, len(raw))
	for i, s := range raw {
		id, err := ParseControlID(s)
		if err != nil {
			return nil, fmt.Errorf("rules: control %d: %w", i, err)
		}
		ids[i] = id
	}
	return ids, nil
}
