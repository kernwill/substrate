package rules

import (
	"fmt"
	"strings"
	"time"
)

// Date is a schema "format: date" value: an ISO-8601 calendar date string
// such as "2026-07-14". It is kept as a string rather than time.Time so
// decoding never fails on a value schema validation would already have
// rejected; use Time to parse it when a comparison or arithmetic is needed.
type Date string

// Time parses d as a calendar date.
func (d Date) Time() (time.Time, error) {
	return time.Parse("2006-01-02", string(d))
}

// DocumentStatus is the publication status of a definitions, requirements,
// or KSI document.
type DocumentStatus string

const (
	StatusStable      DocumentStatus = "stable"
	StatusPlaceholder DocumentStatus = "placeholder"
	StatusEmpty       DocumentStatus = "empty"
)

// EffectiveState says whether adopting a rule, KSI, or definition is
// required, optional, or not applicable.
type EffectiveState string

const (
	EffectiveRequired EffectiveState = "required"
	EffectiveOptional EffectiveState = "optional"
	EffectiveNo       EffectiveState = "no"
)

// ForceLevel is the RFC-2119-style strength of a requirement or indicator statement.
type ForceLevel string

const (
	ForceMust      ForceLevel = "MUST"
	ForceMustNot   ForceLevel = "MUST NOT"
	ForceShould    ForceLevel = "SHOULD"
	ForceShouldNot ForceLevel = "SHOULD NOT"
	ForceMay       ForceLevel = "MAY"
)

// TimeframeType is the unit for a rule's timeframe_num.
type TimeframeType string

const (
	TimeframeBizdays TimeframeType = "bizdays"
	TimeframeDays    TimeframeType = "days"
	TimeframeHours   TimeframeType = "hours"
	TimeframeWeeks   TimeframeType = "weeks"
	TimeframeMonths  TimeframeType = "months"
	TimeframeYears   TimeframeType = "years"
)

// CertificationType distinguishes the 20x and Rev5 certification paths.
type CertificationType string

const (
	Certification20x  CertificationType = "20x"
	CertificationRev5 CertificationType = "Rev5"
)

// ParseCertificationType parses s (case-insensitively) as a
// CertificationType. This is the one place that enumerates valid values,
// so a caller (e.g. a CLI flag parser) doesn't need its own copy of the
// enumeration that could silently drift from the constants above.
func ParseCertificationType(s string) (CertificationType, error) {
	switch strings.ToLower(s) {
	case "20x":
		return Certification20x, nil
	case "rev5":
		return CertificationRev5, nil
	default:
		return "", fmt.Errorf("rules: %q is not a certification type (want 20x or Rev5)", s)
	}
}

// IsValid reports whether c is the zero value (no filter, where c is used
// as an optional query field) or one of the defined CertificationType
// constants. A CertificationType built by casting an arbitrary string
// (rather than through ParseCertificationType) bypasses that validation,
// which is exactly the gap this method lets a caller like
// Dataset.QueryRules close at its own API boundary.
func (c CertificationType) IsValid() bool {
	switch c {
	case "", Certification20x, CertificationRev5:
		return true
	default:
		return false
	}
}

// CertificationPath is who runs the certification: FedRAMP's Program path
// or an individual Agency's authorization path.
type CertificationPath string

const (
	PathProgram CertificationPath = "Program"
	PathAgency  CertificationPath = "Agency"
)

// ParseCertificationPath parses s (case-insensitively) as a CertificationPath.
func ParseCertificationPath(s string) (CertificationPath, error) {
	switch strings.ToLower(s) {
	case "program":
		return PathProgram, nil
	case "agency":
		return PathAgency, nil
	default:
		return "", fmt.Errorf("rules: %q is not a certification path (want Program or Agency)", s)
	}
}

// IsValid reports whether p is the zero value (no filter) or one of the
// defined CertificationPath constants.
func (p CertificationPath) IsValid() bool {
	switch p {
	case "", PathProgram, PathAgency:
		return true
	default:
		return false
	}
}

// ClassName is a FedRAMP 20x certification class.
type ClassName string

const (
	ClassA ClassName = "A"
	ClassB ClassName = "B"
	ClassC ClassName = "C"
	ClassD ClassName = "D"
)

// ParseClassName parses s (case-insensitively) as a ClassName.
func ParseClassName(s string) (ClassName, error) {
	switch strings.ToUpper(s) {
	case "A":
		return ClassA, nil
	case "B":
		return ClassB, nil
	case "C":
		return ClassC, nil
	case "D":
		return ClassD, nil
	default:
		return "", fmt.Errorf("rules: %q is not a certification class (want A, B, C, or D)", s)
	}
}

// IsValid reports whether c is the zero value (no filter) or one of the
// defined ClassName constants.
func (c ClassName) IsValid() bool {
	switch c {
	case "", ClassA, ClassB, ClassC, ClassD:
		return true
	default:
		return false
	}
}

// AffectedParty names who a requirement, indicator, or subset applies to.
type AffectedParty string

const (
	AffectsAdvisors  AffectedParty = "Advisors"
	AffectsAgencies  AffectedParty = "Agencies"
	AffectsAssessors AffectedParty = "Assessors"
	AffectsFedRAMP   AffectedParty = "FedRAMP"
	AffectsProviders AffectedParty = "Providers"
	AffectsEveryone  AffectedParty = "Everyone"
)

// NotificationMethod is how a notification in a requirement's
// "notification" list is delivered.
type NotificationMethod string

const (
	NotifyEmail  NotificationMethod = "email"
	NotifyForm   NotificationMethod = "form"
	NotifyUpdate NotificationMethod = "update"
	NotifyVaries NotificationMethod = "varies"
	NotifyWeb    NotificationMethod = "web"
)

// NotificationParty is who receives a notification.
type NotificationParty string

const (
	NotifyPartyFedRAMP         NotificationParty = "FedRAMP"
	NotifyPartyProvider        NotificationParty = "Provider"
	NotifyPartyAgencyCustomers NotificationParty = "Agency Customers"
	NotifyPartyEveryone        NotificationParty = "Everyone"
	NotifyPartyAllNecessary    NotificationParty = "All Necessary Parties"
	NotifyPartyAllAffected     NotificationParty = "All Affected Parties"
)

// UpdatedEntry records one changelog entry attached to a definition,
// requirement, indicator, or control.
type UpdatedEntry struct {
	Date    Date   `json:"date"`
	Comment string `json:"comment"`

	Extra Extra `json:"-"`
}

type updatedEntryAlias UpdatedEntry

func (u *UpdatedEntry) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*updatedEntryAlias)(u))
	if err != nil {
		return err
	}
	u.Extra = extra
	return nil
}

func (u UpdatedEntry) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(updatedEntryAlias(u), u.Extra)
}

// Artifacts lists the evidence artifact descriptions for a rule or
// indicator, keyed by which certification path they apply under. These
// are prose descriptions of what to produce, not the five default_artifacts
// slots (Info.DefaultArtifacts) that every FRR rule and KSI is assessed
// against in addition to whatever is listed here.
type Artifacts struct {
	All     []string `json:"all,omitempty"`
	TwentyX []string `json:"20x,omitempty"`
	Rev5    []string `json:"rev5,omitempty"`

	Extra Extra `json:"-"`
}

type artifactsAlias Artifacts

func (a *Artifacts) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*artifactsAlias)(a))
	if err != nil {
		return err
	}
	a.Extra = extra
	return nil
}

func (a Artifacts) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(artifactsAlias(a), a.Extra)
}

// RuleSchema points to the JSON Schema describing a rule's own machine-readable payload.
type RuleSchema struct {
	Name string `json:"name"`
	URL  string `json:"url"`

	Extra Extra `json:"-"`
}

type ruleSchemaAlias RuleSchema

func (r *RuleSchema) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*ruleSchemaAlias)(r))
	if err != nil {
		return err
	}
	r.Extra = extra
	return nil
}

func (r RuleSchema) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(ruleSchemaAlias(r), r.Extra)
}

// RuleExample is one worked example attached to a requirement.
type RuleExample struct {
	ID       string   `json:"id"`
	KeyTests []string `json:"key_tests,omitempty"`
	Examples []string `json:"examples,omitempty"`

	Extra Extra `json:"-"`
}

type ruleExampleAlias RuleExample

func (r *RuleExample) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*ruleExampleAlias)(r))
	if err != nil {
		return err
	}
	r.Extra = extra
	return nil
}

func (r RuleExample) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(ruleExampleAlias(r), r.Extra)
}

// Notification describes one party that must be told about something a
// requirement governs, and how.
type Notification struct {
	Party  NotificationParty  `json:"party"`
	Method NotificationMethod `json:"method"`
	Target string             `json:"target"`
	Name   string             `json:"name"`
	URL    string             `json:"url,omitempty"`

	Extra Extra `json:"-"`
}

type notificationAlias Notification

func (n *Notification) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*notificationAlias)(n))
	if err != nil {
		return err
	}
	n.Extra = extra
	return nil
}

func (n Notification) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(notificationAlias(n), n.Extra)
}

// EffectiveDates gives the obtain/maintain/grace schedule for adopting a
// rule, definition, or KSI.
type EffectiveDates struct {
	Obtain           Date        `json:"obtain"`
	Maintain         Date        `json:"maintain"`
	OptionalAdoption Date        `json:"optional_adoption,omitempty"`
	Grace            GracePeriod `json:"grace"`

	Extra Extra `json:"-"`
}

type effectiveDatesAlias EffectiveDates

func (e *EffectiveDates) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*effectiveDatesAlias)(e))
	if err != nil {
		return err
	}
	e.Extra = extra
	return nil
}

func (e EffectiveDates) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(effectiveDatesAlias(e), e.Extra)
}

// GracePeriod is how long past the maintain date a provider has before
// non-adoption counts against them.
type GracePeriod struct {
	Default             Date `json:"default"`
	UntilNextAssessment bool `json:"until_next_assessment"`

	Extra Extra `json:"-"`
}

type gracePeriodAlias GracePeriod

func (g *GracePeriod) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*gracePeriodAlias)(g))
	if err != nil {
		return err
	}
	g.Extra = extra
	return nil
}

func (g GracePeriod) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(gracePeriodAlias(g), g.Extra)
}

// Effective states whether, and on what schedule, adopting the containing
// document, rule, or indicator is required.
type Effective struct {
	Is            EffectiveState  `json:"is"`
	CurrentStatus string          `json:"current_status,omitempty"`
	Date          *EffectiveDates `json:"date,omitempty"`
	Comments      []string        `json:"comments,omitempty"`
	Warnings      []string        `json:"warnings,omitempty"`
	SignupURL     string          `json:"signup_url,omitempty"`

	Extra Extra `json:"-"`
}

type effectiveAlias Effective

func (e *Effective) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*effectiveAlias)(e))
	if err != nil {
		return err
	}
	e.Extra = extra
	return nil
}

func (e Effective) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(effectiveAlias(e), e.Extra)
}
