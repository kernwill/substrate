package rules

// FRRDocument is one document within the dataset's "FRR" (FedRAMP
// Requirements/Recommendations) section, e.g. "AFC" or "IVV". The
// top-level FRR object maps a three-letter document key to one of these.
type FRRDocument struct {
	Info FRRInfo          `json:"info"`
	Data FRRDataContainer `json:"data"`

	Extra Extra `json:"-"`
}

type frrDocumentAlias FRRDocument

func (f *FRRDocument) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frrDocumentAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRRDocument) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frrDocumentAlias(f), f.Extra)
}

// FRRInfo describes an FRR document itself: its subsets, applicable
// timeline, and which fields apply uniformly versus per certification type.
type FRRInfo struct {
	Name      string                         `json:"name"`
	ShortName string                         `json:"short_name"`
	WebName   string                         `json:"web_name"`
	Purpose   string                         `json:"purpose"`
	Status    DocumentStatus                 `json:"status"`
	Tag       string                         `json:"tag,omitempty"`
	Effective *Effective                     `json:"effective,omitempty"`
	Subsets   map[string]FRRSubsetDefinition `json:"subsets,omitempty"`
	Flows     []any                          `json:"flows,omitempty"`
	TwentyX   *FRRInfoCert                   `json:"20x,omitempty"`
	Rev5      *FRRInfoCert                   `json:"rev5,omitempty"`

	Extra Extra `json:"-"`
}

type frrInfoAlias FRRInfo

func (f *FRRInfo) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frrInfoAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRRInfo) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frrInfoAlias(f), f.Extra)
}

// FRRInfoCert is the 20x- or Rev5-scoped variant of FRRInfo's shared fields.
type FRRInfoCert struct {
	Effective *Effective                     `json:"effective,omitempty"`
	Subsets   map[string]FRRSubsetDefinition `json:"subsets,omitempty"`
	Flows     []any                          `json:"flows,omitempty"`

	Extra Extra `json:"-"`
}

type frrInfoCertAlias FRRInfoCert

func (f *FRRInfoCert) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frrInfoCertAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRRInfoCert) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frrInfoCertAlias(f), f.Extra)
}

// FRRSubsetDefinition describes one three-letter subset within a document
// (e.g. "CSO" under "AFC"), and who it applies to.
type FRRSubsetDefinition struct {
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	Applicability FRRSubsetApplicability `json:"applicability"`

	Extra Extra `json:"-"`
}

type frrSubsetDefinitionAlias FRRSubsetDefinition

func (f *FRRSubsetDefinition) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frrSubsetDefinitionAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRRSubsetDefinition) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frrSubsetDefinitionAlias(f), f.Extra)
}

// FRRSubsetApplicability scopes a subset to certification types, paths,
// classes, and affected parties.
type FRRSubsetApplicability struct {
	Types   []CertificationType `json:"types"`
	Paths   []CertificationPath `json:"paths"`
	Classes []ClassName         `json:"classes"`
	Affects []AffectedParty     `json:"affects"`

	Extra Extra `json:"-"`
}

type frrSubsetApplicabilityAlias FRRSubsetApplicability

func (f *FRRSubsetApplicability) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frrSubsetApplicabilityAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRRSubsetApplicability) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frrSubsetApplicabilityAlias(f), f.Extra)
}

// FRRDataContainer holds a document's requirements, keyed by which
// certification path they apply under ("all", "20x", or "rev5"), then by
// three-letter subset, then by full requirement ID (e.g. "AFC-FRP-VRE").
type FRRDataContainer struct {
	All     map[string]map[string]FRRRequirement `json:"all,omitempty"`
	TwentyX map[string]map[string]FRRRequirement `json:"20x,omitempty"`
	Rev5    map[string]map[string]FRRRequirement `json:"rev5,omitempty"`

	Extra Extra `json:"-"`
}

type frrDataContainerAlias FRRDataContainer

func (f *FRRDataContainer) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frrDataContainerAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRRDataContainer) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frrDataContainerAlias(f), f.Extra)
}

// FRRRequirement is a single rule (e.g. "AFC-FRP-VRE"). Its force and
// statement either apply uniformly (Statement/Force set, VariesByClass
// nil) or vary per certification class (VariesByClass set, Statement/
// Force empty) - the dataset's schema treats these as mutually exclusive.
//
// Controls holds raw OSCAL-form control ID strings (e.g. "ac-6.1") as
// found in the dataset; use ParseControlIDs to obtain canonical ControlIDs.
type FRRRequirement struct {
	Name                        string            `json:"name"`
	Statement                   string            `json:"statement,omitempty"`
	VariesByClass               *FRRVariesByClass `json:"varies_by_class,omitempty"`
	FollowingInformation        []string          `json:"following_information,omitempty"`
	FollowingInformationBullets []string          `json:"following_information_bullets,omitempty"`
	Danger                      string            `json:"danger,omitempty"`
	Note                        string            `json:"note,omitempty"`
	Notes                       []string          `json:"notes,omitempty"`
	Related                     []string          `json:"related,omitempty"`
	Reference                   string            `json:"reference,omitempty"`
	ReferenceURL                string            `json:"reference_url,omitempty"`
	ReferenceURLWebName         string            `json:"reference_url_web_name,omitempty"`
	EffectiveDate               *EffectiveDates   `json:"effective_date,omitempty"`
	CorrectiveActions           []string          `json:"corrective_actions,omitempty"`
	Force                       ForceLevel        `json:"force,omitempty"`
	Affects                     []AffectedParty   `json:"affects"`
	Artifacts                   *Artifacts        `json:"artifacts,omitempty"`
	Schema                      *RuleSchema       `json:"schema,omitempty"`
	Examples                    []RuleExample     `json:"examples,omitempty"`
	TimeframeType               TimeframeType     `json:"timeframe_type,omitempty"`
	TimeframeNum                float64           `json:"timeframe_num,omitempty"`
	Notification                []Notification    `json:"notification,omitempty"`
	Controls                    []string          `json:"controls,omitempty"`
	Terms                       []string          `json:"terms,omitempty"`
	Updated                     []UpdatedEntry    `json:"updated"`

	Extra Extra `json:"-"`
}

type frrRequirementAlias FRRRequirement

func (f *FRRRequirement) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frrRequirementAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRRRequirement) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frrRequirementAlias(f), f.Extra)
}

// ControlIDs parses Controls into canonical ControlIDs.
func (f FRRRequirement) ControlIDs() ([]ControlID, error) {
	return ParseControlIDs(f.Controls)
}

// EffectiveForce returns f's force level for a specific certification
// class: the class-specific force from VariesByClass when f varies by
// class, otherwise f's uniform Force. The zero value means f doesn't
// apply to class at all (e.g. a rule whose VariesByClass has no "a"
// entry, queried for ClassA).
func (f FRRRequirement) EffectiveForce(class ClassName) ForceLevel {
	if f.VariesByClass == nil {
		return f.Force
	}
	level := f.VariesByClass.Level(class)
	if level == nil {
		return ""
	}
	return level.Force
}

// FRRVariesByClass holds per-class requirement levels when a rule's force
// or statement differs by certification class.
type FRRVariesByClass struct {
	A *FRRRequirementLevel `json:"a,omitempty"`
	B *FRRRequirementLevel `json:"b,omitempty"`
	C *FRRRequirementLevel `json:"c,omitempty"`
	D *FRRRequirementLevel `json:"d,omitempty"`

	Extra Extra `json:"-"`
}

// Level returns v's requirement level for a specific certification
// class, or nil if v has no entry for it. The single place that maps a
// ClassName to a VariesByClass field, shared by EffectiveForce and
// ruleClasses (query.go) so the four-field enumeration lives in exactly
// one spot.
func (v *FRRVariesByClass) Level(class ClassName) *FRRRequirementLevel {
	if v == nil {
		return nil
	}
	switch class {
	case ClassA:
		return v.A
	case ClassB:
		return v.B
	case ClassC:
		return v.C
	case ClassD:
		return v.D
	default:
		return nil
	}
}

type frrVariesByClassAlias FRRVariesByClass

func (f *FRRVariesByClass) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frrVariesByClassAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRRVariesByClass) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frrVariesByClassAlias(f), f.Extra)
}

// FRRRequirementLevel is one certification class's variant of a
// class-varying requirement.
type FRRRequirementLevel struct {
	Statement            string                                   `json:"statement"`
	FollowingInformation []string                                 `json:"following_information,omitempty"`
	Rev5ControlsList     map[string][]string                      `json:"rev5_controls_list,omitempty"`
	Note                 string                                   `json:"note,omitempty"`
	Notes                []string                                 `json:"notes,omitempty"`
	Force                ForceLevel                               `json:"force"`
	EffectiveDate        *EffectiveDates                          `json:"effective_date,omitempty"`
	TimeframeType        TimeframeType                            `json:"timeframe_type,omitempty"`
	TimeframeNum         float64                                  `json:"timeframe_num,omitempty"`
	PainTimeframes       map[string]map[string]PainTimeframeEntry `json:"pain_timeframes,omitempty"`
	Artifacts            *Artifacts                               `json:"artifacts,omitempty"`

	Extra Extra `json:"-"`
}

type frrRequirementLevelAlias FRRRequirementLevel

func (f *FRRRequirementLevel) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frrRequirementLevelAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRRRequirementLevel) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frrRequirementLevelAlias(f), f.Extra)
}

// Rev5ControlIDs parses one family's rev5_controls_list entries (FedRAMP
// prose form, e.g. "AT-02 (02)") into canonical ControlIDs.
func (f FRRRequirementLevel) Rev5ControlIDs(family string) ([]ControlID, error) {
	return ParseControlIDs(f.Rev5ControlsList[family])
}

// PainTimeframeEntry is one entry in a requirement level's pain_timeframes table.
type PainTimeframeEntry struct {
	TimeframeType TimeframeType `json:"timeframe_type"`
	TimeframeNum  float64       `json:"timeframe_num"`
	Description   string        `json:"description"`

	Extra Extra `json:"-"`
}

type painTimeframeEntryAlias PainTimeframeEntry

func (p *PainTimeframeEntry) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*painTimeframeEntryAlias)(p))
	if err != nil {
		return err
	}
	p.Extra = extra
	return nil
}

func (p PainTimeframeEntry) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(painTimeframeEntryAlias(p), p.Extra)
}
