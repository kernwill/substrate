package rules

// KSITheme is one Key Security Indicator family (e.g. "KSI-CED"), grouping
// related indicators. The top-level KSI object maps a three-letter short
// name to one of these.
type KSITheme struct {
	ID         string                  `json:"id"`
	Name       string                  `json:"name"`
	WebName    string                  `json:"web_name"`
	ShortName  string                  `json:"short_name"`
	Status     DocumentStatus          `json:"status"`
	Indicators map[string]KSIIndicator `json:"indicators"`

	Extra Extra `json:"-"`
}

type ksiThemeAlias KSITheme

func (k *KSITheme) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*ksiThemeAlias)(k))
	if err != nil {
		return err
	}
	k.Extra = extra
	return nil
}

func (k KSITheme) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(ksiThemeAlias(k), k.Extra)
}

// KSIIndicator is a single Key Security Indicator (e.g. "KSI-CED-RAT").
// Its statement either applies uniformly (Statement set, VariesByClass
// nil) or varies per certification class (VariesByClass set, Statement
// empty).
//
// Controls holds raw OSCAL-form control ID strings (e.g. "cp-3") as found
// in the dataset; use ControlIDs to obtain canonical ControlIDs.
type KSIIndicator struct {
	Name          string            `json:"name"`
	Statement     string            `json:"statement,omitempty"`
	Controls      []string          `json:"controls"`
	Reference     string            `json:"reference,omitempty"`
	ReferenceURL  string            `json:"reference_url,omitempty"`
	Updated       []UpdatedEntry    `json:"updated"`
	Artifacts     *Artifacts        `json:"artifacts,omitempty"`
	VariesByClass *KSIVariesByClass `json:"varies_by_class,omitempty"`
	Terms         []string          `json:"terms,omitempty"`

	Extra Extra `json:"-"`
}

type ksiIndicatorAlias KSIIndicator

func (k *KSIIndicator) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*ksiIndicatorAlias)(k))
	if err != nil {
		return err
	}
	k.Extra = extra
	return nil
}

func (k KSIIndicator) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(ksiIndicatorAlias(k), k.Extra)
}

// ControlIDs parses Controls into canonical ControlIDs.
func (k KSIIndicator) ControlIDs() ([]ControlID, error) {
	return ParseControlIDs(k.Controls)
}

// KSIVariesByClass holds per-class indicator levels when an indicator's
// statement differs by certification class.
type KSIVariesByClass struct {
	A *KSIIndicatorLevel `json:"a,omitempty"`
	B *KSIIndicatorLevel `json:"b,omitempty"`
	C *KSIIndicatorLevel `json:"c,omitempty"`
	D *KSIIndicatorLevel `json:"d,omitempty"`

	Extra Extra `json:"-"`
}

type ksiVariesByClassAlias KSIVariesByClass

func (k *KSIVariesByClass) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*ksiVariesByClassAlias)(k))
	if err != nil {
		return err
	}
	k.Extra = extra
	return nil
}

func (k KSIVariesByClass) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(ksiVariesByClassAlias(k), k.Extra)
}

// KSIIndicatorLevel is one certification class's variant of a
// class-varying indicator.
type KSIIndicatorLevel struct {
	Statement string     `json:"statement"`
	Artifacts *Artifacts `json:"artifacts,omitempty"`

	Extra Extra `json:"-"`
}

type ksiIndicatorLevelAlias KSIIndicatorLevel

func (k *KSIIndicatorLevel) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*ksiIndicatorLevelAlias)(k))
	if err != nil {
		return err
	}
	k.Extra = extra
	return nil
}

func (k KSIIndicatorLevel) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(ksiIndicatorLevelAlias(k), k.Extra)
}
