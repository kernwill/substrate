package rules

// ControlFamily maps a control family's two-letter code (e.g. "AC") to its
// controls, keyed by canonical ControlID. The dataset writes those keys in
// CTL key form ("AC-06-01"); decoding parses them into ControlIDs so
// lookups don't depend on string formatting.
type ControlFamily map[ControlID]ControlEntry

// ControlEntry is the guidance and parameters for a single control or
// control enhancement, optionally varying by certification class.
type ControlEntry struct {
	Guidance      []string                    `json:"guidance,omitempty"`
	Parameters    []ControlParameter          `json:"parameters,omitempty"`
	VariesByClass map[string]ControlClassData `json:"varies_by_class,omitempty"`
	Updated       []UpdatedEntry              `json:"updated,omitempty"`

	Extra Extra `json:"-"`
}

type controlEntryAlias ControlEntry

func (c *ControlEntry) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*controlEntryAlias)(c))
	if err != nil {
		return err
	}
	c.Extra = extra
	return nil
}

func (c ControlEntry) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(controlEntryAlias(c), c.Extra)
}

// ControlParameter is one named parameter value (an OSCAL "odp") for a control.
type ControlParameter struct {
	ParameterID string `json:"parameterId"`
	Value       string `json:"value"`

	Extra Extra `json:"-"`
}

type controlParameterAlias ControlParameter

func (c *ControlParameter) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*controlParameterAlias)(c))
	if err != nil {
		return err
	}
	c.Extra = extra
	return nil
}

func (c ControlParameter) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(controlParameterAlias(c), c.Extra)
}

// ControlClassData is a control's guidance and parameters scoped to one
// certification class ("b", "c", or "d").
type ControlClassData struct {
	Guidance   []string           `json:"guidance,omitempty"`
	Parameters []ControlParameter `json:"parameters,omitempty"`

	Extra Extra `json:"-"`
}

type controlClassDataAlias ControlClassData

func (c *ControlClassData) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*controlClassDataAlias)(c))
	if err != nil {
		return err
	}
	c.Extra = extra
	return nil
}

func (c ControlClassData) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(controlClassDataAlias(c), c.Extra)
}
