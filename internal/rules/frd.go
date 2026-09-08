package rules

// FRDDocument is the dataset's "FRD" (FedRAMP Definitions) section: a
// single document containing every defined term.
type FRDDocument struct {
	Info FRDInfo          `json:"info"`
	Data FRDDataContainer `json:"data"`

	Extra Extra `json:"-"`
}

type frdDocumentAlias FRDDocument

func (f *FRDDocument) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frdDocumentAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRDDocument) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frdDocumentAlias(f), f.Extra)
}

// FRDInfo describes the FRD document itself.
type FRDInfo struct {
	Name      string         `json:"name"`
	ShortName string         `json:"short_name"`
	WebName   string         `json:"web_name"`
	Purpose   string         `json:"purpose"`
	Status    DocumentStatus `json:"status"`
	Effective *Effective     `json:"effective,omitempty"`
	TwentyX   *CertEffective `json:"20x,omitempty"`
	Rev5      *CertEffective `json:"rev5,omitempty"`

	Extra Extra `json:"-"`
}

type frdInfoAlias FRDInfo

func (f *FRDInfo) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frdInfoAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRDInfo) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frdInfoAlias(f), f.Extra)
}

// CertEffective is an "effective" entry scoped to one certification type
// (20x or Rev5), as opposed to one that applies uniformly.
type CertEffective struct {
	Effective *Effective `json:"effective,omitempty"`

	Extra Extra `json:"-"`
}

type certEffectiveAlias CertEffective

func (c *CertEffective) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*certEffectiveAlias)(c))
	if err != nil {
		return err
	}
	c.Extra = extra
	return nil
}

func (c CertEffective) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(certEffectiveAlias(c), c.Extra)
}

// FRDDataContainer holds the definitions map, keyed by which
// certification path they apply under ("all", "20x", or "rev5").
type FRDDataContainer struct {
	All     map[string]FRDDefinition `json:"all"`
	TwentyX map[string]FRDDefinition `json:"20x,omitempty"`
	Rev5    map[string]FRDDefinition `json:"rev5,omitempty"`

	Extra Extra `json:"-"`
}

type frdDataContainerAlias FRDDataContainer

func (f *FRDDataContainer) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frdDataContainerAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRDDataContainer) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frdDataContainerAlias(f), f.Extra)
}

// FRDDefinition is a single defined term (FRD-XXX).
type FRDDefinition struct {
	Term            string         `json:"term"`
	Definition      string         `json:"definition"`
	Note            string         `json:"note,omitempty"`
	Notes           []string       `json:"notes,omitempty"`
	Tag             string         `json:"tag,omitempty"`
	Alts            []string       `json:"alts"`
	DoNotLink       bool           `json:"do_not_link,omitempty"`
	Reference       string         `json:"reference,omitempty"`
	ReferenceURL    string         `json:"reference_url,omitempty"`
	ReferenceURLAlt string         `json:"referenceurl,omitempty"`
	Updated         []UpdatedEntry `json:"updated"`

	Extra Extra `json:"-"`
}

type frdDefinitionAlias FRDDefinition

func (f *FRDDefinition) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*frdDefinitionAlias)(f))
	if err != nil {
		return err
	}
	f.Extra = extra
	return nil
}

func (f FRDDefinition) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(frdDefinitionAlias(f), f.Extra)
}
