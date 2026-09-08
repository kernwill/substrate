package rules

// Info is the dataset's top-level "info" object: title, version, and the
// five default artifact-evidence slots every FRR rule and every KSI is
// assessed against (see DefaultArtifacts).
type Info struct {
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Version          string            `json:"version"`
	LastUpdated      Date              `json:"last_updated"`
	DefaultArtifacts *DefaultArtifacts `json:"default_artifacts,omitempty"`

	Extra Extra `json:"-"`
}

type infoAlias Info

func (i *Info) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*infoAlias)(i))
	if err != nil {
		return err
	}
	i.Extra = extra
	return nil
}

func (i Info) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(infoAlias(i), i.Extra)
}

// DefaultArtifacts lists the five evidence slots FRR rules and KSIs are
// assessed against by default: explanation, verification, and validation
// (plus independent verification and validation for FRR). A rule's or
// KSI's overall status is a status per slot, not a single satisfied/
// not_satisfied enum - status computation is out of scope for the rules
// ingestion package and belongs to a backend.
type DefaultArtifacts struct {
	FRR []string `json:"FRR"`
	KSI []string `json:"KSI"`

	Extra Extra `json:"-"`
}

type defaultArtifactsAlias DefaultArtifacts

func (d *DefaultArtifacts) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*defaultArtifactsAlias)(d))
	if err != nil {
		return err
	}
	d.Extra = extra
	return nil
}

func (d DefaultArtifacts) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(defaultArtifactsAlias(d), d.Extra)
}
