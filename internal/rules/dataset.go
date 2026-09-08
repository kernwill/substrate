package rules

import (
	"encoding/json"
	"fmt"
	"os"
)

// Dataset is the typed form of a fedramp-consolidated-rules.json document:
// definitions (FRD), requirements (FRR), Key Security Indicators (KSI),
// and control guidance (CTL).
type Dataset struct {
	Info Info                     `json:"info"`
	FRD  FRDDocument              `json:"FRD"`
	FRR  map[string]FRRDocument   `json:"FRR"`
	KSI  map[string]KSITheme      `json:"KSI"`
	CTL  map[string]ControlFamily `json:"CTL,omitempty"`

	Extra Extra `json:"-"`
}

type datasetAlias Dataset

func (d *Dataset) UnmarshalJSON(data []byte) error {
	extra, err := decodeWithExtra(data, (*datasetAlias)(d))
	if err != nil {
		return err
	}
	d.Extra = extra
	return nil
}

func (d Dataset) MarshalJSON() ([]byte, error) {
	return encodeWithExtra(datasetAlias(d), d.Extra)
}

// Control looks up a single control's guidance by canonical ID.
func (d *Dataset) Control(id ControlID) (ControlEntry, bool) {
	fam, ok := d.CTL[id.Family]
	if !ok {
		return ControlEntry{}, false
	}
	entry, ok := fam[id]
	return entry, ok
}

// Load validates raw against the vendored FedRAMP Consolidated Rules JSON
// Schema and, only if that passes, decodes it into a Dataset. A schema
// violation is returned as a *SchemaError without attempting to decode;
// this is the FR-1.2 "fail loudly on drift" gate.
func Load(raw []byte) (*Dataset, error) {
	if err := ValidateSchema(raw); err != nil {
		return nil, err
	}
	var ds Dataset
	if err := json.Unmarshal(raw, &ds); err != nil {
		return nil, fmt.Errorf("rules: decode dataset: %w", err)
	}
	return &ds, nil
}

// LoadFile reads and Loads the dataset at path.
func LoadFile(path string) (*Dataset, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rules: read dataset: %w", err)
	}
	return Load(raw)
}

// Default returns the FedRAMP Consolidated Rules dataset vendored into
// this binary (internal/rules/data/fedramp-consolidated-rules.json).
func Default() (*Dataset, error) {
	return Load(vendoredDataset)
}
