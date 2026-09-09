package rules

import (
	"encoding/json"
	"testing"
)

func loadVendoredDataset(t *testing.T) *Dataset {
	t.Helper()
	ds, err := LoadFile(vendoredDatasetPath)
	if err != nil {
		t.Fatalf("LoadFile(%q): %v", vendoredDatasetPath, err)
	}
	return ds
}

func TestLoadVendoredDatasetInfo(t *testing.T) {
	ds := loadVendoredDataset(t)

	if got, want := ds.Info.Version, "2026.07.14.01"; got != want {
		t.Errorf("Info.Version = %q, want %q", got, want)
	}
	if got, want := ds.Info.LastUpdated, Date("2026-07-14"); got != want {
		t.Errorf("Info.LastUpdated = %q, want %q", got, want)
	}
	if ds.Info.DefaultArtifacts == nil {
		t.Fatal("Info.DefaultArtifacts = nil, want non-nil")
	}
	// FR-1: a rule's status is a status per default artifact slot, not a
	// single enum - the dataset documents exactly five slots for each of
	// FRR and KSI.
	if got, want := len(ds.Info.DefaultArtifacts.FRR), 5; got != want {
		t.Errorf("len(DefaultArtifacts.FRR) = %d, want %d", got, want)
	}
	if got, want := len(ds.Info.DefaultArtifacts.KSI), 5; got != want {
		t.Errorf("len(DefaultArtifacts.KSI) = %d, want %d", got, want)
	}
}

func TestLoadVendoredDatasetFRD(t *testing.T) {
	ds := loadVendoredDataset(t)

	def, ok := ds.FRD.Data.All["FRD-ACV"]
	if !ok {
		t.Fatal(`FRD.Data.All["FRD-ACV"] missing`)
	}
	if got, want := def.Term, "Accepted Vulnerability"; got != want {
		t.Errorf("FRD-ACV.Term = %q, want %q", got, want)
	}
	if len(def.Updated) == 0 {
		t.Error("FRD-ACV.Updated is empty, want at least one entry")
	}
}

func TestLoadVendoredDatasetFRR(t *testing.T) {
	ds := loadVendoredDataset(t)

	doc, ok := ds.FRR["AFC"]
	if !ok {
		t.Fatal(`FRR["AFC"] missing`)
	}
	if got, want := doc.Info.Name, "Addressing FedRAMP Communication"; got != want {
		t.Errorf("AFC.Info.Name = %q, want %q", got, want)
	}

	rule, ok := doc.Data.All["CSO"]["AFC-CSO-INB"]
	if !ok {
		t.Fatal(`FRR["AFC"].Data.All["CSO"]["AFC-CSO-INB"] missing`)
	}
	if got, want := rule.Force, ForceMust; got != want {
		t.Errorf("AFC-CSO-INB.Force = %q, want %q", got, want)
	}
	if rule.Artifacts == nil || len(rule.Artifacts.All) == 0 {
		t.Error("AFC-CSO-INB.Artifacts.All is empty, want at least one entry")
	}
}

func TestLoadVendoredDatasetFRRVariesByClass(t *testing.T) {
	ds := loadVendoredDataset(t)

	rule, ok := ds.FRR["CCM"].Data.All["QTR"]["CCM-QTR-MTG"]
	if !ok {
		t.Fatal(`FRR["CCM"].Data.All["QTR"]["CCM-QTR-MTG"] missing`)
	}
	if rule.Statement != "" {
		t.Errorf("CCM-QTR-MTG.Statement = %q, want empty (this rule varies by class)", rule.Statement)
	}
	if rule.VariesByClass == nil {
		t.Fatal("CCM-QTR-MTG.VariesByClass = nil, want non-nil")
	}
	c := rule.VariesByClass.C
	if c == nil {
		t.Fatal("CCM-QTR-MTG.VariesByClass.C = nil, want non-nil")
	}
	if got, want := c.Force, ForceMust; got != want {
		t.Errorf("CCM-QTR-MTG class C Force = %q, want %q", got, want)
	}
	if got, want := c.TimeframeType, TimeframeMonths; got != want {
		t.Errorf("CCM-QTR-MTG class C TimeframeType = %q, want %q", got, want)
	}
}

func TestLoadVendoredDatasetKSI(t *testing.T) {
	ds := loadVendoredDataset(t)

	theme, ok := ds.KSI["CED"]
	if !ok {
		t.Fatal(`KSI["CED"] missing`)
	}
	if got, want := theme.ID, "KSI-CED"; got != want {
		t.Errorf("KSI-CED.ID = %q, want %q", got, want)
	}

	indicator, ok := theme.Indicators["KSI-CED-RAT"]
	if !ok {
		t.Fatal(`KSI["CED"].Indicators["KSI-CED-RAT"] missing`)
	}
	ids, err := indicator.ControlIDs()
	if err != nil {
		t.Fatalf("KSI-CED-RAT.ControlIDs(): %v", err)
	}
	want := ControlID{Family: "AT", Base: 2}
	found := false
	for _, id := range ids {
		if id == want {
			found = true
		}
	}
	if !found {
		t.Errorf("KSI-CED-RAT.ControlIDs() = %v, want to contain %+v", ids, want)
	}
}

func TestLoadVendoredDatasetCTL(t *testing.T) {
	ds := loadVendoredDataset(t)

	fam, ok := ds.CTL["AC"]
	if !ok {
		t.Fatal(`CTL["AC"] missing`)
	}
	entry, ok := fam[ControlID{Family: "AC", Base: 6, Enhancement: 1}]
	if !ok {
		t.Fatal(`CTL["AC"][AC-06-01] missing`)
	}
	if len(entry.Parameters) == 0 {
		t.Fatal("AC-06-01.Parameters is empty, want at least one entry")
	}
	if got, want := entry.Parameters[0].ParameterID, "ac-06.01_odp.02"; got != want {
		t.Errorf("AC-06-01.Parameters[0].ParameterID = %q, want %q", got, want)
	}

	// Dataset.Control is the typed lookup surface across the two-level map.
	viaLookup, ok := ds.Control(ControlID{Family: "AC", Base: 6, Enhancement: 1})
	if !ok {
		t.Fatal("Dataset.Control(AC-06-01) not found")
	}
	if viaLookup.Parameters[0].ParameterID != entry.Parameters[0].ParameterID {
		t.Error("Dataset.Control lookup does not match direct map access")
	}
}

// TestLoadVendoredDatasetCounts is a coverage check against the full
// vendored file: it asserts the typed model surfaces exactly as many
// records as the raw JSON contains, so a decode bug that silently drops
// entries (e.g. one document's requirements shadowing another's under a
// wrong map key) shows up as a count mismatch instead of passing quietly.
func TestLoadVendoredDatasetCounts(t *testing.T) {
	ds := loadVendoredDataset(t)

	if got, want := len(ds.FRD.Data.All), 75; got != want {
		t.Errorf("len(FRD.Data.All) = %d, want %d", got, want)
	}
	if got, want := len(ds.FRR), 17; got != want {
		t.Errorf("len(FRR) = %d, want %d", got, want)
	}
	totalRules := 0
	for _, doc := range ds.FRR {
		for _, container := range doc.Data.Buckets() {
			for _, rules := range container {
				totalRules += len(rules)
			}
		}
	}
	if got, want := totalRules, 246; got != want {
		t.Errorf("total FRR rule entries = %d, want %d", got, want)
	}
	if got, want := len(ds.KSI), 10; got != want {
		t.Errorf("len(KSI) = %d, want %d", got, want)
	}
	totalIndicators := 0
	for _, theme := range ds.KSI {
		totalIndicators += len(theme.Indicators)
	}
	if got, want := totalIndicators, 46; got != want {
		t.Errorf("total KSI indicators = %d, want %d", got, want)
	}
	if got, want := len(ds.CTL), 14; got != want {
		t.Errorf("len(CTL) = %d, want %d", got, want)
	}
	totalControls := 0
	for _, fam := range ds.CTL {
		totalControls += len(fam)
	}
	if got, want := totalControls, 79; got != want {
		t.Errorf("total CTL control entries = %d, want %d", got, want)
	}
}

func TestLoadRejectsSchemaViolation(t *testing.T) {
	raw := `{"info": {"title": "x"}}`
	if _, err := Load([]byte(raw)); err == nil {
		t.Fatal("Load(incomplete dataset) succeeded, want error")
	}
}

// TestUnknownFieldsPreserved feeds a JSON object with a field the current
// FRDDefinition struct doesn't know about through decode and re-encode,
// and checks it survives - this is FR-1.1's "preserve unknown fields
// rather than dropping them" in its simplest, most direct form.
func TestUnknownFieldsPreserved(t *testing.T) {
	const input = `{
		"term": "Example Term",
		"definition": "An example.",
		"alts": [],
		"updated": [{"date": "2026-06-24", "comment": "initial"}],
		"a_field_from_a_future_schema_version": {"nested": [1, 2, 3]}
	}`

	var def FRDDefinition
	if err := json.Unmarshal([]byte(input), &def); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if def.Extra == nil {
		t.Fatal("Extra = nil, want the unknown field to be captured")
	}
	raw, ok := def.Extra["a_field_from_a_future_schema_version"]
	if !ok {
		t.Fatal(`Extra["a_field_from_a_future_schema_version"] missing`)
	}
	if got, want := string(raw), `{"nested": [1, 2, 3]}`; normalizeJSON(t, got) != normalizeJSON(t, want) {
		t.Errorf("Extra field = %s, want %s", got, want)
	}

	out, err := json.Marshal(def)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundTripped map[string]json.RawMessage
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		t.Fatalf("Unmarshal(re-encoded): %v", err)
	}
	if _, ok := roundTripped["a_field_from_a_future_schema_version"]; !ok {
		t.Error("re-encoded JSON dropped the unknown field")
	}
	if _, ok := roundTripped["term"]; !ok {
		t.Error("re-encoded JSON dropped a known field")
	}
}

func normalizeJSON(t *testing.T, s string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("normalizeJSON: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("normalizeJSON: %v", err)
	}
	return string(b)
}

// TestDatasetRoundTripPreservesUnknownTopLevelKey exercises the same
// preservation property at the Dataset level, since a future dataset
// version could add a sixth top-level section alongside info/FRD/FRR/KSI/CTL.
func TestDatasetRoundTripPreservesUnknownTopLevelKey(t *testing.T) {
	raw := readVendoredDataset(t)
	var ds Dataset
	if err := json.Unmarshal(raw, &ds); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	out, err := json.Marshal(ds)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var before, after map[string]json.RawMessage
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatalf("Unmarshal(raw): %v", err)
	}
	if err := json.Unmarshal(out, &after); err != nil {
		t.Fatalf("Unmarshal(re-encoded): %v", err)
	}
	for key := range before {
		if _, ok := after[key]; !ok {
			t.Errorf("re-encoded dataset lost top-level key %q", key)
		}
	}
}
