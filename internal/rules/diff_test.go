package rules

import (
	"encoding/json"
	"testing"
)

// TestFRDFRRAndKSIIdsAreGloballyUnique backs flattenFRD's, flattenFRR's,
// and flattenKSI's doc comments: definition, requirement, and indicator
// IDs must be unique across the whole vendored dataset, not just within
// one bucket, document, or theme, or flattening them into a single
// ID-keyed map for diffing would silently drop collisions. (insertUnique
// would also catch this at diff time with a loud error - this test
// additionally confirms today's vendored dataset never actually
// triggers it.)
func TestFRDFRRAndKSIIdsAreGloballyUnique(t *testing.T) {
	ds := loadVendoredDataset(t)

	seenFRD := map[string]bool{}
	frdCount := 0
	for _, bucket := range []map[string]FRDDefinition{ds.FRD.Data.All, ds.FRD.Data.TwentyX, ds.FRD.Data.Rev5} {
		for id := range bucket {
			if seenFRD[id] {
				t.Errorf("FRD definition ID %q is not globally unique across applicability buckets", id)
			}
			seenFRD[id] = true
			frdCount++
		}
	}
	if frdCount == 0 {
		t.Fatal("no FRD definitions found at all")
	}

	seen := map[string]bool{}
	count := 0
	for docKey, doc := range ds.FRR {
		for _, container := range []map[string]map[string]FRRRequirement{doc.Data.All, doc.Data.TwentyX, doc.Data.Rev5} {
			for subsetKey, rules := range container {
				for id := range rules {
					if seen[id] {
						t.Errorf("FRR rule ID %q is not globally unique (seen again under %s/%s)", id, docKey, subsetKey)
					}
					seen[id] = true
					count++
				}
			}
		}
	}
	if count == 0 {
		t.Fatal("no FRR rules found at all")
	}

	seenKSI := map[string]bool{}
	ksiCount := 0
	for themeKey, theme := range ds.KSI {
		for id := range theme.Indicators {
			if seenKSI[id] {
				t.Errorf("KSI indicator ID %q is not globally unique (seen again under %s)", id, themeKey)
			}
			seenKSI[id] = true
			ksiCount++
		}
	}
	if ksiCount == 0 {
		t.Fatal("no KSI indicators found at all")
	}
}

// TestDiffDatasetsFailsLoudlyOnDuplicateID proves DiffDatasets returns an
// error - rather than silently letting one colliding record overwrite
// another via map assignment - when the same ID appears twice within a
// section. Constructed via FRD, whose data container has three
// applicability buckets (all/20x/rev5) a duplicate could span, unlike
// the vendored dataset today which only ever populates "all".
func TestDiffDatasetsFailsLoudlyOnDuplicateID(t *testing.T) {
	ds := loadVendoredDataset(t)
	modified := mustClone(t, ds)

	dup := modified.FRD.Data.All["FRD-ACV"]
	modified.FRD.Data.TwentyX = map[string]FRDDefinition{"FRD-ACV": dup}

	if _, err := DiffDatasets(ds, modified); err == nil {
		t.Fatal("DiffDatasets succeeded with FRD-ACV duplicated across two applicability buckets, want an error")
	}
}

func TestDiffDatasetsIdentical(t *testing.T) {
	ds := loadVendoredDataset(t)
	diff, err := DiffDatasets(ds, ds)
	if err != nil {
		t.Fatalf("DiffDatasets: %v", err)
	}
	if len(diff.Entries) != 0 {
		t.Fatalf("diffing a dataset against itself produced %d entries, want 0", len(diff.Entries))
	}
	if diff.FromVersion != ds.Info.Version || diff.ToVersion != ds.Info.Version {
		t.Errorf("FromVersion=%q ToVersion=%q, want both %q", diff.FromVersion, diff.ToVersion, ds.Info.Version)
	}
}

// mustClone round-trips ds through JSON to get an independent deep copy,
// so mutating the copy can never affect the original loaded dataset that
// other tests in this package share.
func mustClone(t *testing.T, ds *Dataset) *Dataset {
	t.Helper()
	raw, err := json.Marshal(ds)
	if err != nil {
		t.Fatalf("marshal dataset for clone: %v", err)
	}
	var clone Dataset
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatalf("unmarshal dataset clone: %v", err)
	}
	return &clone
}

// TestDiffDatasetsAgainstSyntheticallyModifiedCopy is T-007's specific
// done criterion: diff the real vendored dataset against a copy this
// test deliberately mutates (add/remove/modify one record per section),
// and check the structured output is exactly right.
func TestDiffDatasetsAgainstSyntheticallyModifiedCopy(t *testing.T) {
	original := loadVendoredDataset(t)
	modified := mustClone(t, original)

	// FRD: modify one, remove one, add one.
	acv := modified.FRD.Data.All["FRD-ACV"]
	acv.Definition = acv.Definition + " (synthetically modified for testing)"
	modified.FRD.Data.All["FRD-ACV"] = acv
	delete(modified.FRD.Data.All, "FRD-AAP")
	modified.FRD.Data.All["FRD-ZZZ"] = FRDDefinition{
		Term:       "Synthetic Term",
		Definition: "A definition added only for this test.",
		Alts:       []string{},
		Updated:    []UpdatedEntry{{Date: "2026-01-01", Comment: "synthetic"}},
	}

	// FRR: modify one (flip force), remove one, add one.
	inb := modified.FRR["AFC"].Data.All["CSO"]["AFC-CSO-INB"]
	inb.Force = ForceShould
	modified.FRR["AFC"].Data.All["CSO"]["AFC-CSO-INB"] = inb
	delete(modified.FRR["AFC"].Data.All["CSO"], "AFC-CSO-ACK")
	modified.FRR["AFC"].Data.All["CSO"]["AFC-CSO-ZZZ"] = FRRRequirement{
		Name:      "Synthetic Rule",
		Statement: "Providers MUST do the synthetic thing.",
		Force:     ForceMust,
		Affects:   []AffectedParty{AffectsProviders},
		Updated:   []UpdatedEntry{{Date: "2026-01-01", Comment: "synthetic"}},
	}

	// KSI: modify one, remove one, add one.
	ced := modified.KSI["CED"]
	rat := ced.Indicators["KSI-CED-RAT"]
	rat.Statement = rat.Statement + " (synthetically modified for testing)"
	ced.Indicators["KSI-CED-RAT"] = rat
	scr := modified.KSI["SCR"]
	for id := range scr.Indicators {
		delete(scr.Indicators, id)
		break
	}
	ced.Indicators["KSI-CED-ZZZ"] = KSIIndicator{
		Name:      "Synthetic Indicator",
		Statement: "A synthetic KSI indicator added only for this test.",
		Controls:  []string{"ac-2"},
		Updated:   []UpdatedEntry{{Date: "2026-01-01", Comment: "synthetic"}},
	}
	modified.KSI["CED"] = ced

	// CTL: modify one, remove one, add one.
	acFam := modified.CTL["AC"]
	target := ControlID{Family: "AC", Base: 6, Enhancement: 1}
	entry := acFam[target]
	entry.Guidance = append(entry.Guidance, "Synthetically modified guidance for testing.")
	acFam[target] = entry
	delete(acFam, ControlID{Family: "AC", Base: 20})
	acFam[ControlID{Family: "AC", Base: 99}] = ControlEntry{
		Guidance: []string{"Synthetic control added only for this test."},
	}
	modified.CTL["AC"] = acFam

	diff, err := DiffDatasets(original, modified)
	if err != nil {
		t.Fatalf("DiffDatasets: %v", err)
	}

	checkEntry := func(section Section, id string, want ChangeKind) {
		t.Helper()
		for _, e := range diff.Entries {
			if e.Section == section && e.ID == id {
				if e.Change != want {
					t.Errorf("%s/%s: Change = %q, want %q", section, id, e.Change, want)
				}
				return
			}
		}
		t.Errorf("%s/%s: no diff entry found, want Change=%q", section, id, want)
	}

	checkEntry(SectionFRD, "FRD-ACV", Modified)
	checkEntry(SectionFRD, "FRD-AAP", Removed)
	checkEntry(SectionFRD, "FRD-ZZZ", Added)

	checkEntry(SectionFRR, "AFC-CSO-INB", Modified)
	checkEntry(SectionFRR, "AFC-CSO-ACK", Removed)
	checkEntry(SectionFRR, "AFC-CSO-ZZZ", Added)

	checkEntry(SectionKSI, "KSI-CED-RAT", Modified)
	checkEntry(SectionKSI, "KSI-CED-ZZZ", Added)

	checkEntry(SectionCTL, "AC-06-01", Modified)
	checkEntry(SectionCTL, "AC-20", Removed)
	checkEntry(SectionCTL, "AC-99", Added)

	// Exactly one KSI indicator was removed, from whichever family the
	// loop above happened to touch first - check by count, not by ID,
	// since map iteration order picked it.
	removedKSI := 0
	for _, e := range diff.Removed() {
		if e.Section == SectionKSI {
			removedKSI++
		}
	}
	if removedKSI != 1 {
		t.Errorf("removed KSI entries = %d, want 1", removedKSI)
	}

	// Nothing outside the sections above should show up as changed.
	wantCounts := map[Section]struct{ added, removed, modified int }{
		SectionFRD: {1, 1, 1},
		SectionFRR: {1, 1, 1},
		SectionKSI: {1, 1, 1},
		SectionCTL: {1, 1, 1},
	}
	gotCounts := map[Section]struct{ added, removed, modified int }{}
	for _, e := range diff.Entries {
		c := gotCounts[e.Section]
		switch e.Change {
		case Added:
			c.added++
		case Removed:
			c.removed++
		case Modified:
			c.modified++
		}
		gotCounts[e.Section] = c
	}
	for section, want := range wantCounts {
		got := gotCounts[section]
		if got != want {
			t.Errorf("%s counts = %+v, want %+v", section, got, want)
		}
	}
}

func TestDiffEntryFiltersAndBeforeAfterPayload(t *testing.T) {
	original := loadVendoredDataset(t)
	modified := mustClone(t, original)

	acv := modified.FRD.Data.All["FRD-ACV"]
	acv.Definition = "replaced definition"
	modified.FRD.Data.All["FRD-ACV"] = acv
	delete(modified.FRD.Data.All, "FRD-AAP")
	modified.FRD.Data.All["FRD-ZZZ"] = FRDDefinition{
		Term:       "Synthetic",
		Definition: "synthetic",
		Alts:       []string{},
		Updated:    []UpdatedEntry{{Date: "2026-01-01", Comment: "synthetic"}},
	}

	diff, err := DiffDatasets(original, modified)
	if err != nil {
		t.Fatalf("DiffDatasets: %v", err)
	}

	added := diff.Added()
	removed := diff.Removed()
	modifiedEntries := diff.Modified()
	if len(added) == 0 || len(removed) == 0 || len(modifiedEntries) == 0 {
		t.Fatalf("expected at least one of each kind; got added=%d removed=%d modified=%d", len(added), len(removed), len(modifiedEntries))
	}

	for _, e := range added {
		if e.ID == "FRD-ZZZ" {
			if len(e.Before) != 0 {
				t.Errorf("added entry %s has non-empty Before: %s", e.ID, e.Before)
			}
			var def FRDDefinition
			if err := json.Unmarshal(e.After, &def); err != nil {
				t.Fatalf("unmarshal After for %s: %v", e.ID, err)
			}
			if def.Term != "Synthetic" {
				t.Errorf("added entry %s After.Term = %q, want %q", e.ID, def.Term, "Synthetic")
			}
		}
	}
	for _, e := range removed {
		if e.ID == "FRD-AAP" && len(e.After) != 0 {
			t.Errorf("removed entry %s has non-empty After: %s", e.ID, e.After)
		}
	}
	for _, e := range modifiedEntries {
		if e.ID == "FRD-ACV" {
			if len(e.Before) == 0 || len(e.After) == 0 {
				t.Fatalf("modified entry %s missing Before or After", e.ID)
			}
			var before, after FRDDefinition
			if err := json.Unmarshal(e.Before, &before); err != nil {
				t.Fatalf("unmarshal Before: %v", err)
			}
			if err := json.Unmarshal(e.After, &after); err != nil {
				t.Fatalf("unmarshal After: %v", err)
			}
			if after.Definition != "replaced definition" {
				t.Errorf("modified entry %s After.Definition = %q, want %q", e.ID, after.Definition, "replaced definition")
			}
			if before.Definition == after.Definition {
				t.Errorf("modified entry %s Before and After are identical", e.ID)
			}
		}
	}
}

func TestDiffEntriesSortedBySectionThenID(t *testing.T) {
	original := loadVendoredDataset(t)
	modified := mustClone(t, original)
	delete(modified.FRD.Data.All, "FRD-AAP")
	delete(modified.FRR["AFC"].Data.All["CSO"], "AFC-CSO-ACK")

	diff, err := DiffDatasets(original, modified)
	if err != nil {
		t.Fatalf("DiffDatasets: %v", err)
	}
	for i := 1; i < len(diff.Entries); i++ {
		a, b := diff.Entries[i-1], diff.Entries[i]
		if a.Section > b.Section || (a.Section == b.Section && a.ID > b.ID) {
			t.Fatalf("not sorted: entry %d = %+v comes before %+v", i, a, b)
		}
	}
}
