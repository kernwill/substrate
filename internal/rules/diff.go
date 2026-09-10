package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// ChangeKind classifies how one record differs between two dataset versions.
type ChangeKind string

const (
	Added    ChangeKind = "added"
	Removed  ChangeKind = "removed"
	Modified ChangeKind = "modified"
)

// Section names which part of the dataset a DiffEntry belongs to.
type Section string

const (
	SectionFRD Section = "FRD"
	SectionFRR Section = "FRR"
	SectionKSI Section = "KSI"
	SectionCTL Section = "CTL"
)

// DiffEntry is one added, removed, or modified record between two dataset
// versions. ID is the record's own stable identifier - FRD-XXX, a full FRR
// rule ID such as AFC-CSO-INB, a KSI indicator ID such as KSI-IAM-AAM, or
// a control's CTLKey() such as AC-06-01 - not a tree path, since a rule,
// definition, indicator, or control's location (which document, subset, or
// family it lives under) can move between dataset versions without its ID
// changing; per the FedRAMP rules repo's own guidance, that is a content
// change to describe, not grounds to lose track of the record entirely.
//
// Before and After hold the record's own JSON (an FRDDefinition,
// FRRRequirement, KSIIndicator, or ControlEntry, depending on Section),
// omitted on the side that doesn't apply: Before is absent for Added,
// After is absent for Removed.
type DiffEntry struct {
	Section Section         `json:"section"`
	ID      string          `json:"id"`
	Change  ChangeKind      `json:"change"`
	Before  json.RawMessage `json:"before,omitempty"`
	After   json.RawMessage `json:"after,omitempty"`
}

// Diff is the structured result of comparing two dataset versions (FR-1.4).
type Diff struct {
	FromVersion string      `json:"from_version"`
	ToVersion   string      `json:"to_version"`
	Entries     []DiffEntry `json:"entries"`
}

// Added returns only Diff's added entries, in Diff's stable sort order
// (by Section, then ID).
func (d Diff) Added() []DiffEntry { return d.filter(Added) }

// Removed returns only Diff's removed entries.
func (d Diff) Removed() []DiffEntry { return d.filter(Removed) }

// Modified returns only Diff's modified entries.
func (d Diff) Modified() []DiffEntry { return d.filter(Modified) }

func (d Diff) filter(kind ChangeKind) []DiffEntry {
	var out []DiffEntry
	for _, e := range d.Entries {
		if e.Change == kind {
			out = append(out, e)
		}
	}
	return out
}

// DiffDatasets compares from against to and returns a structured diff of
// FRD definitions, FRR rules, KSI indicators, and CTL control entries.
// Content equality is determined by comparing each record's own JSON
// encoding, which - because every type in this package preserves unknown
// fields (see unknownfields.go) - also catches a change that only touches
// a field this package's struct doesn't yet model by name.
func DiffDatasets(from, to *Dataset) (Diff, error) {
	diff := Diff{FromVersion: from.Info.Version, ToVersion: to.Info.Version}

	frdEntries, err := diffSection(SectionFRD, flattenFRD, from, to)
	if err != nil {
		return Diff{}, err
	}
	diff.Entries = append(diff.Entries, frdEntries...)

	frrEntries, err := diffSection(SectionFRR, flattenFRR, from, to)
	if err != nil {
		return Diff{}, err
	}
	diff.Entries = append(diff.Entries, frrEntries...)

	ksiEntries, err := diffSection(SectionKSI, flattenKSI, from, to)
	if err != nil {
		return Diff{}, err
	}
	diff.Entries = append(diff.Entries, ksiEntries...)

	ctlEntries, err := diffSection(SectionCTL, flattenCTL, from, to)
	if err != nil {
		return Diff{}, err
	}
	diff.Entries = append(diff.Entries, ctlEntries...)

	sort.Slice(diff.Entries, func(i, j int) bool {
		a, b := diff.Entries[i], diff.Entries[j]
		if a.Section != b.Section {
			return a.Section < b.Section
		}
		return a.ID < b.ID
	})
	return diff, nil
}

// diffSection flattens from and to with flatten and diffs the two
// resulting ID-keyed maps under section. DiffDatasets repeated this exact
// shape - flatten from, flatten to, wrap each error with which side it
// came from, diff, append - once per section (FRD, FRR, KSI, CTL); the
// only thing that ever varied was flatten and section, which is exactly
// what generics are for here.
func diffSection[T any](section Section, flatten func(*Dataset) (map[string]T, error), from, to *Dataset) ([]DiffEntry, error) {
	f, err := flatten(from)
	if err != nil {
		return nil, fmt.Errorf("rules: diff: from dataset: %w", err)
	}
	t, err := flatten(to)
	if err != nil {
		return nil, fmt.Errorf("rules: diff: to dataset: %w", err)
	}
	return diffRecords(section, f, t)
}

// diffRecords compares two ID-keyed maps of the same record type and
// returns added, removed, and modified entries.
func diffRecords[T any](section Section, from, to map[string]T) ([]DiffEntry, error) {
	var entries []DiffEntry
	for id, a := range from {
		rawA, err := marshalJSON(a)
		if err != nil {
			return nil, err
		}
		b, ok := to[id]
		if !ok {
			entries = append(entries, DiffEntry{Section: section, ID: id, Change: Removed, Before: rawA})
			continue
		}
		rawB, err := marshalJSON(b)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(rawA, rawB) {
			entries = append(entries, DiffEntry{Section: section, ID: id, Change: Modified, Before: rawA, After: rawB})
		}
	}
	for id, b := range to {
		if _, ok := from[id]; ok {
			continue
		}
		rawB, err := marshalJSON(b)
		if err != nil {
			return nil, err
		}
		entries = append(entries, DiffEntry{Section: section, ID: id, Change: Added, After: rawB})
	}
	return entries, nil
}

// insertUnique adds id/v to m, or returns an error naming the collision
// if id is already present. kind labels the record type in that error
// (e.g. "FRD definition"). Flattening a dataset into an ID-keyed map
// only preserves every record if IDs really are unique; silently letting
// a later entry overwrite an earlier one on collision would violate
// this project's "no map iteration order dependence" and "fail visible,
// never fail silent" invariants at once - which entry survives would
// depend on Go's randomized map iteration order, and the loss would be
// invisible in the diff output.
func insertUnique[T any](m map[string]T, id string, v T, kind string) error {
	if _, exists := m[id]; exists {
		return fmt.Errorf("rules: duplicate %s ID %q found in more than one location", kind, id)
	}
	m[id] = v
	return nil
}

// idValue pairs a record with the ID flattenUnique should key it by -
// the intermediate form each flatten* function collects into before
// calling flattenUnique, since each has its own nested nesting shape
// (buckets, documents, themes, families) to walk to find its IDs.
type idValue[T any] struct {
	id  string
	val T
}

// flattenUnique builds an ID-keyed map from pairs, in ascending ID order,
// failing via insertUnique on the first collision found in that order.
// Sorting before inserting - rather than inserting in whatever order the
// caller's own nested source maps happened to iterate in, which Go
// randomizes per run - makes which duplicate ID gets named in the
// resulting error deterministic across runs, not just whether an error
// occurs at all: two datasets with the same set of duplicate IDs must
// report the same offending ID every time, not whichever one a given
// run's map iteration happened to reach first.
func flattenUnique[T any](kind string, pairs []idValue[T]) (map[string]T, error) {
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].id < pairs[j].id })
	out := make(map[string]T, len(pairs))
	for _, p := range pairs {
		if err := insertUnique(out, p.id, p.val, kind); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// flattenFRD flattens FRD definitions across all three applicability
// buckets (all/20x/rev5) into one ID-keyed map. A given FRD-XXX is
// expected to live in exactly one bucket.
func flattenFRD(ds *Dataset) (map[string]FRDDefinition, error) {
	var pairs []idValue[FRDDefinition]
	for _, bucket := range ds.FRD.Data.Buckets() {
		for id, def := range bucket {
			pairs = append(pairs, idValue[FRDDefinition]{id, def})
		}
	}
	return flattenUnique("FRD definition", pairs)
}

// flattenFRR flattens FRR rules across every document, applicability
// bucket, and subset into one ID-keyed map. Requirement IDs follow
// PROCESS-SUBSET-KEY and are unique across the whole dataset by
// construction (verified against the vendored dataset in diff_test.go),
// so no document or bucket qualifier is needed in the key - but that's a
// fact about today's vendored dataset, not something the schema
// enforces, hence insertUnique rather than a bare map write.
func flattenFRR(ds *Dataset) (map[string]FRRRequirement, error) {
	var pairs []idValue[FRRRequirement]
	for _, doc := range ds.FRR {
		for _, container := range doc.Data.Buckets() {
			for _, rules := range container {
				for id, rule := range rules {
					pairs = append(pairs, idValue[FRRRequirement]{id, rule})
				}
			}
		}
	}
	return flattenUnique("FRR rule", pairs)
}

// flattenKSI flattens KSI indicators across every theme into one
// ID-keyed map. Indicator IDs follow KSI-THEME-KEY and are unique across
// the whole dataset by construction, though - as with FRR above - that's
// not schema-enforced, hence insertUnique.
func flattenKSI(ds *Dataset) (map[string]KSIIndicator, error) {
	var pairs []idValue[KSIIndicator]
	for _, theme := range ds.KSI {
		for id, ind := range theme.Indicators {
			pairs = append(pairs, idValue[KSIIndicator]{id, ind})
		}
	}
	return flattenUnique("KSI indicator", pairs)
}

// flattenCTL flattens CTL control entries across every family into one
// map keyed by each ControlID's CTLKey() form, e.g. "AC-06-01". The
// schema's pattern for a nested control key ("^[A-Z]{2}-\d{2}...$")
// doesn't actually require its two-letter prefix to match the family
// object it's nested under, so two different families could in
// principle both contain a key that parses to the same ControlID -
// hence insertUnique rather than a bare map write here too.
func flattenCTL(ds *Dataset) (map[string]ControlEntry, error) {
	var pairs []idValue[ControlEntry]
	for _, fam := range ds.CTL {
		for id, entry := range fam {
			pairs = append(pairs, idValue[ControlEntry]{id.CTLKey(), entry})
		}
	}
	return flattenUnique("CTL control", pairs)
}
