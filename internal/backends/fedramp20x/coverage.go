package fedramp20x

import "sort"

// CoverageReport is FR-6.7's truthfulness artifact: how many KSI
// indicators fall into each of the three buckets the requirement names -
// Automated, HumanAttested, NotVisible - overall and per family, sorted
// by family code so output stays reproducible regardless of map
// iteration order (Evaluate's own discipline, applied here too).
//
// Coverage is computed purely from IndicatorResult.Status, the same
// output Evaluate already produces for every indicator in the dataset
// (docs/adr/0007) - this file adds no new compliance judgment, only
// aggregation. RequiresAttestation and NotSatisfied are both real
// statuses no family returns yet, but CoverageReport accounts for them
// by name now so its shape never has to change once a family starts
// returning them.
type CoverageReport struct {
	Overall  CoverageBucket   `json:"overall"`
	Families []FamilyCoverage `json:"families"`
}

// FamilyCoverage is one KSI family's CoverageBucket, named.
type FamilyCoverage struct {
	Family string `json:"family"`
	CoverageBucket
}

// CoverageBucket counts indicators by which of FR-6.7's three buckets
// they fall into, plus NotApplicable tracked separately since it isn't
// one of the three - an indicator with no controls in the dataset isn't
// "not visible," it's out of scope.
//
// Applicable and PercentAutomated exclude NotApplicable from the
// denominator: REQUIREMENTS.md section 17.1's exit criterion ("60% of
// applicable rules evidenced automatically") means exactly this by
// "applicable." PercentAutomated is 0 when Applicable is 0, never a
// division by zero.
type CoverageBucket struct {
	// Automated is Satisfied or NotSatisfied: the compiler reached a
	// real verdict, mechanically, one way or the other.
	Automated int `json:"automated"`
	// HumanAttested is RequiresAttestation: determinately outside what
	// any compiler can observe (docs/crosswalk-analysis.md section 9),
	// not a collection gap.
	HumanAttested int `json:"human_attested"`
	// NotVisible is Undetermined: a real gap today - missing evidence,
	// or no Rego module implemented yet for the family.
	NotVisible int `json:"not_visible"`
	// NotApplicable is indicators with no associated controls in the
	// dataset. Excluded from Applicable and PercentAutomated.
	NotApplicable int `json:"not_applicable"`
	// Applicable is Automated + HumanAttested + NotVisible.
	Applicable int `json:"applicable"`
	// PercentAutomated is Automated / Applicable * 100.
	PercentAutomated float64 `json:"percent_automated"`
}

// Coverage aggregates results into a CoverageReport, overall and per
// family. results is Evaluate's own output - one row per indicator in
// the dataset, always (docs/adr/0007) - so every family the dataset
// defines appears in Families even if every one of its indicators is
// NotVisible today.
func Coverage(results []IndicatorResult) CoverageReport {
	overall := &CoverageBucket{}
	byFamily := make(map[string]*CoverageBucket)
	for _, r := range results {
		b, ok := byFamily[r.Family]
		if !ok {
			b = &CoverageBucket{}
			byFamily[r.Family] = b
		}
		tally(b, r.Status)
		tally(overall, r.Status)
	}
	finalize(overall)

	families := make([]string, 0, len(byFamily))
	for f := range byFamily {
		families = append(families, f)
	}
	sort.Strings(families)

	report := CoverageReport{Overall: *overall}
	for _, f := range families {
		b := byFamily[f]
		finalize(b)
		report.Families = append(report.Families, FamilyCoverage{Family: f, CoverageBucket: *b})
	}
	return report
}

func tally(b *CoverageBucket, status Status) {
	switch status {
	case StatusSatisfied, StatusNotSatisfied:
		b.Automated++
	case StatusRequiresAttestation:
		b.HumanAttested++
	case StatusUndetermined:
		b.NotVisible++
	case StatusNotApplicable:
		b.NotApplicable++
	}
}

func finalize(b *CoverageBucket) {
	b.Applicable = b.Automated + b.HumanAttested + b.NotVisible
	if b.Applicable > 0 {
		b.PercentAutomated = float64(b.Automated) / float64(b.Applicable) * 100
	}
}
