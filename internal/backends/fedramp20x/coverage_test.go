package fedramp20x

import "testing"

func TestCoverageBucketsByStatus(t *testing.T) {
	results := []IndicatorResult{
		{Indicator: "KSI-SVC-A", Family: "SVC", Status: StatusSatisfied},
		{Indicator: "KSI-SVC-B", Family: "SVC", Status: StatusNotSatisfied},
		{Indicator: "KSI-SVC-C", Family: "SVC", Status: StatusUndetermined},
		{Indicator: "KSI-IAM-A", Family: "IAM", Status: StatusRequiresAttestation},
		{Indicator: "KSI-IAM-B", Family: "IAM", Status: StatusNotApplicable},
	}

	got := Coverage(results)

	want := CoverageBucket{
		Automated:        2,
		HumanAttested:    1,
		NotVisible:       1,
		NotApplicable:    1,
		Applicable:       4, // excludes the one NotApplicable
		PercentAutomated: 50,
	}
	if got.Overall != want {
		t.Fatalf("Overall = %+v, want %+v", got.Overall, want)
	}
}

func TestCoveragePerFamilySortedAndIndependent(t *testing.T) {
	results := []IndicatorResult{
		{Indicator: "KSI-SVC-A", Family: "SVC", Status: StatusSatisfied},
		{Indicator: "KSI-IAM-A", Family: "IAM", Status: StatusUndetermined},
		{Indicator: "KSI-IAM-B", Family: "IAM", Status: StatusUndetermined},
	}

	got := Coverage(results)

	if len(got.Families) != 2 {
		t.Fatalf("len(Families) = %d, want 2", len(got.Families))
	}
	// IAM sorts before SVC.
	if got.Families[0].Family != "IAM" || got.Families[1].Family != "SVC" {
		t.Fatalf("Families order = %v, want [IAM, SVC]", []string{got.Families[0].Family, got.Families[1].Family})
	}
	if got.Families[0].NotVisible != 2 || got.Families[0].Automated != 0 {
		t.Fatalf("IAM bucket = %+v, want NotVisible=2, Automated=0", got.Families[0].CoverageBucket)
	}
	if got.Families[1].Automated != 1 {
		t.Fatalf("SVC bucket = %+v, want Automated=1", got.Families[1].CoverageBucket)
	}
	// Per-family buckets must not leak into each other's counts.
	if got.Families[0].PercentAutomated != 0 {
		t.Fatalf("IAM PercentAutomated = %v, want 0", got.Families[0].PercentAutomated)
	}
	if got.Families[1].PercentAutomated != 100 {
		t.Fatalf("SVC PercentAutomated = %v, want 100", got.Families[1].PercentAutomated)
	}
}

func TestCoverageEmptyResultsNoDivideByZero(t *testing.T) {
	got := Coverage(nil)
	if got.Overall.Applicable != 0 || got.Overall.PercentAutomated != 0 {
		t.Fatalf("Overall = %+v, want zero-valued", got.Overall)
	}
	if len(got.Families) != 0 {
		t.Fatalf("Families = %v, want empty", got.Families)
	}
}

func TestCoverageAllNotApplicableYieldsZeroPercentNotNaN(t *testing.T) {
	results := []IndicatorResult{
		{Indicator: "KSI-X-A", Family: "X", Status: StatusNotApplicable},
	}
	got := Coverage(results)
	if got.Overall.Applicable != 0 {
		t.Fatalf("Applicable = %d, want 0", got.Overall.Applicable)
	}
	if got.Overall.PercentAutomated != 0 {
		t.Fatalf("PercentAutomated = %v, want 0", got.Overall.PercentAutomated)
	}
}

// TestCoverageMatchesRealEvaluatorTodayHonestly locks in the current,
// disclosed state of the backend (docs/adr/0007): against real
// collector output, every indicator in every family - including
// KSI-SVC, the one family with a real Rego module - reads Undetermined,
// so overall PercentAutomated is 0 today. This test is meant to break
// the moment that stops being true, the same way
// TestEvaluateSVCAgainstRealCollectors already does for Evaluate itself.
func TestCoverageMatchesRealEvaluatorTodayHonestly(t *testing.T) {
	results := []IndicatorResult{
		{Indicator: "KSI-SVC-A", Family: "SVC", Status: StatusUndetermined},
		{Indicator: "KSI-IAM-A", Family: "IAM", Status: StatusUndetermined},
	}
	got := Coverage(results)
	if got.Overall.Automated != 0 || got.Overall.HumanAttested != 0 {
		t.Fatalf("Overall = %+v, want Automated=0, HumanAttested=0", got.Overall)
	}
	if got.Overall.PercentAutomated != 0 {
		t.Fatalf("PercentAutomated = %v, want 0", got.Overall.PercentAutomated)
	}
}
