package rules

import "testing"

func resultIDs(results []RuleResult) map[string]bool {
	ids := make(map[string]bool, len(results))
	for _, r := range results {
		ids[r.ID] = true
	}
	return ids
}

func mustQueryRules(t *testing.T, ds *Dataset, q RuleQuery) []RuleResult {
	t.Helper()
	results, err := ds.QueryRules(q)
	if err != nil {
		t.Fatalf("QueryRules(%+v): %v", q, err)
	}
	return results
}

func TestQueryRulesNoFilterExcludesNonStableByDefault(t *testing.T) {
	ds := loadVendoredDataset(t)
	results := mustQueryRules(t, ds, RuleQuery{})
	ids := resultIDs(results)
	for id := range ids {
		if len(id) >= 3 && id[:3] == "AGU" {
			t.Fatalf("QueryRules({}) included %q from AGU, a placeholder-status document, without IncludeNonStable", id)
		}
	}
	if len(results) == 0 {
		t.Fatal("QueryRules({}) returned no rules at all")
	}
}

func TestQueryRulesIncludeNonStableAddsPlaceholderDoc(t *testing.T) {
	ds := loadVendoredDataset(t)
	without := mustQueryRules(t, ds, RuleQuery{})
	with := mustQueryRules(t, ds, RuleQuery{IncludeNonStable: true})
	if len(with) <= len(without) {
		t.Fatalf("QueryRules({IncludeNonStable: true}) returned %d rules, want more than the %d from the default query", len(with), len(without))
	}
	ids := resultIDs(with)
	if !ids["AGU-AGC-AIP"] {
		t.Fatal("QueryRules({IncludeNonStable: true}) is missing AGU-AGC-AIP")
	}
}

func TestQueryRulesClassFilterUsesRuleLevelOverride(t *testing.T) {
	ds := loadVendoredDataset(t)
	results := mustQueryRules(t, ds, RuleQuery{Class: ClassA})
	ids := resultIDs(results)

	// CCM-QTR-MTG's subset (QTR) declares classes B/C/D only, but the
	// rule itself defines an explicit "a" entry in varies_by_class. The
	// class filter must honor the rule-level override, not the coarser
	// subset-level field, or this rule would wrongly disappear from a
	// --class A query.
	if !ids["CCM-QTR-MTG"] {
		t.Error(`QueryRules({Class: ClassA}) is missing "CCM-QTR-MTG", whose varies_by_class explicitly covers class A`)
	}

	// AFC-CSO-INB has no varies_by_class at all, and its subset (CSO)
	// declares classes B/C/D - it should NOT show up under a Class A
	// query, since there is no signal anywhere that it applies to A.
	if ids["AFC-CSO-INB"] {
		t.Error(`QueryRules({Class: ClassA}) included "AFC-CSO-INB", which has no Class A applicability`)
	}
}

func TestQueryRulesClassFilterMatchesUniformSubsetRules(t *testing.T) {
	ds := loadVendoredDataset(t)
	results := mustQueryRules(t, ds, RuleQuery{Class: ClassC})
	ids := resultIDs(results)
	if !ids["AFC-CSO-INB"] {
		t.Error(`QueryRules({Class: ClassC}) is missing "AFC-CSO-INB" (uniform rule, subset covers B/C/D)`)
	}
}

func TestQueryRulesTypeFilterIncludesSharedAndTypeSpecificRules(t *testing.T) {
	ds := loadVendoredDataset(t)
	results := mustQueryRules(t, ds, RuleQuery{Type: Certification20x})
	ids := resultIDs(results)

	// CPO-CSX-CPM lives under CPO's "20x" container - 20x-specific.
	if !ids["CPO-CSX-CPM"] {
		t.Error(`QueryRules({Type: Certification20x}) is missing "CPO-CSX-CPM", a 20x-only rule`)
	}
	// AFC-CSO-INB lives under AFC's "all" container - shared, so it
	// must appear under a 20x-scoped query too.
	if !ids["AFC-CSO-INB"] {
		t.Error(`QueryRules({Type: Certification20x}) is missing "AFC-CSO-INB", a shared ("all") rule`)
	}

	rev5Only := mustQueryRules(t, ds, RuleQuery{Type: CertificationRev5})
	rev5IDs := resultIDs(rev5Only)
	if rev5IDs["CPO-CSX-CPM"] {
		t.Error(`QueryRules({Type: CertificationRev5}) included "CPO-CSX-CPM", a 20x-only rule`)
	}
	if !rev5IDs["AFC-CSO-INB"] {
		t.Error(`QueryRules({Type: CertificationRev5}) is missing "AFC-CSO-INB", a shared ("all") rule`)
	}
}

// TestQueryRulesTypeFilterAppliesWithinSharedContainer is a direct
// regression test for a bug the code-review's ultra pass found: the
// type filter was never actually checked against a subset's own
// applicability.types - only Path and Class were. That went undetected
// by TestQueryRulesTypeFilterIncludesSharedAndTypeSpecificRules above
// because AFC-CSO-INB's subset allows both 20x and Rev5, so it passed
// whether or not Types was actually being checked.
//
// FRC's "CLA" subset lives in the shared data.all bucket (like AFC-CSO)
// but its applicability.types is ["20x"] only; FRC's "CCL" and "APS"
// subsets, also in data.all, are ["Rev5"] only. Reproduced live before
// the fix: `substrate rules show --type Rev5` included FRC-CLA-ASF, and
// `--type 20x` included FRC-CCL-DCC and FRC-APS-ATO.
func TestQueryRulesTypeFilterAppliesWithinSharedContainer(t *testing.T) {
	ds := loadVendoredDataset(t)

	twentyX := resultIDs(mustQueryRules(t, ds, RuleQuery{Type: Certification20x}))
	if !twentyX["FRC-CLA-ASF"] {
		t.Error(`QueryRules({Type: Certification20x}) is missing "FRC-CLA-ASF" (subset CLA is 20x-only, in the shared "all" container)`)
	}
	if twentyX["FRC-CCL-DCC"] {
		t.Error(`QueryRules({Type: Certification20x}) included "FRC-CCL-DCC", whose subset (CCL) is Rev5-only`)
	}
	if twentyX["FRC-APS-ATO"] {
		t.Error(`QueryRules({Type: Certification20x}) included "FRC-APS-ATO", whose subset (APS) is Rev5-only`)
	}

	rev5 := resultIDs(mustQueryRules(t, ds, RuleQuery{Type: CertificationRev5}))
	if rev5["FRC-CLA-ASF"] {
		t.Error(`QueryRules({Type: CertificationRev5}) included "FRC-CLA-ASF", whose subset (CLA) is 20x-only`)
	}
	if !rev5["FRC-CCL-DCC"] {
		t.Error(`QueryRules({Type: CertificationRev5}) is missing "FRC-CCL-DCC" (subset CCL is Rev5-only, in the shared "all" container)`)
	}
	if !rev5["FRC-APS-ATO"] {
		t.Error(`QueryRules({Type: CertificationRev5}) is missing "FRC-APS-ATO" (subset APS is Rev5-only, in the shared "all" container)`)
	}
}

// TestQueryRulesTypeFilterExcludesEmptyApplicabilitySubsets pins down a
// real, deliberate (documented in matchRuleContainer) behavior: some
// stable subsets - MKT's IAS/CAS, all affecting Assessors/Advisors
// rather than Providers - have applicability.types as an empty array,
// not a populated one restricted to a single value like FRC's. A --type
// filter excludes these rules entirely, even though they show up fine
// unfiltered; this test exists so a future change to how empty
// applicability arrays are handled is a deliberate decision, not an
// accidental side effect noticed only by a golden-fixture diff.
func TestQueryRulesTypeFilterExcludesEmptyApplicabilitySubsets(t *testing.T) {
	ds := loadVendoredDataset(t)

	unfiltered := resultIDs(mustQueryRules(t, ds, RuleQuery{}))
	if !unfiltered["MKT-IAS-OFR"] {
		t.Fatal(`QueryRules({}) is missing "MKT-IAS-OFR" - test assumption invalid`)
	}

	twentyX := resultIDs(mustQueryRules(t, ds, RuleQuery{Type: Certification20x}))
	if twentyX["MKT-IAS-OFR"] {
		t.Error(`QueryRules({Type: Certification20x}) included "MKT-IAS-OFR", whose subset (IAS) has an empty applicability.types array`)
	}
	rev5 := resultIDs(mustQueryRules(t, ds, RuleQuery{Type: CertificationRev5}))
	if rev5["MKT-IAS-OFR"] {
		t.Error(`QueryRules({Type: CertificationRev5}) included "MKT-IAS-OFR", whose subset (IAS) has an empty applicability.types array`)
	}
}

// TestQueryRulesTypeFilterResolvesCommonSubsetFallback is a direct
// regression test for the bug the code-review's ultra pass found: VDR's
// "TFR" subset has an applicability definition only in the common
// info.subsets, never in info.20x.subsets or info.rev5.subsets, even
// though its rules are split into type-specific data.20x/data.rev5
// buckets. Without falling back to the common definition, these rules
// silently vanished from every query - filtered or not.
func TestQueryRulesTypeFilterResolvesCommonSubsetFallback(t *testing.T) {
	ds := loadVendoredDataset(t)

	twentyX := mustQueryRules(t, ds, RuleQuery{Type: Certification20x})
	if !resultIDs(twentyX)["VDR-TFR-MVX"] {
		t.Error(`QueryRules({Type: Certification20x}) is missing "VDR-TFR-MVX" (TFR subset applicability only defined in the common info.subsets)`)
	}

	rev5 := mustQueryRules(t, ds, RuleQuery{Type: CertificationRev5})
	if !resultIDs(rev5)["VDR-TFR-MVF"] {
		t.Error(`QueryRules({Type: CertificationRev5}) is missing "VDR-TFR-MVF" (TFR subset applicability only defined in the common info.subsets)`)
	}

	unfiltered := mustQueryRules(t, ds, RuleQuery{})
	ids := resultIDs(unfiltered)
	if !ids["VDR-TFR-MVX"] || !ids["VDR-TFR-MVF"] {
		t.Error("QueryRules({}) (no filters at all) is missing VDR-TFR-MVX and/or VDR-TFR-MVF")
	}
}

func TestQueryRulesPathFilter(t *testing.T) {
	ds := loadVendoredDataset(t)

	// IVV's CSO subset (General Provider Responsibilities) applies under
	// both Program and Agency paths.
	program := mustQueryRules(t, ds, RuleQuery{Path: PathProgram})
	if len(program) == 0 {
		t.Fatal("QueryRules({Path: PathProgram}) returned no rules")
	}
	if !resultIDs(program)["IVV-CSO-SEI"] {
		t.Error(`QueryRules({Path: PathProgram}) is missing "IVV-CSO-SEI"`)
	}

	// FRC's CLA subset (Mandatory/Recommended/Optional FedRAMP Rules for
	// Class A) is Program-only - applicability.paths = ["Program"], no
	// "Agency". A Program-path result must include it; an Agency-path
	// query must exclude it entirely. This is the negative case the
	// positive-only version of this test used to just describe in a
	// comment without actually checking.
	if !resultIDs(program)["FRC-CLA-MFR"] {
		t.Error(`QueryRules({Path: PathProgram}) is missing "FRC-CLA-MFR" (subset FRC/CLA is Program-only)`)
	}
	agency := mustQueryRules(t, ds, RuleQuery{Path: PathAgency})
	if resultIDs(agency)["FRC-CLA-MFR"] {
		t.Error(`QueryRules({Path: PathAgency}) included "FRC-CLA-MFR", whose subset (FRC/CLA) is Program-only`)
	}
}

func TestQueryRulesResultsAreSortedByID(t *testing.T) {
	ds := loadVendoredDataset(t)
	results := mustQueryRules(t, ds, RuleQuery{Class: ClassC})
	for i := 1; i < len(results); i++ {
		if results[i-1].ID >= results[i].ID {
			t.Fatalf("results not sorted: %q >= %q at index %d", results[i-1].ID, results[i].ID, i)
		}
	}
}

func TestFRRRequirementEffectiveForce(t *testing.T) {
	ds := loadVendoredDataset(t)
	rule := ds.FRR["CCM"].Data.All["QTR"]["CCM-QTR-MTG"]

	cases := []struct {
		class ClassName
		want  ForceLevel
	}{
		{ClassA, ForceMay},
		{ClassB, ForceShould},
		{ClassC, ForceMust},
		{ClassD, ForceMust},
	}
	for _, c := range cases {
		if got := rule.EffectiveForce(c.class); got != c.want {
			t.Errorf("CCM-QTR-MTG.EffectiveForce(%s) = %q, want %q", c.class, got, c.want)
		}
	}

	uniform := ds.FRR["AFC"].Data.All["CSO"]["AFC-CSO-INB"]
	if got, want := uniform.EffectiveForce(ClassC), ForceMust; got != want {
		t.Errorf("AFC-CSO-INB.EffectiveForce(ClassC) = %q, want %q (uniform rule)", got, want)
	}

	// Documents a real limitation, not a bug: AFC-CSO-INB's subset (CSO)
	// only scopes to B/C/D, not A, but EffectiveForce has no way to know
	// that - a FRRRequirement doesn't carry its own containing subset.
	// Calling it directly on a class the subset excludes still returns
	// the uniform Force, per EffectiveForce's own documented contract.
	// This is safe in this package because query.go's ruleClasses
	// (which does have the subset's Applicability.Classes) always
	// filters *before* any caller reaches EffectiveForce - a future
	// caller that skips that step would get a misleading answer, which
	// is exactly why this is pinned down here.
	if got, want := uniform.EffectiveForce(ClassA), ForceMust; got != want {
		t.Errorf("AFC-CSO-INB.EffectiveForce(ClassA) = %q, want %q (documented behavior: EffectiveForce alone can't know class A is out of scope for this rule's subset)", got, want)
	}
}

func TestFRRRequirementUniformForce(t *testing.T) {
	ds := loadVendoredDataset(t)

	// A genuinely non-varying rule.
	plain := ds.FRR["AFC"].Data.All["CSO"]["AFC-CSO-INB"]
	if force, ok := plain.UniformForce(); !ok || force != ForceMust {
		t.Errorf("AFC-CSO-INB.UniformForce() = (%q, %v), want (%q, true)", force, ok, ForceMust)
	}

	// A rule whose varies_by_class block gives every defined class the
	// same force (MUST for a,b,c,d) - only the statement text (a
	// timeframe) differs. This is the false-"VARIES" case the code
	// review's ultra pass found: the CLI used to print VARIES for this
	// rule just because VariesByClass was non-nil.
	sameForce := ds.FRR["IEC"].Data.All["CSO"]["IEC-CSO-FIR"]
	if force, ok := sameForce.UniformForce(); !ok || force != ForceMust {
		t.Errorf("IEC-CSO-FIR.UniformForce() = (%q, %v), want (%q, true)", force, ok, ForceMust)
	}

	// A rule that genuinely varies by force (MAY/SHOULD/MUST/MUST).
	varying := ds.FRR["CCM"].Data.All["QTR"]["CCM-QTR-MTG"]
	if _, ok := varying.UniformForce(); ok {
		t.Error("CCM-QTR-MTG.UniformForce() reported a uniform force, want (_, false)")
	}
}

func TestQueryRulesCombinedFiltersAreConjunctive(t *testing.T) {
	ds := loadVendoredDataset(t)
	broad := mustQueryRules(t, ds, RuleQuery{Class: ClassA})
	narrow := mustQueryRules(t, ds, RuleQuery{Class: ClassA, Type: Certification20x, Path: PathProgram})
	if len(narrow) > len(broad) {
		t.Fatalf("adding Type and Path filters grew the result set from %d to %d; filters should only narrow", len(broad), len(narrow))
	}
}

// TestQueryRulesFailsLoudlyOnUnresolvableSubset proves QueryRules
// returns an error - rather than silently omitting the affected rules -
// when a subset has rules but no applicability definition can be
// resolved anywhere for it.
func TestQueryRulesFailsLoudlyOnUnresolvableSubset(t *testing.T) {
	ds := loadVendoredDataset(t)
	modified := mustClone(t, ds)

	doc := modified.FRR["AFC"]
	delete(doc.Info.Subsets, "CSO")
	modified.FRR["AFC"] = doc

	if _, err := modified.QueryRules(RuleQuery{}); err == nil {
		t.Fatal("QueryRules succeeded after removing a subset's only applicability definition, want an error")
	}
}

// TestQueryRulesRejectsInvalidQueryFields proves QueryRules validates
// its own RuleQuery fields, so a caller who builds one directly (bypassing
// ParseClassName et al., e.g. via a typo or a bare cast) gets a loud
// error instead of a silent, indistinguishable-from-legitimate empty
// result set.
func TestQueryRulesRejectsInvalidQueryFields(t *testing.T) {
	ds := loadVendoredDataset(t)

	cases := []RuleQuery{
		{Class: "a"},      // wrong case; ClassA is "A"
		{Class: "E"},      // not a defined class
		{Type: "rev5"},    // wrong case; CertificationRev5 is "Rev5"
		{Type: "30x"},     // not a defined type
		{Path: "program"}, // wrong case; PathProgram is "Program"
		{Path: "Nowhere"}, // not a defined path
	}
	for _, q := range cases {
		if _, err := ds.QueryRules(q); err == nil {
			t.Errorf("QueryRules(%+v) succeeded, want an error", q)
		}
	}
}

// TestAllBucketSubsetsAlwaysResolveInCommonSubsets backs resolveSubsets'
// doc comment: unlike the "20x"/"rev5" buckets, a subset used under
// doc.Data.All has no type-specific fallback to resolve through, only
// the common doc.Info.Subsets. This confirms that gap is not currently
// live - every subset used under "all", across the whole vendored
// dataset, does have a common definition - so QueryRules({}) never hits
// the ambiguous case resolveSubsets deliberately declines to guess at.
func TestAllBucketSubsetsAlwaysResolveInCommonSubsets(t *testing.T) {
	ds := loadVendoredDataset(t)
	for docKey, doc := range ds.FRR {
		for subsetKey := range doc.Data.All {
			if _, ok := doc.Info.Subsets[subsetKey]; !ok {
				t.Errorf("FRR[%s].Data.All has subset %q with no common Info.Subsets definition - resolveSubsets has no fallback for this and QueryRules({}) would now error", docKey, subsetKey)
			}
		}
	}
}
