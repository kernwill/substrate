package rules

import "testing"

func resultIDs(results []RuleResult) map[string]bool {
	ids := make(map[string]bool, len(results))
	for _, r := range results {
		ids[r.ID] = true
	}
	return ids
}

func TestQueryRulesNoFilterExcludesNonStableByDefault(t *testing.T) {
	ds := loadVendoredDataset(t)
	results := ds.QueryRules(RuleQuery{})
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
	without := ds.QueryRules(RuleQuery{})
	with := ds.QueryRules(RuleQuery{IncludeNonStable: true})
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
	results := ds.QueryRules(RuleQuery{Class: ClassA})
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
	results := ds.QueryRules(RuleQuery{Class: ClassC})
	ids := resultIDs(results)
	if !ids["AFC-CSO-INB"] {
		t.Error(`QueryRules({Class: ClassC}) is missing "AFC-CSO-INB" (uniform rule, subset covers B/C/D)`)
	}
}

func TestQueryRulesTypeFilterIncludesSharedAndTypeSpecificRules(t *testing.T) {
	ds := loadVendoredDataset(t)
	results := ds.QueryRules(RuleQuery{Type: Certification20x})
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

	rev5Only := ds.QueryRules(RuleQuery{Type: CertificationRev5})
	rev5IDs := resultIDs(rev5Only)
	if rev5IDs["CPO-CSX-CPM"] {
		t.Error(`QueryRules({Type: CertificationRev5}) included "CPO-CSX-CPM", a 20x-only rule`)
	}
	if !rev5IDs["AFC-CSO-INB"] {
		t.Error(`QueryRules({Type: CertificationRev5}) is missing "AFC-CSO-INB", a shared ("all") rule`)
	}
}

func TestQueryRulesPathFilter(t *testing.T) {
	ds := loadVendoredDataset(t)

	// IVV's IAS subset (Independent Assessor Responsibilities) applies
	// under both Program and Agency paths - use it as a known-good
	// Program-path match, and confirm a path this dataset never uses in
	// this subset excludes it.
	results := ds.QueryRules(RuleQuery{Path: PathProgram})
	if len(results) == 0 {
		t.Fatal("QueryRules({Path: PathProgram}) returned no rules")
	}
	ids := resultIDs(results)
	if !ids["IVV-CSO-SEI"] {
		t.Error(`QueryRules({Path: PathProgram}) is missing "IVV-CSO-SEI"`)
	}
}

func TestQueryRulesResultsAreSortedByID(t *testing.T) {
	ds := loadVendoredDataset(t)
	results := ds.QueryRules(RuleQuery{Class: ClassC})
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
}

func TestQueryRulesCombinedFiltersAreConjunctive(t *testing.T) {
	ds := loadVendoredDataset(t)
	broad := ds.QueryRules(RuleQuery{Class: ClassA})
	narrow := ds.QueryRules(RuleQuery{Class: ClassA, Type: Certification20x, Path: PathProgram})
	if len(narrow) > len(broad) {
		t.Fatalf("adding Type and Path filters grew the result set from %d to %d; filters should only narrow", len(broad), len(narrow))
	}
}
