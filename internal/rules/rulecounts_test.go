package rules

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

const ruleCountsDocPath = "../../docs/rule-counts.md"

// parseRuleCountsDoc reads the "key: value" block delimited by
// "<!-- rule-counts:begin -->" / "<!-- rule-counts:end -->" in
// docs/rule-counts.md. That block is the doc's single source of truth;
// the prose tables above it are for human readers and are not parsed.
func parseRuleCountsDoc(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(ruleCountsDocPath)
	if err != nil {
		t.Fatalf("open %s: %v", ruleCountsDocPath, err)
	}
	defer f.Close()

	values := make(map[string]string)
	inBlock := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "<!-- rule-counts:begin -->":
			inBlock = true
			continue
		case line == "<!-- rule-counts:end -->":
			inBlock = false
			continue
		case !inBlock || line == "":
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("%s: malformed line in rule-counts block: %q", ruleCountsDocPath, line)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", ruleCountsDocPath, err)
	}
	if inBlock {
		t.Fatalf("%s: rule-counts:begin without a matching rule-counts:end", ruleCountsDocPath)
	}
	if len(values) == 0 {
		t.Fatalf("%s: no rule-counts block found", ruleCountsDocPath)
	}
	return values
}

func docInt(t *testing.T, values map[string]string, key string) int {
	t.Helper()
	raw, ok := values[key]
	if !ok {
		t.Fatalf("%s: missing key %q", ruleCountsDocPath, key)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s: key %q = %q is not an integer: %v", ruleCountsDocPath, key, raw, err)
	}
	return n
}

// includesProviders20x reports whether a subset's applicability covers
// both providers and the 20x certification type - the two filters
// docs/REQUIREMENTS.md section 5's package/assurance rule counts apply.
func includesProviders20x(a FRRSubsetApplicability) bool {
	hasProviders, has20x := false, false
	for _, p := range a.Affects {
		if p == AffectsProviders {
			hasProviders = true
		}
	}
	for _, ty := range a.Types {
		if ty == Certification20x {
			has20x = true
		}
	}
	return hasProviders && has20x
}

// forEachProviderRuleUnder20x calls fn once per rule in doc's "all" and
// "20x" containers whose subset applies to providers under 20x, passing
// along the subset's declared classes for callers that need them. It
// ignores the "rev5" container entirely, since that's Rev5-only by
// construction.
func forEachProviderRuleUnder20x(t *testing.T, docKey string, doc FRRDocument, fn func(rule FRRRequirement, subsetClasses []ClassName)) {
	t.Helper()
	for subset, rules := range doc.Data.All {
		def, ok := doc.Info.Subsets[subset]
		if !ok {
			t.Fatalf("FRR[%s].Data.All has subset %q with no matching Info.Subsets entry", docKey, subset)
		}
		if !includesProviders20x(def.Applicability) {
			continue
		}
		for _, rule := range rules {
			fn(rule, def.Applicability.Classes)
		}
	}
	for subset, rules := range doc.Data.TwentyX {
		if doc.Info.TwentyX == nil {
			t.Fatalf("FRR[%s].Data.TwentyX has subset %q but Info.TwentyX is nil", docKey, subset)
		}
		def, ok := doc.Info.TwentyX.Subsets[subset]
		if !ok {
			t.Fatalf("FRR[%s].Data.TwentyX has subset %q with no matching Info.TwentyX.Subsets entry", docKey, subset)
		}
		if !includesProviders20x(def.Applicability) {
			continue
		}
		for _, rule := range rules {
			fn(rule, def.Applicability.Classes)
		}
	}
}

func providerRuleCountUnder20x(t *testing.T, docKey string, doc FRRDocument) int {
	t.Helper()
	total := 0
	forEachProviderRuleUnder20x(t, docKey, doc, func(FRRRequirement, []ClassName) { total++ })
	return total
}

// ruleClasses returns which certification classes rule applies to.
//
// A rule that varies by class (rule.VariesByClass != nil) states its own
// per-class scope explicitly, and that's the more specific signal: the
// vendored dataset has 12 rules (e.g. CCM-QTR-MTG, IVV-CSO-FIA) that
// define an "a" entry in varies_by_class even though their containing
// subset's blanket applicability.classes lists only B/C/D - explicit,
// optional Class A guidance the subset-level field doesn't capture. A
// uniform rule (no varies_by_class) has no rule-level signal at all, so
// it inherits the subset's classes.
func ruleClasses(rule FRRRequirement, subsetClasses []ClassName) []ClassName {
	if rule.VariesByClass == nil {
		return subsetClasses
	}
	var classes []ClassName
	if rule.VariesByClass.A != nil {
		classes = append(classes, ClassA)
	}
	if rule.VariesByClass.B != nil {
		classes = append(classes, ClassB)
	}
	if rule.VariesByClass.C != nil {
		classes = append(classes, ClassC)
	}
	if rule.VariesByClass.D != nil {
		classes = append(classes, ClassD)
	}
	return classes
}

// TestRuleCountsDocMatchesDataset recomputes every count docs/rule-counts.md
// claims directly from the vendored dataset. If someone updates the
// vendored dataset without updating the doc (or vice versa), this fails
// instead of letting the numbers docs/REQUIREMENTS.md cites go stale.
func TestRuleCountsDocMatchesDataset(t *testing.T) {
	ds := loadVendoredDataset(t)
	want := parseRuleCountsDoc(t)

	if got, want := ds.Info.Version, want["dataset_version"]; got != want {
		t.Errorf("Info.Version = %q, docs/rule-counts.md claims %q", got, want)
	}

	// Dataset totals.
	if got, wantN := len(ds.FRD.Data.All), docInt(t, want, "frd_definitions"); got != wantN {
		t.Errorf("len(FRD.Data.All) = %d, docs/rule-counts.md claims %d", got, wantN)
	}
	if got, wantN := len(ds.FRR), docInt(t, want, "frr_documents"); got != wantN {
		t.Errorf("len(FRR) = %d, docs/rule-counts.md claims %d", got, wantN)
	}
	totalRules := 0
	for _, doc := range ds.FRR {
		for _, container := range []map[string]map[string]FRRRequirement{doc.Data.All, doc.Data.TwentyX, doc.Data.Rev5} {
			for _, rules := range container {
				totalRules += len(rules)
			}
		}
	}
	if wantN := docInt(t, want, "frr_rules_total"); totalRules != wantN {
		t.Errorf("total FRR rule entries = %d, docs/rule-counts.md claims %d", totalRules, wantN)
	}
	if got, wantN := len(ds.KSI), docInt(t, want, "ksi_themes"); got != wantN {
		t.Errorf("len(KSI) = %d, docs/rule-counts.md claims %d", got, wantN)
	}
	totalIndicators := 0
	for _, theme := range ds.KSI {
		totalIndicators += len(theme.Indicators)
	}
	if wantN := docInt(t, want, "ksi_indicators"); totalIndicators != wantN {
		t.Errorf("total KSI indicators = %d, docs/rule-counts.md claims %d", totalIndicators, wantN)
	}
	if got, wantN := len(ds.CTL), docInt(t, want, "ctl_families"); got != wantN {
		t.Errorf("len(CTL) = %d, docs/rule-counts.md claims %d", got, wantN)
	}
	totalControls := 0
	for _, fam := range ds.CTL {
		totalControls += len(fam)
	}
	if wantN := docInt(t, want, "ctl_controls"); totalControls != wantN {
		t.Errorf("total CTL control entries = %d, docs/rule-counts.md claims %d", totalControls, wantN)
	}

	// KSI indicator counts, per family - the KSI analogue of "per ruleset".
	ksiFamilies := map[string]string{
		"CED": "ksi_indicators_ced",
		"CMT": "ksi_indicators_cmt",
		"CNA": "ksi_indicators_cna",
		"IAM": "ksi_indicators_iam",
		"INR": "ksi_indicators_inr",
		"MLA": "ksi_indicators_mla",
		"PIY": "ksi_indicators_piy",
		"RPL": "ksi_indicators_rpl",
		"SCR": "ksi_indicators_scr",
		"SVC": "ksi_indicators_svc",
	}
	for themeKey, wantKey := range ksiFamilies {
		theme, ok := ds.KSI[themeKey]
		if !ok {
			t.Fatalf("KSI[%s] missing", themeKey)
		}
		if got, wantN := len(theme.Indicators), docInt(t, want, wantKey); got != wantN {
			t.Errorf("KSI[%s] indicator count = %d, docs/rule-counts.md claims %d", themeKey, got, wantN)
		}
	}

	// docs/REQUIREMENTS.md section 5: package and assurance rule counts,
	// scoped to rules that affect Providers under the 20x certification
	// type, plus the same scope broken down by certification class.
	packageDocs := map[string]string{
		"CPO": "package_cpo",
		"SCG": "package_scg",
		"SDR": "package_sdr",
	}
	assuranceDocs := map[string]string{
		"VER": "assurance_ver",
		"CCM": "assurance_ccm",
		"SCN": "assurance_scn",
		"IVV": "assurance_ivv",
		"AFC": "assurance_afc",
		"IEC": "assurance_iec",
	}

	classCounts := map[ClassName]int{}
	packageTotal, assuranceTotal := 0, 0
	tally := func(docKey string) int {
		doc, ok := ds.FRR[docKey]
		if !ok {
			t.Fatalf("FRR[%s] missing", docKey)
		}
		total := 0
		forEachProviderRuleUnder20x(t, docKey, doc, func(rule FRRRequirement, subsetClasses []ClassName) {
			total++
			for _, c := range ruleClasses(rule, subsetClasses) {
				classCounts[c]++
			}
		})
		return total
	}
	for docKey, wantKey := range packageDocs {
		got := tally(docKey)
		packageTotal += got
		if wantN := docInt(t, want, wantKey); got != wantN {
			t.Errorf("provider/20x rule count for %s = %d, docs/rule-counts.md claims %d", docKey, got, wantN)
		}
	}
	for docKey, wantKey := range assuranceDocs {
		got := tally(docKey)
		assuranceTotal += got
		if wantN := docInt(t, want, wantKey); got != wantN {
			t.Errorf("provider/20x rule count for %s = %d, docs/rule-counts.md claims %d", docKey, got, wantN)
		}
	}

	if wantN := docInt(t, want, "package_total"); packageTotal != wantN {
		t.Errorf("package rule total = %d, docs/rule-counts.md claims %d", packageTotal, wantN)
	}
	if wantN := docInt(t, want, "assurance_total"); assuranceTotal != wantN {
		t.Errorf("assurance rule total = %d, docs/rule-counts.md claims %d", assuranceTotal, wantN)
	}
	if wantN := docInt(t, want, "package_plus_assurance_total"); packageTotal+assuranceTotal != wantN {
		t.Errorf("package + assurance total = %d, docs/rule-counts.md claims %d", packageTotal+assuranceTotal, wantN)
	}

	classKeys := map[ClassName]string{
		ClassA: "class_a",
		ClassB: "class_b",
		ClassC: "class_c",
		ClassD: "class_d",
	}
	for class, wantKey := range classKeys {
		if wantN := docInt(t, want, wantKey); classCounts[class] != wantN {
			t.Errorf("provider/20x rule count for class %s = %d, docs/rule-counts.md claims %d", class, classCounts[class], wantN)
		}
	}
}
