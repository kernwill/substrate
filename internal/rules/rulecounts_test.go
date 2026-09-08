package rules

import (
	"bufio"
	"os"
	"slices"
	"sort"
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

// providerRulesUnder20x runs the real QueryRules (the same code path
// "substrate rules show" uses) scoped to the 20x certification type,
// with q's other fields (typically just Class) passed through, and
// keeps only results affecting Providers - the one filter dimension
// QueryRules doesn't apply itself, since FR-1.5 only asks for
// class/type/path. Reusing QueryRules here (rather than this test
// hand-rolling its own subset-resolution walk, as an earlier version of
// this file did) means a fix to QueryRules' applicability resolution
// - such as the common-subset fallback fixed alongside this - can't
// silently drift out of sync between the CLI and this doc's numbers.
func providerRulesUnder20x(t *testing.T, ds *Dataset, q RuleQuery) []RuleResult {
	t.Helper()
	q.Type = Certification20x
	results, err := ds.QueryRules(q)
	if err != nil {
		t.Fatalf("QueryRules(%+v): %v", q, err)
	}
	out := results[:0:0]
	for _, r := range results {
		if slices.Contains(r.Rule.Affects, AffectsProviders) {
			out = append(out, r)
		}
	}
	return out
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

	// The five KSI indicators that vary by class, named in rule-counts.md's
	// prose - tracked in the machine-readable block too (not just prose)
	// so a future dataset revision changing which/how many vary can't go
	// stale silently.
	var varyingByClass []string
	for _, theme := range ds.KSI {
		for id, ind := range theme.Indicators {
			if ind.VariesByClass != nil {
				varyingByClass = append(varyingByClass, id)
			}
		}
	}
	sort.Strings(varyingByClass)
	if wantN := docInt(t, want, "ksi_indicators_varying_by_class"); len(varyingByClass) != wantN {
		t.Errorf("KSI indicators varying by class = %d, docs/rule-counts.md claims %d", len(varyingByClass), wantN)
	}
	if wantIDs, gotIDs := want["ksi_indicators_varying_by_class_ids"], strings.Join(varyingByClass, ","); gotIDs != wantIDs {
		t.Errorf("KSI indicators varying by class = %q, docs/rule-counts.md claims %q", gotIDs, wantIDs)
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

	allProviderRules := providerRulesUnder20x(t, ds, RuleQuery{})
	byDoc := map[string]int{}
	for _, r := range allProviderRules {
		byDoc[r.Document]++
	}

	packageTotal, assuranceTotal := 0, 0
	for docKey, wantKey := range packageDocs {
		got := byDoc[docKey]
		packageTotal += got
		if wantN := docInt(t, want, wantKey); got != wantN {
			t.Errorf("provider/20x rule count for %s = %d, docs/rule-counts.md claims %d", docKey, got, wantN)
		}
	}
	for docKey, wantKey := range assuranceDocs {
		got := byDoc[docKey]
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

	// docs/rule-counts.md's "93" figure (and its per-class breakdown) is
	// deliberately scoped to these 9 named rulesets - the ones
	// docs/REQUIREMENTS.md section 5 calls "the package" and "the [six]
	// assurance rulesets" - not every provider-facing, 20x-applicable
	// rule in the dataset. There are more: MKT, CDS, CMU, FRC, MAS, and
	// VDR each carry real provider obligations under 20x too (168 total
	// across all 15 non-placeholder FRR documents, vs. 93 in the named
	// 9), they just aren't part of what REQUIREMENTS.md's "package and
	// ongoing assurance" narrative names. Both figures are recorded and
	// tested below so neither number is mistaken for the other.
	allowlisted := make(map[string]bool, len(packageDocs)+len(assuranceDocs))
	for docKey := range packageDocs {
		allowlisted[docKey] = true
	}
	for docKey := range assuranceDocs {
		allowlisted[docKey] = true
	}

	classKeys := map[ClassName]string{
		ClassA: "class_a",
		ClassB: "class_b",
		ClassC: "class_c",
		ClassD: "class_d",
	}
	allFRRClassKeys := map[ClassName]string{
		ClassA: "provider_20x_all_frr_class_a",
		ClassB: "provider_20x_all_frr_class_b",
		ClassC: "provider_20x_all_frr_class_c",
		ClassD: "provider_20x_all_frr_class_d",
	}
	for class, wantKey := range classKeys {
		classResults := providerRulesUnder20x(t, ds, RuleQuery{Class: class})
		got := 0
		allFRRGot := len(classResults)
		for _, r := range classResults {
			if allowlisted[r.Document] {
				got++
			}
		}
		if wantN := docInt(t, want, wantKey); got != wantN {
			t.Errorf("provider/20x rule count for class %s (named 9 rulesets) = %d, docs/rule-counts.md claims %d", class, got, wantN)
		}
		if wantN := docInt(t, want, allFRRClassKeys[class]); allFRRGot != wantN {
			t.Errorf("provider/20x rule count for class %s (all FRR documents) = %d, docs/rule-counts.md claims %d", class, allFRRGot, wantN)
		}
	}

	if wantN := docInt(t, want, "provider_20x_all_frr_total"); len(allProviderRules) != wantN {
		t.Errorf("provider/20x rule count across all FRR documents = %d, docs/rule-counts.md claims %d", len(allProviderRules), wantN)
	}
}
