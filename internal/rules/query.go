package rules

import "sort"

// RuleQuery filters FRR rules by certification class, type, and path
// (FR-1.5). A zero-value field means "no filter" for that dimension.
type RuleQuery struct {
	Class ClassName
	Type  CertificationType
	Path  CertificationPath

	// IncludeNonStable includes rules from FRR documents whose status is
	// not "stable" (e.g. "placeholder"). Off by default: the vendored
	// dataset currently has one such document (AGU), and per the FedRAMP
	// rules repo's own AI-agent guidance, placeholder and empty content
	// must be treated differently from stable content - a compliance
	// tool should not present provisional, not-yet-finalized rules as
	// applicable requirements unless the caller explicitly opts in.
	IncludeNonStable bool
}

// RuleResult is one FRR rule matched by a query, together with where it
// was found.
type RuleResult struct {
	Document string // FRR document key, e.g. "AFC"
	Subset   string // subset key, e.g. "CSO"
	ID       string // full rule ID, e.g. "AFC-CSO-INB"
	Rule     FRRRequirement
	Status   DocumentStatus
}

// QueryRules returns every FRR rule in ds matching q, sorted by rule ID.
func (ds *Dataset) QueryRules(q RuleQuery) []RuleResult {
	var results []RuleResult
	for docKey, doc := range ds.FRR {
		if doc.Info.Status != StatusStable && !q.IncludeNonStable {
			continue
		}

		// The "all" bucket is shared between certification types by
		// definition, so it's in scope regardless of q.Type.
		results = append(results, matchRuleContainer(docKey, doc.Data.All, doc.Info.Subsets, doc.Info.Status, q)...)

		if q.Type == "" || q.Type == Certification20x {
			var subsets map[string]FRRSubsetDefinition
			if doc.Info.TwentyX != nil {
				subsets = doc.Info.TwentyX.Subsets
			}
			results = append(results, matchRuleContainer(docKey, doc.Data.TwentyX, subsets, doc.Info.Status, q)...)
		}
		if q.Type == "" || q.Type == CertificationRev5 {
			var subsets map[string]FRRSubsetDefinition
			if doc.Info.Rev5 != nil {
				subsets = doc.Info.Rev5.Subsets
			}
			results = append(results, matchRuleContainer(docKey, doc.Data.Rev5, subsets, doc.Info.Status, q)...)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results
}

// matchRuleContainer filters one data container (the rules under "all",
// "20x", or "rev5" for a single FRR document) against q's path and class
// filters. A subset with rules but no matching applicability definition
// is skipped rather than erroring: QueryRules is a best-effort read path
// for already-schema-valid data, not a second validator - ValidateSchema
// is where a malformed dataset gets a loud, structured failure.
func matchRuleContainer(docKey string, container map[string]map[string]FRRRequirement, subsets map[string]FRRSubsetDefinition, status DocumentStatus, q RuleQuery) []RuleResult {
	var out []RuleResult
	for subsetKey, rules := range container {
		def, ok := subsets[subsetKey]
		if !ok {
			continue
		}
		if q.Path != "" && !containsValue(def.Applicability.Paths, q.Path) {
			continue
		}
		for ruleID, rule := range rules {
			if q.Class != "" && !containsValue(ruleClasses(rule, def.Applicability.Classes), q.Class) {
				continue
			}
			out = append(out, RuleResult{Document: docKey, Subset: subsetKey, ID: ruleID, Rule: rule, Status: status})
		}
	}
	return out
}

// ruleClasses returns which certification classes rule applies to.
//
// A rule that varies by class (rule.VariesByClass != nil) states its own
// per-class scope explicitly, and that's the more specific signal: the
// vendored dataset has rules (e.g. CCM-QTR-MTG, IVV-CSO-FIA) that define
// an "a" entry in varies_by_class even though their containing subset's
// blanket applicability.classes lists only B/C/D - explicit, optional
// Class A guidance the subset-level field doesn't capture. This matches
// the FedRAMP rules repo's own guidance: "Respect varies_by_class before
// applying a rule to a specific service class." A uniform rule (no
// varies_by_class) has no rule-level signal at all, so it inherits the
// subset's classes.
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

func containsValue[T comparable](values []T, want T) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
