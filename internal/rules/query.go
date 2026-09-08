package rules

import (
	"fmt"
	"slices"
	"sort"
)

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
//
// It returns an error if a subset has rules but no applicability
// definition can be resolved for it anywhere (see resolveSubsets),
// rather than silently omitting those rules from the result: the
// vendored dataset has real, currently-applicable rules (e.g.
// VDR-TFR-MVX) that would otherwise vanish from every query, filtered or
// not, with no indication anything was left out - "absence of evidence
// is not evidence of compliance" applies to this package's own output,
// not just the compiler's eventual rule verdicts.
func (ds *Dataset) QueryRules(q RuleQuery) ([]RuleResult, error) {
	docKeys := make([]string, 0, len(ds.FRR))
	for k := range ds.FRR {
		docKeys = append(docKeys, k)
	}
	sort.Strings(docKeys)

	var results []RuleResult
	for _, docKey := range docKeys {
		doc := ds.FRR[docKey]
		if doc.Info.Status != StatusStable && !q.IncludeNonStable {
			continue
		}

		r, err := matchRuleContainer(docKey, "all", doc.Data.All, resolveSubsets(doc, ""), doc.Info.Status, q)
		if err != nil {
			return nil, err
		}
		results = append(results, r...)

		if q.Type == "" || q.Type == Certification20x {
			r, err := matchRuleContainer(docKey, "20x", doc.Data.TwentyX, resolveSubsets(doc, Certification20x), doc.Info.Status, q)
			if err != nil {
				return nil, err
			}
			results = append(results, r...)
		}
		if q.Type == "" || q.Type == CertificationRev5 {
			r, err := matchRuleContainer(docKey, "rev5", doc.Data.Rev5, resolveSubsets(doc, CertificationRev5), doc.Info.Status, q)
			if err != nil {
				return nil, err
			}
			results = append(results, r...)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}

// resolveSubsets returns doc's subset applicability definitions for one
// data container ("all", "20x", or "rev5"). Per the FedRAMP rules
// repo's own AI-agent guidance: "Resolve FRR subset definitions from
// common info.subsets plus any matching framework-specific
// info.20x.subsets or info.rev5.subsets." A type-specific entry
// overrides the common one when both define the same subset key; a
// subset with no type-specific override at all still resolves through
// the common map. Missing this fallback is exactly what let
// VDR-TFR-MVX/MVF (defined under doc.Data.TwentyX/Rev5, but only ever
// given an applicability definition in the common doc.Info.Subsets, not
// a type-specific one) go undetected.
func resolveSubsets(doc FRRDocument, container CertificationType) map[string]FRRSubsetDefinition {
	merged := make(map[string]FRRSubsetDefinition, len(doc.Info.Subsets))
	for k, v := range doc.Info.Subsets {
		merged[k] = v
	}
	var override map[string]FRRSubsetDefinition
	switch container {
	case Certification20x:
		if doc.Info.TwentyX != nil {
			override = doc.Info.TwentyX.Subsets
		}
	case CertificationRev5:
		if doc.Info.Rev5 != nil {
			override = doc.Info.Rev5.Subsets
		}
	}
	for k, v := range override {
		merged[k] = v
	}
	return merged
}

// matchRuleContainer filters one data container (the rules under "all",
// "20x", or "rev5" for a single FRR document, named by containerName for
// error messages) against q's path and class filters.
func matchRuleContainer(docKey, containerName string, container map[string]map[string]FRRRequirement, subsets map[string]FRRSubsetDefinition, status DocumentStatus, q RuleQuery) ([]RuleResult, error) {
	var out []RuleResult
	for subsetKey, rules := range container {
		def, ok := subsets[subsetKey]
		if !ok {
			return nil, fmt.Errorf("rules: FRR[%s].data.%s has subset %q with %d rule(s) but no matching applicability definition in info.subsets or the %s-specific override", docKey, containerName, subsetKey, len(rules), containerName)
		}
		if q.Path != "" && !slices.Contains(def.Applicability.Paths, q.Path) {
			continue
		}
		for ruleID, rule := range rules {
			if q.Class != "" && !slices.Contains(ruleClasses(rule, def.Applicability.Classes), q.Class) {
				continue
			}
			out = append(out, RuleResult{Document: docKey, Subset: subsetKey, ID: ruleID, Rule: rule, Status: status})
		}
	}
	return out, nil
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
	for _, c := range [...]ClassName{ClassA, ClassB, ClassC, ClassD} {
		if rule.VariesByClass.Level(c) != nil {
			classes = append(classes, c)
		}
	}
	return classes
}
