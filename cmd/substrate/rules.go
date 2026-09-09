package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/kernwill/substrate/internal/rules"
)

// runRules dispatches "substrate rules <subcommand>": "show" (T-005 /
// FR-1.5) and "diff" (T-007 / FR-1.4).
//
// Only "show" needs the embedded vendored dataset, so it's loaded here,
// scoped to that one subcommand - not in main.go for the whole "rules"
// verb. "diff" takes its own two dataset files as arguments and never
// touches the embedded copy at all.
func runRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "substrate rules: no subcommand given (try: show, diff)")
		return 2
	}
	switch args[0] {
	case "show":
		ds, err := rules.Default()
		if err != nil {
			fmt.Fprintf(stderr, "substrate rules show: load rules dataset: %v\n", err)
			return 2
		}
		return runRulesShow(ds, args[1:], stdout, stderr)
	case "diff":
		return runRulesDiff(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "substrate rules: %q not implemented yet (try: show, diff)\n", args[0])
		return 2
	}
}

// runRulesShow implements "substrate rules show", querying FRR rules by
// certification class, type, and path (FR-1.5).
func runRulesShow(ds *rules.Dataset, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("substrate rules show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	class := fs.String("class", "", "certification class to filter by: A, B, C, or D")
	certType := fs.String("type", "", "certification type to filter by: 20x or Rev5")
	path := fs.String("path", "", "certification path to filter by: Program or Agency")
	includePlaceholder := fs.Bool("include-placeholder", false, "include rules from non-stable (e.g. placeholder) FRR documents")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: substrate rules show [--class A|B|C|D] [--type 20x|Rev5] [--path Program|Agency] [--include-placeholder]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	q := rules.RuleQuery{IncludeNonStable: *includePlaceholder}

	if *class != "" {
		c, err := rules.ParseClassName(*class)
		if err != nil {
			fmt.Fprintf(stderr, "substrate rules show: %v\n", err)
			return 2
		}
		q.Class = c
	}
	if *certType != "" {
		ct, err := rules.ParseCertificationType(*certType)
		if err != nil {
			fmt.Fprintf(stderr, "substrate rules show: %v\n", err)
			return 2
		}
		q.Type = ct
	}
	if *path != "" {
		p, err := rules.ParseCertificationPath(*path)
		if err != nil {
			fmt.Fprintf(stderr, "substrate rules show: %v\n", err)
			return 2
		}
		q.Path = p
	}

	results, err := ds.QueryRules(q)
	if err != nil {
		fmt.Fprintf(stderr, "substrate rules show: %v\n", err)
		return 2
	}

	fmt.Fprintln(stdout, "ID\tFORCE\tNAME")
	for _, r := range results {
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", r.ID, ruleForceColumn(r, q), r.Rule.Name)
	}
	fmt.Fprintf(stdout, "%d rules\n", len(results))
	return 0
}

// ruleForceColumn is the FORCE column for one result row. When the query
// asked for a specific class, show that class's actual force
// (FRRRequirement.EffectiveForce resolves a varies_by_class rule down to
// the right level). Otherwise, show the single force every defined class
// shares (FRRRequirement.UniformForce) - a varies_by_class rule doesn't
// necessarily mean the force itself varies (some only vary the statement
// text, e.g. a timeframe) - and only fall back to "VARIES" when the
// force genuinely differs by class.
func ruleForceColumn(r rules.RuleResult, q rules.RuleQuery) string {
	if q.Class != "" {
		return string(r.Rule.EffectiveForce(q.Class))
	}
	if force, ok := r.Rule.UniformForce(); ok {
		return string(force)
	}
	return "VARIES"
}
