package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kernwill/substrate/internal/rules"
)

// runRules dispatches "substrate rules <subcommand>". Only "show" is
// implemented so far (T-005 / FR-1.5); "diff" is T-007.
func runRules(ds *rules.Dataset, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "substrate rules: no subcommand given (try: show)")
		return 2
	}
	switch args[0] {
	case "show":
		return runRulesShow(ds, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "substrate rules: %q not implemented yet (try: show)\n", args[0])
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
		c, err := parseClass(*class)
		if err != nil {
			fmt.Fprintf(stderr, "substrate rules show: %v\n", err)
			return 2
		}
		q.Class = c
	}
	if *certType != "" {
		ct, err := parseCertType(*certType)
		if err != nil {
			fmt.Fprintf(stderr, "substrate rules show: %v\n", err)
			return 2
		}
		q.Type = ct
	}
	if *path != "" {
		p, err := parseCertPath(*path)
		if err != nil {
			fmt.Fprintf(stderr, "substrate rules show: %v\n", err)
			return 2
		}
		q.Path = p
	}

	results := ds.QueryRules(q)

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
// the right level); otherwise a varying rule has no single force, so say
// so rather than picking one arbitrarily.
func ruleForceColumn(r rules.RuleResult, q rules.RuleQuery) string {
	if q.Class != "" {
		return string(r.Rule.EffectiveForce(q.Class))
	}
	if r.Rule.VariesByClass != nil {
		return "VARIES"
	}
	return string(r.Rule.Force)
}

func parseClass(s string) (rules.ClassName, error) {
	switch strings.ToUpper(s) {
	case "A":
		return rules.ClassA, nil
	case "B":
		return rules.ClassB, nil
	case "C":
		return rules.ClassC, nil
	case "D":
		return rules.ClassD, nil
	default:
		return "", fmt.Errorf("invalid --class %q (want A, B, C, or D)", s)
	}
}

func parseCertType(s string) (rules.CertificationType, error) {
	switch strings.ToLower(s) {
	case "20x":
		return rules.Certification20x, nil
	case "rev5":
		return rules.CertificationRev5, nil
	default:
		return "", fmt.Errorf("invalid --type %q (want 20x or Rev5)", s)
	}
}

func parseCertPath(s string) (rules.CertificationPath, error) {
	switch strings.ToLower(s) {
	case "program":
		return rules.PathProgram, nil
	case "agency":
		return rules.PathAgency, nil
	default:
		return "", fmt.Errorf("invalid --path %q (want Program or Agency)", s)
	}
}
