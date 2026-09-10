package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kernwill/substrate/internal/rules"
)

const rulesDiffUsage = "usage: substrate rules diff [--format text|json] <fileA> <fileB>"

// runRulesDiff implements "substrate rules diff <fileA> <fileB>" (T-007,
// FR-1.4): a structured added/removed/modified diff between two dataset
// files on disk. There is no version registry to resolve a bare version
// string against - the only copy of the dataset this project holds is
// the single vendored, checksummed one - so both arguments are paths to
// dataset JSON files, not version identifiers.
//
// runRulesDiff always returns 0 when it successfully computes and prints a
// diff, regardless of how many entries were added, removed, or modified -
// this is deliberate, not an oversight of main.go's documented "0 pass, 1
// rule regression (CI gate failure), 2 usage or internal error" contract.
// That contract is about substrate gate, the actual CI gate command (not
// yet implemented): it compares a customer's compiled IR against a
// baseline and must fail the build when a *customer's* control regresses.
// rules diff compares two FedRAMP rule dataset files - e.g. this year's
// vendored ruleset against last year's - which is inspection tooling in
// the same family as rules show, analogous to `git diff` reporting that
// two refs differ. A dataset having different rules than another dataset
// is not a rule regression in anyone's compliance posture; treating any
// non-empty diff as exit 1 would make this command fail on virtually
// every real invocation (any two non-identical dataset versions) and
// would conflate "the reference ruleset changed" with "a customer stopped
// meeting a control," which is exactly the confusion Declared-vs-Observed
// exists to prevent for compliance findings generally.
//
// Arguments are parsed by hand rather than via the stdlib flag package:
// flag.FlagSet.Parse stops at the first non-flag argument, so
// "diff a.json b.json --format json" (flag after the positionals, a
// perfectly natural way to type it) would otherwise be misread as four
// positional arguments instead of two plus a flag. This command's
// grammar is simple enough (one optional value flag, two required
// positionals) that a manual scan handles every argument order without
// that trap.
func runRulesDiff(args []string, stdout, stderr io.Writer) int {
	format := "text"
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--format" || a == "-format":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "substrate rules diff: --format requires a value")
				return 2
			}
			i++
			format = args[i]
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "-format="):
			format = strings.TrimPrefix(a, "-format=")
		case a == "-h" || a == "--help":
			fmt.Fprintln(stderr, rulesDiffUsage)
			return 2
		default:
			positional = append(positional, a)
		}
	}

	if len(positional) != 2 {
		fmt.Fprintf(stderr, "substrate rules diff: want exactly two dataset files, got %d\n", len(positional))
		fmt.Fprintln(stderr, rulesDiffUsage)
		return 2
	}
	if format != "text" && format != "json" {
		fmt.Fprintf(stderr, "substrate rules diff: invalid --format %q (want text or json)\n", format)
		return 2
	}

	pathA, pathB := positional[0], positional[1]
	dsA, err := rules.LoadFile(pathA)
	if err != nil {
		fmt.Fprintf(stderr, "substrate rules diff: load %s: %v\n", pathA, err)
		return 2
	}
	dsB, err := rules.LoadFile(pathB)
	if err != nil {
		fmt.Fprintf(stderr, "substrate rules diff: load %s: %v\n", pathB, err)
		return 2
	}

	diff, err := rules.DiffDatasets(dsA, dsB)
	if err != nil {
		fmt.Fprintf(stderr, "substrate rules diff: %v\n", err)
		return 2
	}

	if format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		// The vendored dataset's own rule text uses "<", ">", and "&"
		// verbatim (e.g. "N-rating > 2" in CTL/SI-08 guidance and
		// FRR/VER-TFR-IRI). json.Encoder HTML-escapes those by default
		// (for safe embedding in <script> tags), which would silently
		// rewrite a federal rule's exact wording into >-style
		// escapes in a diff meant to preserve it verbatim.
		enc.SetEscapeHTML(false)
		if err := enc.Encode(diff); err != nil {
			fmt.Fprintf(stderr, "substrate rules diff: encode output: %v\n", err)
			return 2
		}
		return 0
	}

	writeDiffText(stdout, diff)
	return 0
}

func writeDiffText(w io.Writer, diff rules.Diff) {
	fmt.Fprintf(w, "from %s to %s\n", diff.FromVersion, diff.ToVersion)
	fmt.Fprintln(w, "SECTION\tCHANGE\tID")
	for _, e := range diff.Entries {
		fmt.Fprintf(w, "%s\t%s\t%s\n", e.Section, e.Change, e.ID)
	}
	fmt.Fprintf(w, "%d added, %d removed, %d modified\n", len(diff.Added()), len(diff.Removed()), len(diff.Modified()))
}
