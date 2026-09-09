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
