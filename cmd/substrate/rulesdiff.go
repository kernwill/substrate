package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/kernwill/substrate/internal/rules"
)

// runRulesDiff implements "substrate rules diff <fileA> <fileB>" (T-007,
// FR-1.4): a structured added/removed/modified diff between two dataset
// files on disk. There is no version registry to resolve a bare version
// string against - the only copy of the dataset this project holds is
// the single vendored, checksummed one - so both arguments are paths to
// dataset JSON files, not version identifiers.
func runRulesDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("substrate rules diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: substrate rules diff [--format text|json] <fileA> <fileB>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintf(stderr, "substrate rules diff: want exactly two dataset files, got %d\n", fs.NArg())
		fs.Usage()
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "substrate rules diff: invalid --format %q (want text or json)\n", *format)
		return 2
	}

	pathA, pathB := fs.Arg(0), fs.Arg(1)
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

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
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
