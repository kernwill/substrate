package main

import (
	"flag"
	"fmt"
	"io"
)

// runCompile implements "substrate compile --source <dir> --out <dir>"
// (FR-2 through FR-6: parse Terraform/Kubernetes/CI config, build the
// evidence graph, emit FedRAMP 20x artifacts).
//
// Not implemented yet - that's Phase 1 front-end and backend work. This
// stub exists so T-008's golden harness has a real, dedicated command to
// exercise against testdata/fixtures/minimal now, ahead of that work,
// per CLAUDE.md's "write the golden fixture before the parser." When the
// real pipeline lands, this function's body is what gets replaced; its
// flags and usage contract should stay stable.
func runCompile(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("substrate compile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "", "directory containing Terraform, Kubernetes manifests, and CI configuration to compile")
	out := fs.String("out", "", "directory to write compiled artifacts to")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: substrate compile --source <dir> --out <dir>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *source == "" || *out == "" {
		fs.Usage()
		return 2
	}
	fmt.Fprintln(stderr, "substrate compile: not implemented yet (Phase 1: FR-2 through FR-6)")
	return 2
}
