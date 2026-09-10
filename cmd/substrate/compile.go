package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kernwill/substrate/internal/frontend/terraform"
)

// runCompile implements "substrate compile --source <dir> --out <dir>"
// (FR-2 through FR-6: parse Terraform/Kubernetes/CI config, build the
// evidence graph, emit FedRAMP 20x artifacts).
//
// Only the Terraform half of FR-2.1 is real today: it parses *.tf files
// directly under --source (internal/frontend/terraform.Parse) and
// writes the resulting resource graph, as JSON, to
// <out>/terraform.json. Kubernetes manifests and GitHub Actions config
// (the rest of FR-2), building the evidence graph from any of it
// (internal/ir, FR-5), and emitting FedRAMP artifacts from that graph
// (internal/backends, FR-6) remain unimplemented - see
// internal/frontend/terraform's own package doc and graph.go's
// TODO(mapping) for why a resource graph is not yet an ir.Graph.
//
// testdata/fixtures/minimal's own expected/ output reflects whatever
// this function currently does; regenerate it deliberately
// (SUBSTRATE_UPDATE_GOLDEN=1) and review the diff every time this
// function's real behavior changes, per CLAUDE.md's "that diff is a
// change in what we assert to the federal government."
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

	graph, err := terraform.Parse(*source)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse terraform: %v\n", err)
		return 2
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(stderr, "substrate compile: create output directory %s: %v\n", *out, err)
		return 2
	}
	outPath := filepath.Join(*out, "terraform.json")
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: create %s: %v\n", outPath, err)
		return 2
	}
	defer f.Close()
	if err := writeJSON(f, graph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: write %s: %v\n", outPath, err)
		return 2
	}

	fmt.Fprintf(stdout, "parsed %d terraform resource(s) from %s\n", len(graph.Resources), *source)
	return 0
}
