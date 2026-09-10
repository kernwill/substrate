package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kernwill/substrate/internal/frontend/kubernetes"
	"github.com/kernwill/substrate/internal/frontend/terraform"
)

// runCompile implements "substrate compile --source <dir> --out <dir>"
// (FR-2 through FR-6: parse Terraform/Kubernetes/CI config, build the
// evidence graph, emit FedRAMP 20x artifacts).
//
// Two of FR-2's three static sources are real today:
//   - Terraform: parses *.tf files directly under --source
//     (internal/frontend/terraform.Parse), written to
//     <out>/terraform.json.
//   - Kubernetes: parses *.yaml/*.yml files under --source/k8s
//     (internal/frontend/kubernetes.Parse), written to
//     <out>/kubernetes.json. The "k8s" subdirectory is a narrow,
//     provisional convention matching testdata/fixtures/minimal's own
//     layout, not a general answer to "how does substrate know which
//     files under --source are Kubernetes manifests versus something
//     else" - a real include/exclude design (a .gitignore-style filter,
//     most likely) is still deferred, same as noted below for
//     Terraform's own --source scope.
//
// GitHub Actions config (the rest of FR-2), building the evidence graph
// from any of this (internal/ir, FR-5), and emitting FedRAMP artifacts
// from that graph (internal/backends, FR-6) remain unimplemented - see
// internal/frontend/terraform's graph.go for the TODO(mapping) on why a
// resource graph is not yet an ir.Graph, which applies to both parsers
// here identically.
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

	tfGraph, err := terraform.Parse(*source)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse terraform: %v\n", err)
		return 2
	}
	k8sGraph, err := kubernetes.Parse(filepath.Join(*source, "k8s"))
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse kubernetes: %v\n", err)
		return 2
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(stderr, "substrate compile: create output directory %s: %v\n", *out, err)
		return 2
	}
	if err := writeArtifact(*out, "terraform.json", tfGraph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeArtifact(*out, "kubernetes.json", k8sGraph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "parsed %d terraform resource(s) and %d kubernetes resource(s) from %s\n",
		len(tfGraph.Resources), len(k8sGraph.Resources), *source)
	return 0
}

// writeArtifact writes v as JSON to <outDir>/<name>.
func writeArtifact(outDir, name string, v any) error {
	path := filepath.Join(outDir, name)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if err := writeJSON(f, v); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
