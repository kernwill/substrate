package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kernwill/substrate/internal/frontend/kubernetes"
	"github.com/kernwill/substrate/internal/frontend/terraform"
	"github.com/kernwill/substrate/internal/ir"
)

// runCompile implements "substrate compile --source <dir> --out <dir>"
// (FR-2 through FR-6: parse Terraform/Kubernetes/CI config, build the
// evidence graph, emit FedRAMP 20x artifacts).
//
// Two of FR-2's three static sources are real today, and both are now
// mapped into the evidence graph:
//   - Terraform: parses *.tf files directly under --source
//     (internal/frontend/terraform.Parse), written raw to
//     <out>/terraform.json, then mapped to IR nodes/edges
//     (terraform.ToIR) via a small, human-reviewed table of which
//     resource types evidence which NIST 800-53 controls - see that
//     file's mapping functions for the reasoning behind each entry.
//   - Kubernetes: parses *.yaml/*.yml files under --source/k8s
//     (internal/frontend/kubernetes.Parse), written raw to
//     <out>/kubernetes.json, mapped the same way
//     (kubernetes.ToIR). The "k8s" subdirectory is a narrow,
//     provisional convention matching testdata/fixtures/minimal's own
//     layout, not a general answer to "how does substrate know which
//     files under --source are Kubernetes manifests versus something
//     else" - a real include/exclude design (a .gitignore-style filter,
//     most likely) is still deferred, same as noted below for
//     Terraform's own --source scope.
//
// The two frontends' IR output is merged into one ir.Graph, validated,
// and written as JSON Lines to <out>/ir/nodes.jsonl and
// <out>/ir/edges.jsonl (ir.WriteNodesJSONL/WriteEdgesJSONL - the
// package's own stable, byte-reproducible serialization, not ad hoc
// JSON). Neither frontend's mapping table is comprehensive: a resource
// type or field with no reviewed entry produces no node, never a
// guess - see each ToIR's own doc comment.
//
// GitHub Actions config (the rest of FR-2) and emitting FedRAMP
// artifacts from the evidence graph (internal/backends, FR-6) remain
// unimplemented.
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

	tfIR, err := terraform.ToIR(tfGraph)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: map terraform to evidence graph: %v\n", err)
		return 2
	}
	k8sIR, err := kubernetes.ToIR(k8sGraph)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: map kubernetes to evidence graph: %v\n", err)
		return 2
	}
	evidence := ir.Graph{}
	evidence.Nodes = append(evidence.Nodes, tfIR.Nodes...)
	evidence.Nodes = append(evidence.Nodes, k8sIR.Nodes...)
	evidence.Edges = append(evidence.Edges, tfIR.Edges...)
	evidence.Edges = append(evidence.Edges, k8sIR.Edges...)
	if err := evidence.Validate(); err != nil {
		fmt.Fprintf(stderr, "substrate compile: evidence graph: %v\n", err)
		return 2
	}

	irDir := filepath.Join(*out, "ir")
	if err := os.MkdirAll(irDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "substrate compile: create output directory %s: %v\n", irDir, err)
		return 2
	}
	if err := writeJSONLArtifact(irDir, "nodes.jsonl", evidence.Nodes, ir.WriteNodesJSONL); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeJSONLArtifact(irDir, "edges.jsonl", evidence.Edges, ir.WriteEdgesJSONL); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "parsed %d terraform resource(s) and %d kubernetes resource(s) from %s; compiled %d evidence node(s) and %d edge(s)\n",
		len(tfGraph.Resources), len(k8sGraph.Resources), *source, len(evidence.Nodes), len(evidence.Edges))
	return 0
}

// writeJSONLArtifact writes items to <dir>/<name> using write (one of
// ir.WriteNodesJSONL / ir.WriteEdgesJSONL), so the evidence graph is
// serialized with the IR package's own stable, byte-reproducible JSON
// Lines encoding rather than ad hoc JSON.
func writeJSONLArtifact[T any](dir, name string, items []T, write func(io.Writer, []T) error) error {
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if err := write(f, items); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
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
