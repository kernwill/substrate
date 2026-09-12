package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kernwill/substrate/internal/frontend/githubactions"
	"github.com/kernwill/substrate/internal/frontend/kubernetes"
	"github.com/kernwill/substrate/internal/frontend/terraform"
	"github.com/kernwill/substrate/internal/ir"
)

// runCompile implements "substrate compile --source <dir> --out <dir>"
// (FR-2 through FR-6: parse Terraform/Kubernetes/CI config, build the
// evidence graph, emit FedRAMP 20x artifacts).
//
// All three of FR-2's static sources are real today, and all three are
// mapped into the evidence graph:
//   - Terraform: parses *.tf files directly under --source
//     (internal/frontend/terraform.Parse), written raw to
//     <out>/terraform.json, then mapped to IR nodes/edges
//     (terraform.ToIR) via a small, human-reviewed table of which
//     resource types evidence which NIST 800-53 controls - see that
//     file's mapping functions for the reasoning behind each entry.
//   - Kubernetes: parses *.yaml/*.yml files under --source/k8s
//     (internal/frontend/kubernetes.Parse), written raw to
//     <out>/kubernetes.json, mapped the same way (kubernetes.ToIR).
//   - GitHub Actions: parses *.yml/*.yaml files under
//     --source/.github/workflows (internal/frontend/githubactions.Parse),
//     written raw to <out>/github_actions.json, mapped the same way
//     (githubactions.ToIR). Only two of FR-2.6's five bullet points are
//     genuinely static-file-parseable - required reviews, branch
//     protection, and deployment approvals are GitHub repository
//     settings, not workflow YAML content, and need a live API
//     collector (FR-3-shaped work) that doesn't exist yet - see that
//     package's own doc.go.
//
// The "k8s" and ".github/workflows" subdirectories are narrow,
// provisional conventions matching testdata/fixtures/minimal's own
// layout, not a general answer to "how does substrate know which files
// under --source belong to which frontend" - a real include/exclude
// design (a .gitignore-style filter, most likely) is still deferred.
//
// All three frontends' IR output is merged into one ir.Graph, validated,
// and written as JSON Lines to <out>/ir/nodes.jsonl and
// <out>/ir/edges.jsonl (ir.WriteNodesJSONL/WriteEdgesJSONL - the
// package's own stable, byte-reproducible serialization, not ad hoc
// JSON). No frontend's mapping table is comprehensive: a resource type
// or field with no reviewed entry produces no node, never a guess - see
// each ToIR's own doc comment.
//
// Emitting FedRAMP artifacts from the evidence graph (internal/backends,
// FR-6) remains unimplemented.
//
// Nothing is written to --out until every parse, map, and validate step
// above has succeeded: writing happens against a "--out.tmp" sibling
// directory, published at --out only at the very end via two back-to-back
// renames (see the comment where that happens) rather than a delete-then-
// rename, so even a process kill at the worst possible instant leaves a
// recoverable "--out.old" behind instead of --out missing outright. A
// failure partway through a run can therefore never leave --out holding
// some frontends' raw JSON with no matching ir/ output, or a stale ir/
// next to fresh per-frontend JSON from a run that didn't actually finish.
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

	k8sDir := filepath.Join(*source, "k8s")
	ghaDir := filepath.Join(*source, ".github", "workflows")

	tfGraph, err := terraform.Parse(*source)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse terraform: %v\n", err)
		return 2
	}
	k8sGraph, err := kubernetes.Parse(k8sDir)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse kubernetes: %v\n", err)
		return 2
	}
	ghaGraph, err := githubactions.Parse(ghaDir)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse github actions: %v\n", err)
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
	ghaIR, err := githubactions.ToIR(ghaGraph)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: map github actions to evidence graph: %v\n", err)
		return 2
	}
	evidence := ir.Graph{}
	evidence.Nodes = append(evidence.Nodes, tfIR.Nodes...)
	evidence.Nodes = append(evidence.Nodes, k8sIR.Nodes...)
	evidence.Nodes = append(evidence.Nodes, ghaIR.Nodes...)
	evidence.Edges = append(evidence.Edges, tfIR.Edges...)
	evidence.Edges = append(evidence.Edges, k8sIR.Edges...)
	evidence.Edges = append(evidence.Edges, ghaIR.Edges...)
	if err := evidence.Validate(); err != nil {
		fmt.Fprintf(stderr, "substrate compile: evidence graph: %v\n", err)
		return 2
	}

	// Every parse, map, and validate step above must succeed before any
	// of it touches --out. Writing runs entirely against a sibling
	// ".tmp" directory and is only made visible at *out by a single
	// rename at the very end - so a failure past this point (which
	// should only ever be an I/O error, since every step that can find
	// something wrong with the input already has) can never leave *out
	// holding a partial mix of some frontends' raw JSON and no matching
	// ir/ output, or a stale ir/ from a prior run sitting next to fresh
	// per-frontend JSON from this one.
	tmpOut := *out + ".tmp"
	if err := os.RemoveAll(tmpOut); err != nil {
		fmt.Fprintf(stderr, "substrate compile: clear stale %s: %v\n", tmpOut, err)
		return 2
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(tmpOut)
		}
	}()

	if err := os.MkdirAll(tmpOut, 0o755); err != nil {
		fmt.Fprintf(stderr, "substrate compile: create output directory %s: %v\n", tmpOut, err)
		return 2
	}
	if err := writeArtifact(tmpOut, "terraform.json", tfGraph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeArtifact(tmpOut, "kubernetes.json", k8sGraph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeArtifact(tmpOut, "github_actions.json", ghaGraph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}

	irDir := filepath.Join(tmpOut, "ir")
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

	// Publish tmpOut at *out with two back-to-back renames rather than
	// RemoveAll(*out) followed by Rename(tmpOut, *out): os.Rename cannot
	// itself atomically replace an existing non-empty directory (POSIX
	// rename(2) requires the destination directory to be empty), so
	// deleting first was the only way to make Rename succeed - but a
	// process killed between that delete and the rename left *out
	// missing entirely, which is worse than the partial-mix problem this
	// function exists to prevent: no artifact where a stale-but-complete
	// one used to be. Renaming *out out of the way first shrinks that
	// unsafe window from "however long a recursive delete takes" to the
	// gap between two near-instant rename() calls, and - if that exact
	// window is still hit - leaves the previous run's complete output
	// recoverable at backupOut instead of gone.
	backupOut := *out + ".old"
	if _, err := os.Stat(*out); err == nil {
		if err := os.RemoveAll(backupOut); err != nil {
			fmt.Fprintf(stderr, "substrate compile: clear stale %s: %v\n", backupOut, err)
			return 2
		}
		if err := os.Rename(*out, backupOut); err != nil {
			fmt.Fprintf(stderr, "substrate compile: move previous %s aside: %v\n", *out, err)
			return 2
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stderr, "substrate compile: stat %s: %v\n", *out, err)
		return 2
	}
	if err := os.Rename(tmpOut, *out); err != nil {
		fmt.Fprintf(stderr, "substrate compile: publish %s: %v\n", *out, err)
		return 2
	}
	committed = true
	if err := os.RemoveAll(backupOut); err != nil {
		// Not fatal: *out is already correct - a leftover backupOut is
		// disk space, not a correctness problem - but still worth
		// telling the operator so it doesn't silently accumulate.
		fmt.Fprintf(stderr, "substrate compile: warning: could not remove backup %s: %v\n", backupOut, err)
	}

	fmt.Fprintf(stdout, "parsed %d terraform resource(s), %s, and %s from %s; compiled %d evidence node(s) and %d edge(s)\n",
		len(tfGraph.Resources), resourceCount(k8sDir, len(k8sGraph.Resources), "kubernetes resource"),
		resourceCount(ghaDir, len(ghaGraph.Workflows), "github actions workflow"), *source, len(evidence.Nodes), len(evidence.Edges))
	return 0
}

// resourceCount renders a frontend's parsed count for the summary line,
// naming the gap when dir doesn't exist at all rather than printing the
// same "0 <unit>(s)" a directory that exists but is genuinely empty of
// matching files would also produce. Both the "k8s" and
// ".github/workflows" conventions are narrow and provisional (see this
// file's own doc comment above), and a repository that keeps its
// manifests somewhere else deserves a different message than one that
// genuinely has none.
func resourceCount(dir string, count int, unit string) string {
	if count != 0 {
		return fmt.Sprintf("%d %s(s)", count, unit)
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return fmt.Sprintf("0 %s(s) (%s not found)", unit, dir)
	}
	return fmt.Sprintf("0 %s(s)", unit)
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
	if err := write(f, items); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	// Checked, not deferred-and-ignored: a full disk (or a network-mounted
	// --out.tmp) can fail at close time, after buffered Write calls have
	// already returned success - an error here is the only place that
	// surfaces, and this artifact is about to be renamed into place as if
	// it were complete.
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
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
	if err := writeJSON(f, v); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
