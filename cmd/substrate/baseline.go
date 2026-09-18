package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kernwill/substrate/internal/backends/fedramp20x"
)

// baselineSchemaVersion is this file's own JSON shape version,
// independent of ir.SchemaVersion or the rules dataset version - bump
// it if Baseline's own fields change in a way that breaks an older
// baseline file's readability.
const baselineSchemaVersion = "1"

// Baseline is a substrate baseline update's saved output: a snapshot of
// KSI indicator results (the same []fedramp20x.IndicatorResult
// compile's own ksi_results.json holds) plus who recorded it and when.
//
// ApprovedBy/ApprovedAt/GitCommit are FR-7.6's "approval trail," but
// deliberately NOT the Security Decision Record FR-7.6 actually names:
// FR-6.4 (an SDR as its own append-only log with a current-state
// projection) does not exist in this codebase yet. This is a documented
// stand-in scoped to exactly what a baseline needs on its own -
// verified in docs/adr/0011 as a known, disclosed gap rather than a
// claim that this IS the SDR integration FR-7.6 ultimately wants.
type Baseline struct {
	SchemaVersion string                       `json:"schema_version"`
	ApprovedAt    time.Time                    `json:"approved_at"`
	ApprovedBy    string                       `json:"approved_by"`
	GitCommit     string                       `json:"git_commit,omitempty"`
	Results       []fedramp20x.IndicatorResult `json:"results"`
}

// runBaseline dispatches "substrate baseline <subcommand>", matching
// the same subcommand shape "substrate rules show"/"substrate rules
// diff" already use (rules.go's runRules).
func runBaseline(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "substrate baseline: no subcommand given (try: update)")
		return 2
	}
	switch args[0] {
	case "update":
		return runBaselineUpdate(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "substrate baseline: %q not implemented yet (try: update)\n", args[0])
		return 2
	}
}

// runBaselineUpdate implements "substrate baseline update --current
// <file> --out <file>" (FR-7.6).
//
// --current names a ksi_results.json compile already produced - this
// command does not run compile itself, matching the same single-
// responsibility, composed-in-a-pipeline shape docs/adr/0009 already
// established for collect versus compile. Running "substrate compile"
// followed by "substrate baseline update --current <out>/ksi_results.json
// --out <baseline file>" is the intended two-command flow, the same way
// "substrate collect" then "substrate compile --runtime" already is one.
//
// ApprovedBy is read from git config (user.name and user.email, the
// same identity a commit made right now would carry) rather than an
// application-level login system this project has none of; GitCommit
// is read from git rev-parse HEAD, best-effort - its absence (not a
// git repository, or git not on PATH) is not fatal, since a baseline
// is still meaningful without knowing which commit produced it, just
// less traceable.
func runBaselineUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("substrate baseline update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	current := fs.String("current", "", "path to the ksi_results.json to record as the new baseline (from 'substrate compile')")
	out := fs.String("out", "", "path to write the baseline file to")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: substrate baseline update --current <file> --out <file>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *current == "" || *out == "" {
		fs.Usage()
		return 2
	}

	results, err := readArtifact[[]fedramp20x.IndicatorResult](*current)
	if err != nil {
		fmt.Fprintf(stderr, "substrate baseline update: read %s: %v\n", *current, err)
		return 2
	}

	baseline := Baseline{
		SchemaVersion: baselineSchemaVersion,
		ApprovedAt:    time.Now().UTC(),
		ApprovedBy:    gitIdentity(),
		GitCommit:     gitHeadCommit(),
		Results:       *results,
	}

	// writeArtifact, not a hand-rolled create/encode/close sequence: it's
	// the same three-step contract this file used to duplicate, already
	// defined once in compile.go - a future fix there (e.g. an atomic
	// write) should not need a second, separately-maintained copy here
	// to also apply it.
	if err := writeArtifact(filepath.Dir(*out), filepath.Base(*out), baseline); err != nil {
		fmt.Fprintf(stderr, "substrate baseline update: %v\n", err)
		return 2
	}

	fmt.Fprintf(stdout, "recorded baseline for %d indicator(s) approved by %s at %s\n",
		len(baseline.Results), baseline.ApprovedBy, baseline.ApprovedAt.Format(time.RFC3339))
	return 0
}

// LoadBaseline reads and decodes a Baseline file written by
// runBaselineUpdate.
func LoadBaseline(path string) (*Baseline, error) {
	return readArtifact[Baseline](path)
}

// gitIdentity returns "Name <email>" from the local git config, or
// "unknown" if git is unavailable or unconfigured - never fatal, since
// an unattributed baseline is still a real baseline, just a less
// traceable one.
func gitIdentity() string {
	name := gitConfig("user.name")
	email := gitConfig("user.email")
	switch {
	case name != "" && email != "":
		return fmt.Sprintf("%s <%s>", name, email)
	case name != "":
		return name
	case email != "":
		return email
	default:
		return "unknown"
	}
}

func gitConfig(key string) string {
	out, err := exec.CommandContext(context.Background(), "git", "config", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// gitHeadCommit returns the current commit hash, or "" if unavailable
// (not a git repository, git not on PATH, or no commits yet).
func gitHeadCommit() string {
	out, err := exec.CommandContext(context.Background(), "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
