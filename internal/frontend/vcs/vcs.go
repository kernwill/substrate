// Package vcs gives frontend collectors a single, shared way to answer
// "when was this file's content true at the source" (FR-4.1's
// provenance Timestamp): a file's last git commit time, never its
// filesystem modification time.
//
// mtime was tried first (in internal/frontend/terraform) and rejected:
// it is not preserved by git, so the exact same committed content gets
// a different, environment-dependent timestamp on every fresh checkout
// - exactly the non-reproducible value NFR-3 forbids. Shelling out to
// git instead is a deliberate, documented tradeoff against NFR-1's "no
// runtime dependencies" - see docs/adr/0006 for the full reasoning and
// alternatives considered. Every frontend collector that reads static
// files should use this package rather than reinvent the same
// tradeoff file by file.
package vcs

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CommitTime returns filename's (relative to dir) last commit time from
// git, run with dir as the command's own working directory so it
// resolves correctly regardless of where the actual repository root is.
// It returns an error - never a guess - if git is not on PATH, dir is
// not a git working tree, or filename has no commit history.
// Terraform files must be committed to git for substrate compile to
// run against them, and the same now applies to every other frontend
// source.
func CommitTime(dir, filename string) (time.Time, error) {
	cmd := exec.Command("git", "log", "-1", "--format=%cI", "--", filename)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return time.Time{}, fmt.Errorf("git log --format=%%cI -- %s: %w (%s)", filename, err, strings.TrimSpace(stderr.String()))
	}
	line := strings.TrimSpace(stdout.String())
	if line == "" {
		return time.Time{}, fmt.Errorf("%s has no git commit history - substrate requires source files to be committed, so their provenance timestamp (last commit time) is reproducible across checkouts, unlike filesystem modification time", filename)
	}
	t, err := time.Parse(time.RFC3339, line)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse git commit time %q for %s: %w", line, filename, err)
	}
	return t.UTC(), nil
}
