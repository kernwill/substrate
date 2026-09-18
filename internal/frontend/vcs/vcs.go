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
	"sync"
	"time"
)

// CommitTime returns filename's (relative to dir) last commit time from
// git, run with dir as the command's own working directory so it
// resolves correctly regardless of where the actual repository root is.
// It returns an error - never a guess - if git is not on PATH, dir is
// not a git working tree, dir is a shallow clone (see checkNotShallow),
// or filename has no commit history. Terraform files must be committed
// to git for substrate compile to run against them, and the same now
// applies to every other frontend source.
func CommitTime(dir, filename string) (time.Time, error) {
	if err := checkNotShallow(dir); err != nil {
		return time.Time{}, err
	}

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

// shallowCache memoizes checkNotShallow's result per dir: CommitTime is
// called once per source file (every .tf/.yaml file in a directory), and
// without this, every one of those calls would pay for a second git
// subprocess spawn to re-answer the exact same per-directory question.
var (
	shallowCacheMu sync.Mutex
	shallowCache   = map[string]error{}
)

// checkNotShallow fails loudly if dir is a shallow git clone (git's
// `--is-shallow-repository`, e.g. from `git clone --depth N` or actions/
// checkout's default fetch-depth: 1) rather than letting CommitTime
// silently compute a wrong value.
//
// In a shallow clone, `git log -1 -- <file>` does not error - it returns
// the shallow boundary commit as filename's "last commit," even when
// that commit never touched filename at all, because git has no earlier
// history to walk back through and confirm otherwise. That is
// byte-for-byte the "silently wrong instead of loudly absent" outcome
// CLAUDE.md's "fail visible, never fail silent" exists to rule out, and
// it is not a rare edge case: shallow clones are the DEFAULT checkout
// behavior for both actions/checkout (fetch-depth: 1) and many GitLab CI
// configurations (GIT_DEPTH), which are exactly the CI environments this
// tool is meant to run inside for real customers - not a scenario
// confined to this project's own golden tests, which is how this bug was
// actually found: this project's own CI runs a shallow checkout and
// started producing a non-reproducible provenance timestamp (the shallow
// boundary commit's date, which advances on every unrelated push) in
// place of the correct, stable last-commit date for an unchanged
// fixture file. See docs/adr/0006's "Consequences" section, which
// anticipated this exact failure mode before it was ever observed.
func checkNotShallow(dir string) error {
	shallowCacheMu.Lock()
	if err, ok := shallowCache[dir]; ok {
		shallowCacheMu.Unlock()
		return err
	}
	shallowCacheMu.Unlock()

	err := probeShallow(dir)

	shallowCacheMu.Lock()
	shallowCache[dir] = err
	shallowCacheMu.Unlock()
	return err
}

func probeShallow(dir string) error {
	cmd := exec.Command("git", "rev-parse", "--is-shallow-repository")
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git rev-parse --is-shallow-repository: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(stdout.String()) == "true" {
		return fmt.Errorf("%s is a shallow git clone - a file's provenance timestamp (last commit time) cannot be reliably determined without full history: `git log` silently returns the shallow boundary commit's date for ANY file once history runs out, even one that commit never touched. Fetch full history before running substrate compile (actions/checkout's `fetch-depth: 0`, or `git fetch --unshallow`)", dir)
	}
	return nil
}
