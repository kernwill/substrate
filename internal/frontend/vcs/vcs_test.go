package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=substrate-test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=substrate-test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("add", "-A")
	run("commit", "-q", "-m", "test fixture")
}

func TestCommitTimeReturnsUTC(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	initGitRepo(t, dir)

	got, err := CommitTime(dir, "a.txt")
	if err != nil {
		t.Fatalf("CommitTime: %v", err)
	}
	if got.Location() != time.UTC {
		t.Errorf("CommitTime() location = %v, want UTC", got.Location())
	}
	if got.IsZero() {
		t.Error("CommitTime() = zero time, want a real commit time")
	}
}

func TestCommitTimeIgnoresModTime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	initGitRepo(t, dir)

	before, err := CommitTime(dir, "a.txt")
	if err != nil {
		t.Fatalf("CommitTime (before touch): %v", err)
	}

	future := time.Now().Add(72 * time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	after, err := CommitTime(dir, "a.txt")
	if err != nil {
		t.Fatalf("CommitTime (after touch): %v", err)
	}
	if !after.Equal(before) {
		t.Errorf("CommitTime changed after touching mtime with no new commit: got %s, want unchanged %s", after, before)
	}
}

func TestCommitTimeFailsOnUntrackedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	initGitRepo(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("untracked"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}

	if _, err := CommitTime(dir, "b.txt"); err == nil {
		t.Error("CommitTime succeeded on an untracked file, want error")
	}
}

func TestCommitTimeFailsOnNonGitDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if _, err := CommitTime(dir, "a.txt"); err == nil {
		t.Error("CommitTime succeeded outside a git repository, want error")
	}
}

// TestCommitTimeFailsOnShallowClone is a regression test for the bug
// this project's own CI hit: in a shallow clone, `git log -1 -- <file>`
// does not error - it silently returns the shallow boundary commit's
// date for a.txt, even though that commit only ever touched b.txt, never
// a.txt. CommitTime must refuse outright (checkNotShallow, vcs.go)
// rather than let that wrong-but-plausible value through, the same
// "fail visible, never fail silent" reasoning as the untracked-file and
// non-git-directory cases above.
func TestCommitTimeFailsOnShallowClone(t *testing.T) {
	origin := t.TempDir()
	if err := os.WriteFile(filepath.Join(origin, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	initGitRepo(t, origin)

	// A second commit that never touches a.txt, so a shallow clone's
	// only visible commit is one that has nothing to do with a.txt's
	// real last-modified time.
	if err := os.WriteFile(filepath.Join(origin, "b.txt"), []byte("unrelated"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}
	initGitRepo(t, origin)

	wantUnaffected, err := CommitTime(origin, "a.txt")
	if err != nil {
		t.Fatalf("CommitTime on full clone: %v", err)
	}

	clone := filepath.Join(t.TempDir(), "shallow")
	// git ignores --depth for a plain local path clone ("--depth is
	// ignored in local clones; use file:// instead") - the file:// URL
	// form is required to actually exercise a shallow clone here.
	cmd := exec.Command("git", "clone", "--depth", "1", "file://"+origin, clone)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone --depth 1: %v\n%s", err, out)
	}

	got, err := CommitTime(clone, "a.txt")
	if err == nil {
		t.Fatalf("CommitTime on shallow clone succeeded with %s, want a loud error (the correct, full-clone value is %s - a shallow clone must never silently return something else)", got, wantUnaffected)
	}
	if !strings.Contains(err.Error(), "shallow") {
		t.Errorf("CommitTime error = %q, want it to mention the clone is shallow", err)
	}
}
