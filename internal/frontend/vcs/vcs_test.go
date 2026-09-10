package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
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
