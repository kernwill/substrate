package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// githubRequestTimeout bounds every individual GitHub REST API call
// this file makes. /code-review caught that the original version had
// no timeout at all - http.DefaultClient plus a context with no
// deadline - so a GitHub API stall or network hiccup could hang
// runGate indefinitely, blocking the whole CI job until the runner's
// own top-level timeout eventually killed it. That directly
// contradicted this code's own documented "never fails the gate over
// a network issue" promise: a hang blocks the pipeline, which is worse
// than the graceful degradation the non-fatal-warning design intends.
const githubRequestTimeout = 15 * time.Second

// githubOperationTimeout bounds the outer context runGate wraps around
// one whole postGateComment call (find, then create or update) - larger
// than githubRequestTimeout since findMarkedComment may need several
// paginated requests on an active PR, each individually bounded to
// githubRequestTimeout by githubHTTPClient, but the operation as a
// whole still needs its own, longer ceiling.
const githubOperationTimeout = 30 * time.Second

// gateCommentMarker is a hidden marker embedded in every PR comment
// this command posts, so a rerun of gate on the same PR (e.g. a second
// push) updates its own prior comment in place rather than piling up a
// new one on every run - the same pattern most CI bots that comment on
// PRs use (Vercel, Codecov, and similar), chosen deliberately over
// "always post a new comment" to avoid spamming a PR's timeline on
// every push to the same branch.
const gateCommentMarker = "<!-- substrate-gate -->"

// githubConfig is everything postGateComment needs to reach the
// GitHub REST API for one specific PR - built from GitHub Actions' own
// documented environment variables (never anything substrate invents),
// per docs/adr/0011's own reasoning for why this reads ambient CI
// context rather than requiring new flags for information the CI
// environment already has.
type githubConfig struct {
	apiBase  string // overridable for tests; production default is githubAPIBase
	token    string
	owner    string
	repo     string
	prNumber int
}

const githubAPIBase = "https://api.github.com"

// githubConfigFromEnv reads GITHUB_TOKEN, GITHUB_REPOSITORY, and the
// pull request number out of GITHUB_EVENT_PATH (a JSON file GitHub
// Actions writes for every workflow run). Returns a descriptive error,
// never a guess, if any piece is missing - including the ordinary case
// of gate running against a non-pull_request event (a push to main,
// say), which has no PR to comment on at all.
func githubConfigFromEnv() (*githubConfig, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN is not set")
	}
	repository := os.Getenv("GITHUB_REPOSITORY")
	owner, repo, ok := strings.Cut(repository, "/")
	if !ok || owner == "" || repo == "" {
		return nil, fmt.Errorf("GITHUB_REPOSITORY is not set or not in \"owner/repo\" form (got %q)", repository)
	}
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return nil, fmt.Errorf("GITHUB_EVENT_PATH is not set - not running under GitHub Actions?")
	}
	prNumber, err := pullRequestNumberFromEventFile(eventPath)
	if err != nil {
		return nil, fmt.Errorf("determine pull request number from %s: %w", eventPath, err)
	}
	return &githubConfig{apiBase: githubAPIBase, token: token, owner: owner, repo: repo, prNumber: prNumber}, nil
}

// pullRequestNumberFromEventFile reads path (GITHUB_EVENT_PATH's own
// value) and extracts .pull_request.number. Returns a real error - not
// a guess, not zero - if the event has no pull_request key at all,
// which is the correct outcome for any non-PR-triggered workflow run
// (a push, a schedule, a manual dispatch).
func pullRequestNumberFromEventFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var event struct {
		PullRequest *struct {
			Number int `json:"number"`
		} `json:"pull_request"`
	}
	if err := json.NewDecoder(f).Decode(&event); err != nil {
		return 0, fmt.Errorf("parse event payload: %w", err)
	}
	if event.PullRequest == nil {
		return 0, fmt.Errorf("event payload has no pull_request field - this workflow run was not triggered by a pull request")
	}
	return event.PullRequest.Number, nil
}

type githubComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

// githubCommentsPerPage is the page size requested when listing PR
// comments - the maximum GitHub's API allows, to minimize the number of
// round trips findMarkedComment needs on an active PR.
const githubCommentsPerPage = 100

// findMarkedComment returns the ID of the existing PR comment
// containing gateCommentMarker, if any, so upsertComment can update it
// in place instead of creating a duplicate. Pages through every page of
// comments, not just the first: /code-review caught that an earlier
// version fetched only GitHub's default 30-comment first page, so a
// marked comment posted several runs ago on an active PR (more than
// ~30 comments deep) was never found, and every subsequent run created
// a new duplicate instead of updating in place - exactly the
// timeline-spam this whole marker-based design exists to prevent.
func (c *githubConfig) findMarkedComment(ctx context.Context) (int64, bool, error) {
	for page := 1; ; page++ {
		url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments?per_page=%d&page=%d",
			c.apiBase, c.owner, c.repo, c.prNumber, githubCommentsPerPage, page)
		var comments []githubComment
		if err := c.do(ctx, http.MethodGet, url, nil, &comments); err != nil {
			return 0, false, err
		}
		for _, cm := range comments {
			if strings.Contains(cm.Body, gateCommentMarker) {
				return cm.ID, true, nil
			}
		}
		if len(comments) < githubCommentsPerPage {
			return 0, false, nil // last page
		}
	}
}

// createComment posts body as a brand new PR comment.
func (c *githubConfig) createComment(ctx context.Context, body string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", c.apiBase, c.owner, c.repo, c.prNumber)
	return c.do(ctx, http.MethodPost, url, map[string]string{"body": body}, nil)
}

// updateComment replaces the body of the existing comment id in place.
func (c *githubConfig) updateComment(ctx context.Context, id int64, body string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/comments/%d", c.apiBase, c.owner, c.repo, id)
	return c.do(ctx, http.MethodPatch, url, map[string]string{"body": body}, nil)
}

// githubHTTPClient is shared by every do() call so githubRequestTimeout
// bounds each individual request - see that constant's own doc comment
// for why an unbounded http.DefaultClient was a real gap.
var githubHTTPClient = &http.Client{Timeout: githubRequestTimeout}

// do issues one GitHub REST API request, decoding a JSON response body
// into out when non-nil. Kept as one small, dependency-free method
// (net/http and encoding/json only) rather than pulling in a full
// GitHub SDK for the three endpoints this file actually calls - per
// CLAUDE.md's "do not add dependencies casually," a generic REST client
// library is a substantial addition for a surface this narrow.
func (c *githubConfig) do(ctx context.Context, method, url string, body any, out any) error {
	var reqBody *bytes.Buffer
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewBuffer(raw)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: unexpected status %s", method, url, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// postGateComment renders diff's report as a PR comment body and
// creates or updates it via githubConfigFromEnv's own ambient GitHub
// Actions context.
//
// Called on every run where --pr-comment is set, not only when diff
// has a regression: /code-review caught that an earlier version only
// ever called this when diff.Regressions was non-empty, which meant a
// later run that FIXED a previously-reported regression never touched
// the PR at all - the stale "N regression(s) found" comment from the
// earlier run sat on the PR forever, looking like a still-live failure
// to any reviewer skimming the timeline. Now: no marked comment exists
// and nothing regressed - skip entirely, since there is nothing to say
// and nothing previously said that needs correcting. A marked comment
// already exists - always update it in place, to either the current
// regression report or an explicit "previously reported regressions
// are now resolved" message, whichever is true. Nothing exists yet but
// there's a regression to report - create the comment.
func postGateComment(ctx context.Context, diff gateDiff) error {
	cfg, err := githubConfigFromEnv()
	if err != nil {
		return err
	}
	return cfg.postGateComment(ctx, diff)
}

// postGateComment is the decision logic itself, as a method on an
// already-resolved *githubConfig so it's directly testable against an
// httptest.Server (via apiBase) without needing real GitHub Actions
// environment variables.
func (c *githubConfig) postGateComment(ctx context.Context, diff gateDiff) error {
	id, found, err := c.findMarkedComment(ctx)
	if err != nil {
		return fmt.Errorf("list existing comments: %w", err)
	}
	if !found && len(diff.Regressions) == 0 {
		return nil
	}

	body := gateCommentMarker + "\n\n## substrate gate\n\n"
	if len(diff.Regressions) == 0 {
		body += "Previously reported regression(s) are now resolved.\n\n"
	}
	body += "```\n" + renderGateReport(diff) + "```\n"

	if found {
		return c.updateComment(ctx, id, body)
	}
	return c.createComment(ctx, body)
}
