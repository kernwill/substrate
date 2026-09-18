package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/kernwill/substrate/internal/backends/fedramp20x"
	"github.com/kernwill/substrate/internal/ir"
)

// regression is one KSI indicator that was Satisfied in the baseline
// and is no longer Satisfied now - the FR-7.3 case this whole command
// exists to catch.
type regression struct {
	Indicator      string
	BaselineStatus fedramp20x.Status
	CurrentStatus  fedramp20x.Status
	CurrentReason  string
	// EvidenceLocations names where the baseline's own evidence for this
	// indicator was found (file:line, when --nodes was given and those
	// node IDs are still resolvable) - "the prior state," per FR-7.4,
	// grounded in the actual source that used to satisfy it rather than
	// just the word "satisfied" on its own.
	EvidenceLocations []string
}

// improvement is the mirror case: not Satisfied in the baseline, now
// Satisfied. Never a gate failure, but worth reporting - a customer
// fixing something deserves to see that reflected, not just silence.
type improvement struct {
	Indicator      string
	BaselineStatus fedramp20x.Status
	CurrentStatus  fedramp20x.Status
}

// gateDiff is the full comparison between a baseline and a current run.
// New and Missing are informational only, never gate failures: an
// indicator gate has never seen before cannot have "regressed" (FR-7.3
// is about a rule that regressed, not one that's new), and one that
// disappeared entirely (e.g. a ruleset version bump) is a data-shape
// anomaly FR-8.12's own ruleset-migration reporting owns, not this
// command's PR-comment-and-exit-code job.
type gateDiff struct {
	Regressions []regression
	// OtherChanges is every OTHER transition away from Satisfied -
	// today, to NotApplicable or RequiresAttestation - that isRegressedStatus
	// deliberately excludes from Regressions. Neither status means the
	// customer's actual posture got worse: NotApplicable means the
	// control's own scope changed (e.g. the resource it was about was
	// removed), and RequiresAttestation means the compiler now says
	// this needs human sign-off rather than claiming automated proof -
	// a more honest classification, not a worse one. Still reported
	// (never a gate failure), per the same "fail visible, not silent"
	// discipline the rest of this codebase holds to.
	OtherChanges []regression
	Improvements []improvement
	New          []string
	Missing      []string
	Unchanged    int
}

// isRegressedStatus reports whether s, as a transition away from
// Satisfied, represents an actual worsening of posture worth failing
// the gate over. Only NotSatisfied and Undetermined qualify - see
// gateDiff.OtherChanges' own doc comment for why NotApplicable and
// RequiresAttestation don't.
func isRegressedStatus(s fedramp20x.Status) bool {
	return s == fedramp20x.StatusNotSatisfied || s == fedramp20x.StatusUndetermined
}

// diffResults compares baseline against current, keyed by Indicator ID.
// nodesByID is used to resolve a regression's baseline Evidence node
// IDs to file:line locations; pass nil to skip that enrichment (gate's
// own --nodes flag is optional). Returns an error if either input
// carries a duplicate Indicator ID - silently keeping only the last
// entry seen (what a naive map build would do) would make the gate's
// pass/fail decision depend on slice order for a data anomaly, exactly
// the "fail silent" outcome this project's own discipline rules out.
func diffResults(baseline, current []fedramp20x.IndicatorResult, nodesByID map[ir.NodeID]ir.Node) (gateDiff, error) {
	baselineByID, err := indexByIndicator(baseline, "baseline")
	if err != nil {
		return gateDiff{}, err
	}
	currentByID, err := indexByIndicator(current, "current")
	if err != nil {
		return gateDiff{}, err
	}

	var diff gateDiff
	for id, base := range baselineByID {
		cur, ok := currentByID[id]
		if !ok {
			diff.Missing = append(diff.Missing, id)
			continue
		}
		switch {
		case base.Status == fedramp20x.StatusSatisfied && isRegressedStatus(cur.Status):
			diff.Regressions = append(diff.Regressions, regression{
				Indicator:         id,
				BaselineStatus:    base.Status,
				CurrentStatus:     cur.Status,
				CurrentReason:     cur.Reason,
				EvidenceLocations: locationsFor(base.Evidence, nodesByID),
			})
		case base.Status == fedramp20x.StatusSatisfied && cur.Status != fedramp20x.StatusSatisfied:
			diff.OtherChanges = append(diff.OtherChanges, regression{
				Indicator:         id,
				BaselineStatus:    base.Status,
				CurrentStatus:     cur.Status,
				CurrentReason:     cur.Reason,
				EvidenceLocations: locationsFor(base.Evidence, nodesByID),
			})
		case base.Status != fedramp20x.StatusSatisfied && cur.Status == fedramp20x.StatusSatisfied:
			diff.Improvements = append(diff.Improvements, improvement{
				Indicator:      id,
				BaselineStatus: base.Status,
				CurrentStatus:  cur.Status,
			})
		default:
			diff.Unchanged++
		}
	}
	for id := range currentByID {
		if _, ok := baselineByID[id]; !ok {
			diff.New = append(diff.New, id)
		}
	}

	sort.Slice(diff.Regressions, func(i, j int) bool { return diff.Regressions[i].Indicator < diff.Regressions[j].Indicator })
	sort.Slice(diff.OtherChanges, func(i, j int) bool { return diff.OtherChanges[i].Indicator < diff.OtherChanges[j].Indicator })
	sort.Slice(diff.Improvements, func(i, j int) bool { return diff.Improvements[i].Indicator < diff.Improvements[j].Indicator })
	sort.Strings(diff.New)
	sort.Strings(diff.Missing)
	return diff, nil
}

// indexByIndicator builds a map keyed by Indicator ID, failing loudly
// (rather than silently keeping the last entry seen) if results
// contains the same ID more than once. label names which input
// (baseline or current) the error is about, for a caller-legible
// message.
func indexByIndicator(results []fedramp20x.IndicatorResult, label string) (map[string]fedramp20x.IndicatorResult, error) {
	byID := make(map[string]fedramp20x.IndicatorResult, len(results))
	for _, r := range results {
		if _, dup := byID[r.Indicator]; dup {
			return nil, fmt.Errorf("%s results contain duplicate indicator %q", label, r.Indicator)
		}
		byID[r.Indicator] = r
	}
	return byID, nil
}

// locationsFor renders each of ids as "path:line" using nodesByID,
// sorted and deduplicated. An id with no entry in nodesByID (nodesByID
// is nil, meaning --nodes wasn't given, or the node genuinely isn't in
// that file) is simply omitted - a partial or absent location list
// degrades this command's output, never its correctness.
func locationsFor(ids []string, nodesByID map[ir.NodeID]ir.Node) []string {
	seen := make(map[string]bool, len(ids))
	var out []string
	for _, id := range ids {
		node, ok := nodesByID[ir.NodeID(id)]
		if !ok || node.Provenance.Locator.Path == "" {
			continue
		}
		loc := fmt.Sprintf("%s:%d", node.Provenance.Locator.Path, node.Provenance.Locator.Line)
		if seen[loc] {
			continue
		}
		seen[loc] = true
		out = append(out, loc)
	}
	sort.Strings(out)
	return out
}

// Severity is FR-7.5's configurable severity policy.
type Severity string

const (
	SeverityError Severity = "error" // a regression fails the gate (exit 1)
	SeverityWarn  Severity = "warn"  // a regression is reported but does not fail the gate (exit 0)
)

// runGate implements "substrate gate --baseline <file> --current <file>"
// (FR-7.2/7.3/7.5, and FR-7.4 when --pr-comment is given).
//
// --current is a ksi_results.json compile already produced; gate does
// not run compile itself, the same single-responsibility split
// collect/compile already established (docs/adr/0009). --nodes, if
// given, is the matching nodes.jsonl, used only to resolve a
// regression's prior evidence to file:line for the report - its
// absence degrades that one detail, nothing else.
//
// Exit codes: 0 (no regression, or --severity warn), 1 (a regression,
// --severity error - the default), 2 (usage or internal error, e.g. a
// missing or malformed input file). A PR-comment posting failure is
// never promoted into a 2: the compliance regression decision is
// computed and reported independently of whether posting a comment
// about it succeeded, so a GitHub API hiccup can never flip a real
// regression into a false pass, nor fail an otherwise-clean gate run
// over an unrelated network error.
func runGate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("substrate gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baselinePath := fs.String("baseline", "", "path to a baseline file written by 'substrate baseline update'")
	currentPath := fs.String("current", "", "path to the current run's ksi_results.json (from 'substrate compile')")
	nodesPath := fs.String("nodes", "", "optional: path to the matching nodes.jsonl, to resolve regressed indicators' prior evidence to file:line")
	severity := fs.String("severity", string(SeverityError), "severity policy: 'error' fails the gate on a regression, 'warn' reports but does not fail it")
	prComment := fs.Bool("pr-comment", false, "post a PR comment naming any regression (requires GitHub Actions PR context; see runGate's own doc comment)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: substrate gate --baseline <file> --current <file> [--nodes <file>] [--severity error|warn] [--pr-comment]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *baselinePath == "" || *currentPath == "" {
		fs.Usage()
		return 2
	}
	if *severity != string(SeverityError) && *severity != string(SeverityWarn) {
		fmt.Fprintf(stderr, "substrate gate: --severity must be %q or %q, got %q\n", SeverityError, SeverityWarn, *severity)
		return 2
	}

	baseline, err := LoadBaseline(*baselinePath)
	if err != nil {
		fmt.Fprintf(stderr, "substrate gate: read baseline %s: %v\n", *baselinePath, err)
		return 2
	}
	current, err := readArtifact[[]fedramp20x.IndicatorResult](*currentPath)
	if err != nil {
		fmt.Fprintf(stderr, "substrate gate: read %s: %v\n", *currentPath, err)
		return 2
	}

	var nodesByID map[ir.NodeID]ir.Node
	if *nodesPath != "" {
		nodesByID, err = loadNodesByID(*nodesPath)
		if err != nil {
			fmt.Fprintf(stderr, "substrate gate: read %s: %v\n", *nodesPath, err)
			return 2
		}
	}

	diff, err := diffResults(baseline.Results, *current, nodesByID)
	if err != nil {
		fmt.Fprintf(stderr, "substrate gate: %v\n", err)
		return 2
	}
	fmt.Fprint(stdout, renderGateReport(diff))

	if *prComment {
		// Called unconditionally, not just when there's a regression:
		// postGateComment itself decides whether to skip, create, or
		// update - in particular, a run that fixes a previously-reported
		// regression must update the existing marked comment to say so,
		// not leave a stale "regression found" comment sitting on the PR
		// (see postGateComment's own doc comment). Bounded by its own
		// timeout (githubOperationTimeout, github.go) rather than
		// context.Background() unbounded, so a GitHub API stall degrades
		// to the same non-fatal warning path below instead of hanging
		// the whole CI job.
		ctx, cancel := context.WithTimeout(context.Background(), githubOperationTimeout)
		err := postGateComment(ctx, diff)
		cancel()
		if err != nil {
			// Non-fatal by design - see this function's own doc comment.
			fmt.Fprintf(stderr, "substrate gate: warning: post PR comment: %v\n", err)
		}
	}

	if len(diff.Regressions) > 0 && Severity(*severity) == SeverityError {
		return 1
	}
	return 0
}

// loadNodesByID reads path (a nodes.jsonl written by ir.WriteNodesJSONL)
// into a map keyed by NodeID, for locationsFor's own lookups.
func loadNodesByID(path string) (map[ir.NodeID]ir.Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	nodes, err := ir.ReadNodesJSONL(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	byID := make(map[ir.NodeID]ir.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	return byID, nil
}

// renderGateReport renders diff as the same plain text used for both
// stdout (every run) and the PR comment body - one format, not two to
// keep in sync. Every section (New, Missing, OtherChanges,
// Improvements) is printed whenever it has entries, regardless of
// whether Regressions is also non-empty - an earlier version only
// printed New/Missing inside the "no regressions" branch, so a run
// with one real regression alongside several brand-new indicators
// silently never told the reader which was which.
func renderGateReport(diff gateDiff) string {
	var b strings.Builder
	if len(diff.Regressions) == 0 {
		fmt.Fprintf(&b, "substrate gate: no regressions (%d unchanged, %d new, %d improved, %d other status change(s))\n",
			diff.Unchanged, len(diff.New), len(diff.Improvements), len(diff.OtherChanges))
	} else {
		fmt.Fprintf(&b, "substrate gate: %d regression(s) found\n", len(diff.Regressions))
		for _, r := range diff.Regressions {
			fmt.Fprintf(&b, "  - %s: %s -> %s (%s)\n", r.Indicator, r.BaselineStatus, r.CurrentStatus, r.CurrentReason)
			if len(r.EvidenceLocations) > 0 {
				fmt.Fprintf(&b, "    was satisfied via: %s\n", strings.Join(r.EvidenceLocations, ", "))
			}
		}
	}
	for _, oc := range diff.OtherChanges {
		fmt.Fprintf(&b, "  ~ status changed (not a regression): %s: %s -> %s (%s)\n", oc.Indicator, oc.BaselineStatus, oc.CurrentStatus, oc.CurrentReason)
	}
	for _, imp := range diff.Improvements {
		fmt.Fprintf(&b, "  + improved: %s: %s -> %s\n", imp.Indicator, imp.BaselineStatus, imp.CurrentStatus)
	}
	if len(diff.New) > 0 {
		fmt.Fprintf(&b, "  * %d new indicator(s) not in the baseline: %s\n", len(diff.New), strings.Join(diff.New, ", "))
	}
	if len(diff.Missing) > 0 {
		fmt.Fprintf(&b, "  ! %d indicator(s) in the baseline are missing from this run: %s\n", len(diff.Missing), strings.Join(diff.Missing, ", "))
	}
	return b.String()
}
