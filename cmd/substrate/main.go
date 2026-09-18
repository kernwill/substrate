// Command substrate is the compliance compiler CLI.
//
// Design notes for whoever implements this (human or agent):
//
//   - Single static binary. No runtime dependencies. It runs inside a
//     customer's CI, often in GovCloud or air-gapped environments.
//   - Read-only by default. The AWS role we require is read-only and its
//     policy is published. Never ask for more.
//   - No telemetry. Not opt-out, absent. Silent phone-home is disqualifying
//     for our buyers.
//   - Exit codes: 0 pass, 1 rule regression (CI gate failure), 2 usage or
//     internal error. The CI gate depends on this distinction.
//
// Implemented commands:
//
//	substrate rules show    --class C
//	substrate rules diff    <versionA> <versionB>
//	substrate collect       --out <dir>
//	substrate compile       --source <dir> --out <dir> [--runtime <dir>]
//	substrate gate          --baseline <file> --current <file> [--nodes <file>] [--severity error|warn] [--pr-comment]
//	substrate baseline update --current <file> --out <file>
//	substrate ir query      --dir <out>/ir --control AC-2 [--format text|json]
//
// collect and compile are deliberately separate (FR-3 runtime
// collection vs FR-2/FR-5/FR-6 static parsing, the evidence graph, and
// the backend): collect needs live AWS credentials, compile does not
// unless --runtime points at collect's own prior output. See
// collect.go's and compile.go's own doc comments, and docs/adr/0009.
//
// gate and baseline update are FR-7's CI gate: baseline update records
// the current run's KSI results as the new baseline (with an approval
// trail - see baseline.go's own doc comment on why that's a documented
// stand-in for FR-6.4's Security Decision Record, not the SDR itself,
// which doesn't exist in this codebase yet); gate diffs a later run
// against that baseline and fails (exit 1) if a previously Satisfied
// indicator regressed. --pr-comment additionally posts the regression
// to the triggering pull request via the GitHub REST API, using
// GitHub Actions' own ambient environment (GITHUB_TOKEN,
// GITHUB_REPOSITORY, GITHUB_EVENT_PATH) rather than new flags for
// information the CI environment already provides. See gate.go's,
// github.go's, and baseline.go's own doc comments, and docs/adr/0011.
//
// ir query is FR-5.5/FR-4.6: given a directory a prior "substrate
// compile" wrote its ir/ output to, returns every fact (node, and any
// attestation, if that file exists) bearing on a given control, each
// with its full provenance - see irquery.go's own doc comment.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "substrate: no command given (try: rules, collect, compile, gate, baseline)")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "rules":
		os.Exit(runRules(os.Args[2:], os.Stdout, os.Stderr))
	case "collect":
		os.Exit(runCollect(os.Args[2:], os.Stdout, os.Stderr))
	case "compile":
		os.Exit(runCompile(os.Args[2:], os.Stdout, os.Stderr))
	case "gate":
		os.Exit(runGate(os.Args[2:], os.Stdout, os.Stderr))
	case "baseline":
		os.Exit(runBaseline(os.Args[2:], os.Stdout, os.Stderr))
	case "ir":
		os.Exit(runIR(os.Args[2:], os.Stdout, os.Stderr))
	default:
		fmt.Fprintf(os.Stderr, "substrate: %q not implemented yet\n", os.Args[1])
		os.Exit(2)
	}
}
