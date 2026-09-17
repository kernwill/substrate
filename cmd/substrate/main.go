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
//	substrate rules show   --class C
//	substrate rules diff   <versionA> <versionB>
//	substrate collect      --out <dir>
//	substrate compile      --source <dir> --out <dir> [--runtime <dir>]
//
// collect and compile are deliberately separate (FR-3 runtime
// collection vs FR-2/FR-5/FR-6 static parsing, the evidence graph, and
// the backend): collect needs live AWS credentials, compile does not
// unless --runtime points at collect's own prior output. See
// collect.go's and compile.go's own doc comments, and docs/adr/0009.
//
// Planned commands (see docs/REQUIREMENTS.md):
//
//	substrate ir query     --control AC-2
//	substrate gate         --baseline <file>
//	substrate baseline update
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "substrate: no command given (try: rules, collect, compile, ir, gate)")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "rules":
		os.Exit(runRules(os.Args[2:], os.Stdout, os.Stderr))
	case "collect":
		os.Exit(runCollect(os.Args[2:], os.Stdout, os.Stderr))
	case "compile":
		os.Exit(runCompile(os.Args[2:], os.Stdout, os.Stderr))
	default:
		fmt.Fprintf(os.Stderr, "substrate: %q not implemented yet\n", os.Args[1])
		os.Exit(2)
	}
}
