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
// Planned commands (see docs/REQUIREMENTS.md):
//
//	substrate rules show   --class C
//	substrate rules diff   <versionA> <versionB>
//	substrate collect      --source <dir>
//	substrate compile      --source <dir> --out <dir>
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
	fmt.Fprintf(os.Stderr, "substrate: %q not implemented yet\n", os.Args[1])
	os.Exit(2)
}
