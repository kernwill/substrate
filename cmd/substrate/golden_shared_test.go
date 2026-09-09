package main

import (
	"flag"
	"os"
)

// updateGolden and the SUBSTRATE_UPDATE_GOLDEN environment variable are
// the two deliberate-regeneration triggers every golden test in this
// package (TestGoldenRulesShow, TestGoldenRulesDiff, TestGoldenCompile)
// must honor identically - see goldenUpdateRequested. They used to be
// checked inconsistently (one test file checked only the flag, another
// checked both), which meant `make golden-update` (which sets only the
// env var) silently regenerated some golden suites and not others.
var updateGolden = flag.Bool("update", false, "update golden files")

// goldenUpdateRequested reports whether the current test run should
// deliberately regenerate golden fixtures rather than compare against
// them. Every golden test in this package must call this instead of
// checking *updateGolden or the environment variable directly, so a
// future third trigger only needs to be added in one place.
func goldenUpdateRequested() bool {
	return *updateGolden || os.Getenv("SUBSTRATE_UPDATE_GOLDEN") != ""
}
