// Package githubactions parses GitHub Actions workflow files (FR-2.6).
//
// CONTRACT (per internal/frontend's own contract, which this package
// inherits):
//   - Produces raw facts, with full provenance, tagged Declared.
//   - Knows nothing about any compliance framework or NIST 800-53
//     control family - see internal/frontend/terraform's graph.go for
//     the shared TODO(mapping) note; this package's own ir.go resolves
//     it the same way internal/frontend/terraform's and
//     internal/frontend/kubernetes's do.
//
// FR-2.6 lists five things to extract: required reviews, branch
// protection, deployment approvals, secret scanning, and dependency
// review. Only the last one is genuinely visible in a workflow YAML
// file. The other four are GitHub repository settings - branch
// protection rules, required-reviewer counts, environment protection
// rules, and the repository's Secret Scanning feature toggle - none of
// which are expressed in any file committed to the repository at all;
// they live in GitHub's own configuration, reachable only through its
// REST or GraphQL API. This is not a "not yet implemented" gap the way
// Helm rendering is for internal/frontend/kubernetes: no amount of
// additional static-file parsing could ever produce these facts. They
// belong to a live GitHub API collector, which is FR-3-shaped work
// (runtime collection), not FR-2 (static parsing), despite FR-2.6's own
// wording grouping them together.
//
// What this package actually does, matching what
// testdata/fixtures/minimal/.github/workflows/ci.yml exercises:
//   - Extracts a workflow's top-level "permissions" block, when
//     explicitly declared, recording the granted scopes verbatim. A
//     workflow with no explicit permissions block (relying on the
//     account or organization's default GITHUB_TOKEN permissions)
//     produces no fact - there is nothing declared to measure, the same
//     principle as an unmapped Terraform or Kubernetes resource.
//   - Detects any job step using actions/dependency-review-action,
//     regardless of the job's own name.
//
// Not modeled, deferred rather than guessed at: job-level "permissions"
// overrides (only the workflow-level block is read; no fixture
// exercises a job-level override), reusable workflow calls
// ("uses: ./.github/workflows/other.yml"), and composite/local actions.
package githubactions
