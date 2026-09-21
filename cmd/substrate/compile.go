package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kernwill/substrate/internal/backends/fedramp20x"
	awscollectors "github.com/kernwill/substrate/internal/frontend/collectors/aws"
	oktacollectors "github.com/kernwill/substrate/internal/frontend/collectors/okta"
	"github.com/kernwill/substrate/internal/frontend/dockerfile"
	"github.com/kernwill/substrate/internal/frontend/githubactions"
	"github.com/kernwill/substrate/internal/frontend/kubernetes"
	"github.com/kernwill/substrate/internal/frontend/terraform"
	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/rules"
)

// runCompile implements "substrate compile --source <dir> --out <dir>"
// (FR-2 through FR-6: parse Terraform/Kubernetes/CI config, build the
// evidence graph, emit FedRAMP 20x artifacts).
//
// All three of FR-2's static sources are real today, and all three are
// mapped into the evidence graph. "Written raw" below means written as
// each Parse call returns it, AFTER that package's own redaction pass
// (internal/redact, FR-4.4) already ran - never a byte-verbatim mirror
// of the source file. See docs/redaction-coverage.md for exactly what
// that pass does and does not catch.
//   - Terraform: parses *.tf files directly under --source
//     (internal/frontend/terraform.Parse), written raw to
//     <out>/terraform.json, then mapped to IR nodes/edges
//     (terraform.ToIR) via a small, human-reviewed table of which
//     resource types evidence which NIST 800-53 controls - see that
//     file's mapping functions for the reasoning behind each entry.
//   - Kubernetes: parses *.yaml/*.yml files under --source/k8s
//     (internal/frontend/kubernetes.Parse), written raw to
//     <out>/kubernetes.json, mapped the same way (kubernetes.ToIR).
//   - GitHub Actions: parses *.yml/*.yaml files under
//     --source/.github/workflows (internal/frontend/githubactions.Parse),
//     written raw to <out>/github_actions.json, mapped the same way
//     (githubactions.ToIR). Only two of FR-2.6's five bullet points are
//     genuinely static-file-parseable - required reviews, branch
//     protection, and deployment approvals are GitHub repository
//     settings, not workflow YAML content, and need a live API
//     collector (FR-3-shaped work) that doesn't exist yet - see that
//     package's own doc.go.
//   - Dockerfile: parses Dockerfile/Dockerfile.* files directly under
//     --source (internal/frontend/dockerfile.Parse), written raw to
//     <out>/dockerfile.json, mapped the same way (dockerfile.ToIR) -
//     FR-2.7's base-image extraction, SHOULD priority.
//
// The "k8s" and ".github/workflows" subdirectories are narrow,
// provisional conventions matching testdata/fixtures/minimal's own
// layout, not a general answer to "how does substrate know which files
// under --source belong to which frontend" - a real include/exclude
// design (a .gitignore-style filter, most likely) is still deferred.
//
// All three frontends' IR output is merged into one ir.Graph, validated,
// and written as JSON Lines to <out>/ir/nodes.jsonl and
// <out>/ir/edges.jsonl (ir.WriteNodesJSONL/WriteEdgesJSONL - the
// package's own stable, byte-reproducible serialization, not ad hoc
// JSON). No frontend's mapping table is comprehensive: a resource type
// or field with no reviewed entry produces no node, never a guess - see
// each ToIR's own doc comment.
//
// --runtime <dir>, if given, is a directory previously written by
// "substrate collect --out <dir>" (collect.go): this command reads
// <runtime>/aws_s3.json, <runtime>/aws_iam.json,
// <runtime>/aws_cloudtrail.json, <runtime>/aws_security_groups.json,
// <runtime>/aws_subnets.json, <runtime>/aws_guardduty.json, and
// <runtime>/aws_config.json back in, maps them through the same
// awscollectors.ToIR/IAMToIR/CloudTrailToIR/SecurityGroupsToIR/
// SubnetsToIR/GuardDutyToIR/ConfigToIR this package's own unit tests
// exercise, and merges their nodes into the evidence graph alongside
// the three static frontends' - the Observed half of FR-4.2,
// next to everything above's Declared half. Omitting --runtime is not a
// degraded mode; it is compile's default, and always has been - a
// customer's CI-triggered compile has no need to touch AWS at all
// unless they specifically want Observed evidence folded in. See
// docs/adr/0009 for why collection is its own command rather than a
// flag that makes compile itself reach out to AWS.
//
// Okta evidence (FR-3.9) is read back the same way, but only when
// <runtime>/okta_mfa.json actually exists: unlike the three AWS
// artifacts, collect.go only writes its four Okta artifacts when it was
// itself given --okta-org-url (Okta collection is optional there,
// collect.go's own doc comment explains why). A --runtime directory
// from an AWS-only collect run - the common case today - must compile
// cleanly with zero Okta nodes, not be treated as corrupt for lacking
// files collect.go never promised to write in the first place.
//
// The merged evidence graph is then scored against the vendored FedRAMP
// Consolidated Rules dataset (internal/rules.Default) by
// internal/backends/fedramp20x.Evaluate (FR-6.1), written to
// <out>/ksi_results.json. Three of the ten KSI families have a real Rego
// evaluation module today - rego/ksi/svc, rego/ksi/iam, and rego/ksi/cna
// (see evaluate.go's own doc comment, which is the authoritative list;
// this comment names them explicitly rather than a count precisely so
// it can't silently drift out of sync with that one again the way an
// earlier version of this comment did) - every indicator in the other
// seven families comes back undetermined with an explicit "not yet
// implemented" reason rather than being silently omitted, and even a
// module that exists will mostly read undetermined for a real
// repository today, honestly, since the frontends above evidence only a
// handful of the many controls each indicator references. See
// docs/adr/0007 for why that's the deliberate, honest state of the
// backend right now rather than a bug.
//
// ksiResults is also aggregated into FR-6.7's coverage report
// (fedramp20x.Coverage), written to <out>/coverage.json: how many
// indicators, overall and per KSI family, are Automated (a real
// satisfied/not_satisfied verdict), HumanAttested (requires_attestation -
// determinately outside what any compiler can observe), or NotVisible
// (undetermined - a real gap). See docs/adr/0012.
//
// Nothing is written to --out until every parse, map, and validate step
// above has succeeded: writing happens against a "--out.tmp" sibling
// directory, published at --out only at the very end via two back-to-back
// renames (see the comment where that happens) rather than a delete-then-
// rename, so even a process kill at the worst possible instant leaves a
// recoverable "--out.old" behind instead of --out missing outright. A
// failure partway through a run can therefore never leave --out holding
// some frontends' raw JSON with no matching ir/ output, or a stale ir/
// next to fresh per-frontend JSON from a run that didn't actually finish.
//
// testdata/fixtures/minimal's own expected/ output reflects whatever
// this function currently does; regenerate it deliberately
// (SUBSTRATE_UPDATE_GOLDEN=1) and review the diff every time this
// function's real behavior changes, per CLAUDE.md's "that diff is a
// change in what we assert to the federal government."
func runCompile(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("substrate compile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := fs.String("source", "", "directory containing Terraform, Kubernetes manifests, and CI configuration to compile")
	out := fs.String("out", "", "directory to write compiled artifacts to")
	runtime := fs.String("runtime", "", "optional: directory previously written by 'substrate collect --out <dir>', to merge Observed runtime evidence in alongside the static frontends")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: substrate compile --source <dir> --out <dir> [--runtime <dir>]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *source == "" || *out == "" {
		fs.Usage()
		return 2
	}

	k8sDir := filepath.Join(*source, "k8s")
	ghaDir := filepath.Join(*source, ".github", "workflows")

	tfGraph, err := terraform.Parse(*source)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse terraform: %v\n", err)
		return 2
	}
	k8sGraph, err := kubernetes.Parse(k8sDir)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse kubernetes: %v\n", err)
		return 2
	}
	ghaGraph, err := githubactions.Parse(ghaDir)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse github actions: %v\n", err)
		return 2
	}
	dockerGraph, err := dockerfile.Parse(*source)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: parse dockerfile: %v\n", err)
		return 2
	}

	tfIR, err := terraform.ToIR(tfGraph)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: map terraform to evidence graph: %v\n", err)
		return 2
	}
	k8sIR, err := kubernetes.ToIR(k8sGraph)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: map kubernetes to evidence graph: %v\n", err)
		return 2
	}
	ghaIR, err := githubactions.ToIR(ghaGraph)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: map github actions to evidence graph: %v\n", err)
		return 2
	}
	dockerIR, err := dockerfile.ToIR(dockerGraph)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: map dockerfile to evidence graph: %v\n", err)
		return 2
	}
	evidence := ir.Graph{}
	evidence.Nodes = append(evidence.Nodes, tfIR.Nodes...)
	evidence.Nodes = append(evidence.Nodes, k8sIR.Nodes...)
	evidence.Nodes = append(evidence.Nodes, ghaIR.Nodes...)
	evidence.Nodes = append(evidence.Nodes, dockerIR.Nodes...)
	evidence.Edges = append(evidence.Edges, tfIR.Edges...)
	evidence.Edges = append(evidence.Edges, k8sIR.Edges...)
	evidence.Edges = append(evidence.Edges, ghaIR.Edges...)
	evidence.Edges = append(evidence.Edges, dockerIR.Edges...)

	// runtimeSummary is built entirely inside this block, not from
	// variables hoisted above it: a zero bucket/user count and "runtime
	// ingestion never ran at all" must never look the same to a reader
	// skimming past the declaration site.
	runtimeSummary := ""
	if *runtime != "" {
		s3Graph, err := readArtifact[awscollectors.S3Graph](filepath.Join(*runtime, awsS3ArtifactName))
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: read runtime evidence: %v\n", err)
			return 2
		}
		iamGraph, err := readArtifact[awscollectors.IAMGraph](filepath.Join(*runtime, awsIAMArtifactName))
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: read runtime evidence: %v\n", err)
			return 2
		}
		cloudTrailGraph, err := readArtifact[awscollectors.CloudTrailGraph](filepath.Join(*runtime, awsCloudTrailArtifactName))
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: read runtime evidence: %v\n", err)
			return 2
		}
		securityGroupsGraph, err := readArtifact[awscollectors.SecurityGroupsGraph](filepath.Join(*runtime, awsSecurityGroupsArtifactName))
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: read runtime evidence: %v\n", err)
			return 2
		}
		subnetsGraph, err := readArtifact[awscollectors.SubnetsGraph](filepath.Join(*runtime, awsSubnetsArtifactName))
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: read runtime evidence: %v\n", err)
			return 2
		}
		guardDutyGraph, err := readArtifact[awscollectors.GuardDutyGraph](filepath.Join(*runtime, awsGuardDutyArtifactName))
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: read runtime evidence: %v\n", err)
			return 2
		}
		configGraph, err := readArtifact[awscollectors.ConfigGraph](filepath.Join(*runtime, awsConfigArtifactName))
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: read runtime evidence: %v\n", err)
			return 2
		}
		s3IR, err := awscollectors.ToIR(s3Graph)
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: map aws s3 to evidence graph: %v\n", err)
			return 2
		}
		iamIR, err := awscollectors.IAMToIR(iamGraph)
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: map aws iam to evidence graph: %v\n", err)
			return 2
		}
		cloudTrailIR, err := awscollectors.CloudTrailToIR(cloudTrailGraph)
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: map aws cloudtrail to evidence graph: %v\n", err)
			return 2
		}
		securityGroupsIR, err := awscollectors.SecurityGroupsToIR(securityGroupsGraph)
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: map aws security groups to evidence graph: %v\n", err)
			return 2
		}
		subnetsIR, err := awscollectors.SubnetsToIR(subnetsGraph)
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: map aws subnets to evidence graph: %v\n", err)
			return 2
		}
		guardDutyIR, err := awscollectors.GuardDutyToIR(guardDutyGraph)
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: map aws guardduty to evidence graph: %v\n", err)
			return 2
		}
		configIR, err := awscollectors.ConfigToIR(configGraph)
		if err != nil {
			fmt.Fprintf(stderr, "substrate compile: map aws config to evidence graph: %v\n", err)
			return 2
		}
		evidence.Nodes = append(evidence.Nodes, s3IR.Nodes...)
		evidence.Nodes = append(evidence.Nodes, iamIR.Nodes...)
		evidence.Nodes = append(evidence.Nodes, cloudTrailIR.Nodes...)
		evidence.Nodes = append(evidence.Nodes, securityGroupsIR.Nodes...)
		evidence.Nodes = append(evidence.Nodes, subnetsIR.Nodes...)
		evidence.Nodes = append(evidence.Nodes, guardDutyIR.Nodes...)
		evidence.Nodes = append(evidence.Nodes, configIR.Nodes...)
		runtimeSummary = fmt.Sprintf("; ingested runtime evidence for %d s3 bucket(s), %d iam user(s), %d cloudtrail trail(s), %d security group rule(s), %d subnet(s), %d guardduty detector(s), and %d config recorder(s) from %s",
			len(s3Graph.Buckets), len(iamGraph.Users), len(cloudTrailGraph.Trails), len(securityGroupsGraph.Rules), len(subnetsGraph.Subnets), len(guardDutyGraph.Detectors), len(configGraph.Recorders), *runtime)

		// Okta evidence (FR-3.9) is read back only when okta_mfa.json is
		// actually present - unlike the three AWS artifacts above, which
		// collect.go always writes, collect.go writes all four Okta
		// artifacts only when it was itself given --okta-org-url
		// (collect.go's own doc comment on why Okta collection is
		// optional there). A --runtime directory from an AWS-only collect
		// run is the common case today and must compile cleanly with no
		// Okta evidence, not fail as if the directory were corrupt. Once
		// present, all four are required together - readArtifact's own
		// loud-failure-on-missing-file behavior is exactly right for that
		// case, since collect.go never writes fewer than all four.
		oktaMFAPath := filepath.Join(*runtime, oktaMFAArtifactName)
		if _, statErr := os.Stat(oktaMFAPath); statErr == nil {
			mfaGraph, err := readArtifact[oktacollectors.MFAEnrollmentGraph](oktaMFAPath)
			if err != nil {
				fmt.Fprintf(stderr, "substrate compile: read okta runtime evidence: %v\n", err)
				return 2
			}
			sessionPolicyGraph, err := readArtifact[oktacollectors.SessionPolicyGraph](filepath.Join(*runtime, oktaSessionPolicyArtifactName))
			if err != nil {
				fmt.Fprintf(stderr, "substrate compile: read okta runtime evidence: %v\n", err)
				return 2
			}
			provisioningGraph, err := readArtifact[oktacollectors.ProvisioningEventGraph](filepath.Join(*runtime, oktaProvisioningArtifactName))
			if err != nil {
				fmt.Fprintf(stderr, "substrate compile: read okta runtime evidence: %v\n", err)
				return 2
			}
			adminRoleGraph, err := readArtifact[oktacollectors.AdminRoleAssignmentGraph](filepath.Join(*runtime, oktaAdminRoleArtifactName))
			if err != nil {
				fmt.Fprintf(stderr, "substrate compile: read okta runtime evidence: %v\n", err)
				return 2
			}

			mfaIR, err := oktacollectors.MFAEnrollmentToIR(mfaGraph)
			if err != nil {
				fmt.Fprintf(stderr, "substrate compile: map okta mfa enrollment to evidence graph: %v\n", err)
				return 2
			}
			sessionPolicyIR, err := oktacollectors.SessionPolicyToIR(sessionPolicyGraph)
			if err != nil {
				fmt.Fprintf(stderr, "substrate compile: map okta session policy to evidence graph: %v\n", err)
				return 2
			}
			provisioningIR, err := oktacollectors.ProvisioningEventsToIR(provisioningGraph)
			if err != nil {
				fmt.Fprintf(stderr, "substrate compile: map okta provisioning events to evidence graph: %v\n", err)
				return 2
			}
			adminRoleIR, err := oktacollectors.AdminRoleAssignmentsToIR(adminRoleGraph)
			if err != nil {
				fmt.Fprintf(stderr, "substrate compile: map okta admin role assignments to evidence graph: %v\n", err)
				return 2
			}
			evidence.Nodes = append(evidence.Nodes, mfaIR.Nodes...)
			evidence.Nodes = append(evidence.Nodes, sessionPolicyIR.Nodes...)
			evidence.Nodes = append(evidence.Nodes, provisioningIR.Nodes...)
			evidence.Nodes = append(evidence.Nodes, adminRoleIR.Nodes...)
			runtimeSummary += fmt.Sprintf("; ingested okta runtime evidence for %d mfa policy(ies), %d session policy rule(s), %d provisioning event(s), and %d user(s) with role assignments",
				len(mfaGraph.Policies), len(sessionPolicyGraph.Rules), len(provisioningGraph.Events), len(adminRoleGraph.Users))
		}
	}

	if err := evidence.Validate(); err != nil {
		fmt.Fprintf(stderr, "substrate compile: evidence graph: %v\n", err)
		return 2
	}

	ds, err := rules.Default()
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: load rules dataset: %v\n", err)
		return 2
	}
	ksiResults, err := fedramp20x.Evaluate(context.Background(), ds, evidence)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: evaluate KSI indicators: %v\n", err)
		return 2
	}
	coverage := fedramp20x.Coverage(ksiResults)

	// Every parse, map, and validate step above must succeed before any
	// of it touches --out. Writing runs entirely against a sibling
	// ".tmp" directory and is only made visible at *out by a single
	// rename at the very end - so a failure past this point (which
	// should only ever be an I/O error, since every step that can find
	// something wrong with the input already has) can never leave *out
	// holding a partial mix of some frontends' raw JSON and no matching
	// ir/ output, or a stale ir/ from a prior run sitting next to fresh
	// per-frontend JSON from this one.
	tmpOut := *out + ".tmp"
	if err := os.RemoveAll(tmpOut); err != nil {
		fmt.Fprintf(stderr, "substrate compile: clear stale %s: %v\n", tmpOut, err)
		return 2
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(tmpOut)
		}
	}()

	if err := os.MkdirAll(tmpOut, 0o755); err != nil {
		fmt.Fprintf(stderr, "substrate compile: create output directory %s: %v\n", tmpOut, err)
		return 2
	}
	if err := writeArtifact(tmpOut, "terraform.json", tfGraph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeArtifact(tmpOut, "kubernetes.json", k8sGraph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeArtifact(tmpOut, "github_actions.json", ghaGraph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeArtifact(tmpOut, "dockerfile.json", dockerGraph); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}

	irDir := filepath.Join(tmpOut, "ir")
	if err := os.MkdirAll(irDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "substrate compile: create output directory %s: %v\n", irDir, err)
		return 2
	}
	if err := writeJSONLArtifact(irDir, "nodes.jsonl", evidence.Nodes, ir.WriteNodesJSONL); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeJSONLArtifact(irDir, "edges.jsonl", evidence.Edges, ir.WriteEdgesJSONL); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeArtifact(tmpOut, "ksi_results.json", ksiResults); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	if err := writeArtifact(tmpOut, "coverage.json", coverage); err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}

	// Publish tmpOut at *out - see publishOutput's own doc comment for
	// why this is two renames with a restore path, not a single
	// delete-then-rename.
	warning, err := publishOutput(tmpOut, *out)
	if err != nil {
		fmt.Fprintf(stderr, "substrate compile: %v\n", err)
		return 2
	}
	committed = true
	if warning != "" {
		fmt.Fprintf(stderr, "substrate compile: warning: %s\n", warning)
	}

	fmt.Fprintf(stdout, "parsed %d terraform resource(s), %s, %s, and %d dockerfile stage(s) from %s%s; compiled %d evidence node(s) and %d edge(s); evaluated %d KSI indicator(s): %s; coverage: %s\n",
		len(tfGraph.Resources), resourceCount(k8sDir, len(k8sGraph.Resources), "kubernetes resource"),
		resourceCount(ghaDir, len(ghaGraph.Workflows), "github actions workflow"), len(dockerGraph.Stages), *source, runtimeSummary, len(evidence.Nodes), len(evidence.Edges),
		len(ksiResults), statusTally(ksiResults), formatCoverage(coverage.Overall))
	return 0
}

// publishOutput moves tmpOut into place at out with two back-to-back
// renames rather than RemoveAll(out) followed by Rename(tmpOut, out):
// os.Rename cannot itself atomically replace an existing non-empty
// directory (POSIX rename(2) requires the destination directory to be
// empty), so deleting first was the only way to make Rename succeed -
// but a process killed between that delete and the rename left out
// missing entirely, which is worse than the partial-mix problem this
// function exists to prevent: no artifact where a stale-but-complete
// one used to be. Renaming out out of the way first shrinks that
// unsafe window from "however long a recursive delete takes" to the
// gap between two near-instant rename() calls, and publishFromTmp
// restores the previous output from that backup if the second rename
// still fails inside that window, rather than leaving out missing.
//
// Returns a non-fatal warning (a leftover backup that couldn't be
// cleaned up after a successful publish - disk space, not a
// correctness problem) alongside a nil error, or a nil warning
// alongside a real error.
func publishOutput(tmpOut, out string) (warning string, err error) {
	backupOut := out + ".old"
	hadPrevious := false
	if _, statErr := os.Stat(out); statErr == nil {
		hadPrevious = true
		if err := os.RemoveAll(backupOut); err != nil {
			return "", fmt.Errorf("clear stale %s: %w", backupOut, err)
		}
		if err := os.Rename(out, backupOut); err != nil {
			return "", fmt.Errorf("move previous %s aside: %w", out, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("stat %s: %w", out, statErr)
	}
	return publishFromTmp(tmpOut, out, backupOut, hadPrevious)
}

// publishFromTmp performs the second rename (tmpOut -> out) and, if it
// fails and hadPrevious is true, restores backupOut back to out rather
// than leaving out missing - the exact failure this whole two-rename
// scheme exists to avoid, which a naive "rename, and if that fails just
// report the error" version of this function missed: a process killed
// (or any other rename failure) between the two renames left out
// missing entirely, with the previous good output stranded, un-restored,
// at backupOut. Split out from publishOutput so this specific recovery
// path - the one a failure between the two renames exercises - can be
// tested directly against a pre-arranged filesystem state, without
// needing to force a real os.Rename failure at exactly the right
// instant (see compile_test.go).
func publishFromTmp(tmpOut, out, backupOut string, hadPrevious bool) (warning string, err error) {
	if err := os.Rename(tmpOut, out); err != nil {
		if !hadPrevious {
			return "", fmt.Errorf("publish %s: %w", out, err)
		}
		if restoreErr := os.Rename(backupOut, out); restoreErr != nil {
			return "", fmt.Errorf("publish %s: %w (restoring previous output from %s also failed: %v)", out, err, backupOut, restoreErr)
		}
		return "", fmt.Errorf("publish %s: %w (previous output restored)", out, err)
	}
	if hadPrevious {
		if err := os.RemoveAll(backupOut); err != nil {
			return fmt.Sprintf("could not remove backup %s: %v", backupOut, err), nil
		}
	}
	return "", nil
}

// statusTally renders results' status counts as "N satisfied, N
// undetermined, ...", one term per status that actually occurs, in a
// fixed status order so the summary line reads the same way (and is
// diffable the same way) run to run regardless of which indicators
// happened to produce which status. A status with zero results is
// omitted rather than printed as "0 satisfied" - the common case today
// (no not_satisfied, not_applicable, or requires_attestation results
// anywhere, since no family implements those paths yet) would otherwise
// clutter every real run's output with three permanently-zero terms.
func statusTally(results []fedramp20x.IndicatorResult) string {
	order := []fedramp20x.Status{
		fedramp20x.StatusSatisfied,
		fedramp20x.StatusNotSatisfied,
		fedramp20x.StatusUndetermined,
		fedramp20x.StatusNotApplicable,
		fedramp20x.StatusRequiresAttestation,
	}
	counts := make(map[fedramp20x.Status]int, len(order))
	for _, r := range results {
		counts[r.Status]++
	}

	var terms []string
	for _, status := range order {
		if n := counts[status]; n > 0 {
			terms = append(terms, fmt.Sprintf("%d %s", n, status))
		}
	}
	if len(terms) == 0 {
		return "none"
	}
	return strings.Join(terms, ", ")
}

// formatCoverage renders FR-6.7's coverage bucket for the summary line.
// Unlike statusTally, a zero term is never omitted here: "0 automated, 0
// human-attested, N not visible" is exactly the honest message the
// coverage report exists to surface, not clutter to hide - see
// docs/adr/0012.
func formatCoverage(b fedramp20x.CoverageBucket) string {
	return fmt.Sprintf("%d automated, %d human-attested, %d not visible (%.1f%% of %d applicable)",
		b.Automated, b.HumanAttested, b.NotVisible, b.PercentAutomated, b.Applicable)
}

// resourceCount renders a frontend's parsed count for the summary line,
// naming the gap when dir doesn't exist at all rather than printing the
// same "0 <unit>(s)" a directory that exists but is genuinely empty of
// matching files would also produce. Both the "k8s" and
// ".github/workflows" conventions are narrow and provisional (see this
// file's own doc comment above), and a repository that keeps its
// manifests somewhere else deserves a different message than one that
// genuinely has none.
func resourceCount(dir string, count int, unit string) string {
	if count != 0 {
		return fmt.Sprintf("%d %s(s)", count, unit)
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return fmt.Sprintf("0 %s(s) (%s not found)", unit, dir)
	}
	return fmt.Sprintf("0 %s(s)", unit)
}

// writeJSONLArtifact writes items to <dir>/<name> using write (one of
// ir.WriteNodesJSONL / ir.WriteEdgesJSONL), so the evidence graph is
// serialized with the IR package's own stable, byte-reproducible JSON
// Lines encoding rather than ad hoc JSON.
func writeJSONLArtifact[T any](dir, name string, items []T, write func(io.Writer, []T) error) error {
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := write(f, items); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	// Checked, not deferred-and-ignored: a full disk (or a network-mounted
	// --out.tmp) can fail at close time, after buffered Write calls have
	// already returned success - an error here is the only place that
	// surfaces, and this artifact is about to be renamed into place as if
	// it were complete.
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// writeArtifact writes v as JSON to <outDir>/<name>.
func writeArtifact(outDir, name string, v any) error {
	path := filepath.Join(outDir, name)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := writeJSON(f, v); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
