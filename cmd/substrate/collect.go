package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"golang.org/x/sync/errgroup"

	awscollectors "github.com/kernwill/substrate/internal/frontend/collectors/aws"
	oktacollectors "github.com/kernwill/substrate/internal/frontend/collectors/okta"
)

// awsS3ArtifactName, awsIAMArtifactName, and awsCloudTrailArtifactName
// are collect's own output filenames - written here, read back by
// compile.go's --runtime ingestion, and asserted against by both
// commands' tests. One shared definition rather than each site
// repeating the literal string, so a rename can't silently desync
// collect's writer from compile's reader.
const (
	awsS3ArtifactName             = "aws_s3.json"
	awsIAMArtifactName            = "aws_iam.json"
	awsCloudTrailArtifactName     = "aws_cloudtrail.json"
	awsSecurityGroupsArtifactName = "aws_security_groups.json"
	awsSubnetsArtifactName        = "aws_subnets.json"
	awsGuardDutyArtifactName      = "aws_guardduty.json"
	awsConfigArtifactName         = "aws_config.json"
	awsSecurityHubArtifactName    = "aws_securityhub.json"
	awsKMSArtifactName            = "aws_kms.json"

	oktaMFAArtifactName           = "okta_mfa.json"
	oktaSessionPolicyArtifactName = "okta_session_policy.json"
	oktaProvisioningArtifactName  = "okta_provisioning.json"
	oktaAdminRoleArtifactName     = "okta_admin_role.json"
)

// oktaScopes is the combined OAuth scope list every Okta collector this
// command runs needs, documented in docs/okta-api-scopes.md - kept in
// sync with that file by hand, the same "updated in lockstep, nothing
// checks the two match automatically yet" caveat
// docs/aws-readonly-policy.json's own doc comment already carries for
// AWS.
var oktaScopes = []string{"okta.policies.read", "okta.logs.read", "okta.users.read", "okta.roles.read"}

// oktaEventsDefaultLookbackHours is how far back --okta-events-since
// looks for provisioning/deprovisioning events when not given
// explicitly: 7 days, not 24 hours, chosen deliberately wide rather than
// tight to a daily CI cadence - substrate tracks no "time since last
// successful collect run" state anywhere yet (provisioning.go's own doc
// comment), so a narrower default would silently lose lifecycle events
// across any gap in collect's own run cadence (a skipped day, a paused
// pipeline) with no mechanism to detect or backfill the gap. A
// same-event re-collected across overlapping windows on consecutive runs
// is harmless: each compile run's IR is a fresh snapshot, nothing
// persists or dedupes node IDs across runs.
const oktaEventsDefaultLookbackHours = 7 * 24

// oktaResults bundles all four Okta collectors' output as one unit,
// nil as a whole when --okta-org-url was not given (Okta collection
// skipped entirely) rather than nil field-by-field - collectOkta below
// either populates every field or returns a nil *oktaResults, so a
// caller never has to reason about a partially-populated bundle.
type oktaResults struct {
	MFA           *oktacollectors.MFAEnrollmentGraph
	SessionPolicy *oktacollectors.SessionPolicyGraph
	Provisioning  *oktacollectors.ProvisioningEventGraph
	AdminRole     *oktacollectors.AdminRoleAssignmentGraph
}

// runCollect implements "substrate collect --out <dir>" (FR-3: runtime
// collection, "the evidence-of-effectiveness half," IVV-CSO-SEE).
//
// Deliberately a separate command from compile, matching the CLI
// surface docs/REQUIREMENTS.md has always described (rather than a flag
// on compile): compile's own evidence-graph build should not need live
// AWS credentials on every invocation - most compile runs are triggered
// by a pull request, which has no reason to touch a customer's AWS
// account - and continuous-assurance-style re-collection (FR-8.9) runs
// on its own cadence independent of any particular compile. compile
// reads collect's output back in via --runtime <dir> if given (see
// compile.go); if omitted, compile runs exactly as it always has, with
// no Observed evidence at all.
//
// Builds an AWS client from the SDK's own default credential chain
// (config.LoadDefaultConfig) - see internal/frontend/collectors/aws's
// own doc.go for why credential handling is entirely the caller's (and
// ultimately the customer's) responsibility, never substrate's own.
// Runs every runtime collector this package has today (S3, IAM,
// CloudTrail; more will follow per docs/adr/0008's roadmap) and writes
// each one's raw output to <out>/aws_s3.json / <out>/aws_iam.json /
// <out>/aws_cloudtrail.json, published the same
// atomic way compile's own --out is (publishOutput/publishFromTmp,
// compile.go) - a partial failure must not leave --out holding one
// collector's fresh output next to another's stale or missing one.
//
// AWS collection is unconditional - it always runs, and fails the whole
// command if config.LoadDefaultConfig can't resolve credentials. Okta
// collection (FR-3.9, internal/frontend/collectors/okta) is optional,
// gated on --okta-org-url being given: unlike AWS, Okta has no ambient
// default credential chain to fall back to (docs/adr/0015), and no real
// customer has configured an Okta API Services app yet, so requiring it
// unconditionally would break every existing AWS-only invocation of this
// command. This is a deliberate, disclosed asymmetry - not a design this
// command is finished with - worth revisiting once Okta collection has
// real customer usage to make mandatory-by-default a reasonable default.
func runCollect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("substrate collect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "directory to write collected runtime facts to")
	oktaOrgURL := fs.String("okta-org-url", "", "optional: Okta org base URL (e.g. https://example.okta.com) - enables Okta collection (FR-3.9) when set")
	oktaClientID := fs.String("okta-client-id", "", "Okta API Services app client ID (required if --okta-org-url is set)")
	oktaKeyID := fs.String("okta-key-id", "", "optional: the Okta API Services app's key ID, if it has more than one key registered")
	oktaPrivateKeyPath := fs.String("okta-private-key", "", "path to the Okta API Services app's private key, PEM-encoded (required if --okta-org-url is set)")
	oktaTokenPath := fs.String("okta-token-path", "/oauth2/v1/token", "Okta OAuth token endpoint path, appended to --okta-org-url")
	oktaEventsSinceHours := fs.Int("okta-events-since-hours", oktaEventsDefaultLookbackHours, "how many hours back to look for Okta provisioning/deprovisioning events")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: substrate collect --out <dir> [--okta-org-url <url> --okta-client-id <id> --okta-private-key <path>] [--okta-key-id <id>] [--okta-token-path <path>] [--okta-events-since-hours <n>]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fs.Usage()
		return 2
	}
	// Okta flags are all-or-nothing: a partially-configured Okta org
	// (a URL with no client ID, say) is far more likely a typo or a
	// forgotten flag than a deliberate choice, so it fails loudly here
	// rather than silently skipping Okta collection the way omitting
	// --okta-org-url entirely does.
	if *oktaOrgURL != "" && (*oktaClientID == "" || *oktaPrivateKeyPath == "") {
		fmt.Fprintln(stderr, "substrate collect: --okta-org-url requires --okta-client-id and --okta-private-key")
		fs.Usage()
		return 2
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "substrate collect: load AWS configuration: %v\n", err)
		return 2
	}
	observedAt := time.Now().UTC()

	var oktaClient *oktacollectors.RESTClient
	if *oktaOrgURL != "" {
		privateKey, err := loadOktaPrivateKey(*oktaPrivateKeyPath)
		if err != nil {
			fmt.Fprintf(stderr, "substrate collect: load okta private key: %v\n", err)
			return 2
		}
		tokenSource, err := oktacollectors.NewTokenSource(oktacollectors.Config{
			OrgURL:     *oktaOrgURL,
			TokenPath:  *oktaTokenPath,
			ClientID:   *oktaClientID,
			PrivateKey: privateKey,
			KeyID:      *oktaKeyID,
			Scopes:     oktaScopes,
		})
		if err != nil {
			fmt.Fprintf(stderr, "substrate collect: configure okta token source: %v\n", err)
			return 2
		}
		oktaClient = oktacollectors.NewRESTClient(*oktaOrgURL, tokenSource, nil)
	}

	// S3, IAM, CloudTrail, security groups, subnets, GuardDuty, AWS
	// Config, Security Hub, KMS, and (if configured) the four Okta
	// collectors are all independent, so collect everything concurrently
	// rather than paying every service's full latency back to back - the
	// same reasoning concurrent.go's collectConcurrent already applies
	// one level down, inside each collector, to its own per-item API
	// calls.
	var s3Graph *awscollectors.S3Graph
	var iamGraph *awscollectors.IAMGraph
	var cloudTrailGraph *awscollectors.CloudTrailGraph
	var securityGroupsGraph *awscollectors.SecurityGroupsGraph
	var subnetsGraph *awscollectors.SubnetsGraph
	var guardDutyGraph *awscollectors.GuardDutyGraph
	var configGraph *awscollectors.ConfigGraph
	var securityHubGraph *awscollectors.SecurityHubGraph
	var kmsGraph *awscollectors.KMSGraph
	var okta *oktaResults
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		s3Graph, err = awscollectors.CollectS3(gctx, s3.NewFromConfig(cfg), observedAt)
		if err != nil {
			return fmt.Errorf("collect s3: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		iamGraph, err = awscollectors.CollectIAM(gctx, iam.NewFromConfig(cfg), observedAt)
		if err != nil {
			return fmt.Errorf("collect iam: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		cloudTrailGraph, err = awscollectors.CollectCloudTrail(gctx, cloudtrail.NewFromConfig(cfg), observedAt)
		if err != nil {
			return fmt.Errorf("collect cloudtrail: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		securityGroupsGraph, err = awscollectors.CollectSecurityGroups(gctx, ec2.NewFromConfig(cfg), observedAt)
		if err != nil {
			return fmt.Errorf("collect security groups: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		subnetsGraph, err = awscollectors.CollectSubnets(gctx, ec2.NewFromConfig(cfg), observedAt)
		if err != nil {
			return fmt.Errorf("collect subnets: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		guardDutyGraph, err = awscollectors.CollectGuardDuty(gctx, guardduty.NewFromConfig(cfg), observedAt)
		if err != nil {
			return fmt.Errorf("collect guardduty: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		configGraph, err = awscollectors.CollectConfig(gctx, configservice.NewFromConfig(cfg), observedAt)
		if err != nil {
			return fmt.Errorf("collect config: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		securityHubGraph, err = awscollectors.CollectSecurityHub(gctx, securityhub.NewFromConfig(cfg), observedAt)
		if err != nil {
			return fmt.Errorf("collect securityhub: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		var err error
		kmsGraph, err = awscollectors.CollectKMS(gctx, kms.NewFromConfig(cfg), observedAt)
		if err != nil {
			return fmt.Errorf("collect kms: %w", err)
		}
		return nil
	})
	if oktaClient != nil {
		since := observedAt.Add(-time.Duration(*oktaEventsSinceHours) * time.Hour)
		results := &oktaResults{}
		okta = results
		g.Go(func() error {
			var err error
			results.MFA, err = oktacollectors.CollectMFAEnrollmentPolicies(gctx, oktaClient, observedAt)
			if err != nil {
				return fmt.Errorf("collect okta mfa enrollment policies: %w", err)
			}
			return nil
		})
		g.Go(func() error {
			var err error
			results.SessionPolicy, err = oktacollectors.CollectSessionPolicies(gctx, oktaClient, observedAt)
			if err != nil {
				return fmt.Errorf("collect okta session policies: %w", err)
			}
			return nil
		})
		g.Go(func() error {
			var err error
			results.Provisioning, err = oktacollectors.CollectProvisioningEvents(gctx, oktaClient, observedAt, since, observedAt)
			if err != nil {
				return fmt.Errorf("collect okta provisioning events: %w", err)
			}
			return nil
		})
		g.Go(func() error {
			var err error
			results.AdminRole, err = oktacollectors.CollectAdminRoleAssignments(gctx, oktaClient, observedAt)
			if err != nil {
				return fmt.Errorf("collect okta admin role assignments: %w", err)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		fmt.Fprintf(stderr, "substrate collect: %v\n", err)
		return 2
	}

	warning, err := writeCollectOutput(*out, s3Graph, iamGraph, cloudTrailGraph, securityGroupsGraph, subnetsGraph, guardDutyGraph, configGraph, securityHubGraph, kmsGraph, okta)
	if err != nil {
		fmt.Fprintf(stderr, "substrate collect: %v\n", err)
		return 2
	}
	if warning != "" {
		fmt.Fprintf(stderr, "substrate collect: warning: %s\n", warning)
	}

	summary := fmt.Sprintf("collected %d s3 bucket(s), %d iam user(s), %d cloudtrail trail(s), %d security group rule(s), %d subnet(s), %d guardduty detector(s), %d config recorder(s), %d securityhub subscription(s), and %d kms key(s)",
		len(s3Graph.Buckets), len(iamGraph.Users), len(cloudTrailGraph.Trails), len(securityGroupsGraph.Rules), len(subnetsGraph.Subnets), len(guardDutyGraph.Detectors), len(configGraph.Recorders), len(securityHubGraph.Hubs), len(kmsGraph.Keys))
	if okta != nil {
		summary += fmt.Sprintf("; %d okta mfa policy(ies), %d okta session policy rule(s), %d okta provisioning event(s), and %d okta user(s) with role assignments",
			len(okta.MFA.Policies), len(okta.SessionPolicy.Rules), len(okta.Provisioning.Events), len(okta.AdminRole.Users))
	}
	fmt.Fprintf(stdout, "%s into %s\n", summary, *out)
	return 0
}

// loadOktaPrivateKey reads and parses the PEM-encoded private key at
// path. Okta API Services apps' keys are generated either as PKCS#1
// ("BEGIN RSA PRIVATE KEY", the openssl genrsa default) or PKCS#8
// ("BEGIN PRIVATE KEY", what many newer tools produce) - both are tried
// rather than assuming one, since which a given customer's key-generation
// process produces is not something this command controls or can guess
// from the file alone.
func loadOktaPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: not a PKCS#1 or PKCS#8 private key: %w", path, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: private key is not RSA", path)
	}
	return key, nil
}

// writeCollectOutput writes s3Graph, iamGraph, cloudTrailGraph,
// securityGroupsGraph, subnetsGraph, guardDutyGraph, configGraph,
// securityHubGraph, and kmsGraph to their AWS artifact files (always),
// and okta's four graphs to their own artifact files only when okta is
// non-nil (Okta collection ran) - published atomically via the same
// publishOutput/publishFromTmp compile.go's own --out publish uses (see
// that function's doc comment for the full reasoning), including its
// non-fatal warning return (a leftover backup directory that couldn't
// be cleaned up after an otherwise-successful publish; disk space, not
// a correctness problem, but still worth surfacing to the caller rather
// than silently discarding). Split out from runCollect so this
// write/publish logic - the part with real, bug-prone behavior - is
// directly unit-testable against synthetic graphs, without needing live
// AWS/Okta credentials or a fake client at the CLI layer; every
// Collect* function already has its own thorough, fixture-backed tests
// one level down.
func writeCollectOutput(out string, s3Graph *awscollectors.S3Graph, iamGraph *awscollectors.IAMGraph, cloudTrailGraph *awscollectors.CloudTrailGraph, securityGroupsGraph *awscollectors.SecurityGroupsGraph, subnetsGraph *awscollectors.SubnetsGraph, guardDutyGraph *awscollectors.GuardDutyGraph, configGraph *awscollectors.ConfigGraph, securityHubGraph *awscollectors.SecurityHubGraph, kmsGraph *awscollectors.KMSGraph, okta *oktaResults) (warning string, err error) {
	tmpOut := out + ".tmp"
	if err := os.RemoveAll(tmpOut); err != nil {
		return "", fmt.Errorf("clear stale %s: %w", tmpOut, err)
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(tmpOut)
		}
	}()

	if err := os.MkdirAll(tmpOut, 0o755); err != nil {
		return "", fmt.Errorf("create output directory %s: %w", tmpOut, err)
	}
	if err := writeArtifact(tmpOut, awsS3ArtifactName, s3Graph); err != nil {
		return "", err
	}
	if err := writeArtifact(tmpOut, awsIAMArtifactName, iamGraph); err != nil {
		return "", err
	}
	if err := writeArtifact(tmpOut, awsCloudTrailArtifactName, cloudTrailGraph); err != nil {
		return "", err
	}
	if err := writeArtifact(tmpOut, awsSecurityGroupsArtifactName, securityGroupsGraph); err != nil {
		return "", err
	}
	if err := writeArtifact(tmpOut, awsSubnetsArtifactName, subnetsGraph); err != nil {
		return "", err
	}
	if err := writeArtifact(tmpOut, awsGuardDutyArtifactName, guardDutyGraph); err != nil {
		return "", err
	}
	if err := writeArtifact(tmpOut, awsConfigArtifactName, configGraph); err != nil {
		return "", err
	}
	if err := writeArtifact(tmpOut, awsSecurityHubArtifactName, securityHubGraph); err != nil {
		return "", err
	}
	if err := writeArtifact(tmpOut, awsKMSArtifactName, kmsGraph); err != nil {
		return "", err
	}
	if okta != nil {
		if err := writeArtifact(tmpOut, oktaMFAArtifactName, okta.MFA); err != nil {
			return "", err
		}
		if err := writeArtifact(tmpOut, oktaSessionPolicyArtifactName, okta.SessionPolicy); err != nil {
			return "", err
		}
		if err := writeArtifact(tmpOut, oktaProvisioningArtifactName, okta.Provisioning); err != nil {
			return "", err
		}
		if err := writeArtifact(tmpOut, oktaAdminRoleArtifactName, okta.AdminRole); err != nil {
			return "", err
		}
	}

	warning, err = publishOutput(tmpOut, out)
	if err != nil {
		return "", err
	}
	committed = true
	return warning, nil
}
