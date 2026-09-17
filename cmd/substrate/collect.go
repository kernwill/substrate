package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"golang.org/x/sync/errgroup"

	awscollectors "github.com/kernwill/substrate/internal/frontend/collectors/aws"
)

// awsS3ArtifactName and awsIAMArtifactName are collect's own two output
// filenames - written here, read back by compile.go's --runtime
// ingestion, and asserted against by both commands' tests. One shared
// definition rather than each site repeating the literal string, so a
// rename can't silently desync collect's writer from compile's reader.
const (
	awsS3ArtifactName  = "aws_s3.json"
	awsIAMArtifactName = "aws_iam.json"
)

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
// Runs every runtime collector this package has today (S3, IAM; more
// will follow per docs/adr/0008's roadmap) and writes each one's raw
// output to <out>/aws_s3.json / <out>/aws_iam.json, published the same
// atomic way compile's own --out is (publishOutput/publishFromTmp,
// compile.go) - a partial failure must not leave --out holding one
// collector's fresh output next to another's stale or missing one.
func runCollect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("substrate collect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "directory to write collected runtime facts to")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: substrate collect --out <dir>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
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

	// S3 and IAM are independent services with no data dependency
	// between them, so collect them concurrently rather than paying
	// their full latencies back to back - the same reasoning
	// concurrent.go's collectConcurrent already applies one level down,
	// inside each collector, to its own per-item API calls.
	var s3Graph *awscollectors.S3Graph
	var iamGraph *awscollectors.IAMGraph
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
	if err := g.Wait(); err != nil {
		fmt.Fprintf(stderr, "substrate collect: %v\n", err)
		return 2
	}

	warning, err := writeCollectOutput(*out, s3Graph, iamGraph)
	if err != nil {
		fmt.Fprintf(stderr, "substrate collect: %v\n", err)
		return 2
	}
	if warning != "" {
		fmt.Fprintf(stderr, "substrate collect: warning: %s\n", warning)
	}

	fmt.Fprintf(stdout, "collected %d s3 bucket(s) and %d iam user(s) into %s\n",
		len(s3Graph.Buckets), len(iamGraph.Users), *out)
	return 0
}

// writeCollectOutput writes s3Graph and iamGraph to <out>/aws_s3.json
// and <out>/aws_iam.json, published atomically via the same
// publishOutput/publishFromTmp compile.go's own --out publish uses (see
// that function's doc comment for the full reasoning) - including its
// non-fatal warning return (a leftover backup directory that couldn't
// be cleaned up after an otherwise-successful publish; disk space, not
// a correctness problem, but still worth surfacing to the caller rather
// than silently discarding). Split out from runCollect so this
// write/publish logic - the part with real, bug-prone behavior - is
// directly unit-testable against synthetic graphs, without needing live
// AWS credentials or a fake client at the CLI layer; CollectS3 and
// CollectIAM already have their own thorough, fixture-backed tests one
// level down.
func writeCollectOutput(out string, s3Graph *awscollectors.S3Graph, iamGraph *awscollectors.IAMGraph) (warning string, err error) {
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

	warning, err = publishOutput(tmpOut, out)
	if err != nil {
		return "", err
	}
	committed = true
	return warning, nil
}
