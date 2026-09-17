package aws

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// maxConcurrentItems is the bounded-worker-pool limit every collector in
// this package uses. Each item (a bucket, a user) needs several
// independent per-item API calls with no cross-item dependency, so
// collecting sequentially turns an account with hundreds or thousands of
// items into that many sequential round trips; a fixed worker limit gets
// most of the win without needing per-account tuning or a flag nobody
// would set correctly on a CI gate's first run.
const maxConcurrentItems = 16

// collectConcurrent runs fetch once per entry in items, up to
// maxConcurrentItems at a time, and returns the results in the same
// order as items - shared by CollectS3 and CollectIAM, which grew
// identical copies of this exact shape (errgroup.WithContext + SetLimit,
// a per-index closure writing into a pre-sized slice) independently
// before this existed; /code-review flagged the duplication as the same
// class of drift risk internal/frontend/controls, provenance.go, and
// awsNodeID already exist to prevent for this package.
//
// fetch must never return a non-nil error for an individual item's own
// failure to resolve - every collector in this package records a
// per-item failure as an Unresolved fact instead (see each file's own
// doc comments on why). A non-nil error from fetch here would cancel
// every other in-flight item via ctx, which is not what an unrelated
// item's API failure should ever do.
func collectConcurrent[T any](ctx context.Context, items []string, fetch func(ctx context.Context, item string) T) ([]T, error) {
	results := make([]T, len(items))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentItems)
	for i, item := range items {
		i, item := i, item
		g.Go(func() error {
			results[i] = fetch(gctx, item)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}
