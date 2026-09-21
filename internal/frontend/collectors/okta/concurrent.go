package okta

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// maxConcurrentItems mirrors aws.maxConcurrentItems exactly - the same
// bounded-worker-pool limit, for the same reason: adminrole.go's
// per-user roles fan-out turns an org with thousands of users into that
// many sequential round trips if run one at a time.
const maxConcurrentItems = 16

// collectConcurrent mirrors aws.collectConcurrent exactly (see its own
// doc comment for the full reasoning) - duplicated here rather than
// exported from aws and imported, since internal/frontend/collectors/aws
// and internal/frontend/collectors/okta are siblings with no reason for
// one to depend on the other's private helpers, and this is eleven
// lines, not a package worth factoring out for two callers.
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
