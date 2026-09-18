// Package fedramp20x maps the framework-agnostic evidence graph
// (internal/ir) onto FedRAMP 20x's Key Security Indicators, evaluated in
// Rego under rego/ksi (FR-6.1). This is the one package in the tree
// allowed to know what a KSI is - see CLAUDE.md's architectural
// invariants and scripts/check-boundaries.sh.
package fedramp20x

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	oparego "github.com/open-policy-agent/opa/v1/rego"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/rules"
	substraterego "github.com/kernwill/substrate/rego"
)

// Evaluate scores every KSI indicator in ds against the evidence in g,
// one Rego module per family (FR-6.1), returned sorted by indicator ID so
// the result stays reproducible regardless of map iteration order (FR-5.3's
// discipline, applied to this backend's own output too).
//
// A family with no Rego module embedded under rego/ksi/<lowercase family>
// yet returns undetermined for every one of its indicators, naming the
// gap explicitly rather than omitting the family from the result -
// FR-6.7's coverage report needs to account for every indicator the
// dataset defines, not just the ones this package has implemented so
// far. Today rego/ksi/svc, rego/ksi/iam, and rego/ksi/cna exist; the
// other seven KSI families fall through to notImplemented.
func Evaluate(ctx context.Context, ds *rules.Dataset, g ir.Graph) ([]IndicatorResult, error) {
	families := make([]string, 0, len(ds.KSI))
	for f := range ds.KSI {
		families = append(families, f)
	}
	sort.Strings(families)

	var out []IndicatorResult
	for _, family := range families {
		theme := ds.KSI[family]
		results, err := evaluateFamily(ctx, family, theme, g)
		if err != nil {
			return nil, fmt.Errorf("fedramp20x: evaluate KSI family %s: %w", family, err)
		}
		out = append(out, results...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Indicator < out[j].Indicator })
	return out, nil
}

// moduleDir is the embedded rego/ksi subdirectory for family (e.g. "svc"
// for "SVC"). A family with no such directory has no implemented module
// yet.
func moduleDir(family string) string {
	return "ksi/" + strings.ToLower(family)
}

// preparedFamily is one KSI family's compiled Rego query, cached for the
// life of the process (see preparedQueryFor). Present is false when the
// family has no embedded module directory at all - distinct from Err,
// which means a module directory exists but failed to compile.
type preparedFamily struct {
	Present bool
	Query   oparego.PreparedEvalQuery
	Err     error
}

var (
	preparedMu    sync.Mutex
	preparedCache = map[string]preparedFamily{}
)

// preparedQueryFor returns family's compiled, prepared query, compiling
// it at most once per process rather than once per Evaluate call. The
// embedded module source never changes at runtime, so recompiling it on
// every call - the original shape of this function - would have paid
// full Rego parse-and-compile cost on every single Evaluate invocation
// once more than one family has a real module, including in any
// repeated-call path (substrate gate, dataset-diff comparisons) that
// calls Evaluate more than once per process lifetime.
func preparedQueryFor(family string) preparedFamily {
	preparedMu.Lock()
	defer preparedMu.Unlock()
	if cached, ok := preparedCache[family]; ok {
		return cached
	}
	pf := compileFamily(family)
	preparedCache[family] = pf
	return pf
}

// compileFamily loads and compiles family's embedded Rego module set, if
// one exists. It uses context.Background() rather than any caller's
// context: compiling static, embedded source has nothing to do with a
// particular Evaluate call's lifetime, and the result is cached and reused
// by calls with entirely different contexts.
func compileFamily(family string) preparedFamily {
	dir := moduleDir(family)
	entries, err := fs.ReadDir(substraterego.FS, dir)
	if err != nil {
		return preparedFamily{Present: false}
	}

	var opts []func(*oparego.Rego)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		path := dir + "/" + e.Name()
		content, err := fs.ReadFile(substraterego.FS, path)
		if err != nil {
			return preparedFamily{Present: true, Err: fmt.Errorf("read embedded module %s: %w", path, err)}
		}
		opts = append(opts, oparego.Module(path, string(content)))
	}
	if len(opts) == 0 {
		return preparedFamily{Present: true, Err: fmt.Errorf("KSI family %s has a module directory %q with no .rego files in it", family, dir)}
	}

	query := fmt.Sprintf("data.fedramp20x.ksi.%s.results", strings.ToLower(family))
	opts = append(opts, oparego.Query(query))

	pq, err := oparego.New(opts...).PrepareForEval(context.Background())
	return preparedFamily{Present: true, Query: pq, Err: err}
}

// evaluateFamily runs family's prepared Rego query (if one is embedded)
// against g and theme, or falls back to notImplemented when it isn't.
func evaluateFamily(ctx context.Context, family string, theme rules.KSITheme, g ir.Graph) ([]IndicatorResult, error) {
	pf := preparedQueryFor(family)
	if !pf.Present {
		return notImplemented(family, theme), nil
	}
	if pf.Err != nil {
		return nil, pf.Err
	}

	rs, err := pf.Query.Eval(ctx, oparego.EvalInput(buildInput(g, theme)))
	if err != nil {
		return nil, fmt.Errorf("evaluate KSI family %s: %w", family, err)
	}
	return decodeResults(family, rs)
}

// regoResult is one entry of a family module's "results" set, decoded
// from the raw Rego output.
type regoResult struct {
	Indicator       string   `json:"indicator"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason"`
	RemediationHint string   `json:"remediation_hint,omitempty"`
	Evidence        []string `json:"evidence,omitempty"`
}

// decodeResults converts one Eval call's ResultSet - a single expression
// whose value is family's "results" set - into IndicatorResults. An empty
// ResultSet means the query itself produced no bindings at all (as
// opposed to a query that ran and found zero results, which OPA
// represents as one binding holding an empty set) - that only happens if
// the module's "results" rule doesn't exist under the queried package
// path, which is this package's own bug (a typo in query, or a module
// whose package declaration doesn't match its directory), not a fact
// about the KSI family being evaluated.
func decodeResults(family string, rs oparego.ResultSet) ([]IndicatorResult, error) {
	if len(rs) == 0 {
		return nil, fmt.Errorf("query for KSI family %s produced no result set - check the module's package declaration matches its directory", family)
	}
	raw, ok := rs[0].Expressions[0].Value.([]any)
	if !ok {
		return nil, fmt.Errorf("KSI family %s: results has unexpected shape %T", family, rs[0].Expressions[0].Value)
	}

	out := make([]IndicatorResult, 0, len(raw))
	for _, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("KSI family %s: result entry has unexpected shape %T", family, v)
		}
		var rr regoResult
		if err := decodeInto(m, &rr); err != nil {
			return nil, fmt.Errorf("KSI family %s: decode result entry: %w", family, err)
		}
		out = append(out, IndicatorResult{
			Indicator:       rr.Indicator,
			Family:          family,
			Status:          Status(rr.Status),
			Reason:          rr.Reason,
			RemediationHint: rr.RemediationHint,
			Evidence:        rr.Evidence,
		})
	}
	return out, nil
}

// decodeInto decodes m (a Rego result's already-parsed
// map[string]interface{}) into dst via a JSON round trip - the simplest
// correct way to get OPA's dynamically-typed output into a concrete Go
// struct without hand-writing a field-by-field type assertion for each of
// regoResult's fields.
func decodeInto(m map[string]any, dst any) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}

// notImplemented returns an Undetermined result for every indicator
// theme defines, for a KSI family that has no Rego module yet.
func notImplemented(family string, theme rules.KSITheme) []IndicatorResult {
	names := make([]string, 0, len(theme.Indicators))
	for name := range theme.Indicators {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]IndicatorResult, 0, len(names))
	for _, name := range names {
		out = append(out, IndicatorResult{
			Indicator:       name,
			Family:          family,
			Status:          StatusUndetermined,
			Reason:          "no Rego evaluation module implemented yet for this KSI family",
			RemediationHint: fmt.Sprintf("implement rego/ksi/%s and wire it into internal/backends/fedramp20x", strings.ToLower(family)),
		})
	}
	return out
}
