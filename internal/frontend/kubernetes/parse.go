package kubernetes

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kernwill/substrate/internal/frontend/vcs"
	"github.com/kernwill/substrate/internal/provenance"
	"github.com/kernwill/substrate/internal/redact"
)

// CollectorVersion is this package's own collector version (FR-4.1),
// bumped whenever a change here could produce different facts from the
// same manifests. It is independent of the overall substrate binary
// version.
const CollectorVersion = "kubernetes/v0.1.0"

// Parse reads every *.yaml and *.yml file directly in dir (not
// recursively - matching internal/frontend/terraform's own scoping) and
// returns the resource graph of Kubernetes objects they declare.
//
// Resources are returned sorted by address, and files are read in
// sorted path order, so Parse's own output does not depend on
// filesystem directory-listing order - see
// internal/frontend/terraform.Parse's doc comment for the same
// reasoning applied there.
func Parse(dir string) (*ResourceGraph, error) {
	var matches []string
	for _, pattern := range []string{"*.yaml", "*.yml"} {
		m, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, fmt.Errorf("kubernetes: glob %s: %w", dir, err)
		}
		matches = append(matches, m...)
	}
	sort.Strings(matches)

	declaredAt := make(map[ResourceAddress]string) // address -> "file:line" of first declaration
	graph := &ResourceGraph{}
	for _, path := range matches {
		t, err := vcs.CommitTime(dir, filepath.Base(path))
		if err != nil {
			return nil, fmt.Errorf("kubernetes: %s: %w", path, err)
		}

		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("kubernetes: open %s: %w", path, err)
		}
		resources, err := parseFile(path, f, t)
		f.Close()
		if err != nil {
			return nil, err
		}

		for _, r := range resources {
			loc := fmt.Sprintf("%s:%d", r.Provenance.Locator.Path, r.Provenance.Locator.Line)
			if prev, dup := declaredAt[r.Address]; dup {
				return nil, fmt.Errorf("kubernetes: %s: duplicate object %s, first declared at %s", loc, r.Address, prev)
			}
			declaredAt[r.Address] = loc
			graph.Resources = append(graph.Resources, r)
		}
	}

	sort.Slice(graph.Resources, func(i, j int) bool {
		a, b := graph.Resources[i].Address, graph.Resources[j].Address
		if a.APIVersion != b.APIVersion {
			return a.APIVersion < b.APIVersion
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return graph, nil
}

// parseFile decodes every YAML document in r (path is used only for
// error messages and Locator.Path) into a Resource, using commitTime as
// every resulting Resource's Provenance.Timestamp.
func parseFile(path string, r io.Reader, commitTime time.Time) ([]Resource, error) {
	dec := yaml.NewDecoder(r)
	var resources []Resource
	for i := 0; ; i++ {
		var node yaml.Node
		err := dec.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("kubernetes: parse %s (document %d): %w", path, i, err)
		}
		if len(node.Content) == 0 {
			// An empty document, e.g. a leading or trailing "---" with
			// nothing between it and the next separator.
			continue
		}
		line := node.Line
		if len(node.Content) > 0 && node.Content[0].Line > 0 {
			line = node.Content[0].Line
		}

		var doc map[string]any
		if err := node.Decode(&doc); err != nil {
			return nil, fmt.Errorf("kubernetes: %s:%d: document %d is not a YAML mapping: %w", path, line, i, err)
		}
		if doc == nil {
			// A "null" document - e.g. two "---" separators with nothing
			// meaningful between them - decodes successfully into a nil
			// map rather than erroring or leaving node.Content empty.
			// Same case as the len(node.Content) == 0 check above, just
			// caught one step later.
			continue
		}

		addr, err := addressOf(doc)
		if err != nil {
			return nil, fmt.Errorf("kubernetes: %s:%d: document %d: %w", path, line, i, err)
		}

		// Redact at collection (CLAUDE.md), before doc is stored on
		// Resource.Attributes and written raw to disk. A Secret object's
		// "data"/"stringData" fields are, by Kubernetes' own convention,
		// entirely secret material regardless of what any individual key
		// inside them is named - "data" itself isn't a secret-shaped key
		// name (a ConfigMap has one too, and that one is NOT secret), so
		// this has to be a Kind-aware rule rather than something
		// redact.Value's generic key-name pass could ever catch on its
		// own. Applied before the generic pass below, which still runs
		// over everything else - an annotation or env value named
		// "password" anywhere, Secret or not.
		if addr.Kind == "Secret" {
			if _, ok := doc["data"]; ok {
				doc["data"] = redact.Placeholder
			}
			if _, ok := doc["stringData"]; ok {
				doc["stringData"] = redact.Placeholder
			}
		}
		// kubectl writes the object's full prior manifest into this
		// annotation on every apply, re-serialized as one JSON string -
		// including a Secret's own "data"/"stringData" if the object
		// ever was one, or any other object's own secret-shaped fields.
		// redact.Value's generic pass below only recurses into actual
		// map/slice structure, never into a string that happens to
		// itself contain JSON text, so this annotation would otherwise
		// carry an unredacted snapshot of exactly what the rule above
		// just redacted. Unconditional on Kind: any object can carry it.
		if metadata, ok := doc["metadata"].(map[string]any); ok {
			if annotations, ok := metadata["annotations"].(map[string]any); ok {
				const lastAppliedConfigAnnotation = "kubectl.kubernetes.io/last-applied-configuration"
				if _, ok := annotations[lastAppliedConfigAnnotation]; ok {
					annotations[lastAppliedConfigAnnotation] = redact.Placeholder
				}
			}
		}
		doc = redact.Value(doc).(map[string]any)

		resources = append(resources, Resource{
			Address:    addr,
			Attributes: doc,
			Provenance: provenance.Record{
				SourceType:       "kubernetes",
				Locator:          provenance.Locator{Path: path, Line: line},
				Timestamp:        commitTime,
				CollectorVersion: CollectorVersion,
				Basis:            provenance.Declared,
				Confidence:       provenance.Deterministic,
			},
		})
	}
	return resources, nil
}

// addressOf extracts doc's ResourceAddress from its required
// apiVersion, kind, and metadata.name fields (and optional
// metadata.namespace), failing loudly if any required field is absent
// or the wrong shape - a document missing these isn't a Kubernetes
// object this package can address at all, never something to guess at
// (FR-2.3's "never guess" principle, applied to the same requirement
// here as in internal/frontend/terraform).
func addressOf(doc map[string]any) (ResourceAddress, error) {
	apiVersion, ok := doc["apiVersion"].(string)
	if !ok || apiVersion == "" {
		return ResourceAddress{}, fmt.Errorf("missing or non-string \"apiVersion\" - not a Kubernetes object (a Helm template that failed to render, perhaps?)")
	}
	kind, ok := doc["kind"].(string)
	if !ok || kind == "" {
		return ResourceAddress{}, fmt.Errorf("missing or non-string \"kind\"")
	}
	metadata, ok := doc["metadata"].(map[string]any)
	if !ok {
		return ResourceAddress{}, fmt.Errorf("missing or non-mapping \"metadata\"")
	}
	name, ok := metadata["name"].(string)
	if !ok || name == "" {
		return ResourceAddress{}, fmt.Errorf("missing or non-string \"metadata.name\"")
	}
	namespace, _ := metadata["namespace"].(string) // absent means cluster-scoped, not an error

	return ResourceAddress{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name}, nil
}
