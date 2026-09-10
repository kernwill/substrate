package githubactions

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/kernwill/substrate/internal/frontend/vcs"
	"github.com/kernwill/substrate/internal/provenance"
)

// CollectorVersion is this package's own collector version (FR-4.1),
// bumped whenever a change here could produce different facts from the
// same workflow files. It is independent of the overall substrate
// binary version.
const CollectorVersion = "githubactions/v0.1.0"

// Parse reads every *.yml and *.yaml file directly in dir
// (conventionally ".github/workflows"; not recursively, matching
// internal/frontend/terraform and internal/frontend/kubernetes's own
// scoping) and returns the workflow graph they declare.
//
// Workflows are returned sorted by path, and files are read in sorted
// path order, so Parse's own output does not depend on filesystem
// directory-listing order - see internal/frontend/terraform.Parse's
// doc comment for the same reasoning applied there.
func Parse(dir string) (*WorkflowGraph, error) {
	var matches []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, fmt.Errorf("githubactions: glob %s: %w", dir, err)
		}
		matches = append(matches, m...)
	}
	sort.Strings(matches)

	graph := &WorkflowGraph{}
	for _, path := range matches {
		t, err := vcs.CommitTime(dir, filepath.Base(path))
		if err != nil {
			return nil, fmt.Errorf("githubactions: %s: %w", path, err)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("githubactions: read %s: %w", path, err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("githubactions: parse %s: %w", path, err)
		}
		if doc == nil {
			continue // an empty file has no workflow to record
		}

		name, _ := doc["name"].(string)
		graph.Workflows = append(graph.Workflows, Workflow{
			Address:    WorkflowAddress{Path: path, Name: name},
			Attributes: doc,
			Provenance: provenance.Record{
				SourceType:       "github_actions",
				Locator:          provenance.Locator{Path: path, Line: 1},
				Timestamp:        t,
				CollectorVersion: CollectorVersion,
				Basis:            provenance.Declared,
				Confidence:       provenance.Deterministic,
			},
		})
	}

	sort.Slice(graph.Workflows, func(i, j int) bool {
		return graph.Workflows[i].Address.Path < graph.Workflows[j].Address.Path
	})
	return graph, nil
}
