package dockerfile

import (
	"fmt"

	"github.com/kernwill/substrate/internal/provenance"
)

// StageAddress identifies one build stage: Path is the Dockerfile it
// came from, Index is the stage's 0-based position (the Nth FROM
// instruction encountered in the file, in file order), and Name is its
// "AS <name>" label if the instruction declared one (empty otherwise).
type StageAddress struct {
	Path  string `json:"path"`
	Index int    `json:"index"`
	Name  string `json:"name,omitempty"`
}

// String renders a as "path#index[name]", or "path#index" when the
// stage has no AS name.
func (a StageAddress) String() string {
	if a.Name != "" {
		return fmt.Sprintf("%s#%d[%s]", a.Path, a.Index, a.Name)
	}
	return fmt.Sprintf("%s#%d", a.Path, a.Index)
}

// BaseImageKind classifies what a FROM instruction's image argument
// actually refers to - see this package's own doc comment for why the
// distinction matters to FR-2.7's supply-chain-evidence scope. Only
// meaningful when the owning Stage's Provenance.Confidence is
// Deterministic; the zero value (empty string) is what an Unresolved
// stage carries.
type BaseImageKind string

const (
	BaseImageExternal   BaseImageKind = "external"
	BaseImageScratch    BaseImageKind = "scratch"
	BaseImageLocalStage BaseImageKind = "local_stage"
)

// BaseImage is one FROM instruction's resolved image reference.
// Repository, Tag, and Digest are populated only when Kind is
// BaseImageExternal - scratch and a local-stage reference have no
// repository/tag/digest to record, and an unresolved stage has none of
// these fields populated at all (see Stage's own doc comment).
type BaseImage struct {
	Kind       BaseImageKind `json:"kind,omitempty"`
	Repository string        `json:"repository,omitempty"`
	Tag        string        `json:"tag,omitempty"`
	Digest     string        `json:"digest,omitempty"`
}

// Stage is one parsed FROM instruction, treated as a single fact
// (FR-4.1's provenance granularity is per-instruction here, at the
// instruction's own starting line - matching
// internal/frontend/kubernetes's per-object granularity, one level
// finer than internal/frontend/githubactions's per-file granularity).
//
// Image is meaningful only when Provenance.Confidence is Deterministic:
// an Unresolved stage (an unexpanded build argument in the image
// reference - see this package's doc comment) carries a zero BaseImage,
// the same "never guess" treatment every other frontend and collector
// in this codebase applies to a value it could not statically
// determine.
type Stage struct {
	Address    StageAddress      `json:"address"`
	Image      BaseImage         `json:"image"`
	Provenance provenance.Record `json:"provenance"`
}

// DockerfileGraph is every FROM instruction parsed from one directory's
// Dockerfile(s), per FR-2.7.
type DockerfileGraph struct {
	Stages []Stage `json:"stages"`
}
