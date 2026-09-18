package dockerfile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kernwill/substrate/internal/frontend/vcs"
	"github.com/kernwill/substrate/internal/provenance"
	"github.com/kernwill/substrate/internal/redact"
)

// CollectorVersion is this package's own collector version (FR-4.1),
// bumped whenever a change here could produce different facts from the
// same Dockerfile content. Independent of the overall substrate binary
// version.
const CollectorVersion = "dockerfile/v0.1.0"

// Parse reads every "Dockerfile" and "Dockerfile.*" file directly in
// dir (not recursively - matching every other frontend's own scoping,
// and the same provisional "narrow convention, not a general answer to
// which files belong to which frontend" caveat cmd/substrate/compile.go
// already carries for its k8s/.github/workflows subdirectory choices).
// A lowercase "dockerfile" is a real convention in some repositories
// too but is deliberately not matched here, to keep this first pass's
// glob as unambiguous as Terraform's *.tf.
//
// Stages are returned in file-then-instruction order, and files are
// read in sorted path order, so Parse's own output does not depend on
// filesystem directory-listing order - see
// internal/frontend/terraform.Parse's doc comment for the same
// reasoning applied there. No further sort is needed after appending:
// stages within one file are already produced in their own deterministic
// parse order (the Nth FROM instruction encountered), not from any
// unordered source like a map.
func Parse(dir string) (*DockerfileGraph, error) {
	var matches []string
	for _, pattern := range []string{"Dockerfile", "Dockerfile.*"} {
		m, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, fmt.Errorf("dockerfile: glob %s: %w", dir, err)
		}
		matches = append(matches, m...)
	}
	sort.Strings(matches)

	graph := &DockerfileGraph{}
	for _, path := range matches {
		t, err := vcs.CommitTime(dir, filepath.Base(path))
		if err != nil {
			return nil, fmt.Errorf("dockerfile: %s: %w", path, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("dockerfile: read %s: %w", path, err)
		}
		stages, err := parseStages(path, string(raw), t)
		if err != nil {
			return nil, err
		}
		graph.Stages = append(graph.Stages, stages...)
	}
	return graph, nil
}

// logicalLine is one Dockerfile instruction after line-continuation
// joining and comment/blank-line stripping.
type logicalLine struct {
	Line int // the instruction's starting physical line number (1-based)
	Text string
}

// logicalLines joins raw's physical lines into instructions, following
// Docker's own default line-continuation rule (a trailing "\", the
// default escape character absent a "# escape=`" parser directive this
// package does not read - a real but rare enough divergence not worth
// the added complexity for a SHOULD-priority frontend). Blank lines and
// comment lines (first non-whitespace character "#") are dropped
// entirely rather than joined into a neighboring instruction - matching
// how Docker's own parser treats them.
func logicalLines(raw string) []logicalLine {
	physical := strings.Split(raw, "\n")
	var out []logicalLine
	var buf strings.Builder
	startLine := 0
	for i, rawLine := range physical {
		lineNum := i + 1
		line := strings.TrimRight(rawLine, "\r")
		if buf.Len() == 0 {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			startLine = lineNum
		}
		content := strings.TrimRight(line, " \t")
		continued := strings.HasSuffix(content, "\\")
		if continued {
			content = strings.TrimSuffix(content, "\\")
		}
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(strings.TrimSpace(content))
		if !continued {
			out = append(out, logicalLine{Line: startLine, Text: buf.String()})
			buf.Reset()
		}
	}
	if buf.Len() > 0 {
		// A trailing "\" on the file's last physical line has nothing left
		// to continue onto - keep what was buffered rather than silently
		// dropping an otherwise-complete-looking instruction.
		out = append(out, logicalLine{Line: startLine, Text: buf.String()})
	}
	return out
}

// parseStages extracts every FROM instruction from content (path's own
// text), stamping commitTime as each resulting Stage's
// Provenance.Timestamp.
func parseStages(path, content string, commitTime time.Time) ([]Stage, error) {
	var stages []Stage
	stageNames := make(map[string]bool)

	for _, ll := range logicalLines(content) {
		fields := strings.Fields(ll.Text)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}

		args := fields[1:]
		// Skip leading flags (e.g. "--platform=$BUILDPLATFORM") - none of
		// them change which image is being referenced.
		for len(args) > 0 && strings.HasPrefix(args[0], "--") {
			args = args[1:]
		}
		if len(args) == 0 {
			return nil, fmt.Errorf("dockerfile: %s:%d: FROM instruction with no image argument", path, ll.Line)
		}
		spec := args[0]

		var stageName string
		if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
			stageName = args[2]
		}

		index := len(stages)
		addr := StageAddress{Path: path, Index: index, Name: stageName}
		image, unresolvedReason := classifyImageSpec(spec, stageNames)

		var rec provenance.Record
		if unresolvedReason != "" {
			rec = provenance.Record{
				SourceType:       "dockerfile",
				Locator:          provenance.Locator{Path: path, Line: ll.Line},
				Timestamp:        commitTime,
				CollectorVersion: CollectorVersion,
				Basis:            provenance.Declared,
				Confidence:       provenance.Unresolved,
				UnresolvedReason: redact.String(unresolvedReason),
			}
			image = BaseImage{}
		} else {
			rec = provenance.Record{
				SourceType:       "dockerfile",
				Locator:          provenance.Locator{Path: path, Line: ll.Line},
				Timestamp:        commitTime,
				CollectorVersion: CollectorVersion,
				Basis:            provenance.Declared,
				Confidence:       provenance.Deterministic,
			}
		}

		stages = append(stages, Stage{Address: addr, Image: image, Provenance: rec})

		if stageName != "" {
			stageNames[stageName] = true
		}
	}

	return stages, nil
}

// classifyImageSpec resolves a FROM instruction's image argument
// (everything before any "AS <name>", flags already stripped) into a
// BaseImage, or an unresolved reason - see this package's doc comment
// for the three BaseImageKind outcomes and why an unresolved one is
// possible at all.
//
// priorStageNames must contain only stage names declared EARLIER in the
// same file (parseStages adds each stage's name after classifying it,
// never before) - Docker itself only allows a FROM to reference a stage
// that already exists by the time it's read.
func classifyImageSpec(spec string, priorStageNames map[string]bool) (BaseImage, string) {
	if strings.ContainsRune(spec, '$') {
		return BaseImage{}, fmt.Sprintf("base image reference %q contains an unresolved build argument or variable - substrate does not track ARG declarations or perform variable substitution", spec)
	}
	if strings.EqualFold(spec, "scratch") {
		return BaseImage{Kind: BaseImageScratch}, ""
	}
	if priorStageNames[spec] {
		return BaseImage{Kind: BaseImageLocalStage}, ""
	}

	repoAndTag, digest := spec, ""
	if at := strings.IndexByte(spec, '@'); at != -1 {
		repoAndTag, digest = spec[:at], spec[at+1:]
	}

	// The tag separator is the LAST colon after the last slash - a colon
	// before the last slash is a registry host's port (e.g.
	// "localhost:5000/myimage"), never a tag separator. Mirrors how
	// Docker's own reference parser (and every other container tooling
	// implementation of the same grammar) disambiguates the two.
	repo, tag := repoAndTag, ""
	searchFrom := 0
	if lastSlash := strings.LastIndex(repoAndTag, "/"); lastSlash != -1 {
		searchFrom = lastSlash + 1
	}
	if colon := strings.IndexByte(repoAndTag[searchFrom:], ':'); colon != -1 {
		tag = repoAndTag[searchFrom+colon+1:]
		repo = repoAndTag[:searchFrom+colon]
	}

	return BaseImage{Kind: BaseImageExternal, Repository: repo, Tag: tag, Digest: digest}, ""
}
