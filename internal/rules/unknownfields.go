// Package-internal support for preserving unknown JSON fields (FR-1.1:
// "preserve unknown fields rather than dropping them").
//
// Approach and why: every typed struct in this package pairs a hand-written
// alias type (`type xAlias X`, which strips X's own UnmarshalJSON/MarshalJSON
// so the alias can be decoded/encoded with the plain struct-tag machinery
// without recursing) with decodeWithExtra/encodeWithExtra below. Those two
// functions use reflection once, at the call site, to read the alias's json
// tags and compute which top-level object keys are "known" versus "extra".
//
// Three alternatives were considered and rejected:
//
//   - Hand-listing each type's known keys as string literals in its
//     UnmarshalJSON. This duplicates the json tags already on the struct;
//     the two lists WILL drift the first time a field is added to one but
//     not the other, and the failure mode is silent (a field meant to be
//     "known" quietly ends up in Extra, or vice versa).
//   - Code generation (e.g. a go:generate step emitting the key lists).
//     Correct, but adds a build-time tool and a generated-file convention
//     for a problem reflection already solves at run time in ~30 lines.
//     Out of proportion for a Phase 0 ingestion package on a small team.
//   - A third-party "structs with extra fields" library (e.g. one of the
//     mapstructure-adjacent packages). Another dependency for something
//     the standard library's encoding/json and reflect packages already
//     do directly - CLAUDE.md is explicit that dependencies aren't added
//     casually.
//
// Reflection has a real per-call cost, but it doesn't matter here: a
// Dataset is loaded once per compiler invocation (hundreds of records
// decoded, not millions), not re-decoded per rule evaluation or on any
// request path. The JSON unmarshaling this rides on top of already
// dominates the cost of loading the ~450-record vendored dataset; the
// reflection pass adds an immeasurable fraction on top of that. If this
// package ever moves to decoding datasets in a hot loop, revisit this -
// until then, optimizing it would be solving a problem this code doesn't have.
package rules

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// Extra holds the fields of a JSON object that have no corresponding named
// field on the Go struct that decoded it. Every typed struct in this
// package carries an Extra field so that a dataset produced by a newer
// (or differently configured) version of the schema round-trips without
// silently losing data: unknown fields survive decode, and are written
// back out on encode.
//
// A nil Extra means the object had no unmapped fields.
type Extra map[string]json.RawMessage

// decodeWithExtra unmarshals data into out (a pointer to a struct) using
// the standard decoder, then returns whichever top-level object fields in
// data were not consumed by one of out's json-tagged fields.
func decodeWithExtra(data []byte, out any) (Extra, error) {
	if err := json.Unmarshal(data, out); err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	for _, name := range jsonFieldNames(out) {
		delete(raw, name)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	return Extra(raw), nil
}

// encodeWithExtra marshals v (a struct value) and merges extra's fields
// back into the resulting object, so fields decodeWithExtra preserved are
// not lost on re-encode.
func encodeWithExtra(v any, extra Extra) ([]byte, error) {
	b, err := marshalJSON(v)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return b, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, rv := range extra {
		m[k] = rv
	}
	return marshalJSON(m)
}

// marshalJSON is json.Marshal, except it doesn't HTML-escape "<", ">",
// and "&". json.Marshal always escapes those (safe for embedding in
// <script> tags, which nothing here does), and would otherwise silently
// rewrite real dataset content the moment any typed value in this
// package is marshaled - e.g. CTL/SI-08's guidance and FRR
// VER-TFR-IRI's statement both contain a literal ">" today.
//
// This alone is NOT sufficient to guarantee escape-free bytes reach a
// caller: Go's json package re-applies HTML-escaping to a nested
// json.Marshaler's returned bytes based on the OUTERMOST Marshal/Encode
// call's own setting, regardless of what that nested Marshaler did
// internally - a plain top-level json.Marshal(someRule) still escapes
// today, because the package-level json.Marshal function has no way to
// disable it. This is verified by TestMarshalJSONAloneIsNotEnough, which
// exists specifically to keep this claim honest. Every caller in this
// codebase that needs verbatim bytes (cmd/substrate/rulesdiff.go's JSON
// output, this package's own diffRecords in diff.go, which calls this
// same marshalJSON directly) uses its own escape-disabled json.Encoder
// as the true outermost call, which is what actually makes the fix
// visible; this function makes it possible for those outer
// callers to succeed, by not baking the escapes in one level down where
// no outer setting could undo them.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// jsonFieldNames returns the JSON object keys that a struct's json tags
// claim, given a pointer to that struct (or the struct value itself).
func jsonFieldNames(v any) []string {
	rt := reflect.TypeOf(v)
	for rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		return nil
	}
	names := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag, ok := f.Tag.Lookup("json")
		if !ok {
			names = append(names, f.Name)
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		names = append(names, name)
	}
	return names
}
