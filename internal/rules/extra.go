package rules

import (
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
	b, err := json.Marshal(v)
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
	return json.Marshal(m)
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
