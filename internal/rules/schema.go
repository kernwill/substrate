package rules

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed data/fedramp-consolidated-rules.schema.json
var schemaJSON []byte

//go:embed data/fedramp-consolidated-rules.json
var vendoredDataset []byte

// schemaURL is the schema's own "$id". It has no meaning as a network
// address here; it's just the resource name the compiler resolves
// "$ref"s against.
const schemaURL = "https://fedramp.gov/schema/documentation.json"

var compiledSchema *jsonschema.Schema

func init() {
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		panic(fmt.Sprintf("rules: invalid embedded schema: %v", err))
	}

	c := jsonschema.NewCompiler()
	// The schema uses a negative lookahead (frr_requirement_id's pattern
	// excludes KSI-shaped IDs) to disambiguate two ID spaces that would
	// otherwise overlap. JSON Schema's "pattern" dialect is ECMA-262
	// regex, which supports lookaround; Go's stdlib regexp (RE2) does
	// not and rejects the schema outright. dlclark/regexp2 implements
	// ECMA-262 semantics, so we use it instead of the default engine.
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		re, err := regexp2.Compile(s, regexp2.ECMAScript)
		if err != nil {
			return nil, err
		}
		return ecmaRegexp{re}, nil
	})
	if err := c.AddResource(schemaURL, schemaDoc); err != nil {
		panic(fmt.Sprintf("rules: invalid embedded schema: %v", err))
	}
	s, err := c.Compile(schemaURL)
	if err != nil {
		panic(fmt.Sprintf("rules: compile embedded schema: %v", err))
	}
	compiledSchema = s
}

// ecmaRegexp adapts *regexp2.Regexp to jsonschema.Regexp.
type ecmaRegexp struct{ re *regexp2.Regexp }

func (r ecmaRegexp) MatchString(s string) bool {
	matched, err := r.re.MatchString(s)
	if err != nil {
		// jsonschema.Regexp's interface has no error return - see its
		// definition in santhosh-tekuri/jsonschema/v6 - so there is no way
		// to propagate this as a real error through schema validation.
		// regexp2 only errors here for things like an exceeded match
		// timeout, which this package never configures, so in practice
		// this should be unreachable. Silently treating an engine error as
		// "does not match" would be exactly the kind of collapse CLAUDE.md
		// forbids ("never collapse undetermined into either satisfied or
		// not_satisfied") applied to schema validation itself: it could
		// make a well-formed dataset fail validation, or a malformed one
		// pass, with no indication anything went wrong. Panic instead,
		// consistent with this file's own init() failing loudly on schema
		// construction problems it also considers "should never happen."
		panic(fmt.Sprintf("rules: regexp2 match error for pattern %q: %v", r.re.String(), err))
	}
	return matched
}

func (r ecmaRegexp) String() string { return r.re.String() }

// SchemaError reports that a dataset failed validation against the
// vendored FedRAMP Consolidated Rules JSON Schema: a missing required
// field, an unexpected property, a value that doesn't match a documented
// enum or pattern, or any other deviation. It wraps the underlying
// jsonschema.ValidationError, whose message includes the JSON pointer to
// the offending location.
type SchemaError struct {
	err error
}

func (e *SchemaError) Error() string {
	return "rules: dataset failed schema validation: " + e.err.Error()
}

func (e *SchemaError) Unwrap() error { return e.err }

// ValidateSchema validates raw JSON bytes against the vendored FedRAMP
// Consolidated Rules schema, independent of decoding it into a Dataset.
// It fails loudly: a schema violation is returned as a *SchemaError
// rather than being ignored or silently accepted.
func ValidateSchema(raw []byte) error {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("rules: invalid JSON: %w", err)
	}
	if err := compiledSchema.Validate(v); err != nil {
		return &SchemaError{err: err}
	}
	return nil
}
