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
	return err == nil && matched
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
