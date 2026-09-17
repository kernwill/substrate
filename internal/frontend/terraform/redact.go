package terraform

import "github.com/kernwill/substrate/internal/redact"

// redactAttributes returns attrs with every secret-shaped attribute
// (per redact.KeyLooksSecret) replaced wholesale and every other string
// leaf passed through redact.String, applied at collection (CLAUDE.md)
// before Parse ever returns a Resource.
//
// This is terraform-specific glue internal/redact's own generic Value
// function can't provide directly: a resolved leaf attribute's own
// Value field does hold the bare `any` shape Value expects (per
// AttributeValue's own doc comment), but a nested block's Value holds a
// map[string]AttributeValue or []map[string]AttributeValue instead (see
// evalBody in parse.go) - only this package knows how to walk that
// shape, so it walks it itself and calls into redact's lower-level
// KeyLooksSecret/String/Value primitives rather than expecting Value to
// understand a type it was never meant to know about.
func redactAttributes(attrs map[string]AttributeValue) map[string]AttributeValue {
	out := make(map[string]AttributeValue, len(attrs))
	for name, av := range attrs {
		if redact.KeyLooksSecret(name) {
			if av.Unresolved != "" {
				// Nothing was ever resolved here to redact - preserve the
				// reason rather than fabricating a resolved Placeholder
				// value where none exists (which would violate
				// AttributeValue's own "never both" invariant in spirit).
				// Still passed through redact.String: most Unresolved
				// reasons are this package's own fixed diagnostic text,
				// but evalAttribute's "could not evaluate expression: %s"
				// case embeds an hcl diagnostic's own Error() string,
				// which is not this package's own text and is not
				// guaranteed never to echo source content.
				out[name] = AttributeValue{Unresolved: redact.String(av.Unresolved)}
				continue
			}
			out[name] = AttributeValue{Value: redact.Placeholder}
			continue
		}
		out[name] = redactAttributeValue(av)
	}
	return out
}

// redactAttributeValue redacts av's own Value, recursing into the two
// nested-block shapes evalBody produces (map[string]AttributeValue,
// []map[string]AttributeValue) directly, and delegating to
// redact.Value for every other shape (the bare string/bool/float64/
// []any/map[string]any a resolved leaf attribute's Value actually
// holds). Unresolved is redacted uniformly across every branch (via the
// shared unresolved variable) - see redactAttributes' own comment on
// why an Unresolved reason isn't automatically safe text.
func redactAttributeValue(av AttributeValue) AttributeValue {
	unresolved := redact.String(av.Unresolved)
	switch v := av.Value.(type) {
	case map[string]AttributeValue:
		return AttributeValue{Value: redactAttributes(v), Unresolved: unresolved}
	case []map[string]AttributeValue:
		out := make([]map[string]AttributeValue, len(v))
		for i, m := range v {
			out[i] = redactAttributes(m)
		}
		return AttributeValue{Value: out, Unresolved: unresolved}
	default:
		return AttributeValue{Value: redact.Value(av.Value), Unresolved: unresolved}
	}
}
