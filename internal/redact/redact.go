// Package redact scrubs secrets, tokens, and PII at the moment of
// collection.
//
// Redaction happens BEFORE anything is written to disk. Assume every
// output artifact will be committed to a customer repository, because
// it will be.
//
// Two independent detection layers, both documented in
// docs/redaction-coverage.md - keep that file in sync with this one:
//
//   - Key-name matching (KeyLooksSecret): a map key whose name matches a
//     known secret-shaped pattern (e.g. "password", "api_key") has its
//     entire value replaced with Placeholder, regardless of what the
//     value actually contains. This is the primary defense: IaC and
//     manifest formats are naturally key-value shaped, and a field named
//     "password" is far more reliably a password than any pattern
//     matched against its content could be.
//   - Content pattern matching (String): a small set of high-confidence,
//     unambiguous formats (a PEM private key block, an AWS access key
//     ID, a JWT) are redacted wherever they appear, regardless of the
//     key name pointing at them. This is a defense-in-depth layer for
//     exactly the cases key-name matching misses - a secret sitting in a
//     field whose name gives no hint at all (e.g. a bare "value").
//
// Neither layer is exhaustive, and this package does not claim to be.
// It deliberately errs toward over-redaction: a false positive here
// removes a harmless string from a collected fact, which costs nothing
// this project cares about; a false negative lets a real secret reach a
// customer's own committed repository, which is the failure this
// package exists to prevent. When genuinely uncertain, redact.
package redact

import (
	"regexp"
	"strings"
)

// Placeholder replaces any value this package redacts. It is a fixed,
// recognizable string - not a hash, not a truncation - so a redacted
// value is never mistaken for a real one and never leaks partial
// information about what was removed.
const Placeholder = "[REDACTED]"

// secretKeyNames are name fragments (matched case-insensitively as
// substrings, not whole-word) that mark a map key's value as secret-
// shaped regardless of content. Substring matching is deliberately
// broader than whole-word matching - "webhook_token" and "api_token"
// both contain "token" - trading a higher false-positive rate (an
// unrelated field like "token_endpoint" also matches, redacting a URL
// that wasn't actually secret) for a lower false-negative rate, which
// is the correct tradeoff per this package's own documented bias toward
// over-redaction.
//
// This list is a starting point, not a claim of completeness - see
// docs/redaction-coverage.md for the maintained, authoritative copy and
// what it deliberately does not cover.
var secretKeyNames = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"api_key",
	"apikey",
	"access_key",
	"accesskey",
	"private_key",
	"privatekey",
	"client_secret",
	"credential",
	"connection_string",
	"bearer",
}

// contentPatterns are high-confidence, unambiguous secret formats
// redacted wherever they appear in a string, independent of any
// enclosing key name. Each is documented in docs/redaction-coverage.md
// alongside secretKeyNames.
var contentPatterns = []*regexp.Regexp{
	// PEM-encoded private key block (RSA, EC, OPENSSH, DSA, or generic).
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	// AWS access key ID: a documented set of 4-letter type prefixes
	// (access key, temporary/STS, EC2 instance profile ID, IAM role ID,
	// service-linked role/user/group prefixes) followed by 16 uppercase
	// alphanumeric characters.
	regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b`),
	// JWT: three base64url segments separated by dots, the first two
	// always starting with "ey" (base64 for the JSON `{"`  header/payload
	// open brace).
	regexp.MustCompile(`\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
}

// KeyLooksSecret reports whether name - an attribute, field, or map key
// name - matches one of secretKeyNames, case-insensitively. Callers
// that find true should replace the corresponding value with
// Placeholder wholesale, without recursing into it: a value under a key
// named "password" is secret regardless of whether it happens to be a
// string, a nested object, or anything else.
func KeyLooksSecret(name string) bool {
	lower := strings.ToLower(name)
	for _, frag := range secretKeyNames {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// String returns s with every contentPatterns match replaced by
// Placeholder, or s unchanged if nothing matched. Safe to call on any
// string, including ones already known not to contain a secret - it is
// the defense-in-depth layer, meant to run even on values KeyLooksSecret
// already passed as not secret-shaped by name.
func String(s string) string {
	for _, pattern := range contentPatterns {
		s = pattern.ReplaceAllString(s, Placeholder)
	}
	return s
}

// Value recursively redacts v, which must be one of the shapes
// encoding/json or a YAML library decoding into `any` produces: string,
// bool, an integer or float kind, []any, map[string]any, or nil. A
// map[string]any entry whose key KeyLooksSecret reports true for is
// replaced with Placeholder wholesale, not recursed into. Every string
// leaf - map values, slice elements, or a bare string passed directly -
// is passed through String. Any other type (including a struct, or a
// map keyed by something other than string) is returned unchanged:
// Value is for exactly this collection of dynamically-typed shapes, the
// ones internal/frontend's YAML- and JSON-decoding collectors actually
// produce, not a general-purpose reflection-based object walker.
func Value(v any) any {
	switch val := v.(type) {
	case string:
		return String(val)
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			if KeyLooksSecret(k) {
				out[k] = Placeholder
				continue
			}
			out[k] = Value(vv)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, vv := range val {
			out[i] = Value(vv)
		}
		return out
	default:
		return v
	}
}
