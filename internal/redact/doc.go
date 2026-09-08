// Package redact scrubs secrets, tokens, and PII at the moment of collection.
//
// Redaction happens BEFORE anything is written to disk. Assume every output
// artifact will be committed to a customer repository, because it will be.
package redact
