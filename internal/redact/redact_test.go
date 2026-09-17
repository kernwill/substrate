package redact

import (
	"strings"
	"testing"
)

func TestKeyLooksSecret(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"password", true},
		{"Password", true},
		{"db_password", true},
		{"PASSWD", true},
		{"api_key", true},
		{"apiKey", true},
		{"client_secret", true},
		{"access_key", true},
		{"private_key", true},
		{"connection_string", true},
		{"github_token", true},
		{"bearer_token", true},
		// Deliberately over-broad, per the package's documented
		// over-redaction bias: "token" as a substring catches this too,
		// even though it's arguably benign (a URL, not a secret).
		{"token_endpoint", true},

		{"name", false},
		{"region", false},
		{"bucket_name", false},
		{"status", false},
		{"algorithm", false},
	}
	for _, c := range cases {
		if got := KeyLooksSecret(c.name); got != c.want {
			t.Errorf("KeyLooksSecret(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestStringRedactsPEMPrivateKey(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEA\n-----END RSA PRIVATE KEY-----"
	got := String("cert_data = \"" + pem + "\"")
	if got == "cert_data = \""+pem+"\"" {
		t.Fatal("PEM private key block was not redacted")
	}
	if !containsPlaceholder(got) {
		t.Errorf("got %q, want it to contain %q", got, Placeholder)
	}
	if strings.Contains(got, "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEA") {
		t.Error("redacted output still contains the private key body")
	}
}

func TestStringRedactsAWSAccessKeyID(t *testing.T) {
	got := String("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
	want := "aws_access_key_id = " + Placeholder
	if got != want {
		t.Errorf("String(...) = %q, want %q", got, want)
	}
}

func TestStringRedactsJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	got := String("Authorization: Bearer " + jwt)
	if strings.Contains(got, jwt) {
		t.Errorf("JWT was not redacted: %q", got)
	}
	if !containsPlaceholder(got) {
		t.Errorf("got %q, want it to contain %q", got, Placeholder)
	}
}

func TestStringLeavesUnrelatedContentAlone(t *testing.T) {
	for _, s := range []string{
		"aws:kms",
		"Enabled",
		"arn:aws:s3:::my-bucket",
		"",
		"a perfectly normal sentence about buckets",
	} {
		if got := String(s); got != s {
			t.Errorf("String(%q) = %q, want it unchanged", s, got)
		}
	}
}

func TestValueRedactsByKeyNameWholesale(t *testing.T) {
	in := map[string]any{
		"name":     "example",
		"password": "hunter2",
		"nested": map[string]any{
			"api_key": "abc123",
			"region":  "us-east-1",
		},
	}
	out := Value(in).(map[string]any)

	if out["name"] != "example" {
		t.Errorf("name = %v, want unchanged", out["name"])
	}
	if out["password"] != Placeholder {
		t.Errorf("password = %v, want %q", out["password"], Placeholder)
	}
	nested := out["nested"].(map[string]any)
	if nested["api_key"] != Placeholder {
		t.Errorf("nested.api_key = %v, want %q", nested["api_key"], Placeholder)
	}
	if nested["region"] != "us-east-1" {
		t.Errorf("nested.region = %v, want unchanged", nested["region"])
	}
}

// TestValueRedactsSecretShapedValueRegardlessOfKeyName confirms the
// content-pattern layer fires even under an innocuous-looking key name
// that KeyLooksSecret would never flag - the defense-in-depth case this
// package's own doc comment describes.
func TestValueRedactsSecretShapedValueRegardlessOfKeyName(t *testing.T) {
	in := map[string]any{
		"value": "AKIAIOSFODNN7EXAMPLE",
	}
	out := Value(in).(map[string]any)
	if out["value"] != Placeholder {
		t.Errorf("value = %v, want %q (content-pattern match under a non-secret-shaped key)", out["value"], Placeholder)
	}
}

func TestValueRecursesIntoSlicesOfMaps(t *testing.T) {
	in := map[string]any{
		"items": []any{
			map[string]any{"token": "abc"},
			map[string]any{"name": "ok"},
		},
	}
	out := Value(in).(map[string]any)
	items := out["items"].([]any)
	if items[0].(map[string]any)["token"] != Placeholder {
		t.Errorf("items[0].token = %v, want %q", items[0].(map[string]any)["token"], Placeholder)
	}
	if items[1].(map[string]any)["name"] != "ok" {
		t.Errorf("items[1].name = %v, want unchanged", items[1].(map[string]any)["name"])
	}
}

func TestValuePassesThroughNonSecretScalars(t *testing.T) {
	for _, v := range []any{true, false, 3.14, 42, nil} {
		if got := Value(v); got != v {
			t.Errorf("Value(%v) = %v, want unchanged", v, got)
		}
	}
}

func containsPlaceholder(s string) bool {
	return strings.Contains(s, Placeholder)
}
