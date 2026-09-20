package okta

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fakeTokenEndpoint is a fake httpDoer standing in for Okta's token
// endpoint, the same fixture-substitution pattern aws's fakeS3 uses -
// no real HTTP call, no live Okta dependency (FR-3.10).
type fakeTokenEndpoint struct {
	calls int

	// responses is served in order, one per call; the last entry
	// repeats once exhausted. Lets a test script a token, then an
	// expiry-triggered refresh, without hand-managing indices.
	responses []fakeTokenResponse
	// capturedRequests records each request's decoded form body, so
	// tests can assert on the assertion/grant_type/scope sent without
	// re-parsing a raw http.Request.
	capturedForms []map[string][]string
}

type fakeTokenResponse struct {
	status int
	body   string
}

func (f *fakeTokenEndpoint) Do(req *http.Request) (*http.Response, error) {
	if err := req.ParseForm(); err != nil {
		return nil, err
	}
	f.capturedForms = append(f.capturedForms, map[string][]string(req.PostForm))

	i := f.calls
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	f.calls++
	r := f.responses[i]

	return &http.Response{
		StatusCode: r.status,
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Header:     make(http.Header),
	}, nil
}

func testConfig(t *testing.T, doer httpDoer) Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	return Config{
		OrgURL:     "https://example.okta.com",
		TokenPath:  "/oauth2/v1/token",
		ClientID:   "test-client-id",
		PrivateKey: key,
		KeyID:      "test-kid",
		Scopes:     []string{"okta.users.read", "okta.logs.read"},
		HTTPClient: doer,
	}
}

func TestBuildClientAssertion_Shape(t *testing.T) {
	cfg := testConfig(t, nil)

	assertion, err := buildClientAssertion(cfg)
	if err != nil {
		t.Fatalf("buildClientAssertion: %v", err)
	}

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a 3-segment JWT, got %d segments", len(parts))
	}

	header := decodeSegment(t, parts[0])
	if header["alg"] != "RS256" {
		t.Errorf("header.alg = %v, want RS256", header["alg"])
	}
	if header["kid"] != cfg.KeyID {
		t.Errorf("header.kid = %v, want %v", header["kid"], cfg.KeyID)
	}

	claims := decodeSegment(t, parts[1])
	if claims["iss"] != cfg.ClientID {
		t.Errorf("claims.iss = %v, want %v", claims["iss"], cfg.ClientID)
	}
	if claims["sub"] != cfg.ClientID {
		t.Errorf("claims.sub = %v, want %v", claims["sub"], cfg.ClientID)
	}
	wantAud := cfg.OrgURL + cfg.TokenPath
	if claims["aud"] != wantAud {
		t.Errorf("claims.aud = %v, want %v", claims["aud"], wantAud)
	}
	if claims["jti"] == "" || claims["jti"] == nil {
		t.Error("claims.jti is empty, want a random value")
	}

	exp, iat := claims["exp"].(float64), claims["iat"].(float64)
	if exp-iat != assertionLifetime.Seconds() {
		t.Errorf("exp-iat = %v seconds, want %v", exp-iat, assertionLifetime.Seconds())
	}
}

func TestBuildClientAssertion_UniqueJTI(t *testing.T) {
	cfg := testConfig(t, nil)

	a1, err := buildClientAssertion(cfg)
	if err != nil {
		t.Fatalf("buildClientAssertion: %v", err)
	}
	a2, err := buildClientAssertion(cfg)
	if err != nil {
		t.Fatalf("buildClientAssertion: %v", err)
	}

	c1 := decodeSegment(t, strings.Split(a1, ".")[1])
	c2 := decodeSegment(t, strings.Split(a2, ".")[1])
	if c1["jti"] == c2["jti"] {
		t.Error("two assertions minted the same jti, want unique per exchange (replay protection)")
	}
}

func TestTokenSource_ExchangesAndCaches(t *testing.T) {
	fake := &fakeTokenEndpoint{
		responses: []fakeTokenResponse{
			{status: http.StatusOK, body: `{"access_token":"token-1","expires_in":3600}`},
		},
	}
	src, err := NewTokenSource(testConfig(t, fake))
	if err != nil {
		t.Fatalf("NewTokenSource: %v", err)
	}

	tok1, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok1 != "token-1" {
		t.Errorf("Token = %q, want token-1", tok1)
	}

	tok2, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if tok2 != "token-1" {
		t.Errorf("cached Token = %q, want token-1", tok2)
	}
	if fake.calls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (second call should hit the cache)", fake.calls)
	}
}

func TestTokenSource_RefreshesNearExpiry(t *testing.T) {
	fake := &fakeTokenEndpoint{
		responses: []fakeTokenResponse{
			// expires_in shorter than tokenRefreshSkew: every call
			// should be treated as already-expired and re-exchanged.
			{status: http.StatusOK, body: `{"access_token":"token-1","expires_in":1}`},
			{status: http.StatusOK, body: `{"access_token":"token-2","expires_in":1}`},
		},
	}
	src, err := NewTokenSource(testConfig(t, fake))
	if err != nil {
		t.Fatalf("NewTokenSource: %v", err)
	}

	tok1, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	tok2, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok1 == tok2 {
		t.Errorf("both tokens were %q, want a refresh once within skew of expiry", tok1)
	}
	if fake.calls != 2 {
		t.Errorf("token endpoint called %d times, want 2", fake.calls)
	}
}

func TestTokenSource_SendsExpectedRequestShape(t *testing.T) {
	fake := &fakeTokenEndpoint{
		responses: []fakeTokenResponse{
			{status: http.StatusOK, body: `{"access_token":"token-1","expires_in":3600}`},
		},
	}
	cfg := testConfig(t, fake)
	src, err := NewTokenSource(cfg)
	if err != nil {
		t.Fatalf("NewTokenSource: %v", err)
	}
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}

	form := fake.capturedForms[0]
	if got := form["grant_type"]; len(got) != 1 || got[0] != "client_credentials" {
		t.Errorf("grant_type = %v, want [client_credentials]", got)
	}
	if got := form["client_assertion_type"]; len(got) != 1 || got[0] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type = %v, want the jwt-bearer urn", got)
	}
	wantScope := strings.Join(cfg.Scopes, " ")
	if got := form["scope"]; len(got) != 1 || got[0] != wantScope {
		t.Errorf("scope = %v, want [%v]", got, wantScope)
	}
	if got := form["client_assertion"]; len(got) != 1 || len(strings.Split(got[0], ".")) != 3 {
		t.Errorf("client_assertion = %v, want a 3-segment JWT", got)
	}
}

func TestTokenSource_ErrorResponseSurfacesOktaError(t *testing.T) {
	fake := &fakeTokenEndpoint{
		responses: []fakeTokenResponse{
			{status: http.StatusBadRequest, body: `{"error":"invalid_client","error_description":"client authentication failed"}`},
		},
	}
	src, err := NewTokenSource(testConfig(t, fake))
	if err != nil {
		t.Fatalf("NewTokenSource: %v", err)
	}

	_, err = src.Token(context.Background())
	if err == nil {
		t.Fatal("Token succeeded, want an error for a 400 response")
	}
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("error = %v, want it to surface Okta's error code", err)
	}
}

func TestNewTokenSource_RequiresFields(t *testing.T) {
	base := testConfig(t, &fakeTokenEndpoint{})

	cases := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"missing OrgURL", func(c *Config) { c.OrgURL = "" }},
		{"missing TokenPath", func(c *Config) { c.TokenPath = "" }},
		{"missing ClientID", func(c *Config) { c.ClientID = "" }},
		{"missing PrivateKey", func(c *Config) { c.PrivateKey = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if _, err := NewTokenSource(cfg); err == nil {
				t.Errorf("NewTokenSource with %s: want an error, got nil", tc.name)
			}
		})
	}
}

func decodeSegment(t *testing.T, seg string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decoding base64url segment: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("unmarshaling segment JSON: %v", err)
	}
	return v
}
