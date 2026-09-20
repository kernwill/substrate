package okta

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthCollectorVersion is this file's own collector version (FR-4.1),
// independent of the eventual per-capability collector versions (MFA
// enforcement, session policy, and so on) - see aws.IAMCollectorVersion
// for the same per-file versioning convention.
const AuthCollectorVersion = "okta-auth/v0.1.0"

// assertionLifetime is how long a signed JWT client assertion is valid
// for before Okta's token endpoint rejects it. Okta accepts up to one
// hour; this package uses a much shorter window because the assertion
// is single-use (minted fresh for every token exchange, never reused)
// and a short exp bounds the damage of a signed-but-unsent assertion
// leaking somehow (e.g. into a log line a future bug writes).
const assertionLifetime = 5 * time.Minute

// tokenRefreshSkew is how far before a cached access token's actual
// expiry this package treats it as already expired and re-exchanges it.
// A collection run making several sequential API calls must not have
// one succeed and the next fail because the token expired mid-run.
const tokenRefreshSkew = 30 * time.Second

// Config is everything needed to authenticate to one Okta org via
// docs/adr/0015's private-key-JWT client-credentials flow. This package
// never constructs or stores these values itself; production callers
// build a Config from whatever the customer provisioned (see this
// package's doc.go) and pass it in.
type Config struct {
	// OrgURL is the customer's Okta org base URL, e.g.
	// "https://example.okta.com" - no path, no trailing slash.
	OrgURL string
	// TokenPath is the token endpoint's path, appended to OrgURL. Okta
	// orgs vary between "/oauth2/v1/token" (org authorization server)
	// and "/oauth2/<authServerId>/v1/token" (a custom authorization
	// server) - which one a given customer's API Services app is
	// registered against is a setup-time fact, not something this
	// package guesses.
	TokenPath string
	// ClientID is the API Services app's client ID. Used as both the
	// OAuth client_id and the JWT assertion's iss/sub claims per the
	// private-key-JWT spec (RFC 7523).
	ClientID string
	// PrivateKey signs the JWT client assertion. Never logged, never
	// serialized by this package, never round-tripped through
	// provenance - credential material must never reach a Locator or
	// an UnresolvedReason string the way a raw API error's text does
	// (see aws.unresolvedRecord's doc comment for that precedent).
	PrivateKey *rsa.PrivateKey
	// KeyID is the optional "kid" header identifying which public key
	// (of possibly several registered on the API Services app) signed
	// the assertion. Omit if the app has exactly one key registered.
	KeyID string
	// Scopes are the OAuth scopes requested, space-joined into the
	// token request. Set per collector by the production wiring code
	// that constructs a Config - this package doesn't hardcode a
	// scope list, since which scopes are needed depends on which
	// FR-3.9 sub-collectors (MFA, session policy, logs, role
	// assignments) are actually being run.
	Scopes []string
	// HTTPClient makes the token-exchange HTTP call. Defaults to
	// http.DefaultClient if nil - unlike PrivateKey, this is
	// transport plumbing, not customer credential material, so a
	// default is safe to provide.
	HTTPClient httpDoer
}

// httpDoer names only the one method this package's HTTP calls need,
// the same narrow-interface pattern aws.S3API uses for the AWS SDK -
// satisfied structurally by *http.Client with no adapter code, and by a
// fake in this package's tests.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// TokenSource exchanges a Config's private key for short-lived OAuth
// access tokens and caches the result until it's close to expiry. One
// TokenSource is safe for concurrent use by multiple collectors sharing
// a single Okta org connection.
type TokenSource struct {
	cfg Config

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewTokenSource builds a TokenSource from cfg, defaulting HTTPClient to
// http.DefaultClient if unset. It performs no network call itself -
// the first token exchange happens lazily on the first Token call.
func NewTokenSource(cfg Config) (*TokenSource, error) {
	if cfg.OrgURL == "" {
		return nil, errors.New("okta: Config.OrgURL is required")
	}
	if cfg.TokenPath == "" {
		return nil, errors.New("okta: Config.TokenPath is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("okta: Config.ClientID is required")
	}
	if cfg.PrivateKey == nil {
		return nil, errors.New("okta: Config.PrivateKey is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	return &TokenSource{cfg: cfg}, nil
}

// Token returns a valid bearer access token, exchanging a fresh one if
// none is cached or the cached one is within tokenRefreshSkew of
// expiring.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Add(tokenRefreshSkew).Before(s.expiresAt) {
		return s.token, nil
	}

	token, expiresIn, err := exchangeToken(ctx, s.cfg)
	if err != nil {
		return "", err
	}
	s.token = token
	s.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return s.token, nil
}

// tokenResponse is the subset of Okta's token endpoint response this
// package needs. Okta's actual response includes token_type and scope
// too; they're not consumed here so they're deliberately left out
// rather than modeled and ignored.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// exchangeToken performs one private-key-JWT client-credentials token
// exchange (RFC 7523 / RFC 6749 section 4.4), split out from
// TokenSource.Token so it has no lock or cache state to fake in tests -
// just a Config in, a token and lifetime out.
func exchangeToken(ctx context.Context, cfg Config) (token string, expiresIn int64, err error) {
	assertion, err := buildClientAssertion(cfg)
	if err != nil {
		return "", 0, fmt.Errorf("okta: building client assertion: %w", err)
	}

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {strings.Join(cfg.Scopes, " ")},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}

	tokenURL := strings.TrimRight(cfg.OrgURL, "/") + cfg.TokenPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("okta: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("okta: token request: %w", err)
	}
	defer resp.Body.Close()

	var body tokenResponse
	if decodeErr := json.NewDecoder(resp.Body).Decode(&body); decodeErr != nil {
		return "", 0, fmt.Errorf("okta: decoding token response (status %d): %w", resp.StatusCode, decodeErr)
	}

	if resp.StatusCode != http.StatusOK {
		if body.Error != "" {
			return "", 0, fmt.Errorf("okta: token endpoint returned %d: %s: %s", resp.StatusCode, body.Error, body.ErrorDesc)
		}
		return "", 0, fmt.Errorf("okta: token endpoint returned %d", resp.StatusCode)
	}
	if body.AccessToken == "" {
		return "", 0, errors.New("okta: token endpoint response had no access_token")
	}
	return body.AccessToken, body.ExpiresIn, nil
}

// buildClientAssertion signs a JWT per RFC 7523 section 3: iss and sub
// both set to the client ID (this app authenticates as itself, not on
// behalf of a user), aud set to the token endpoint, a short exp, and a
// random jti so Okta can reject a replayed assertion.
func buildClientAssertion(cfg Config) (string, error) {
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}
	if cfg.KeyID != "" {
		header["kid"] = cfg.KeyID
	}

	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("generating jti: %w", err)
	}

	now := time.Now()
	tokenURL := strings.TrimRight(cfg.OrgURL, "/") + cfg.TokenPath
	claims := map[string]any{
		"iss": cfg.ClientID,
		"sub": cfg.ClientID,
		"aud": tokenURL,
		"iat": now.Unix(),
		"exp": now.Add(assertionLifetime).Unix(),
		"jti": jti,
	}

	headerSeg, err := encodeSegment(header)
	if err != nil {
		return "", fmt.Errorf("encoding header: %w", err)
	}
	claimsSeg, err := encodeSegment(claims)
	if err != nil {
		return "", fmt.Errorf("encoding claims: %w", err)
	}

	signingInput := headerSeg + "." + claimsSeg
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, cfg.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing assertion: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func encodeSegment(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
