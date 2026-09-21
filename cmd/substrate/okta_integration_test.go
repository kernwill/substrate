package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awscollectors "github.com/kernwill/substrate/internal/frontend/collectors/aws"
	oktacollectors "github.com/kernwill/substrate/internal/frontend/collectors/okta"

	"github.com/kernwill/substrate/internal/backends/fedramp20x"
)

// TestOktaEvidenceFlowsThroughRealCompile is the strongest verification
// available without a live Okta org (docs/okta-api-scopes.md's own
// still-open item, and the phase-1 backend state this session's memory
// tracks): it drives the real okta.TokenSource/RESTClient HTTP path -
// private-key-JWT signing, token exchange, and all four collection
// calls - against a fake Okta org (an httptest.Server implementing the
// same REST surface a real org exposes), writes the result through the
// real writeCollectOutput, then runs the real substrate compile
// --runtime pipeline against it twice (with and without the Okta
// runtime directory) and diffs a real KSI Rego evaluation's output
// between the two runs.
//
// The diff, not mere IR-node presence, is what actually proves this:
// TestCompileIngestsOktaRuntimeEvidence (compile_test.go) already
// confirms nodes.jsonl contains the right nodes using synthetic Go
// structs, bypassing HTTP/auth entirely. This test additionally proves
// (a) the real auth/HTTP client code this package never otherwise
// exercises actually works against something Okta-shaped, and (b) the
// new evidence is genuinely consumed by rego/ksi/iam's real evaluation
// logic - an indicator's "missing controls" list actually shrinks -
// not just that a node with the right control ID happens to exist
// somewhere in the graph.
func TestOktaEvidenceFlowsThroughRealCompile(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	server := httptest.NewServer(fakeOktaOrgHandler(t))
	defer server.Close()

	tokenSource, err := oktacollectors.NewTokenSource(oktacollectors.Config{
		OrgURL:     server.URL,
		TokenPath:  "/oauth2/v1/token",
		ClientID:   "test-client",
		PrivateKey: privateKey,
		Scopes:     oktaScopes,
	})
	if err != nil {
		t.Fatalf("NewTokenSource: %v", err)
	}
	client := oktacollectors.NewRESTClient(server.URL, tokenSource, nil)

	ctx := context.Background()
	observedAt := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

	mfaGraph, err := oktacollectors.CollectMFAEnrollmentPolicies(ctx, client, observedAt)
	if err != nil {
		t.Fatalf("CollectMFAEnrollmentPolicies against fake org: %v", err)
	}
	sessionGraph, err := oktacollectors.CollectSessionPolicies(ctx, client, observedAt)
	if err != nil {
		t.Fatalf("CollectSessionPolicies against fake org: %v", err)
	}
	provisioningGraph, err := oktacollectors.CollectProvisioningEvents(ctx, client, observedAt, observedAt.Add(-7*24*time.Hour), observedAt)
	if err != nil {
		t.Fatalf("CollectProvisioningEvents against fake org: %v", err)
	}
	adminRoleGraph, err := oktacollectors.CollectAdminRoleAssignments(ctx, client, observedAt)
	if err != nil {
		t.Fatalf("CollectAdminRoleAssignments against fake org: %v", err)
	}
	if len(mfaGraph.Policies) == 0 || len(sessionGraph.Rules) == 0 || len(provisioningGraph.Events) == 0 || len(adminRoleGraph.Users) == 0 {
		t.Fatalf("fake org returned no data for one or more collectors: mfa=%d session=%d provisioning=%d adminrole=%d",
			len(mfaGraph.Policies), len(sessionGraph.Rules), len(provisioningGraph.Events), len(adminRoleGraph.Users))
	}

	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	okta := &oktaResults{MFA: mfaGraph, SessionPolicy: sessionGraph, Provisioning: provisioningGraph, AdminRole: adminRoleGraph}
	if _, err := writeCollectOutput(runtimeDir, &awscollectors.S3Graph{}, &awscollectors.IAMGraph{}, &awscollectors.CloudTrailGraph{}, &awscollectors.SecurityGroupsGraph{}, &awscollectors.SubnetsGraph{}, &awscollectors.GuardDutyGraph{}, &awscollectors.ConfigGraph{}, okta); err != nil {
		t.Fatalf("writeCollectOutput: %v", err)
	}

	beforeOut := filepath.Join(t.TempDir(), "before")
	var stdout, stderr bytes.Buffer
	if code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", beforeOut}, &stdout, &stderr); code != 0 {
		t.Fatalf("runCompile (before) exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	before := readKSIResults(t, beforeOut)

	afterOut := filepath.Join(t.TempDir(), "after")
	stdout.Reset()
	stderr.Reset()
	if code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", afterOut, "--runtime", runtimeDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("runCompile (after) exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	after := readKSIResults(t, afterOut)

	// KSI-IAM-ELP references both ia-2 (MFA enrollment) and ac-12
	// (session policy) - see internal/rules/data/fedramp-consolidated-rules.json.
	elpBefore := findIndicatorOrFail(t, before, "KSI-IAM-ELP")
	elpAfter := findIndicatorOrFail(t, after, "KSI-IAM-ELP")
	assertControlMissingBecomesResolved(t, "KSI-IAM-ELP", "ia-2 (mfa enrollment)", "ia-2", elpBefore.Reason, elpAfter.Reason)
	assertControlMissingBecomesResolved(t, "KSI-IAM-ELP", "ac-12 (session policy)", "ac-12", elpBefore.Reason, elpAfter.Reason)

	// KSI-IAM-JIT references both ac-2.4 (provisioning events) and
	// ac-6.5 (admin role assignments).
	jitBefore := findIndicatorOrFail(t, before, "KSI-IAM-JIT")
	jitAfter := findIndicatorOrFail(t, after, "KSI-IAM-JIT")
	assertControlMissingBecomesResolved(t, "KSI-IAM-JIT", "ac-2.4 (provisioning events)", "ac-2.4", jitBefore.Reason, jitAfter.Reason)
	assertControlMissingBecomesResolved(t, "KSI-IAM-JIT", "ac-6.5 (admin role assignments)", "ac-6.5", jitBefore.Reason, jitAfter.Reason)
}

// assertControlMissingBecomesResolved is the shared shape of this
// test's four checks: control must be named as missing in beforeReason
// (rego/ksi/iam's undetermined "reason" text, "missing IR evidence for
// control(s): [...]" - a sanity check that the diff is meaningful at
// all; if it were already resolved by some other frontend, the "after"
// side proving nothing would go unnoticed) and must NOT be named as
// missing in afterReason.
func assertControlMissingBecomesResolved(t *testing.T, indicator, label, control, beforeReason, afterReason string) {
	t.Helper()
	if !strings.Contains(beforeReason, control) {
		t.Errorf("%s: before ingesting okta evidence, reason = %q, want it to still list %s (%s) as missing - otherwise this check proves nothing", indicator, beforeReason, control, label)
	}
	if strings.Contains(afterReason, control) {
		t.Errorf("%s: after ingesting okta evidence, reason = %q, still lists %s (%s) as missing", indicator, afterReason, control, label)
	}
}

func readKSIResults(t *testing.T, outDir string) []fedramp20x.IndicatorResult {
	t.Helper()
	results, err := readArtifact[[]fedramp20x.IndicatorResult](filepath.Join(outDir, "ksi_results.json"))
	if err != nil {
		t.Fatalf("read ksi_results.json: %v", err)
	}
	return *results
}

func findIndicatorOrFail(t *testing.T, results []fedramp20x.IndicatorResult, id string) fedramp20x.IndicatorResult {
	t.Helper()
	for _, r := range results {
		if r.Indicator == id {
			return r
		}
	}
	t.Fatalf("no result for indicator %s", id)
	return fedramp20x.IndicatorResult{}
}

// fakeOktaOrgHandler implements just enough of Okta's REST surface for
// okta.RESTClient's four collection calls (plus the token endpoint) to
// succeed against something structurally real - real HTTP, real JSON,
// real query-string filtering by policy type - rather than a Go struct
// substrate's own collectors never actually parse over the wire. It is
// not a claim that this matches every real Okta org's exact response
// shape in full (see docs/okta-api-scopes.md's still-open item on that);
// it is deliberately the minimum needed to prove this package's own
// client code against a real HTTP round trip.
func fakeOktaOrgHandler(t *testing.T) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /oauth2/v1/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("fake okta org: parse token request form: %v", err)
		}
		if got := r.PostForm.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			t.Errorf("fake okta org: client_assertion_type = %q, want the jwt-bearer urn", got)
		}
		writeFakeOktaResponse(t, w, map[string]any{"access_token": "fake-access-token", "expires_in": 3600})
	})

	mux.HandleFunc("GET /api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("type") {
		case "MFA_ENROLL":
			writeFakeOktaResponse(t, w, []map[string]any{
				{
					"id": "policy-1", "name": "Default MFA Policy", "status": "ACTIVE", "priority": 1,
					"settings": map[string]any{
						"factors": map[string]any{
							"okta_verify": map[string]any{"enroll": map[string]any{"self": "REQUIRED"}},
						},
					},
				},
			})
		case "OKTA_SIGN_ON":
			writeFakeOktaResponse(t, w, []map[string]any{
				{"id": "policy-2", "name": "Default Sign-On Policy", "status": "ACTIVE", "priority": 1, "settings": map[string]any{}},
			})
		default:
			http.Error(w, "unexpected policy type", http.StatusBadRequest)
		}
	})

	mux.HandleFunc("GET /api/v1/policies/{id}/rules", func(w http.ResponseWriter, r *http.Request) {
		writeFakeOktaResponse(t, w, []map[string]any{
			{
				"id": "rule-1", "name": "Default Rule", "status": "ACTIVE", "priority": 1,
				"actions": map[string]any{
					"signon": map[string]any{
						"session": map[string]any{
							"maxSessionIdleMinutes":     120,
							"maxSessionLifetimeMinutes": 720,
							"usePersistentCookie":       false,
						},
					},
				},
			},
		})
	})

	mux.HandleFunc("GET /api/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		writeFakeOktaResponse(t, w, []map[string]any{
			{
				"uuid": "evt-1", "published": "2026-09-20T12:00:00.000Z", "eventType": "user.lifecycle.deactivate",
				"outcome": map[string]any{"result": "SUCCESS"},
				"actor":   map[string]any{"id": "actor-1", "type": "System", "displayName": "Okta Workflows"},
				"target":  []map[string]any{{"id": "user-1", "type": "User", "displayName": "Departed Employee"}},
			},
		})
	})

	mux.HandleFunc("GET /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		writeFakeOktaResponse(t, w, []map[string]any{
			{"id": "user-1", "status": "ACTIVE", "profile": map[string]any{"login": "user1@example.com"}},
		})
	})

	mux.HandleFunc("GET /api/v1/users/{id}/roles", func(w http.ResponseWriter, r *http.Request) {
		writeFakeOktaResponse(t, w, []map[string]any{
			{"id": "role-1", "type": "SUPER_ADMIN", "label": "Super Administrator", "status": "ACTIVE"},
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("fake okta org: unexpected request %s %s", r.Method, r.URL.String())
		http.NotFound(w, r)
	})

	return mux
}

// writeFakeOktaResponse is this file's own JSON writer, not the
// package-level writeJSON (jsonutil.go) - that one targets io.Writer
// with indentation tuned for on-disk artifacts; this one only needs to
// hand a fake HTTP response back and fail the test loudly if encoding
// somehow breaks.
func writeFakeOktaResponse(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("fake okta org: encode response: %v", err)
	}
}
