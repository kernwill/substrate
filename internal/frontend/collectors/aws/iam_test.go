package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/kernwill/substrate/internal/provenance"
)

// fakeIAM implements IAMAPI by serving canned data loaded from this
// package's testdata fixtures (FR-3.10) instead of calling AWS.
type fakeIAM struct {
	userNames     []string
	loginProfiles map[string]struct {
		HasProfile bool
		Err        string
	}
	mfaDevices map[string]struct {
		Count int
		Err   string
	}
	accessKeys map[string]struct {
		Keys []struct {
			Active     bool
			CreateDate time.Time
		}
		Err string
	}
}

func loadFakeIAM(t *testing.T) *fakeIAM {
	t.Helper()
	readJSON := func(name string, v any) { readTestdataJSON(t, name, v) }

	f := &fakeIAM{}
	readJSON("iam_users.json", &f.userNames)

	var loginRaw map[string]struct {
		HasProfile bool   `json:"has_profile"`
		Error      string `json:"error"`
	}
	readJSON("iam_login_profiles.json", &loginRaw)
	f.loginProfiles = make(map[string]struct {
		HasProfile bool
		Err        string
	}, len(loginRaw))
	for k, v := range loginRaw {
		f.loginProfiles[k] = struct {
			HasProfile bool
			Err        string
		}{v.HasProfile, v.Error}
	}

	var mfaRaw map[string]struct {
		Count int    `json:"count"`
		Error string `json:"error"`
	}
	readJSON("iam_mfa_devices.json", &mfaRaw)
	f.mfaDevices = make(map[string]struct {
		Count int
		Err   string
	}, len(mfaRaw))
	for k, v := range mfaRaw {
		f.mfaDevices[k] = struct {
			Count int
			Err   string
		}{v.Count, v.Error}
	}

	var keysRaw map[string]struct {
		Keys []struct {
			Active     bool      `json:"active"`
			CreateDate time.Time `json:"create_date"`
		} `json:"keys"`
		Error string `json:"error"`
	}
	readJSON("iam_access_keys.json", &keysRaw)
	f.accessKeys = make(map[string]struct {
		Keys []struct {
			Active     bool
			CreateDate time.Time
		}
		Err string
	}, len(keysRaw))
	for k, v := range keysRaw {
		var keys []struct {
			Active     bool
			CreateDate time.Time
		}
		for _, kk := range v.Keys {
			keys = append(keys, struct {
				Active     bool
				CreateDate time.Time
			}{kk.Active, kk.CreateDate})
		}
		f.accessKeys[k] = struct {
			Keys []struct {
				Active     bool
				CreateDate time.Time
			}
			Err string
		}{keys, v.Error}
	}

	return f
}

func (f *fakeIAM) ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	out := &iam.ListUsersOutput{}
	for _, name := range f.userNames {
		n := name
		out.Users = append(out.Users, types.User{UserName: &n})
	}
	return out, nil
}

func (f *fakeIAM) GetLoginProfile(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	p, ok := f.loginProfiles[*params.UserName]
	if !ok {
		return nil, &types.NoSuchEntityException{}
	}
	if p.Err != "" {
		return nil, errors.New(p.Err)
	}
	if !p.HasProfile {
		return nil, &types.NoSuchEntityException{}
	}
	return &iam.GetLoginProfileOutput{}, nil
}

func (f *fakeIAM) ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	m, ok := f.mfaDevices[*params.UserName]
	if !ok {
		return &iam.ListMFADevicesOutput{}, nil
	}
	if m.Err != "" {
		return nil, errors.New(m.Err)
	}
	out := &iam.ListMFADevicesOutput{}
	for i := 0; i < m.Count; i++ {
		out.MFADevices = append(out.MFADevices, types.MFADevice{})
	}
	return out, nil
}

func (f *fakeIAM) ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	a, ok := f.accessKeys[*params.UserName]
	if !ok {
		return &iam.ListAccessKeysOutput{}, nil
	}
	if a.Err != "" {
		return nil, errors.New(a.Err)
	}
	out := &iam.ListAccessKeysOutput{}
	for _, k := range a.Keys {
		status := types.StatusTypeInactive
		if k.Active {
			status = types.StatusTypeActive
		}
		createDate := k.CreateDate
		out.AccessKeyMetadata = append(out.AccessKeyMetadata, types.AccessKeyMetadata{
			Status:     status,
			CreateDate: &createDate,
		})
	}
	return out, nil
}

// nilCreateDateIAM is a minimal IAMAPI whose ListAccessKeys returns one
// access key with no CreateDate - a shape AWS's own SDK type allows
// (AccessKeyMetadata.CreateDate is a plain pointer) but does not
// document as ever actually happening. Only ListAccessKeys is exercised
// by TestCollectAccessKeysUnresolvedOnMissingCreateDate below; the other
// three methods panic if ever called, so an accidental broadening of
// that test fails loudly rather than silently calling into a stub.
type nilCreateDateIAM struct{}

func (nilCreateDateIAM) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	panic("nilCreateDateIAM: ListUsers not implemented")
}

func (nilCreateDateIAM) GetLoginProfile(context.Context, *iam.GetLoginProfileInput, ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	panic("nilCreateDateIAM: GetLoginProfile not implemented")
}

func (nilCreateDateIAM) ListMFADevices(context.Context, *iam.ListMFADevicesInput, ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	panic("nilCreateDateIAM: ListMFADevices not implemented")
}

func (nilCreateDateIAM) ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: []types.AccessKeyMetadata{
			{Status: types.StatusTypeActive, CreateDate: nil},
		},
	}, nil
}

// TestCollectAccessKeysUnresolvedOnMissingCreateDate is a regression
// test: an earlier version of collectAccessKeys silently dropped a key
// with no CreateDate from Keys while still reporting the overall result
// as Deterministic - undercounting a user's real key inventory with no
// signal anything was omitted. If this ever happens against a real
// account, the whole result must come back Unresolved instead.
func TestCollectAccessKeysUnresolvedOnMissingCreateDate(t *testing.T) {
	got := collectAccessKeys(context.Background(), nilCreateDateIAM{}, "someone", testObservedAt)
	if got.Provenance.Confidence != provenance.Unresolved {
		t.Fatalf("Provenance.Confidence = %q, want %q", got.Provenance.Confidence, provenance.Unresolved)
	}
	if got.Provenance.UnresolvedReason == "" {
		t.Error("Provenance.UnresolvedReason is empty")
	}
	if len(got.Keys) != 0 {
		t.Errorf("Keys = %v, want empty (the whole result is Unresolved, not partially populated)", got.Keys)
	}
}

func TestCollectIAM(t *testing.T) {
	client := loadFakeIAM(t)
	graph, err := CollectIAM(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectIAM: %v", err)
	}
	if len(graph.Users) != 5 {
		t.Fatalf("got %d users, want 5", len(graph.Users))
	}

	byName := make(map[string]IAMUser, len(graph.Users))
	for _, u := range graph.Users {
		byName[u.Name] = u
	}

	alice := byName["alice"]
	if alice.ConsolePassword == nil || !alice.ConsolePassword.Enabled || alice.ConsolePassword.Provenance.Confidence != provenance.Deterministic {
		t.Errorf("alice.ConsolePassword = %+v, want enabled and resolved", alice.ConsolePassword)
	}
	if alice.MFADevices == nil || alice.MFADevices.Count != 2 {
		t.Errorf("alice.MFADevices = %+v, want count 2", alice.MFADevices)
	}
	if alice.AccessKeys == nil || alice.AccessKeys.Provenance.Confidence != provenance.Deterministic || len(alice.AccessKeys.Keys) != 1 {
		t.Fatalf("alice.AccessKeys = %+v, want 1 resolved key", alice.AccessKeys)
	}
	wantAliceAge := int(testObservedAt.Sub(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)).Hours() / 24)
	if got := alice.AccessKeys.Keys[0]; !got.Active || got.AgeDays != wantAliceAge {
		t.Errorf("alice access key = %+v, want active with age %d", got, wantAliceAge)
	}

	bob := byName["bob"]
	if bob.MFADevices == nil || bob.MFADevices.Count != 0 || bob.MFADevices.Provenance.Confidence != provenance.Deterministic {
		t.Errorf("bob.MFADevices = %+v, want a resolved zero count (has console password but no MFA)", bob.MFADevices)
	}
	if bob.AccessKeys == nil || len(bob.AccessKeys.Keys) != 2 {
		t.Fatalf("bob.AccessKeys = %+v, want 2 keys", bob.AccessKeys)
	}
	activeCount := 0
	for _, k := range bob.AccessKeys.Keys {
		if k.Active {
			activeCount++
		}
	}
	if activeCount != 1 {
		t.Errorf("bob has %d active keys, want 1", activeCount)
	}

	carol := byName["carol"]
	if carol.ConsolePassword == nil || carol.ConsolePassword.Enabled || carol.ConsolePassword.Provenance.Confidence != provenance.Deterministic {
		t.Errorf("carol.ConsolePassword = %+v, want a resolved 'no profile' fact (NoSuchEntity is documented, not unresolved)", carol.ConsolePassword)
	}
	if carol.MFADevices == nil || carol.MFADevices.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("carol.MFADevices = %+v, want Unresolved (simulated API error)", carol.MFADevices)
	}
	if carol.AccessKeys == nil || carol.AccessKeys.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("carol.AccessKeys = %+v, want Unresolved (simulated API error)", carol.AccessKeys)
	}

	dave := byName["dave"]
	if dave.ConsolePassword == nil || dave.ConsolePassword.Enabled {
		t.Errorf("dave.ConsolePassword = %+v, want resolved false", dave.ConsolePassword)
	}
	if dave.AccessKeys == nil || dave.AccessKeys.Provenance.Confidence != provenance.Deterministic || len(dave.AccessKeys.Keys) != 0 {
		t.Errorf("dave.AccessKeys = %+v, want a resolved, empty key list", dave.AccessKeys)
	}

	erin := byName["erin"]
	if erin.ConsolePassword == nil || erin.ConsolePassword.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("erin.ConsolePassword = %+v, want Unresolved (simulated non-NoSuchEntity error)", erin.ConsolePassword)
	}
	if erin.ConsolePassword != nil && erin.ConsolePassword.Provenance.UnresolvedReason == "" {
		t.Error("erin.ConsolePassword.Provenance.UnresolvedReason is empty")
	}
}

// TestCollectIAMEveryFieldNonNil mirrors TestCollectS3EveryFieldNonNil
// (s3_test.go): no user's ConsolePassword/MFADevices/AccessKeys is ever a
// bare nil, even when every underlying call fails.
func TestCollectIAMEveryFieldNonNil(t *testing.T) {
	client := loadFakeIAM(t)
	graph, err := CollectIAM(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectIAM: %v", err)
	}
	for _, u := range graph.Users {
		if u.ConsolePassword == nil {
			t.Errorf("%s.ConsolePassword is nil, want a non-nil fact", u.Name)
		}
		if u.MFADevices == nil {
			t.Errorf("%s.MFADevices is nil, want a non-nil fact", u.Name)
		}
		if u.AccessKeys == nil {
			t.Errorf("%s.AccessKeys is nil, want a non-nil fact", u.Name)
		}
	}
}

func TestCollectIAMUsersSortedByName(t *testing.T) {
	client := loadFakeIAM(t)
	graph, err := CollectIAM(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectIAM: %v", err)
	}
	for i := 1; i < len(graph.Users); i++ {
		if graph.Users[i-1].Name >= graph.Users[i].Name {
			t.Fatalf("users not sorted: %q >= %q", graph.Users[i-1].Name, graph.Users[i].Name)
		}
	}
}
