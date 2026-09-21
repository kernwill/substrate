package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// fakeKMS implements KMSAPI by serving canned data loaded from this
// package's testdata fixtures (FR-3.10) instead of calling AWS.
type fakeKMS struct {
	keys map[string]struct {
		ARN             string
		KeyManager      string
		KeyState        string
		RotationEnabled bool
		RotationError   string
		DescribeError   string
	}
}

func loadFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	var raw map[string]struct {
		ARN             string `json:"arn"`
		KeyManager      string `json:"key_manager"`
		KeyState        string `json:"key_state"`
		RotationEnabled bool   `json:"rotation_enabled"`
		RotationError   string `json:"rotation_error"`
		DescribeError   string `json:"describe_error"`
	}
	readTestdataJSON(t, "kms_keys.json", &raw)

	f := &fakeKMS{keys: make(map[string]struct {
		ARN             string
		KeyManager      string
		KeyState        string
		RotationEnabled bool
		RotationError   string
		DescribeError   string
	}, len(raw))}
	for k, v := range raw {
		f.keys[k] = struct {
			ARN             string
			KeyManager      string
			KeyState        string
			RotationEnabled bool
			RotationError   string
			DescribeError   string
		}{v.ARN, v.KeyManager, v.KeyState, v.RotationEnabled, v.RotationError, v.DescribeError}
	}
	return f
}

func (f *fakeKMS) ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	var entries []types.KeyListEntry
	for id := range f.keys {
		id := id
		entries = append(entries, types.KeyListEntry{KeyId: &id})
	}
	return &kms.ListKeysOutput{Keys: entries}, nil
}

func (f *fakeKMS) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	k, ok := f.keys[*params.KeyId]
	if !ok {
		return nil, errors.New("fakeKMS: no fixture registered for key " + *params.KeyId)
	}
	if k.DescribeError != "" {
		return nil, errors.New(k.DescribeError)
	}
	manager := types.KeyManagerTypeCustomer
	if k.KeyManager == "AWS" {
		manager = types.KeyManagerTypeAws
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{
		KeyId:      params.KeyId,
		Arn:        strPtr(k.ARN),
		KeyManager: manager,
		KeyState:   types.KeyState(k.KeyState),
	}}, nil
}

func (f *fakeKMS) GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	k, ok := f.keys[*params.KeyId]
	if !ok {
		return nil, errors.New("fakeKMS: no fixture registered for key " + *params.KeyId)
	}
	if k.RotationError != "" {
		return nil, errors.New(k.RotationError)
	}
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: k.RotationEnabled}, nil
}

func TestCollectKMS(t *testing.T) {
	client := loadFakeKMS(t)
	graph, err := CollectKMS(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectKMS: %v", err)
	}

	// key-aws-managed excluded entirely; key-describe-error dropped at
	// the metadata stage (no fact at all); key-customer-rotated,
	// key-customer-not-rotated, and key-customer-error all produce a
	// Key (the last one Unresolved) -> 3 entries.
	if len(graph.Keys) != 3 {
		t.Fatalf("got %d keys, want 3 (aws-managed excluded, describe-error dropped)", len(graph.Keys))
	}

	byID := make(map[string]Key, len(graph.Keys))
	for _, k := range graph.Keys {
		byID[k.KeyID] = k
	}

	if _, ok := byID["key-aws-managed"]; ok {
		t.Error("key-aws-managed present in output, want it excluded entirely (not customer-managed)")
	}
	if _, ok := byID["key-describe-error"]; ok {
		t.Error("key-describe-error present in output, want it dropped (DescribeKey itself failed)")
	}

	rotated := byID["key-customer-rotated"]
	if rotated.Provenance.Confidence != "deterministic" {
		t.Fatalf("key-customer-rotated.Provenance.Confidence = %v, want deterministic", rotated.Provenance.Confidence)
	}
	if !rotated.RotationStatusResolved || !rotated.RotationEnabled {
		t.Errorf("key-customer-rotated = %+v, want RotationStatusResolved=true RotationEnabled=true", rotated)
	}

	notRotated := byID["key-customer-not-rotated"]
	if !notRotated.RotationStatusResolved || notRotated.RotationEnabled {
		t.Errorf("key-customer-not-rotated = %+v, want RotationStatusResolved=true RotationEnabled=false (a resolved false, not an absence)", notRotated)
	}

	errKey := byID["key-customer-error"]
	if errKey.Provenance.Confidence != "unresolved" {
		t.Fatalf("key-customer-error.Provenance.Confidence = %v, want unresolved", errKey.Provenance.Confidence)
	}
	if errKey.Provenance.UnresolvedReason == "" {
		t.Error("key-customer-error.Provenance.UnresolvedReason is empty")
	}
}

func TestCollectKMSSortedByID(t *testing.T) {
	client := loadFakeKMS(t)
	graph, err := CollectKMS(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectKMS: %v", err)
	}
	for i := 1; i < len(graph.Keys); i++ {
		if graph.Keys[i-1].KeyID >= graph.Keys[i].KeyID {
			t.Fatalf("keys not sorted: %q >= %q", graph.Keys[i-1].KeyID, graph.Keys[i].KeyID)
		}
	}
}
