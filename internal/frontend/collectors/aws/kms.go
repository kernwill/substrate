package aws

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/kernwill/substrate/internal/provenance"
)

// KMSCollectorVersion is this file's own collector version (FR-4.1),
// independent of every other collector version in this package.
const KMSCollectorVersion = "aws-kms/v0.1.0"

// KMSAPI names only the KMS operations this file's collector calls. See
// this package's doc.go for why this is a narrow, hand-written
// interface rather than the full *kms.Client (FR-3.10's fixture-based
// testing).
type KMSAPI interface {
	ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// Key is one collected customer-managed KMS key - FR-3.3's rotation
// half specifically (key policy documents are a separate, larger
// follow-on this collector does not attempt yet: a real JSON policy
// needs actual policy-evaluation logic to be a meaningful compliance
// fact, not just a status flag, the same "defer the complex data
// model" call security groups made for IPv6/cross-group references).
//
// AWS-managed keys (KeyManager AWS, e.g. the default aws/s3, aws/rds
// service keys) are deliberately excluded entirely, not collected with
// Present:false or any other placeholder - their rotation is not
// customer-configurable at all (KMS always rotates them yearly,
// unconditionally), so including them would only add non-actionable
// "always true" noise to the evidence graph, not a real customer
// decision this control cares about.
//
// RotationEnabled is only meaningful when RotationStatusResolved is
// true. Rather than pre-filtering by key spec/usage to guess which key
// types support rotation (asymmetric, HMAC, imported-material, and
// custom-key-store keys don't) - a list that could be incomplete or
// drift from AWS's own - this collector always calls
// GetKeyRotationStatus and records whatever the live API says,
// including a real failure, rather than assuming a key's eligibility
// from its own static attributes.
type Key struct {
	KeyID                  string `json:"key_id"`
	Arn                    string `json:"arn"`
	KeyState               string `json:"key_state"`
	RotationStatusResolved bool   `json:"rotation_status_resolved"`
	RotationEnabled        bool   `json:"rotation_enabled"`

	Provenance provenance.Record `json:"provenance"`
}

// KMSGraph is every customer-managed KMS key found in the account/
// Region the caller's client is configured for.
type KMSGraph struct {
	Keys []Key `json:"keys"`
}

// CollectKMS lists every KMS key in the caller's account/Region, reads
// each one's metadata to filter to customer-managed keys only, then
// reads each customer-managed key's live rotation status - the same
// list-then-per-item-fan-out shape aws.CollectIAM uses for AWS users.
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// never derived from time.Now() here, matching every other collector in
// this package (FR-5.3).
func CollectKMS(ctx context.Context, client KMSAPI, observedAt time.Time) (*KMSGraph, error) {
	ids, err := listKeyIDs(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("aws: kms: list keys: %w", err)
	}

	metadata, err := collectConcurrent(ctx, ids, func(ctx context.Context, id string) *types.KeyMetadata {
		return describeKey(ctx, client, id)
	})
	if err != nil {
		return nil, fmt.Errorf("aws: kms: describe keys: %w", err)
	}

	var customerManagedIDs []string
	byID := make(map[string]*types.KeyMetadata, len(ids))
	for i, id := range ids {
		if metadata[i] == nil {
			continue
		}
		byID[id] = metadata[i]
		if metadata[i].KeyManager == types.KeyManagerTypeCustomer {
			customerManagedIDs = append(customerManagedIDs, id)
		}
	}

	rotationStatuses, err := collectConcurrent(ctx, customerManagedIDs, func(ctx context.Context, id string) Key {
		return buildKey(ctx, client, id, byID[id], observedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("aws: kms: collect rotation status: %w", err)
	}

	sort.Slice(rotationStatuses, func(i, j int) bool { return rotationStatuses[i].KeyID < rotationStatuses[j].KeyID })
	return &KMSGraph{Keys: rotationStatuses}, nil
}

// listKeyIDs pages through every key ID in the account/Region, sorted
// for the same reproducibility reasons listBucketNames documents
// (s3.go).
func listKeyIDs(ctx context.Context, client KMSAPI) ([]string, error) {
	paginator := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
	var ids []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, k := range page.Keys {
			if k.KeyId == nil {
				continue
			}
			ids = append(ids, *k.KeyId)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// describeKey reads one key's metadata (KeyManager, KeyState, Arn).
// Returns nil on a real API failure - DescribeKey failing for a key
// ListKeys just returned is unexpected enough (a permissions gap, or
// the key was deleted in the window between the two calls) that this
// collector drops the key from consideration entirely rather than
// guess its KeyManager; a dropped key produces no fact at all, the same
// "never guess" treatment every other mapper in this codebase applies,
// just at the metadata-lookup stage instead of the mapping stage.
func describeKey(ctx context.Context, client KMSAPI, id string) *types.KeyMetadata {
	out, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &id})
	if err != nil || out.KeyMetadata == nil {
		return nil
	}
	return out.KeyMetadata
}

// buildKey reads id's live rotation status and combines it with the
// metadata already resolved by describeKey. A GetKeyRotationStatus
// failure is genuinely unresolved - unlike KeyManager filtering above,
// this collector does not pre-guess which key specs support rotation
// (see Key's own doc comment), so a failure here could mean "this key
// type doesn't support rotation" or a real API problem, and this
// collector honestly can't tell those apart from the error alone.
func buildKey(ctx context.Context, client KMSAPI, id string, meta *types.KeyMetadata, observedAt time.Time) Key {
	const api = "kms:GetKeyRotationStatus"
	base := Key{KeyID: id, Arn: valueOrEmpty(meta.Arn), KeyState: string(meta.KeyState)}

	out, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: &id})
	if err != nil {
		base.Provenance = kmsUnresolvedRecord(id, api, err.Error(), observedAt)
		return base
	}

	base.RotationStatusResolved = true
	base.RotationEnabled = out.KeyRotationEnabled
	base.Provenance = kmsRecord(id, api, observedAt)
	return base
}

// kmsRecord and kmsUnresolvedRecord are thin wrappers around this
// package's shared observedRecord/unresolvedRecord (provenance.go),
// fixing this file's own collector version - same pattern as
// securityGroupRecord/guardDutyRecord.
func kmsRecord(keyID, api string, observedAt time.Time) provenance.Record {
	return observedRecord(KMSCollectorVersion, api, map[string]string{"key_id": keyID}, observedAt)
}

func kmsUnresolvedRecord(keyID, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(KMSCollectorVersion, api, reason, map[string]string{"key_id": keyID}, observedAt)
}
