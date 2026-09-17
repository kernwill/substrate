package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/kernwill/substrate/internal/provenance"
)

// IAMCollectorVersion is this file's own collector version (FR-4.1),
// independent of S3CollectorVersion and the overall binary version.
const IAMCollectorVersion = "aws-iam/v0.1.0"

// IAMAPI names only the IAM operations this file's collector calls. See
// this package's doc.go for why this is a narrow, hand-written interface
// rather than the full *iam.Client (FR-3.10's fixture-based testing).
type IAMAPI interface {
	ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	GetLoginProfile(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
	ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
}

// IAMUser is one collected IAM user. ConsolePassword, MFADevices, and
// AccessKeys are never nil - see Bucket's doc comment (s3.go) for why
// this package always records a fact, resolved or not, rather than
// dropping a field it couldn't resolve.
//
// Roles and policies (also named in FR-3.1) are not collected here.
// Scoped to users/MFA/access-key-age for this first pass, the same
// incremental scoping this package's S3 collector used (encryption and
// public access block first, logging collected but unmapped, nothing
// about lifecycle rules or replication attempted at all) - enumerating
// and evaluating role trust policies and attached permissions is a
// substantially different, larger problem worth its own collector.
type IAMUser struct {
	Name            string           `json:"name"`
	ConsolePassword *ConsolePassword `json:"console_password"`
	MFADevices      *MFADevices      `json:"mfa_devices"`
	AccessKeys      *AccessKeys      `json:"access_keys"`
}

// ConsolePassword is whether a user has ever had a console login
// profile - GetLoginProfile's own documented NoSuchEntity error is a
// real, resolved "no" here, not treated as unresolved: unlike
// s3.go's GetPublicAccessBlock nuance, this absence is exactly what
// AWS's own API contract documents it to mean, not an ambiguous partial
// signal that depends on some other, uncollected setting.
type ConsolePassword struct {
	Enabled    bool              `json:"enabled"`
	Provenance provenance.Record `json:"provenance"`
}

// MFADevices is how many MFA devices a user has enrolled. Enrollment (a
// non-zero count) is the measurement; whether zero counts as a compliance
// gap depends on whether the user even has a console password to begin
// with (ConsolePassword), which is exactly the kind of multi-field
// judgment a backend predicate makes, not this collector.
type MFADevices struct {
	Count      int               `json:"count"`
	Provenance provenance.Record `json:"provenance"`
}

// AccessKeys is one user's access keys and their ages as of when this
// collector ran. Keys is meaningful only when Provenance.Confidence is
// Deterministic - an empty Keys slice is ambiguous between "this user
// genuinely has none" and "the API call failed," which is exactly why
// the resolved/unresolved signal lives on this wrapping struct's own
// Provenance rather than being inferred from Keys being empty.
type AccessKeys struct {
	Keys       []AccessKey       `json:"keys"`
	Provenance provenance.Record `json:"provenance"`
}

// AccessKey is one access key's status and age, in days, as of the
// collector's observation time.
type AccessKey struct {
	Active  bool `json:"active"`
	AgeDays int  `json:"age_days"`
}

// IAMGraph is every IAM user this collector found in one account pass,
// per FR-3.1.
type IAMGraph struct {
	Users []IAMUser `json:"users"`
}

// CollectIAM lists every IAM user visible to client and reads their
// console login profile, MFA devices, and access keys, up to
// maxConcurrentItems at a time (collectConcurrent, concurrent.go).
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp
// and used to compute each access key's age - see CollectS3's doc
// comment (s3.go) for why this package never calls time.Now() itself.
func CollectIAM(ctx context.Context, client IAMAPI, observedAt time.Time) (*IAMGraph, error) {
	names, err := listIAMUserNames(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("aws: iam: list users: %w", err)
	}
	users, err := collectConcurrent(ctx, names, func(ctx context.Context, name string) IAMUser {
		return IAMUser{
			Name:            name,
			ConsolePassword: collectConsolePassword(ctx, client, name, observedAt),
			MFADevices:      collectMFADevices(ctx, client, name, observedAt),
			AccessKeys:      collectAccessKeys(ctx, client, name, observedAt),
		}
	})
	if err != nil {
		return nil, fmt.Errorf("aws: iam: collect users: %w", err)
	}
	return &IAMGraph{Users: users}, nil
}

// listIAMUserNames pages through every user in the account, sorted for
// the same reproducibility reasons listBucketNames documents (s3.go).
func listIAMUserNames(ctx context.Context, client IAMAPI) ([]string, error) {
	paginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	var names []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range page.Users {
			if u.UserName == nil {
				continue
			}
			names = append(names, *u.UserName)
		}
	}
	sort.Strings(names)
	return names, nil
}

// iamRecord and iamUnresolvedRecord are thin wrappers around this
// package's shared observedRecord/unresolvedRecord (provenance.go) - see
// s3.go's s3Record/s3UnresolvedRecord for the same pattern and why it
// exists (a duplicated-literal risk /code-review caught once this
// package grew a second collector).
func iamRecord(user, api string, observedAt time.Time) provenance.Record {
	return observedRecord(IAMCollectorVersion, api, map[string]string{"user": user}, observedAt)
}

func iamUnresolvedRecord(user, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(IAMCollectorVersion, api, reason, map[string]string{"user": user}, observedAt)
}

// collectConsolePassword reads whether user has a console login profile.
// GetLoginProfile's documented behavior on a user with none is a
// NoSuchEntity error (types.NoSuchEntityException) - a real, resolved
// "no console password," not an unresolved outcome. Any other error
// (permissions, throttling) is genuinely unresolved.
func collectConsolePassword(ctx context.Context, client IAMAPI, user string, observedAt time.Time) *ConsolePassword {
	const api = "iam:GetLoginProfile"
	_, err := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: &user})
	if err == nil {
		return &ConsolePassword{Enabled: true, Provenance: iamRecord(user, api, observedAt)}
	}
	var noSuchEntity *types.NoSuchEntityException
	if errors.As(err, &noSuchEntity) {
		return &ConsolePassword{Enabled: false, Provenance: iamRecord(user, api, observedAt)}
	}
	return &ConsolePassword{Provenance: iamUnresolvedRecord(user, api, err.Error(), observedAt)}
}

// collectMFADevices counts user's enrolled MFA devices. Unlike
// GetLoginProfile, ListMFADevices does not error for zero devices - it
// returns a successful, empty page - so a real API error is the only
// unresolved case here.
func collectMFADevices(ctx context.Context, client IAMAPI, user string, observedAt time.Time) *MFADevices {
	const api = "iam:ListMFADevices"
	paginator := iam.NewListMFADevicesPaginator(client, &iam.ListMFADevicesInput{UserName: &user})
	count := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return &MFADevices{Provenance: iamUnresolvedRecord(user, api, err.Error(), observedAt)}
		}
		count += len(page.MFADevices)
	}
	return &MFADevices{Count: count, Provenance: iamRecord(user, api, observedAt)}
}

// collectAccessKeys lists user's access keys and computes each one's age
// in whole days as of observedAt. A key with no CreateDate in the
// response (undocumented by AWS as a possible shape, but not type-system
// impossible - AccessKeyMetadata.CreateDate is a plain pointer, and
// expected to never actually happen in practice against a real account)
// makes the WHOLE result Unresolved, rather than silently dropping just
// that one key from an otherwise-Deterministic Keys list: a partial
// result with no signal that anything was omitted is exactly the
// "byte-identical to a bucket/user that was never queried at all" fail-
// silent outcome CollectS3's own doc comment (s3.go) already rules out
// for its per-field API failures, applied here to a per-item response
// anomaly instead of a whole-call error.
func collectAccessKeys(ctx context.Context, client IAMAPI, user string, observedAt time.Time) *AccessKeys {
	const api = "iam:ListAccessKeys"
	paginator := iam.NewListAccessKeysPaginator(client, &iam.ListAccessKeysInput{UserName: &user})
	var keys []AccessKey
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return &AccessKeys{Provenance: iamUnresolvedRecord(user, api, err.Error(), observedAt)}
		}
		for _, k := range page.AccessKeyMetadata {
			if k.CreateDate == nil {
				return &AccessKeys{Provenance: iamUnresolvedRecord(user, api, "response included an access key with no create date", observedAt)}
			}
			keys = append(keys, AccessKey{
				Active:  k.Status == types.StatusTypeActive,
				AgeDays: int(observedAt.Sub(*k.CreateDate).Hours() / 24),
			})
		}
	}
	return &AccessKeys{Keys: keys, Provenance: iamRecord(user, api, observedAt)}
}
