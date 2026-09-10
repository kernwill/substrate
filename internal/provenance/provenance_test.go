package provenance

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func validRecord() Record {
	return Record{
		SourceType:       "terraform",
		Locator:          Locator{Path: "main.tf", Line: 12},
		Timestamp:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		CollectorVersion: "v0.1.0",
		Basis:            Declared,
		Confidence:       Deterministic,
	}
}

func TestRecordValidateAcceptsWellFormedDeterministicRecord(t *testing.T) {
	if err := validRecord().Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestRecordValidateAcceptsLiveAPIRecord(t *testing.T) {
	r := validRecord()
	r.SourceType = "aws_iam_api"
	r.Locator = Locator{API: "iam:GetAccountPasswordPolicy"}
	r.Basis = Observed
	if err := r.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestRecordValidateAcceptsUnresolvedWithReason(t *testing.T) {
	r := validRecord()
	r.Confidence = Unresolved
	r.UnresolvedReason = "variable interpolated from an unresolvable remote module input"
	if err := r.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestRecordValidateRejectsMissingSourceType(t *testing.T) {
	r := validRecord()
	r.SourceType = ""
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing source_type")
	}
}

func TestRecordValidateRejectsEmptyLocator(t *testing.T) {
	r := validRecord()
	r.Locator = Locator{}
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error for a locator with neither path nor api")
	}
}

func TestRecordValidateRejectsLocatorWithBothPathAndAPI(t *testing.T) {
	r := validRecord()
	r.Locator = Locator{Path: "main.tf", API: "iam:GetAccountPasswordPolicy"}
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error for a locator setting both path and api")
	}
}

func TestRecordValidateRejectsZeroTimestamp(t *testing.T) {
	r := validRecord()
	r.Timestamp = time.Time{}
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error for zero timestamp")
	}
}

// TestRecordValidateRejectsNonUTCTimestamp is a regression test for a gap
// the code review's ultra pass found: Validate checked only that
// Timestamp was non-zero, never that it was actually UTC, despite the
// field's own doc comment claiming "Always UTC, so two collectors in
// different time zones produce byte-identical output for the same
// underlying instant." A timestamp fixed to a non-UTC location - even one
// at the same offset, like a fixed +00:00 zone instead of Z - marshals to
// a different string ("+00:00" instead of "Z"), which would silently
// break that reproducibility guarantee.
func TestRecordValidateRejectsNonUTCTimestamp(t *testing.T) {
	r := validRecord()
	r.Timestamp = r.Timestamp.In(time.FixedZone("", 0))
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error for a timestamp not in time.UTC")
	}

	r2 := validRecord()
	r2.Timestamp = r2.Timestamp.In(time.FixedZone("EST", -5*60*60))
	if err := r2.Validate(); err == nil {
		t.Error("Validate() = nil, want error for a timestamp in a non-UTC zone")
	}
}

func TestRecordValidateRejectsMissingCollectorVersion(t *testing.T) {
	r := validRecord()
	r.CollectorVersion = ""
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing collector_version")
	}
}

func TestRecordValidateRejectsInvalidBasis(t *testing.T) {
	r := validRecord()
	r.Basis = "guessed"
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error for invalid basis")
	}
}

func TestRecordValidateRejectsInvalidConfidence(t *testing.T) {
	r := validRecord()
	r.Confidence = "pretty_sure"
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error for invalid confidence")
	}
}

func TestRecordValidateRejectsUnresolvedWithoutReason(t *testing.T) {
	r := validRecord()
	r.Confidence = Unresolved
	r.UnresolvedReason = ""
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error: unresolved confidence requires a reason")
	}
}

func TestRecordValidateRejectsReasonOnResolvedFact(t *testing.T) {
	r := validRecord()
	r.Confidence = Deterministic
	r.UnresolvedReason = "should not be set"
	if err := r.Validate(); err == nil {
		t.Error("Validate() = nil, want error: unresolved_reason set on a non-unresolved fact")
	}
}

func TestRecordJSONRoundTrip(t *testing.T) {
	want := validRecord()
	want.Locator.Parameters = map[string]string{"region": "us-gov-west-1"}

	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Record
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !got.Timestamp.Equal(want.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, want.Timestamp)
	}
	got.Timestamp = want.Timestamp // time.Time equality via reflect.DeepEqual is representation-sensitive; already checked above
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

// TestRecordJSONIsByteReproducible backs this package's "no wall-clock
// time in output" reproducibility contract: marshaling the exact same
// Record value twice - including its Timestamp, which is data about the
// fact, not about when the test ran - must produce byte-identical JSON.
func TestRecordJSONIsByteReproducible(t *testing.T) {
	r := validRecord()
	a, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("two marshals of the same Record differ:\n%s\n%s", a, b)
	}
}
