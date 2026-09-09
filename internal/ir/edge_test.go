package ir

import "testing"

func validEdge(from, to NodeID) Edge {
	return Edge{
		From:          from,
		To:            to,
		Relationship:  "attached_to",
		Provenance:    validProvenance(),
		SchemaVersion: SchemaVersion,
	}
}

func TestEdgeValidateAcceptsWellFormedEdge(t *testing.T) {
	if err := validEdge("n1", "n2").Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestEdgeValidateRejectsMissingFrom(t *testing.T) {
	e := validEdge("n1", "n2")
	e.From = ""
	if err := e.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing from")
	}
}

func TestEdgeValidateRejectsMissingTo(t *testing.T) {
	e := validEdge("n1", "n2")
	e.To = ""
	if err := e.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing to")
	}
}

func TestEdgeValidateRejectsMissingRelationship(t *testing.T) {
	e := validEdge("n1", "n2")
	e.Relationship = ""
	if err := e.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing relationship")
	}
}

func TestEdgeValidateRejectsMissingSchemaVersion(t *testing.T) {
	e := validEdge("n1", "n2")
	e.SchemaVersion = ""
	if err := e.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing schema_version")
	}
}

func TestEdgeValidatePropagatesInvalidProvenance(t *testing.T) {
	e := validEdge("n1", "n2")
	e.Provenance.CollectorVersion = ""
	if err := e.Validate(); err == nil {
		t.Error("Validate() = nil, want error propagated from an invalid Provenance")
	}
}
