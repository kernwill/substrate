package aws

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// cloudTrailAuditRecordGeneration is the control assignment for whether
// a trail is actively logging and how completely it covers the
// account: base AU-12 (Audit Record Generation). KSI-MLA-LET and
// KSI-MLA-OSM (internal/rules/data/fedramp-consolidated-rules.json)
// both cite au-12, and the vendored dataset's own AU-12 override
// parameter (au-12_odp.01) reads "at least all information system and
// network components where audit capability is deployed/available" -
// IsMultiRegionTrail and IsOrganizationTrail are exactly that
// completeness claim, and IsLogging is whether audit record generation
// is actually happening at all, not merely configured.
//
// Local to this file rather than internal/frontend/controls: there is
// no Terraform-side (Declared) CloudTrail mapping yet to share this
// value with - this is the first CloudTrail control assignment in the
// codebase, not a second Basis for an already-reviewed one.
var cloudTrailAuditRecordGeneration = ir.Control{Family: "AU", Base: 12}

// cloudTrailLogFileValidation is the control assignment for whether log
// file integrity validation is enabled: base AU-9 (Protection of Audit
// Information). Log file validation is CloudTrail's own tamper-detection
// mechanism for the audit trail itself - digitally signed digest files
// that let a customer detect after-the-fact modification or deletion of
// delivered log files - which is squarely AU-9's subject (also cited by
// KSI-MLA-OSM). Base control, no enhancement: this collector does not
// determine whether validation failures are actually being checked
// (that is closer to AU-9's own monitoring intent than to a static
// enablement flag), so asserting an enhancement would claim more than
// this single boolean supports.
var cloudTrailLogFileValidation = ir.Control{Family: "AU", Base: 9}

// CloudTrailToIR converts g's trails into IR nodes: audit record
// generation (IsLogging plus multi-region/organization-trail scope,
// mapped to cloudTrailAuditRecordGeneration) and log file validation
// (mapped to cloudTrailLogFileValidation). A trail whose corresponding
// fact could not be resolved (Provenance.Confidence != Deterministic)
// produces no node for it, the same "never guess" treatment every other
// mapper in this codebase applies. Named CloudTrailToIR, not a second
// ToIR, matching IAMToIR's precedent for this package's second-and-later
// collectors (ToIR itself is already S3's, in ir.go).
//
// KMSKeyID and CloudWatchLogsLogGroupARN are deliberately not mapped
// here - see Trail's own doc comment (cloudtrail.go) for why.
func CloudTrailToIR(g *CloudTrailGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, t := range g.Trails {
		if node, ok := mapTrailAuditRecordGeneration(t); ok {
			out.Nodes = append(out.Nodes, node)
		}
		if node, ok := mapTrailLogFileValidation(t); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

func cloudTrailNodeID(trail, aspect string) ir.NodeID {
	return awsNodeID("cloudtrail", trail, aspect)
}

// mapTrailAuditRecordGeneration records whether t is actively logging
// and how completely it covers the account. Requires BOTH Config and
// Logging to be resolved: the control assignment's own rationale
// (cloudTrailAuditRecordGeneration) cites multi-region/organization
// scope together with active logging status as one claim about audit
// record generation, and a node missing either half would silently
// assert the unresolved one as if it were known.
func mapTrailAuditRecordGeneration(t Trail) (ir.Node, bool) {
	if t.Config == nil || t.Config.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}
	if t.Logging == nil || t.Logging.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}
	return ir.Node{
		ID:            cloudTrailNodeID(t.Name, "audit-record-generation"),
		ControlFamily: cloudTrailAuditRecordGeneration.Family,
		Controls:      []ir.Control{cloudTrailAuditRecordGeneration},
		Kind:          "cloudtrail_trail_audit_record_generation",
		Attributes: map[string]string{
			"is_logging":            strconv.FormatBool(t.Logging.IsLogging),
			"is_multi_region_trail": strconv.FormatBool(t.Config.IsMultiRegionTrail),
			"is_organization_trail": strconv.FormatBool(t.Config.IsOrganizationTrail),
		},
		Provenance:    t.Logging.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}

// mapTrailLogFileValidation records whether t has log file integrity
// validation enabled.
func mapTrailLogFileValidation(t Trail) (ir.Node, bool) {
	if t.Config == nil || t.Config.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}
	return ir.Node{
		ID:            cloudTrailNodeID(t.Name, "log-file-validation"),
		ControlFamily: cloudTrailLogFileValidation.Family,
		Controls:      []ir.Control{cloudTrailLogFileValidation},
		Kind:          "cloudtrail_trail_log_file_validation",
		Attributes: map[string]string{
			"log_file_validation_enabled": strconv.FormatBool(t.Config.LogFileValidationEnabled),
		},
		Provenance:    t.Config.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
