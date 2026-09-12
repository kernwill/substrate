package kubernetes

import (
	"fmt"
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
)

// ToIR converts g's resources into IR nodes, using a small, explicit,
// human-reviewed table of which Kubernetes object fields evidence which
// NIST 800-53 controls - see this file's mapping functions for the
// reasoning behind each one. An object whose Kind (or whose relevant
// fields) has no reviewed entry produces no node at all - this package
// never guesses a control family nobody has reviewed, the same
// principle internal/frontend/terraform's ir.go applies.
//
// A mapping function decides only WHICH CONTROL a field is ABOUT, never
// whether its value represents good or bad security posture - it
// records the value found, verbatim, as the node's measurement
// (FR-5.9). Whether a given value counts as the control being
// satisfied is a backend predicate.
//
// There are no edges: this package does not model cross-object
// references (RBAC bindings, secret mounts) yet - see doc.go.
func ToIR(g *ResourceGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, r := range g.Resources {
		nodes, err := mapResource(r)
		if err != nil {
			return ir.Graph{}, fmt.Errorf("kubernetes: map %s to IR: %w", r.Address, err)
		}
		out.Nodes = append(out.Nodes, nodes...)
	}
	return out, nil
}

func mapResource(r Resource) ([]ir.Node, error) {
	switch r.Address.Kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		return mapPodSecurityContext(r)
	case "NetworkPolicy":
		return mapNetworkPolicyDefaultDeny(r)
	default:
		return nil, nil
	}
}

// mapPodSecurityContext maps a pod template's securityContext, and each
// container's own securityContext, to CM-7 (Least Functionality) -
// matching the crosswalk analysis' own row 25 ("least functionality,
// unnecessary services disabled"). Pod-level and container-level
// settings are recorded as separate nodes (one node per container,
// since a Deployment can have several), since each is independently
// meaningful evidence and a Deployment's container count varies.
func mapPodSecurityContext(r Resource) ([]ir.Node, error) {
	podSpec, ok := podSpecOf(r.Attributes)
	if !ok {
		return nil, nil
	}

	var nodes []ir.Node
	if podSC, ok := asMap(podSpec["securityContext"]); ok {
		if attrs := flattenToStrings("", podSC); len(attrs) > 0 {
			nodes = append(nodes, ir.Node{
				ID:            nodeID(r.Address, "pod-security-context"),
				ControlFamily: "CM",
				Controls:      []ir.Control{{Family: "CM", Base: 7}},
				Kind:          "pod_security_context",
				Attributes:    attrs,
				Provenance:    r.Provenance,
				SchemaVersion: ir.SchemaVersion,
			})
		}
	}

	containers, _ := podSpec["containers"].([]any)
	for i, c := range containers {
		container, ok := asMap(c)
		if !ok {
			continue
		}
		containerSC, ok := asMap(container["securityContext"])
		if !ok {
			continue
		}
		attrs := flattenToStrings("", containerSC)
		if len(attrs) == 0 {
			continue
		}
		if name, ok := container["name"].(string); ok {
			attrs["container_name"] = name
		}
		nodes = append(nodes, ir.Node{
			ID:            nodeID(r.Address, fmt.Sprintf("container-security-context[%d]", i)),
			ControlFamily: "CM",
			Controls:      []ir.Control{{Family: "CM", Base: 7}},
			Kind:          "container_security_context",
			Attributes:    attrs,
			Provenance:    r.Provenance,
			SchemaVersion: ir.SchemaVersion,
		})
	}
	return nodes, nil
}

// mapNetworkPolicyDefaultDeny maps a NetworkPolicy to SC-7(5) (Boundary
// Protection - Deny by Default), specifically when it declares both
// Ingress and Egress policy types with no rules of either kind -
// Kubernetes' default-deny idiom. This includes a spec that spells the
// empty rule list out explicitly ("ingress: []"), not just one that
// omits the field entirely - see hasRules. A NetworkPolicy that lists
// actual allow rules is a different posture (allow-by-exception, which
// is real but not yet distinguished from "well-scoped" here) and is
// left unmapped rather than guessed at.
func mapNetworkPolicyDefaultDeny(r Resource) ([]ir.Node, error) {
	spec, ok := asMap(r.Attributes["spec"])
	if !ok {
		return nil, nil
	}
	policyTypes, _ := spec["policyTypes"].([]any)
	hasIngressType, hasEgressType := false, false
	for _, pt := range policyTypes {
		switch pt {
		case "Ingress":
			hasIngressType = true
		case "Egress":
			hasEgressType = true
		}
	}
	if !hasIngressType || !hasEgressType || hasRules(spec["ingress"]) || hasRules(spec["egress"]) {
		return nil, nil
	}

	attrs := flattenToStrings("policy_types", policyTypes)
	return []ir.Node{{
		ID:            nodeID(r.Address, "default-deny"),
		ControlFamily: "SC",
		Controls:      []ir.Control{{Family: "SC", Base: 7, Enhancement: 5}},
		Kind:          "network_policy_default_deny",
		Attributes:    attrs,
		Provenance:    r.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}}, nil
}

// hasRules reports whether v - a NetworkPolicy spec's "ingress" or
// "egress" field, decoded from YAML - actually lists any rule.
//
// Checking the field's mere presence in the map (an earlier version of
// mapNetworkPolicyDefaultDeny did exactly that: `_, ok := spec["ingress"]`)
// is not the same question: an explicit "ingress: []" - still valid,
// still the more auditable way to spell default-deny - decodes to a
// present key holding an empty slice, and mere-presence would wrongly
// disqualify it from the exact posture this mapper exists to recognize.
func hasRules(v any) bool {
	list, ok := v.([]any)
	return ok && len(list) > 0
}

func nodeID(addr ResourceAddress, suffix string) ir.NodeID {
	return ir.NodeID(fmt.Sprintf("kubernetes:%s#%s", addr.String(), suffix))
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// podSpecOf navigates a Deployment/StatefulSet/DaemonSet's common shape
// down to its pod template spec (spec.template.spec).
func podSpecOf(attrs map[string]any) (map[string]any, bool) {
	spec, ok := asMap(attrs["spec"])
	if !ok {
		return nil, false
	}
	template, ok := asMap(spec["template"])
	if !ok {
		return nil, false
	}
	return asMap(template["spec"])
}

// flattenToStrings converts a nested YAML-decoded value (map[string]any,
// []any, or a scalar) into the flat string map ir.Node.Attributes
// requires (FR-5.9), dot-joining nested keys and bracket-indexing list
// elements, e.g. {"a": {"b": true}} at prefix "" becomes {"a.b": "true"}.
func flattenToStrings(prefix string, v any) map[string]string {
	out := make(map[string]string)
	flattenInto(prefix, v, out)
	return out
}

func flattenInto(prefix string, v any, out map[string]string) {
	switch val := v.(type) {
	case map[string]any:
		for k, vv := range val {
			flattenInto(joinPath(prefix, k), vv, out)
		}
	case []any:
		for i, vv := range val {
			flattenInto(fmt.Sprintf("%s[%d]", prefix, i), vv, out)
		}
	case string:
		out[prefix] = val
	case bool:
		out[prefix] = strconv.FormatBool(val)
	case int:
		out[prefix] = strconv.Itoa(val)
	case float64:
		out[prefix] = strconv.FormatFloat(val, 'f', -1, 64)
	case nil:
		// Nothing to measure; omit rather than record an empty string.
	default:
		out[prefix] = fmt.Sprintf("%v", val)
	}
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}
