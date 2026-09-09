#!/usr/bin/env bash
# Architectural boundary enforcement.
#
# The three-stage compiler only works if framework-specific logic stays in
# backends. If this check fails, the fix is to move code, never to relax
# the check.
#
# A line may opt out of the vocabulary check with the marker:
#     substrate:allow-vocab
# Use it only in documentation that must name the forbidden terms.
set -euo pipefail

MOD=$(head -1 go.mod | awk '{print $2}')
fail=0

check() {
  local from="$1" to="$2" why="$3"
  if grep -rn --include="*.go" "\"${MOD}/${to}" "${from}" 2>/dev/null | grep -v "_test.go"; then
    echo "BOUNDARY VIOLATION: ${from} imports ${to}"
    echo "  ${why}"
    fail=1
  fi
}

check "internal/frontend"   "internal/backends" "Framework logic must live in backends only."
check "internal/ir"         "internal/backends" "The IR is framework-agnostic by definition."
check "internal/ir"         "internal/frontend" "The IR consumes facts through interfaces, not concrete parsers."
# internal/provenance is a transitive dependency of internal/ir (Node and
# Edge embed provenance.Record) - the same two invariants above apply to
# it one hop out, or a violation there would reach the IR anyway without
# either check above ever seeing it.
check "internal/provenance" "internal/backends" "Provenance is shared by frontend and ir; it must stay framework-agnostic too."
check "internal/provenance" "internal/frontend" "Provenance must not depend on the collectors that produce it."

if grep -rniE --include="*.go" "\b(ksi|fedramp|cmmc|pci[-_ ]?dss)\b" internal/ir internal/provenance 2>/dev/null \
   | grep -v 'substrate:allow-vocab'; then
  echo "BOUNDARY VIOLATION: framework vocabulary found in internal/ir or internal/provenance"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "See CLAUDE.md, section 'Architectural invariants'."
  exit 1
fi
echo "boundaries ok"
