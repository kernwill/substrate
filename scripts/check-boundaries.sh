#!/usr/bin/env bash
# Architectural boundary enforcement.
#
# The three-stage compiler only works if framework-specific logic stays in
# backends. If this check fails, the fix is to move code, never to relax
# the check.
set -euo pipefail

MOD=$(head -1 go.mod | awk '{print $2}')
fail=0

check() {
  local from="$1" to="$2" why="$3"
  if grep -rn --include="*.go" "\"${MOD}/${to}" "${from}" 2>/dev/null | grep -v "_test.go" ; then
    echo "BOUNDARY VIOLATION: ${from} imports ${to}"
    echo "  ${why}"
    fail=1
  fi
}

check "internal/frontend" "internal/backends" "Framework logic must live in backends only."
check "internal/ir"       "internal/backends" "The IR is framework-agnostic by definition."
check "internal/ir"       "internal/frontend" "The IR consumes facts through interfaces, not concrete parsers."

# No framework vocabulary in the IR. If 'KSI' appears in the IR, the design has failed.
if grep -rniE --include="*.go" "\b(ksi|fedramp|cmmc|pci[-_ ]?dss)\b" internal/ir 2>/dev/null; then
  echo "BOUNDARY VIOLATION: framework vocabulary found in internal/ir"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "See CLAUDE.md, section 'Architectural invariants'."
  exit 1
fi
echo "boundaries ok"
