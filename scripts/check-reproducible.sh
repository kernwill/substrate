#!/usr/bin/env bash
# Reproducibility check: same input plus same engine version must produce
# byte-identical output. This is what lets an assessor re-run our work.
set -euo pipefail

FIXTURE="${1:-testdata/fixtures/minimal}"
OUT1=$(mktemp -d); OUT2=$(mktemp -d)
trap 'rm -rf "$OUT1" "$OUT2"' EXIT

./bin/substrate compile --source "$FIXTURE" --out "$OUT1" >/dev/null
sleep 1   # prove we are not accidentally embedding wall-clock time
./bin/substrate compile --source "$FIXTURE" --out "$OUT2" >/dev/null

if diff -r "$OUT1" "$OUT2" >/dev/null; then
  echo "reproducible ok"
else
  echo "REPRODUCIBILITY FAILURE: output differs between identical runs"
  diff -r "$OUT1" "$OUT2" || true
  exit 1
fi
