#!/bin/sh
# Build the image, run the sample IIS logs, assert the 3 expected hits. Usage: sh tests/check.sh
set -e
cd "$(dirname "$0")/.."
docker build -q -t zircolite-iis . >/dev/null
out="$PWD/tests/out"; rm -rf "$out"; mkdir -p "$out"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/tests/logs:/logs:ro" -v "$PWD/tests/rules:/rules:ro" -v "$out:/out" \
  zircolite-iis -q >/dev/null 2>&1
lines=$(docker run --rm -v "$out:/out:ro" --entrypoint python3 zircolite-iis -c \
  'import json; print(sorted(m["SourceLine"] for r in json.load(open("/out/detected.json")) for m in r["matches"]))')
[ "$lines" = "[5, 12, 13]" ] && echo "PASS: hits on lines $lines" || { echo "FAIL: got $lines (want [5, 12, 13])"; exit 1; }
