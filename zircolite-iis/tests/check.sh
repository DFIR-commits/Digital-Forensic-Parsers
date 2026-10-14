#!/bin/sh
# Build the image, run tests/logs (IIS + EVTX) and assert the expected hits. Usage: sh tests/check.sh
set -e
cd "$(dirname "$0")/.."
docker build -q -t zircolite-iis . >/dev/null
out="$PWD/tests/out"; rm -rf "$out"; mkdir -p "$out"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/tests/logs:/logs:ro" -v "$PWD/tests/rules:/rules:ro" -v "$out:/out" \
  zircolite-iis -q >/dev/null 2>&1
got=$(docker run --rm -v "$out:/out:ro" --entrypoint python3 zircolite-iis -c '
import json
iis = sorted(m["SourceLine"] for r in json.load(open("/out/detected.json")) for m in r["matches"])
evtx = sorted(r["title"] for r in json.load(open("/out/detected_evtx.json")))
print(iis, evtx)')
! grep -E "ERROR|WARNING" "$out"/zircolite*.log || { echo "FAIL: errors in zircolite logs"; exit 1; }
want="[5, 12, 13] ['File Download Via Bitsadmin - Sysmon']"
[ "$got" = "$want" ] && echo "PASS: $got" || { echo "FAIL: got $got (want $want)"; exit 1; }
