"""Run Zircolite on IIS W3C logs and EVTX files.

Container entrypoint: converts every W3C file under /logs to JSON lines (one output file
per log, converted in parallel) and runs Zircolite with the rules in /rules
(-> /out/detected.json). Separate files let Zircolite scan them in parallel too: it only
parallelises across files, so one merged file would run on a single core. .evtx files under /logs
go to Zircolite as they are, with its bundled SigmaHQ Windows ruleset or $EVTX_RULES
(-> /out/detected_evtx.json). Extra arguments are passed to both runs unchanged.

- Every #Fields: line is honoured (IIS rewrites it on restart and the set can change).
- cs(Header) becomes the Sigma webserver name: cs(Cookie) -> cs-cookie.
- Zircolite strips '-' from field names, while Sigma rules keep it (cs-uri-stem), so
  each field seen is mapped to itself in a copy of Zircolite's config.
- Each event gets `timestamp` (date + time, UTC as IIS logs it), SourceFile, SourceLine.
"""
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import yaml

ZIRCOLITE = "/opt/zircolite"
EVENTS = os.environ.get("EVENTS", "/tmp/events")  # a directory; -e EVENTS=/out/events keeps it
CONFIG = "/tmp/config.yaml"


def sigma_name(field):
    # cs(User-Agent) -> cs-user-agent, cs(Cookie) -> cs-cookie
    if "(" in field and field.endswith(")"):
        prefix, header = field[:-1].split("(", 1)
        return f"{prefix}-{header}".lower()
    return field


def convert(job):
    """One W3C log -> one JSON-lines file. Returns (events, field names seen)."""
    path, dest = job
    fields, n, seen = None, 0, set()
    with open(path, encoding="utf-8", errors="replace") as f, open(dest, "w", encoding="utf-8") as out:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\r\n")
            if line.startswith("#Fields:"):
                fields = [sigma_name(x) for x in line[8:].split()]
                seen.update(fields)
            elif line and not line.startswith("#") and fields:
                values = line.split(" ")
                if len(values) != len(fields):
                    print(f"[!] {path}:{lineno}: {len(values)} values for {len(fields)} fields, skipped", file=sys.stderr)
                    continue
                event = dict(zip(fields, values))
                if "date" in event and "time" in event:
                    event["timestamp"] = f"{event['date']}T{event['time']}Z"
                event["SourceFile"] = str(path)
                event["SourceLine"] = lineno
                out.write(json.dumps(event, separators=(",", ":")) + "\n")
                n += 1
    if not n:
        os.remove(dest)
    return n, seen


def write_config(seen):
    with open(f"{ZIRCOLITE}/config/config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    config["mappings"].update({name: name for name in seen if not name.isalnum()})
    # transforms_dir is relative to the config file, and this copy lives in /tmp
    config["transforms_dir"] = f"{ZIRCOLITE}/config/transforms/"
    with open(CONFIG, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f)


def zircolite(*args):
    return subprocess.run(["python3", "zircolite.py", *args, *sys.argv[1:]], cwd=ZIRCOLITE).returncode


def main():
    src = Path(os.environ.get("LOGS", "/logs"))
    files = sorted(p for p in src.rglob("*") if p.is_file()) if src.is_dir() else [src]
    evtx = [p for p in files if p.suffix.lower() == ".evtx"]
    logs = [p for p in files if p not in evtx]
    shutil.rmtree(EVENTS, ignore_errors=True)
    os.makedirs(EVENTS)
    # numbered names: IIS reuses file names (u_ex261001.log) across sites and hosts
    jobs = [(p, f"{EVENTS}/{i:06d}_{p.name}.json") for i, p in enumerate(logs)]
    seen, total, w3c, skipped = set(), 0, 0, []
    with ProcessPoolExecutor(int(os.environ.get("WORKERS", 0)) or None) as pool:
        for p, (n, fields) in zip(logs, pool.map(convert, jobs, chunksize=4)):
            seen |= fields
            total += n
            w3c += n > 0
            if not n:
                skipped.append(p)
    print(f"[+] {total} IIS events from {w3c} W3C file(s), {len(evtx)} EVTX file(s)", file=sys.stderr)
    if skipped:
        print(f"[!] {len(skipped)} file(s) are neither W3C nor .evtx and were skipped: "
              + ", ".join(map(str, skipped[:5])) + (" ..." if len(skipped) > 5 else ""), file=sys.stderr)
    if not total and not evtx:
        sys.exit("[-] no W3C or EVTX logs found under " + str(src))

    rc = 0
    if total:
        write_config(seen)
        rc |= zircolite("-e", EVENTS, "--json-input", "-f", "json", "-c", CONFIG, "-r", "/rules",
                        "-o", "/out/detected.json", "-l", "/out/zircolite.log")
    if evtx:
        rc |= zircolite("-e", str(src), "-r", os.environ.get("EVTX_RULES", "rules/rules_windows_merged.json"),
                        "-o", "/out/detected_evtx.json", "-l", "/out/zircolite_evtx.log")
    sys.exit(rc)


if __name__ == "__main__":
    main()
