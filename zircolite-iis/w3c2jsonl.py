"""Run Zircolite on IIS W3C logs.

Container entrypoint: converts every W3C file under /logs to JSON lines, then runs
Zircolite with the rules in /rules and writes results to /out. Extra arguments are
passed to Zircolite unchanged.

- Every #Fields: line is honoured (IIS rewrites it on restart and the set can change).
- cs(Header) becomes the Sigma webserver name: cs(Cookie) -> cs-cookie.
- Zircolite strips '-' from field names, while Sigma rules keep it (cs-uri-stem), so
  each field seen is mapped to itself in a copy of Zircolite's config.
- Each event gets `timestamp` (date + time, UTC as IIS logs it), SourceFile, SourceLine.
"""
import json
import os
import sys
from pathlib import Path

import yaml

ZIRCOLITE = "/opt/zircolite"
EVENTS = os.environ.get("EVENTS", "/tmp/events.json")  # -e EVENTS=/out/events.json keeps it
CONFIG = "/tmp/config.yaml"


def sigma_name(field):
    # cs(User-Agent) -> cs-user-agent, cs(Cookie) -> cs-cookie
    if "(" in field and field.endswith(")"):
        prefix, header = field[:-1].split("(", 1)
        return f"{prefix}-{header}".lower()
    return field


def convert(path, out, seen):
    fields, n = None, 0
    with open(path, encoding="utf-8", errors="replace") as f:
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
                out.write(json.dumps(event) + "\n")
                n += 1
    return n


def write_config(seen):
    with open(f"{ZIRCOLITE}/config/config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    config["mappings"].update({name: name for name in seen if not name.isalnum()})
    # transforms_dir is relative to the config file, and this copy lives in /tmp
    config["transforms_dir"] = f"{ZIRCOLITE}/config/transforms/"
    with open(CONFIG, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f)


def main():
    src = Path(os.environ.get("LOGS", "/logs"))
    files = sorted(p for p in src.rglob("*") if p.is_file()) if src.is_dir() else [src]
    seen, total = set(), 0
    with open(EVENTS, "w", encoding="utf-8") as out:
        for p in files:
            total += convert(p, out, seen)
    print(f"[+] {total} IIS events from {len(files)} file(s)", file=sys.stderr)
    if not total:
        sys.exit("[-] no W3C events found under " + str(src))
    write_config(seen)

    os.chdir(ZIRCOLITE)
    os.execvp("python3", ["python3", "zircolite.py", "-e", EVENTS, "--json-input", "-c", CONFIG,
                          "-r", "/rules", "-o", "/out/detected.json", "-l", "/out/zircolite.log",
                          *sys.argv[1:]])


if __name__ == "__main__":
    main()
