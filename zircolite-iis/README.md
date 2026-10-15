# zircolite-iis

Runs Sigma `webserver`/`iis` rules against IIS W3C logs, and the SigmaHQ Windows rules against any `.evtx` files next to them, with
[Zircolite](https://github.com/wagga40/Zircolite) 4.5.0, in Docker. Zircolite has no W3C
reader, so `w3c2jsonl.py` turns the logs into JSON lines first. It reads every `#Fields:`
header and renames `cs(Cookie)` to `cs-cookie`, `cs(User-Agent)` to `cs-user-agent` and so on.
It also keeps the hyphens in field names so they match the rule fields. Every hit records
`SourceFile` and `SourceLine`.

## Set up (any Linux box with Docker)

```sh
git clone --depth 1 https://github.com/DFIR-commits/Digital-Forensic-Parsers.git
docker build -t zircolite-iis Digital-Forensic-Parsers/zircolite-iis
```

Offline box: on a machine with internet run `docker save zircolite-iis | gzip > zircolite-iis.tar.gz`,
copy the file over, then run `docker load < zircolite-iis.tar.gz`.

## Run

```sh
mkdir -p out
docker run --rm --user "$(id -u):$(id -g)" \
  -v /path/to/iis/logs:/logs:ro \
  -v /path/to/sigma/rules:/rules:ro \
  -v "$PWD/out:/out" \
  zircolite-iis
```

- `/logs`: a folder searched recursively, or one file. It can hold IIS W3C logs, `.evtx` files, or both.
  Any other file is skipped, with a warning naming it.
- `/rules`: a folder of Sigma `.yml` rules for the IIS logs, searched recursively. For a single rule, mount it as `-v /path/rule.yml:/rules/rule.yml:ro`.
- IIS results go to `out/detected.json`, and Zircolite's log to `out/zircolite.log`.
- EVTX files are passed to Zircolite unchanged and checked against its bundled SigmaHQ Windows
  ruleset (`rules_windows_merged.json`, about 4,500 rules). Results go to `out/detected_evtx.json`
  and the log to `out/zircolite_evtx.log`. To use another ruleset, add
  `-e EVTX_RULES=rules/rules_windows_all.json` (SigmaHQ plus community rules) before `zircolite-iis`.
- Each IIS log is converted to its own JSON-lines file, on all CPU cores, and Zircolite gets
  the folder. Zircolite only runs in parallel across files, so this lets it use every core
  on large cases. It picks the mode itself: many small files go into one database, large ones
  are scanned file by file in parallel. `-w N` (after `zircolite-iis`) caps Zircolite's
  workers; `-e WORKERS=N` caps the converter's.
- The converted JSON is about twice the size of the logs: every line repeats each field
  name, plus `SourceFile`, `SourceLine` and `timestamp`. It goes to `/tmp/events` inside the
  container and is deleted with it. To keep it, add `-e EVENTS=/out/events` (a folder) before
  `zircolite-iis`. For big cases, make sure Docker has room for it.
- Any extra arguments after `zircolite-iis` go to both Zircolite runs. For example, `--min-level high`
  loads only rules at that level or above, and `--working-db disk` keeps large cases out of RAM.
  Don't pass `-o`: both runs would write to the same file.
- Check the `.json` result files, not the console summary. A rule without `level:` matches, but the
  summary still says "Detections None".

## Test

```sh
sh tests/check.sh    # builds the image, runs tests/logs, expects IIS hits on lines 5, 12, 13 and one EVTX hit
```

`tests/logs/sample_bitsadmin.evtx` is a test fixture from the Zircolite repository (LGPL-3.0).

Values are matched raw, exactly as IIS writes them, so a space shows up as `+`
(`Mozilla/5.0+(Windows...`). Write rule values that way too.
