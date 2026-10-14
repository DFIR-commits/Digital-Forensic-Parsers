# zircolite-iis

Runs Sigma `webserver`/`iis` rules against IIS W3C logs with
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

- `/logs`: a folder of W3C logs, searched recursively (`u_ex*.log`), or one file.
- `/rules`: a folder of Sigma `.yml` rules, searched recursively. For a single rule, mount it as `-v /path/rule.yml:/rules/rule.yml:ro`.
- Results go to `out/detected.json`, and Zircolite's own log goes to `out/zircolite.log`.
- To keep the converted JSON (one event per line), add `-e EVENTS=/out/events.json` before `zircolite-iis`.
- Any extra arguments go straight to Zircolite. For example, add `--csv -o /out/detected.csv`
  for CSV output, or `--min-level high` to load only rules at that level or above.

## Test

```sh
sh tests/check.sh    # builds the image, runs tests/logs against tests/rules, expects hits on lines 5, 12, 13
```

Values are matched raw, exactly as IIS writes them, so a space shows up as `+`
(`Mozilla/5.0+(Windows...`). Write rule values that way too.
