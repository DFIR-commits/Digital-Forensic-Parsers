#!/usr/bin/env python3
"""Probe a DFIR-IRIS instance layer by layer: DNS, TCP, TLS, then the API.

Makes the same request yarax-scanner does: GET /manage/cases/filter with a
Bearer key. Standard library only. Read-only: nothing is changed in IRIS.

  python3 iris_probe.py https://iris.example:443 --key API_KEY [--insecure] [--case 2]
  (or set IRIS_API_KEY instead of --key)
"""
import argparse, json, os, socket, ssl, sys, time, urllib.parse, urllib.request


def step(name, fn):
    t = time.monotonic()
    try:
        out = fn()
        print(f"[ OK ] {name} ({(time.monotonic() - t) * 1000:.0f} ms){': ' + out if out else ''}")
        return True
    except Exception as e:
        print(f"[FAIL] {name}: {type(e).__name__}: {e}")
        if isinstance(e, ConnectionResetError):
            print("       connection reset by peer (os error 104): something closed the connection.")
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--key", default=os.environ.get("IRIS_API_KEY"))
    ap.add_argument("--insecure", action="store_true", help="skip certificate verification (IRIS default cert is self-signed)")
    ap.add_argument("--case", type=int, help="also fetch this case's IOCs")
    ap.add_argument("--timeout", type=float, default=15)
    a = ap.parse_args()
    if not a.key:
        sys.exit("need --key or IRIS_API_KEY")

    u = urllib.parse.urlsplit(a.url.strip().rstrip("/"))
    host, https = u.hostname, u.scheme == "https"
    port = u.port or (443 if https else 80)
    base = f"{u.scheme}://{u.netloc}{u.path}"
    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE

    print(f"target {base}  ({host}:{port}, {'https' if https else 'http'})")
    proxies = {k: v for k, v in os.environ.items() if k.lower() in ("https_proxy", "http_proxy", "no_proxy")}
    print(f"proxy env: {proxies or 'none'}  (urllib below honours it; the raw socket checks do not)")

    def dns():
        return ", ".join(sorted({ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}))
    if not step("DNS", dns):
        return 1

    def tcp():
        socket.create_connection((host, port), a.timeout).close()
    if not step("TCP connect", tcp):
        return 1

    if https:
        def tls():
            with socket.create_connection((host, port), a.timeout) as s, ctx.wrap_socket(s, server_hostname=host) as t:
                cert = t.getpeercert() if not a.insecure else None
                subj = dict(x[0] for x in cert["subject"]).get("commonName", "?") if cert else "unverified"
                return f"{t.version()} {t.cipher()[0]} cert={subj}"
        if not step("TLS handshake", tls):
            print("       certificate errors: rerun with --insecure (IRIS ships a self-signed cert).")
            print("       anything else with TCP OK: wrong port/scheme, a proxy/WAF, or a client-cert requirement.")

        def plain():  # does the port answer plain HTTP? (means https:// is the wrong scheme)
            with socket.create_connection((host, port), a.timeout) as s:
                s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                return repr(s.recv(80).split(b"\r\n")[0].decode(errors="replace"))
        step("plain HTTP on same port (expect an error or 400 on a TLS port)", plain)

    def api(path):
        req = urllib.request.Request(base + path, headers={"Authorization": f"Bearer {a.key}", "Accept": "application/json"})
        handlers = [urllib.request.HTTPSHandler(context=ctx)] if https else []
        try:
            r = urllib.request.build_opener(*handlers).open(req, timeout=a.timeout)
            code, body = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read()
        if code in (401, 403):
            raise RuntimeError(f"HTTP {code}: key rejected or lacks permission")
        if code != 200:
            raise RuntimeError(f"HTTP {code}: {body[:200]!r}")
        try:
            v = json.loads(body)
        except ValueError:
            raise RuntimeError(f"HTTP 200 but not JSON (wrong URL?): {body[:120]!r}")
        if v.get("status") != "success":
            raise RuntimeError(f"IRIS error: {v.get('message')}")
        return v["data"]

    def cases():
        d = api("/manage/cases/filter?per_page=100&page=1")
        rows = d.get("cases", [])
        for c in rows[:20]:
            print(f"         #{c.get('case_id'):<5} {(c.get('state') or {}).get('state_name', ''):<8} {c.get('name')}")
        return f"{d.get('total')} case(s), next_page={d.get('next_page')}"
    ok = step("GET /manage/cases/filter", cases)

    if a.case:
        def iocs():
            d = api(f"/case/ioc/list?cid={a.case}")
            return f"{len(d.get('ioc', []))} IOC(s) in case {a.case}"
        ok = step(f"GET /case/ioc/list?cid={a.case}", iocs) and ok

    def version():
        d = api("/api/versions")
        return f"IRIS {d.get('iris_current')}, API {d.get('api_current')}"
    step("GET /api/versions", version)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
