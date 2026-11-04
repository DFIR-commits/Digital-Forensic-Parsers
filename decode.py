#!/usr/bin/env python3
"""
Decode Splunk CSV rows.

Pipeline per row (column: request_decoded):
  1. URL decode
  2. Extract base64 from CompressedDataTable="..."  (also handles ""..."" / """"..."""")
  3. base64 decode -> gunzip (only if gzip magic bytes are present)
  4. Extract base64 value(s) following type="xsd:string"
  5. base64 decode (gunzip again only if needed) -> final text

Every input row is kept. New columns are appended:
  decoded_data   final decoded text (multiple values joined by a separator)
  decode_status  layers applied, e.g. "url,table_b64,gzip,inner_b64"
  decode_error   empty on success, otherwise what went wrong

Usage:
  python decode_splunk.py input.csv output.csv
  python decode_splunk.py input.csv output.csv --column request_decoded
"""
import argparse
import base64
import binascii
import gzip
import re
import sys
from urllib.parse import unquote

import pandas as pd

# CompressedDataTable="<b64>"  or  CompressedDataTable=""<b64>""  or  """"<b64>""""
RE_TABLE = re.compile(r'CompressedDataTable\s*=\s*"+\s*([^"]+?)\s*"+', re.IGNORECASE | re.DOTALL)

# type="xsd:string"<b64>   or   type="xsd:string">< b64 ><   (tolerates >, quotes, whitespace)
RE_XSD = re.compile(
    r'type\s*=\s*"+\s*xsd:string\s*"+\s*>?\s*"*\s*([A-Za-z0-9+/_\-=\s]+?)\s*"*\s*(?:<|$)',
    re.IGNORECASE | re.DOTALL,
)

VALUE_SEPARATOR = "\n----\n"


def b64_decode(s: str) -> bytes:
    """Lenient base64 decode: strips whitespace, restores '+' lost as spaces, fixes padding."""
    s = re.sub(r"\s+", "", s.replace(" ", "+"))
    s = s.rstrip("=")
    s += "=" * (-len(s) % 4)
    if "-" in s or "_" in s:
        return base64.urlsafe_b64decode(s)
    return base64.b64decode(s)


def maybe_gunzip(b: bytes):
    """Gunzip only if data starts with the gzip magic bytes. Returns (bytes, was_gzipped)."""
    if b[:2] == b"\x1f\x8b":
        return gzip.decompress(b), True
    return b, False


def to_text(b: bytes) -> str:
    for enc in ("utf-8", "utf-16"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("latin-1")


def decode_value(val):
    status, errors = [], []

    if val is None or (isinstance(val, float) and pd.isna(val)) or str(val).strip() == "":
        return "", "", "empty"

    try:
        # 1. URL decode
        text = unquote(str(val))
        status.append("url")
        # still percent-encoded? (double-encoded) decode once more
        if re.search(r"%[0-9A-Fa-f]{2}", text) and "CompressedDataTable" not in text:
            text = unquote(text)
            status.append("url2")

        # 2. Pull out CompressedDataTable base64
        m = RE_TABLE.search(text)
        if not m:
            return "", ",".join(status), "CompressedDataTable not found"
        status.append("table_b64")

        # 3. base64 -> gunzip
        raw = b64_decode(m.group(1))
        raw, gz = maybe_gunzip(raw)
        if gz:
            status.append("gzip")
        inner = to_text(raw)

        # 4. Pull out base64 value(s) after type="xsd:string"
        matches = RE_XSD.findall(inner)
        if not matches:
            # nothing matched; return the gunzipped text so no data is lost
            return inner, ",".join(status), 'type="xsd:string" not found (returning gunzipped text)'

        # 5. base64 decode each value (gunzip again only if needed)
        outputs = []
        for i, b in enumerate(matches):
            try:
                data = b64_decode(b)
                data, gz2 = maybe_gunzip(data)
                if gz2 and "gzip2" not in status:
                    status.append("gzip2")
                outputs.append(to_text(data))
            except (binascii.Error, ValueError, OSError) as e:
                errors.append(f"value {i}: {e}")
                outputs.append(b)  # keep the raw string rather than dropping it
        status.append("inner_b64")
        return VALUE_SEPARATOR.join(outputs), ",".join(status), "; ".join(errors)

    except Exception as e:  # keep the row, record the problem
        return "", ",".join(status), f"{type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--column", default="request_decoded")
    args = ap.parse_args()

    df = pd.read_csv(args.input, dtype=str, keep_default_na=False)
    if args.column not in df.columns:
        sys.exit(f"Column '{args.column}' not found. Columns: {list(df.columns)}")

    results = df[args.column].apply(decode_value)
    df["decoded_data"] = results.str[0]
    df["decode_status"] = results.str[1]
    df["decode_error"] = results.str[2]

    df.to_csv(args.output, index=False, encoding="utf-8-sig")

    ok = (df["decode_error"] == "").sum()
    print(f"{len(df)} rows processed, {ok} clean, {len(df) - ok} with notes -> {args.output}")
    print("Note: Excel truncates cells over 32,767 characters; the CSV itself is not truncated.")


if __name__ == "__main__":
    main()
