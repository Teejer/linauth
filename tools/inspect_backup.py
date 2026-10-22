#!/usr/bin/env python3
"""Inspect a WinAuth backup zip without exposing secrets in the transcript.

Run it in your own terminal:
    python3 tools/inspect_backup.py "/mnt/files/Systems Administration/Keepass/Winauth Master 2026-06-17.zip"

It prompts for the zip password and prints a structural summary only:
account types, issuers/labels, and which parameters are used. Secret values
are masked (we show only their length / a fingerprint prefix).
"""
import base64
import getpass
import re
import sys
import zipfile
from urllib.parse import urlparse, parse_qs, unquote

HEXISH = re.compile(r"^[0-9a-fA-F]+$")


def mask(v: str) -> str:
    if len(v) <= 6:
        return f"<{len(v)} chars>"
    return f"{v[:3]}… ({len(v)} chars)"


def base32_note(secret: str) -> str:
    try:
        raw = base64.b32decode(secret.upper(), casefold=True)
        return f"base32 ok -> {len(raw)} raw bytes"
    except Exception as e:  # noqa: BLE001
        return f"NOT valid base32 ({e})"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    import os
    pwfile = os.environ.get("WINAUTH_PWD_FILE")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        print(f"zip entries: {names}")
        inner = names[0]
        if pwfile:
            with open(pwfile, "rb") as f:
                pwd = f.read().strip()
        else:
            pwd = getpass.getpass("zip password: ").encode()
        try:
            data = z.read(inner, pwd=pwd)
        except RuntimeError as e:
            print(f"DECRYPT FAILED: {e}")
            return 1
    text = data.decode("utf-8", errors="replace")
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    print(f"account lines: {len(lines)}\n")
    types: dict[str, int] = {}
    for i, line in enumerate(lines, 1):
        try:
            u = urlparse(line)
        except Exception as e:  # noqa: BLE001
            print(f"{i:2}: UNPARSEABLE line: {e}")
            continue
        if u.scheme != "otpauth":
            print(f"{i:2}: non-otpauth scheme: {u.scheme}  raw prefix: {line[:15]}…")
            continue
        atype = u.netloc or u.path.strip("/")
        types[atype] = types.get(atype, 0) + 1
        q = {k: [unquote(x) for x in v] for k, v in parse_qs(u.query).items()}
        label = unquote((u.path.lstrip("/") if u.netloc else u.path).strip("/") or "")
        issuer = (q.get("issuer") or [""])[0]
        # which parameters are present (values only for the harmless ones)
        info = []
        if "secret" in q:
            info.append(base32_note(q["secret"][0]))
        for p in ("digits", "algorithm", "period", "counter"):
            if p in q:
                info.append(f"{p}={q[p][0]}")
        for p in ("serial", "deviceid", "data", "icon"):
            if p in q:
                info.append(f"{p}={mask(q[p][0])}")
        unknown = sorted(set(q) - {"secret", "digits", "algorithm", "period",
                                   "counter", "serial", "deviceid", "data",
                                   "icon", "issuer"})
        if unknown:
            info.append("UNKNOWN PARAMS: " + ",".join(unknown))
        print(f"{i:2}: {atype:5} issuer={issuer!r} label={label!r}  " + "; ".join(info))
    print("\nsummary:", dict(types))
    return 0


if __name__ == "__main__":
    sys.exit(main())
