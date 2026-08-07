"""CertView — list CurrentUser\\My certificates (read-only)."""
from __future__ import annotations

import json
import subprocess
from typing import Any

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _decode_cli(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if not data:
        return ""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("oem", errors="replace")


def _ps_json(script: str, timeout: int = 60) -> Any:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        timeout=timeout,
        creationflags=_CREATE_NO_WINDOW,
    )
    out = _decode_cli(proc.stdout).strip()
    err = _decode_cli(proc.stderr).strip()
    if proc.returncode != 0 and not out:
        raise RuntimeError(err or f"PowerShell exit {proc.returncode}")
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"raw": out, "stderr": err, "returncode": proc.returncode}


def list_certs() -> dict:
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
Get-ChildItem Cert:\\CurrentUser\\My | Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter, HasPrivateKey |
  Sort-Object NotAfter -Descending | ConvertTo-Json -Compress -Depth 3
"""
    data = _ps_json(script, timeout=60)
    if data is None:
        rows: list = []
    elif isinstance(data, dict):
        rows = [data]
    else:
        rows = list(data)
    return {"ok": True, "certs": rows, "count": len(rows)}
