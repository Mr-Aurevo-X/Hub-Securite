# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

"""PermissionAudit logic — ACL via Get-Acl / takeown+icacls."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_HOST_DIR = Path(__file__).resolve().parent.parent
if str(_HOST_DIR) not in sys.path:
    sys.path.insert(0, str(_HOST_DIR))

from security import is_blocked_system_path, safe_resolve_under  # noqa: E402


def _ps_json(script: str, timeout: int = 120) -> Any:
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
    )
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode != 0 and not out:
        raise RuntimeError(err or f"PowerShell exit {proc.returncode}")
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"raw": out, "stderr": err, "returncode": proc.returncode}


def _run_cmd(args: list[str], timeout: int = 300) -> tuple[int, str, str]:
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
    )
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


def get_acl(folder_path: str) -> dict:
    try:
        fp = Path(str(folder_path or "").strip())
        if not fp.exists():
            return {"ok": False, "error": "Chemin introuvable", "entries": []}
        script = rf"""
$ErrorActionPreference = 'Stop'
$p = '{str(fp).replace("'", "''")}'
$acl = Get-Acl -LiteralPath $p
$owner = [string]$acl.Owner
$rows = @()
foreach ($ace in $acl.Access) {{
  $rows += [pscustomobject]@{{
    identity = [string]$ace.IdentityReference
    rights = [string]$ace.FileSystemRights
    type = [string]$ace.AccessControlType
    inherited = [bool]$ace.IsInherited
  }}
}}
[pscustomobject]@{{
  owner = $owner
  path = $p
  entries = $rows
}} | ConvertTo-Json -Compress -Depth 5
"""
        data = _ps_json(script)
        if not isinstance(data, dict):
            return {"ok": False, "error": "Réponse ACL invalide", "entries": []}
        entries = data.get("entries") or []
        if isinstance(entries, dict):
            entries = [entries]
        return {
            "ok": True,
            "owner": data.get("owner") or "",
            "path": data.get("path") or str(fp),
            "entries": list(entries),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "entries": []}


def take_ownership(
    folder_path: str,
    *,
    is_admin: bool,
    session_root: str | Path | None = None,
) -> dict:
    try:
        if not is_admin:
            return {"ok": False, "error": "Administrateur requis", "admin": False}
        if session_root is None:
            return {"ok": False, "error": "Session root required — scan or pick a folder first"}
        try:
            root = Path(session_root).expanduser().resolve()
        except (OSError, RuntimeError):
            return {"ok": False, "error": "Invalid session root"}
        fp = safe_resolve_under(folder_path, [root])
        if fp is None:
            return {"ok": False, "error": "Path outside scanned/chosen folder"}
        if is_blocked_system_path(fp):
            return {"ok": False, "error": "System path blocked"}
        if not fp.exists():
            return {"ok": False, "error": "Chemin introuvable"}
        target = str(fp)
        rc1, out1, err1 = _run_cmd(["takeown", "/F", target, "/R", "/D", "Y"])
        user = os.environ.get("USERNAME") or ""
        rc2, out2, err2 = _run_cmd(
            ["icacls", target, "/grant", f"{user}:(OI)(CI)F", "/T", "/C"]
        )
        if rc1 != 0 and rc2 != 0:
            return {
                "ok": False,
                "error": (err1 or err2 or out1 or out2 or "takeown/icacls failed").strip(),
            }
        return {"ok": True, "path": target, "admin": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
