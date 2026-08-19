# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

"""FileLock logic — find processes locking a file (Restart Manager + openfiles)."""
from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes
from pathlib import Path

CCH_RM_SESSION_KEY = 32
RM_MAX_APP_NAME = 255
RM_MAX_SVC_NAME = 63
ERROR_MORE_DATA = 234


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwProcessId", wintypes.DWORD),
        ("ProcessStartTime", wintypes.FILETIME),
    ]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * (RM_MAX_APP_NAME + 1)),
        ("strServiceShortName", wintypes.WCHAR * (RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", wintypes.DWORD),
        ("AppStatus", wintypes.ULONG),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]


def find_locks_restart_manager(filepath: str) -> list[dict]:
    rstrtmgr = ctypes.windll.rstrtmgr
    session_handle = wintypes.DWORD()
    session_key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY + 1)
    res = rstrtmgr.RmStartSession(ctypes.byref(session_handle), 0, session_key)
    if res != 0:
        raise OSError(f"RmStartSession failed: {res}")
    rows: list[dict] = []
    try:
        path = str(Path(filepath).resolve())
        files = (ctypes.c_wchar_p * 1)(path)
        res = rstrtmgr.RmRegisterResources(session_handle, 1, files, 0, None, 0, None)
        if res != 0:
            raise OSError(f"RmRegisterResources failed: {res}")
        n_proc = wintypes.UINT(0)
        reason = wintypes.UINT(0)
        res = rstrtmgr.RmGetList(
            session_handle,
            ctypes.byref(n_proc),
            None,
            None,
            ctypes.byref(reason),
        )
        if res not in (0, ERROR_MORE_DATA):
            return rows
        count = max(1, int(n_proc.value))
        arr_type = RM_PROCESS_INFO * count
        arr = arr_type()
        n_proc2 = wintypes.UINT(count)
        res = rstrtmgr.RmGetList(
            session_handle,
            ctypes.byref(n_proc2),
            ctypes.byref(arr),
            None,
            ctypes.byref(reason),
        )
        if res != 0:
            return rows
        seen: set[int] = set()
        for i in range(int(n_proc2.value)):
            info = arr[i]
            pid = int(info.Process.dwProcessId)
            if pid <= 0 or pid in seen:
                continue
            seen.add(pid)
            name = str(info.strAppName or "").strip() or str(info.strServiceShortName or "").strip()
            rows.append({"pid": pid, "name": name or f"PID {pid}", "source": "RestartManager"})
    finally:
        rstrtmgr.RmEndSession(session_handle)
    return rows


def find_locks_openfiles(filepath: str) -> list[dict]:
    target = str(Path(filepath).resolve()).lower()
    proc = subprocess.run(
        ["openfiles", "/query", "/fo", "CSV"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
    )
    if proc.returncode != 0:
        return []
    rows: list[dict] = []
    seen: set[int] = set()
    for line in (proc.stdout or "").splitlines()[1:]:
        parts = [p.strip().strip('"') for p in line.split('","')]
        if len(parts) < 5:
            continue
        open_file = parts[4].lower()
        if target not in open_file and open_file not in target:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        if pid in seen:
            continue
        seen.add(pid)
        rows.append({"pid": pid, "name": parts[2] or f"PID {pid}", "source": "openfiles"})
    return rows


def find_locks(file_path: str) -> dict:
    """Return {ok, path, processes, count, method} or error dict."""
    try:
        fp = Path(str(file_path or "").strip())
        if not fp.exists():
            return {"ok": False, "error": "Fichier introuvable", "processes": []}
        path = str(fp.resolve())
        processes: list[dict] = []
        method = "RestartManager"
        try:
            processes = find_locks_restart_manager(path)
        except Exception:
            processes = []
        if not processes:
            method = "openfiles"
            processes = find_locks_openfiles(path)
        return {
            "ok": True,
            "path": path,
            "processes": processes,
            "count": len(processes),
            "method": method,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "processes": []}
