# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

"""WinAudit — PowerShell JSON bridge (read-only scan)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

from security import safe_open_path

def assets_root() -> Path:
    return Path(__file__).resolve().parent

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

class WinAuditBridge:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or assets_root()
        self.api_ps1 = self.root / "api" / "Invoke-WinAuditApi.ps1"
        self.progress_path = self.root / "logs" / "scan-progress.json"
        self._scan_lock = threading.Lock()
        self._scan_thread: threading.Thread | None = None
        self._scan_proc: subprocess.Popen[bytes] | None = None
        self._scan_running = False
        self._scan_cancelled = False
        self._scan_error: str | None = None
        self._scan_result: dict[str, Any] | None = None

    def _invoke_api(
        self,
        action: str,
        payload: dict | None = None,
        *,
        track_as_scan: bool = False,
    ) -> dict:
        if payload is None:
            payload = {}
        if not self.api_ps1.is_file():
            return {"ok": False, "error": f"API introuvable: {self.api_ps1}", "data": None}

        req = {"action": action, "payload": payload}
        fd_in, path_in = tempfile.mkstemp(prefix="winaudit-in-", suffix=".json")
        fd_out, path_out = tempfile.mkstemp(prefix="winaudit-out-", suffix=".json")
        os.close(fd_in)
        os.close(fd_out)
        proc: subprocess.Popen[bytes] | None = None
        try:
            Path(path_in).write_text(json.dumps(req, ensure_ascii=False), encoding="utf-8")
            Path(path_out).write_text("", encoding="utf-8")

            creationflags = 0
            if sys.platform == "win32":
                creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

            proc = subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(self.api_ps1),
                    "-InFile",
                    path_in,
                    "-OutFile",
                    path_out,
                ],
                cwd=str(self.root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
            )
            if track_as_scan:
                with self._scan_lock:
                    self._scan_proc = proc

            try:
                stdout_b, stderr_b = proc.communicate(timeout=3600)
            except subprocess.TimeoutExpired:
                self._kill_proc(proc)
                return {"ok": False, "error": "Timeout (scan trop long)", "data": None}

            if track_as_scan:
                with self._scan_lock:
                    cancelled = self._scan_cancelled
                    self._scan_proc = None
                if cancelled:
                    return {"ok": False, "error": "cancelled", "data": {"cancelled": True}}

            raw = Path(path_out).read_text(encoding="utf-8").strip()
            if not raw:
                if track_as_scan and self._scan_cancelled:
                    return {"ok": False, "error": "cancelled", "data": {"cancelled": True}}
                err = (_decode_cli(stderr_b) or _decode_cli(stdout_b) or f"exit {proc.returncode}").strip()
                return {"ok": False, "error": err or "Reponse API vide", "data": None}
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                if track_as_scan and self._scan_cancelled:
                    return {"ok": False, "error": "cancelled", "data": {"cancelled": True}}
                return {"ok": False, "error": f"JSON invalide: {raw[:400]}", "data": None}
        except Exception as exc:  # noqa: BLE001
            if track_as_scan and self._scan_cancelled:
                return {"ok": False, "error": "cancelled", "data": {"cancelled": True}}
            return {"ok": False, "error": str(exc), "data": None}
        finally:
            if track_as_scan:
                with self._scan_lock:
                    self._scan_proc = None
            for p in (path_in, path_out):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def run(self, action: str, payload: dict | None = None) -> dict:
        return self._invoke_api(action, payload, track_as_scan=False)

    @staticmethod
    def _kill_proc(proc: subprocess.Popen[bytes] | None) -> None:
        if proc is None or proc.poll() is not None:
            return
        try:
            if sys.platform == "win32" and proc.pid:
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
                    timeout=15,
                )
            else:
                proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _write_progress_fallback(
        self,
        percent: int,
        phase: str,
        detail: str,
        done: bool,
        error: str | None = None,
        cancelled: bool = False,
    ) -> None:
        try:
            self.progress_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "percent": percent,
                "phase": phase,
                "detail": detail,
                "done": done,
                "error": error,
                "cancelled": cancelled,
                "updatedAt": None,
            }
            self.progress_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    def _read_progress_file(self) -> dict[str, Any]:
        if not self.progress_path.is_file():
            return {
                "percent": 0,
                "phase": "",
                "detail": "",
                "done": False,
                "error": None,
                "cancelled": False,
                "updatedAt": None,
            }
        try:
            return json.loads(self.progress_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {
                "percent": 0,
                "phase": "",
                "detail": "",
                "done": False,
                "error": None,
                "cancelled": False,
                "updatedAt": None,
            }

    def _run_scan_worker(self) -> None:
        try:
            res = self._invoke_api("runScan", {}, track_as_scan=True)
            with self._scan_lock:
                cancelled = self._scan_cancelled
            if cancelled or (res and res.get("error") == "cancelled"):
                self._scan_error = None
                self._scan_result = None
                self._write_progress_fallback(
                    0, "Annule", "Scan annule par l'utilisateur", True, None, cancelled=True
                )
            elif not res or not res.get("ok"):
                err = (res or {}).get("error") or "Echec du scan"
                self._scan_error = str(err)
                self._scan_result = None
                self._write_progress_fallback(100, "Erreur", str(err), True, str(err))
            else:
                self._scan_error = None
                self._scan_result = res.get("data")
                prog = self._read_progress_file()
                if not prog.get("done"):
                    self._write_progress_fallback(
                        100,
                        "Termine",
                        prog.get("detail") or "Scan termine",
                        True,
                        None,
                    )
        except Exception as exc:  # noqa: BLE001
            with self._scan_lock:
                cancelled = self._scan_cancelled
            if cancelled:
                self._scan_error = None
                self._scan_result = None
                self._write_progress_fallback(
                    0, "Annule", "Scan annule par l'utilisateur", True, None, cancelled=True
                )
            else:
                self._scan_error = str(exc)
                self._scan_result = None
                self._write_progress_fallback(100, "Erreur", str(exc), True, str(exc))
        finally:
            with self._scan_lock:
                self._scan_running = False
                self._scan_proc = None

    def start_scan(self) -> dict:
        with self._scan_lock:
            if self._scan_running:
                return {"ok": False, "error": "Un scan est deja en cours", "data": None}
            self._scan_running = True
            self._scan_cancelled = False
            self._scan_error = None
            self._scan_result = None
            self._scan_proc = None
            self._write_progress_fallback(0, "Persistence", "Demarrage...", False, None)
            self._scan_thread = threading.Thread(target=self._run_scan_worker, daemon=True)
            self._scan_thread.start()
        return {"ok": True, "error": None, "data": {"started": True}}

    def cancel_scan(self) -> dict:
        with self._scan_lock:
            if not self._scan_running:
                return {"ok": True, "error": None, "data": {"cancelled": False, "wasRunning": False}}
            self._scan_cancelled = True
            proc = self._scan_proc
        self._kill_proc(proc)
        self._write_progress_fallback(
            0, "Annule", "Scan annule par l'utilisateur", True, None, cancelled=True
        )
        return {"ok": True, "error": None, "data": {"cancelled": True, "wasRunning": True}}

    def get_scan_progress(self) -> dict:
        prog = self._read_progress_file()
        with self._scan_lock:
            running = self._scan_running
            err = self._scan_error
            cancelled = self._scan_cancelled or bool(prog.get("cancelled"))
        if err and not running and not cancelled:
            prog["done"] = True
            prog["error"] = err
            if not prog.get("phase"):
                prog["phase"] = "Erreur"
        return {
            "ok": True,
            "error": None,
            "data": {
                "percent": int(prog.get("percent") or 0),
                "phase": prog.get("phase") or "",
                "detail": prog.get("detail") or "",
                "done": bool(prog.get("done")) and not running,
                "running": running,
                "cancelled": cancelled and not running,
                "error": None if cancelled else (prog.get("error") or err),
                "updatedAt": prog.get("updatedAt"),
            },
        }

    def get_scan_result(self) -> dict:
        with self._scan_lock:
            if self._scan_running:
                return {"ok": False, "error": "Scan encore en cours", "data": None}
            if self._scan_cancelled:
                return {"ok": False, "error": "cancelled", "data": {"cancelled": True}}
            if self._scan_error:
                return {"ok": False, "error": self._scan_error, "data": None}
            if self._scan_result is not None:
                return {"ok": True, "error": None, "data": self._scan_result}
        return self.run("getLastResult", {})

    def open_path(self, path: str) -> dict:
        safe, err = safe_open_path(path, deny_exec=True)
        if safe is None:
            return {"ok": False, "error": err or "Chemin refuse"}
        try:
            os.startfile(str(safe))  # type: ignore[attr-defined]
            return {"ok": True}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
