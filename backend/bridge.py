# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

"""Hub-Securite namespace APIs — flatten bridge (host.py + backend/)."""
from __future__ import annotations

import subprocess

from pathlib import Path
import sys

_BACKEND = Path(__file__).resolve().parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import ctypes
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import webview

from tools.certview import service as mod_cert
from tools.fileguard import file_lock as mod_file_lock
from tools.fileguard import permission_audit as mod_perm
from tools.reporadar import service as mod_repo
from tools.winaudit.bridge import WinAuditBridge
from security import ConfirmGate
from suite_launch import launch_suite_app, resolve_suite_accent, resolve_suite_language

# _BACKEND already on sys.path (tools.* imports). No legacy modules/ path.

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

# ── FileGuard ────────────────────────────────────────────────────────────────

class FileGuardApi:
    """Locks + ACL audit; ConfirmGate on take_ownership."""

    def __init__(self, gate: ConfirmGate) -> None:
        self._confirm = gate
        self._window: Any = None
        self._session_root: Path | None = None

    def set_window(self, window: Any) -> None:
        self._window = window

    def _set_session_root(self, path: str | Path | None) -> None:
        if not path:
            return
        try:
            self._session_root = Path(str(path)).expanduser().resolve()
        except (OSError, RuntimeError):
            pass

    def pick_file(self) -> dict:
        if self._window is None or not hasattr(self._window, "create_file_dialog"):
            return {"ok": False, "error": "Dialogue fichier indisponible"}
        try:
            result = self._window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False)
            if not result:
                return {"ok": True, "path": None}
            path = result[0] if isinstance(result, (list, tuple)) else result
            return {"ok": True, "path": str(path)}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def pick_folder(self) -> dict:
        if self._window is None or not hasattr(self._window, "create_file_dialog"):
            return {"ok": False, "error": "Dialogue dossier indisponible"}
        try:
            result = self._window.create_file_dialog(webview.FOLDER_DIALOG, allow_multiple=False)
            if not result:
                return {"ok": True, "path": None}
            path = result[0] if isinstance(result, (list, tuple)) else result
            self._set_session_root(path)
            return {"ok": True, "path": str(path)}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def find_locks(self, file_path: str) -> dict:
        result = mod_file_lock.find_locks(file_path)
        if result.get("ok"):
            result["admin"] = _is_admin()
        return result

    def get_acl(self, folder_path: str) -> dict:
        result = mod_perm.get_acl(folder_path)
        if result.get("ok"):
            result["admin"] = _is_admin()
            self._set_session_root(result.get("path") or folder_path)
        return result

    def prepare_take_ownership(self, folder_path: str) -> dict:
        path = str(folder_path or "").strip()
        if not path:
            return {"ok": False, "error": "Chemin vide", "token": None}
        if self._session_root is None:
            return {
                "ok": False,
                "error": "Session root required — scan or pick a folder first",
                "token": None,
            }
        try:
            token = self._confirm.prepare("take_ownership", path)
        except ValueError as exc:
            return {"ok": False, "error": str(exc), "token": None}
        return {"ok": True, "token": token}

    def take_ownership(self, folder_path: str, token: str = "") -> dict:
        path = str(folder_path or "").strip()
        if not self._confirm.consume(str(token or ""), "take_ownership", path):
            return {"ok": False, "error": "Confirmation token invalid or expired"}
        return mod_perm.take_ownership(
            path,
            is_admin=_is_admin(),
            session_root=self._session_root,
        )

    def open_dedicated(self) -> dict:
        return launch_suite_app("FileGuard")

# ── CertView ─────────────────────────────────────────────────────────────────

class CertViewApi:
    def list_certs(self) -> dict:
        try:
            return mod_cert.list_certs()
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def open_dedicated(self) -> dict:
        return launch_suite_app("CertView")

# ── RepoRadar ────────────────────────────────────────────────────────────────

class RepoRadarApi:
    def get_default_roots(self) -> dict:
        return {"ok": True, "roots": mod_repo.default_roots()}

    def scan_repos(self, roots: list[str] | None = None, max_depth: int = 3) -> dict:
        try:
            return mod_repo.scan_repos(roots, max_depth)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def open_folder(self, path: str) -> dict:
        return mod_repo.open_folder(path)

    def fetch_repo(self, path: str) -> dict:
        return mod_repo.fetch_repo(path)

    def open_dedicated(self) -> dict:
        return launch_suite_app("RepoRadar")

# ── WinAudit ─────────────────────────────────────────────────────────────────

class WinAuditApi:
    """Read-only OS audit — no ConfirmGate mutators."""

    def __init__(self) -> None:
        self._bridge = WinAuditBridge()

    def run(self, action: str, payload: dict | None = None) -> dict:
        return self._bridge.run(action, payload)

    def start_scan(self) -> dict:
        return self._bridge.start_scan()

    def cancel_scan(self) -> dict:
        return self._bridge.cancel_scan()

    def get_scan_progress(self) -> dict:
        return self._bridge.get_scan_progress()

    def get_scan_result(self) -> dict:
        return self._bridge.get_scan_result()

    def is_admin(self) -> bool:
        return _is_admin()

    def open_path(self, path: str) -> dict:
        return self._bridge.open_path(path)

    def open_dedicated(self) -> dict:
        return launch_suite_app("WinAudit")

HUB_TITLE = "PC Command | Security"
HUB_ID = "securite"
_HUB_ROOT = _BACKEND.parent
from window_chrome import WindowChromeMixin  # noqa: E402
import hub_update  # noqa: E402

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _ps_json(script: str, timeout: int = 20) -> Any:
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
    proc = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=flags, text=True)
    out = (proc.stdout or "").strip()
    if not out:
        return None
    import json as _json

    try:
        return _json.loads(out)
    except _json.JSONDecodeError:
        return {"raw": out, "returncode": proc.returncode}

class DashboardApi:
    """Lecture seule — aucun mutator."""

    def __init__(self, hub: "Api") -> None:
        self._hub = hub

    def get_metrics_url(self) -> dict:
        """URL of embedded localhost metrics API for Accueil live UI."""
        host = getattr(self._hub, "_metrics_host", "127.0.0.1") or "127.0.0.1"
        port = int(getattr(self._hub, "_metrics_port", 0) or 0)
        if port <= 0:
            return {"ok": False, "url": "", "error": "metrics offline"}
        return {"ok": True, "url": f"http://{host}:{port}/api/metrics"}

    def get_kpis(self) -> dict:
        base: dict[str, Any] = {
            "ok": True,
            "admin": is_admin(),
            "partial": False,
            "modules": 4,
            "status": "ready",
            "firewallOn": None,
            "firewallProfiles": None,
            "firewallEnabled": None,
            "certCount": None,
            "certsExpiringSoon": None,
            "findingsCount": None,
            "auditAgeDays": None,
            "hasAudit": False,
        }
        try:
            data = _ps_json(
                r"""
$ErrorActionPreference='SilentlyContinue'
$profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
$enabled = @($profiles | Where-Object { $_.Enabled }).Count
$now = Get-Date
$certs = @(Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue)
$soon = @($certs | Where-Object { $_.NotAfter -lt $now.AddDays(30) -and $_.NotAfter -ge $now })
[pscustomobject]@{
  firewallProfiles = $profiles.Count
  firewallEnabled = $enabled
  firewallOn = ($profiles.Count -gt 0 -and $enabled -eq $profiles.Count)
  certCount = $certs.Count
  certsExpiringSoon = $soon.Count
} | ConvertTo-Json -Compress
"""
            )
            if isinstance(data, dict):
                base.update(data)
        except Exception as exc:  # noqa: BLE001
            base["partial"] = True
            base["error"] = str(exc)

        try:
            scan = self._hub.winaudit.get_scan_result()
            payload = scan.get("data") if isinstance(scan, dict) else None
            result: Any = None
            if isinstance(payload, dict):
                if isinstance(payload.get("result"), dict):
                    result = payload["result"]
                elif payload.get("Findings") is not None or payload.get("GeneratedAt"):
                    result = payload
            if scan.get("ok") and isinstance(result, dict):
                findings = result.get("Findings") or result.get("findings") or []
                base["hasAudit"] = True
                base["findingsCount"] = len(findings) if isinstance(findings, list) else 0
                gen = result.get("GeneratedAt") or result.get("generatedAt")
                age = _audit_age_days(gen)
                if age is not None:
                    base["auditAgeDays"] = age
        except Exception as exc:  # noqa: BLE001
            base["partial"] = True
            if not base.get("error"):
                base["error"] = str(exc)
        return base

    def list_modules(self) -> dict:
        return {"ok": True, "modules": self._hub.module_catalog()}

def _audit_age_days(gen: Any) -> float | None:
    if gen is None:
        return None
    dt: datetime | None = None
    if isinstance(gen, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(gen), tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            dt = None
    else:
        s = str(gen).strip()
        m = re.search(r"/Date\((-?\d+)\)/", s)
        if m:
            try:
                dt = datetime.fromtimestamp(int(m.group(1)) / 1000.0, tz=timezone.utc)
            except (OSError, OverflowError, ValueError):
                dt = None
        else:
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                dt = None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return max(0.0, (now - dt.astimezone(timezone.utc)).total_seconds() / 86400.0)

class Api(WindowChromeMixin):
    def __init__(self) -> None:
        self._window: Any = None
        self._maximized = False
        self._confirm = ConfirmGate(ttl_seconds=90.0)
        self._metrics_host = "127.0.0.1"
        self._metrics_port = 0
        self.dashboard = DashboardApi(self)
        self.fileguard = FileGuardApi(self._confirm)
        self.certview = CertViewApi()
        self.reporadar = RepoRadarApi()
        self.winaudit = WinAuditApi()

    def set_window(self, window: Any) -> None:
        WindowChromeMixin.set_window(self, window)
        self.fileguard.set_window(window)

    def module_catalog(self) -> list[dict]:
        return [
            {
                "id": "fileguard",
                "label": "FileGuard",
                "desc": "Ownership / garde fichiers",
                "apps": ["FileGuard"],
            },
            {
                "id": "certview",
                "label": "CertView",
                "desc": "Certificats locaux",
                "apps": ["CertView"],
            },
            {
                "id": "reporadar",
                "label": "RepoRadar",
                "desc": "Scan repos",
                "apps": ["RepoRadar"],
            },
            {
                "id": "winaudit",
                "label": "WinAudit",
                "desc": "Audit OS lecture seule",
                "apps": ["WinAudit"],
            },
        ]

    def get_suite_accent(self) -> dict:
        return {"ok": True, "accent": resolve_suite_accent()}

    def get_suite_settings(self) -> dict:
        return {
            "ok": True,
            "accent": resolve_suite_accent(),
            "language": resolve_suite_language(),
        }

    def get_suite_language(self) -> dict:
        return {"ok": True, "language": resolve_suite_language()}

    def set_suite_language(self, language: str = "fr") -> dict:
        lang = str(language or "").strip().lower()
        if lang not in ("fr", "en"):
            return {"ok": False, "error": "language must be fr or en"}
        hub_update.write_user_settings_merge({"language": lang})
        return {
            "ok": True,
            "language": lang,
            "path": str(hub_update.user_settings_path()),
        }

    def is_admin(self) -> dict:
        return {"ok": True, "admin": is_admin()}

    def set_metrics_endpoint(self, host: str = "127.0.0.1", port: int = 0) -> dict:
        h = (host or "127.0.0.1").strip().lower()
        if h not in ("127.0.0.1", "localhost", "::1"):
            return {"ok": False, "error": "metrics host must be loopback"}
        self._metrics_host = "127.0.0.1" if h in ("127.0.0.1", "localhost") else "::1"
        self._metrics_port = int(port or 0)
        return {"ok": True, "host": self._metrics_host, "port": self._metrics_port}

    def set_window_title(self, title: str = "") -> dict:
        title = (title or "").strip() or HUB_TITLE
        try:
            if self._window is not None:
                self._window.set_title(title)
            return {"ok": True, "title": title}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def get_app_version(self) -> dict:
        ver = hub_update.get_local_suite_version(_HUB_ROOT)
        return {
            "ok": True,
            "version": ver,
            "hubId": HUB_ID,
            "title": hub_update.title_with_version(HUB_TITLE, ver),
        }

        def list_crypto_donations(self) -> dict:
        return hub_update.list_crypto_donations()

    def copy_crypto_address(self, asset_id: str = "") -> dict:
        return hub_update.copy_crypto_address(asset_id)

    def open_support_url(self, kind: str = "") -> dict:
        return hub_update.open_support_url(kind)

    def get_update_check_pref(self) -> dict:
        enabled = hub_update.is_github_update_check_enabled()
        return {
            "ok": True,
            "checkGithubUpdates": enabled,
            "path": str(hub_update.user_settings_path()),
        }

    def set_update_check_pref(self, enabled: bool = True) -> dict:
        return hub_update.set_github_update_check(bool(enabled))

    def get_about_local_paths(self) -> dict:
        return hub_update.about_local_paths(_HUB_ROOT, hub_id=HUB_ID)

    def check_latest_release(self) -> dict:
        return hub_update.check_hub_release(HUB_ID, _HUB_ROOT)

    def open_release_page(self, url: str = "") -> dict:
        target = (url or "").strip()
        if not target:
            info = hub_update.check_hub_release(HUB_ID, _HUB_ROOT)
            target = str(info.get("releaseUrl") or "")
        return hub_update.open_release_url(target)

    def open_suite_app(self, name: str) -> dict:
        return launch_suite_app(name)

