"""Hub-Securite namespace APIs — Couche B H6-A (in-process)."""
from __future__ import annotations

import ctypes
import sys
from pathlib import Path
from typing import Any

import webview

from modules.certview import service as mod_cert
from modules.fileguard import file_lock as mod_file_lock
from modules.fileguard import permission_audit as mod_perm
from modules.reporadar import service as mod_repo
from modules.winaudit.bridge import WinAuditBridge
from security import ConfirmGate
from suite_launch import launch_suite_app

_HOST = Path(__file__).resolve().parent
_MOD = _HOST / "modules"
if str(_HOST) not in sys.path:
    sys.path.insert(0, str(_HOST))


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
