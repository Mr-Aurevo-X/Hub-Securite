"""RepoRadar — multi-repo Git discovery / inspect / fetch."""
from __future__ import annotations

import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SKIP_DIR_NAMES = {
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".git",
    "archives",
    "backups",
    "done",
    "recovery",
}

_scan_lock = threading.Lock()
_scanning = False


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


def hub_app_dir() -> Path:
    # host/modules/reporadar/service.py → Hub-Securite/
    return Path(__file__).resolve().parents[3]


def default_roots() -> list[str]:
    suite = hub_app_dir().parent
    tree = suite.parent
    roots: list[str] = []
    for p in (suite, tree):
        if p.is_dir():
            roots.append(str(p))
    return roots


def _git(cwd: Path, *args: str, timeout: int = 20) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
        out = _decode_cli(proc.stdout).strip()
        err = _decode_cli(proc.stderr).strip()
        return proc.returncode, out if out else err
    except FileNotFoundError:
        return 127, "git introuvable"
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as exc:
        return 1, str(exc)


def discover_repos(roots: list[str], max_depth: int = 3) -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()

    def walk(base: Path, depth: int) -> None:
        if depth > max_depth or not base.is_dir():
            return
        git_dir = base / ".git"
        if git_dir.exists():
            key = str(base.resolve()).lower()
            if key not in seen:
                seen.add(key)
                found.append(base.resolve())
            return
        try:
            children = list(base.iterdir())
        except OSError:
            return
        for child in children:
            if not child.is_dir():
                continue
            if child.name in SKIP_DIR_NAMES or child.name.startswith("."):
                continue
            walk(child, depth + 1)

    for root in roots:
        p = Path(root)
        if p.is_dir():
            walk(p, 0)
    return sorted(found, key=lambda x: x.name.lower())


def inspect_repo(path: Path) -> dict[str, Any]:
    name = path.name
    branch = ""
    dirty = False
    ahead = 0
    behind = 0
    remote = ""
    last = ""
    ok = True
    error = ""

    rc, out = _git(path, "rev-parse", "--is-inside-work-tree")
    if rc != 0 or out.strip() != "true":
        return {
            "ok": False,
            "name": name,
            "path": str(path),
            "error": out or "pas un repo git",
        }

    rc, out = _git(path, "branch", "--show-current")
    branch = out if rc == 0 else "?"

    rc, out = _git(path, "status", "--porcelain")
    if rc == 0:
        dirty = bool(out.strip())
    else:
        ok = False
        error = out

    rc, out = _git(path, "remote", "get-url", "origin")
    if rc == 0:
        remote = out

    rc, out = _git(path, "log", "-1", "--format=%h %s (%cr)")
    if rc == 0:
        last = out

    rc, out = _git(path, "rev-list", "--left-right", "--count", "@{upstream}...HEAD")
    if rc == 0 and out:
        parts = out.split()
        if len(parts) >= 2:
            try:
                behind = int(parts[0])
                ahead = int(parts[1])
            except ValueError:
                pass

    return {
        "ok": ok,
        "name": name,
        "path": str(path),
        "branch": branch,
        "dirty": dirty,
        "ahead": ahead,
        "behind": behind,
        "remote": remote,
        "last": last,
        "error": error,
    }


def scan_repos(roots: list[str] | None = None, max_depth: int = 3) -> dict:
    global _scanning
    with _scan_lock:
        if _scanning:
            return {"ok": False, "error": "Scan deja en cours"}
        _scanning = True
    try:
        use_roots = [r for r in (roots or default_roots()) if str(r).strip()]
        if not use_roots:
            use_roots = default_roots()
        repos = discover_repos(use_roots, max_depth=max(1, min(int(max_depth or 3), 5)))
        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(inspect_repo, p): p for p in repos}
            for fut in as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    p = futs[fut]
                    results.append(
                        {
                            "ok": False,
                            "name": p.name,
                            "path": str(p),
                            "error": str(exc),
                        }
                    )
        results.sort(key=lambda r: (not r.get("dirty"), r.get("name", "").lower()))
        return {
            "ok": True,
            "count": len(results),
            "dirtyCount": sum(1 for r in results if r.get("dirty")),
            "repos": results,
            "roots": use_roots,
        }
    finally:
        with _scan_lock:
            _scanning = False


def open_folder(path: str) -> dict:
    p = Path(path or "")
    if not p.is_dir():
        return {"ok": False, "error": "Dossier introuvable"}
    try:
        os.startfile(str(p))  # type: ignore[attr-defined]
        return {"ok": True}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def fetch_repo(path: str) -> dict:
    p = Path(path or "")
    if not (p / ".git").exists():
        return {"ok": False, "error": "Pas un repo"}
    rc, out = _git(p, "fetch", "--all", "--prune", timeout=120)
    info = inspect_repo(p)
    info["fetchOk"] = rc == 0
    info["fetchOut"] = out
    return {"ok": rc == 0, "repo": info, "error": "" if rc == 0 else out}
