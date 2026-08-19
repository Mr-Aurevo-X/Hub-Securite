# Hub-Securite — L'Atelier PC Command

Hub catégorie — Couche B + H7 native + flatten `host.py` / `backend/`.

## Aperçu

| Accueil | Module |
|---------|--------|
| ![Dashboard](docs/screenshots/dashboard.png) | ![WinAudit](docs/screenshots/winaudit.png) |

## Modules

| Module | Rôle |
|--------|------|
| FileGuard | Ownership / garde fichiers |
| CertView | Certificats |
| RepoRadar | Scan repos |
| WinAudit | Audit OS read-only |

## Lancer

```bat
Lancer.cmd
```

Nécessite Python + `pywebview` (+ deps hub). Admin hérité du launcher ; UAC aussi dans `main()`.

## Structure

```text
host.py                 # entry + UAC + webview
backend/
  bridge.py             # Api + namespaces
  security.py / window_chrome.py / suite_launch.py
  tools/                # logique métier
ui/                     # pas de ui/embedded/
```

Titres HWND : `L'Atelier PC Command — Sécurité` / `[Module|Segment]`.

`_source_apps/` = clones référence des anciennes mini-apps (non shippés). SoT runtime = `backend/tools/`.
