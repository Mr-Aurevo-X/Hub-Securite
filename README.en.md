[Français](README.md) · [English](README.en.md)

# Hub-Securite — PC Command

**Read-only** distribution. No pull requests or issues (`CONTRIBUTING.md`).

**Security** hub. License: PolyForm Noncommercial 1.0.0. Publisher: **Mr-Aurevo-X**. Local-first, no publisher telemetry (`PRIVACY.md`).

## Overview

| Home | Module |
|---------|--------|
| ![Dashboard](docs/screenshots/dashboard.png) | ![WinAudit](docs/screenshots/winaudit.png) |

## Modules

| Module | Role |
|--------|------|
| FileGuard | File ownership / guard |
| CertView | Certificates |
| RepoRadar | Local repo scan |
| WinAudit | Read-only OS audit |

## Where it installs

| Mode | Location |
|------|----------|
| **Release** (`Launch-Hub-Securite.zip`) | **Portable** folder: extract anywhere, run `Launch-Hub-Securite.exe` from that folder. |
| **Version / stamp** | `%LOCALAPPDATA%\PCCommand\` |
| **Accent / language prefs** | `%LOCALAPPDATA%\Mr-Aurevo-X\user-settings.json` (if present) |
| **Dev (sources)** | Repo clone + `Lancer.cmd` |

Download: [Hub-Securite Releases](https://github.com/Mr-Aurevo-X/Hub-Securite/releases).

```bat
Lancer.cmd
```

Windows may flag the app as potentially unsafe: binaries are not Authenticode-signed (no paid publisher certificate). That is a SmartScreen reputation warning, not an antivirus verdict.

HWND titles: `PC Command | Security`. Isolation: `ISOLATION.md`.

---

Dreamed by **Mr-Aurevo-X**. Cursor made the dream real.

[![Discord](https://img.shields.io/badge/Discord-Mr--Aurevo--X-5865F2?style=for-the-badge&logo=discord&logoColor=white&labelColor=050807)](https://discord.com/users/406891052516114442)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-39ff14?style=for-the-badge&logo=paypal&logoColor=00f0ff&labelColor=050807)](https://www.paypal.com/paypalme/aurevo1)
[![Revolut](https://img.shields.io/badge/Revolut-mr__aurevo__x-00f0ff?style=for-the-badge&logo=revolut&logoColor=39ff14&labelColor=050807)](https://revolut.me/mr_aurevo_x)
