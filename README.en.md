[Français](README.md) · [English](README.en.md)

# PC Command | Security

**Security** hub — files, certificates, repos, Windows audit. Posture Home (firewall / findings), native modules.  
**Void Glow** · **local-first** (optional GitHub check) · PolyForm Noncommercial 1.0.0 · **Mr-Aurevo-X**

## Preview

| Home | WinAudit |
|------|----------|
| ![Home](docs/screenshots/dashboard.png) | ![WinAudit](docs/screenshots/winaudit.png) |

## Modules

| Module | Role |
|--------|------|
| FileGuard | File integrity / guard |
| CertView | Certificates |
| RepoRadar | Repos & surfaces |
| **WinAudit** | Windows audit · findings · ConfirmGate |

## Why this hub

- **Read-only** posture Home — no dashboard mutators
- ConfirmGate on system-touching actions
- FR | EN · support · About (Terms / Privacy / Legal notice / Notices)

## Where it lives

| Mode | Location |
|------|----------|
| **Release** (`Launch-Hub-Securite.zip`) | **Portable** folder — `Launch-Hub-Securite.exe` |
| Metadata / version | `%LOCALAPPDATA%\PCCommand\` |
| Prefs | `%LOCALAPPDATA%\Mr-Aurevo-X\user-settings.json` (shared) |
| Dev | Clone + `Lancer.cmd` |

Download: [Hub-Securite Releases](https://github.com/Mr-Aurevo-X/Hub-Securite/releases) · tag **v2.0.0**

## Launch

```bat
Lancer.cmd
```

Windows may show “potentially unwanted”: binaries are **not** Authenticode-signed (no paid publisher cert). That is a **SmartScreen** reputation warning, not an antivirus verdict.

HWND title: `PC Command | Security` / `[Module]`. See `PRIVACY.md` · `ISOLATION.md` · `LICENSE`.

---

Dreamed by **Mr-Aurevo-X**. Cursor made the dream real.

[![Discord](https://img.shields.io/badge/Discord-Mr--Aurevo--X-5865F2?style=for-the-badge&logo=discord&logoColor=white&labelColor=050807)](https://discord.com/users/406891052516114442)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-39ff14?style=for-the-badge&logo=paypal&logoColor=00f0ff&labelColor=050807)](https://www.paypal.com/paypalme/aurevo1)
[![Revolut](https://img.shields.io/badge/Revolut-mr__aurevo__x-00f0ff?style=for-the-badge&logo=revolut&logoColor=39ff14&labelColor=050807)](https://revolut.me/mr_aurevo_x)
