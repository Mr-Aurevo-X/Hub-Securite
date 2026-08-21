[Français](README.md) · [English](README.en.md)

# PC Command | Security

**Security** hub — files, certificates, repos, Windows audit. Posture Home (firewall / findings), native modules.  
**Free for life** · **as local as possible** · PolyForm Noncommercial 1.0.0 · **Mr-Aurevo-X**

## Preview

| Home | WinAudit |
|------|----------|
| ![Home](docs/screenshots/dashboard.png) | ![WinAudit](docs/screenshots/winaudit.png) |

## Modules

| Module | Role |
|--------|------|
| FileGuard | File integrity / guard |
| CertView | Certificates |
| RepoRadar | Local repos · inspect · git Fetch (when you run it) |
| **WinAudit** | Windows audit · score · findings |

## Why this hub

- **Free for life** — no subscription, no account
- **As local as possible** — FileGuard, CertView and WinAudit stay on your machine
- **Unused module = no egress** ; only voluntary module egress: **RepoRadar → Fetch** to **your repos’** git remotes (if you click)
- Only suite option: GitHub version check — **opt-out** in About
- Confirmation before system actions · FR | EN · read-only posture Home

## On your PC

| What | Where |
|------|-------|
| **App** (`Launch-Hub-Securite.zip`) | Portable folder — extract, run `Launch-Hub-Securite.exe` |
| Metadata / version | `%LOCALAPPDATA%\PCCommand\` |
| Prefs (language, updates…) | `%LOCALAPPDATA%\Mr-Aurevo-X\user-settings.json` (shared across apps) |

Download: [Hub-Securite Releases](https://github.com/Mr-Aurevo-X/Hub-Securite/releases) · tag **v2.0.0**

## Launch

1. Download the zip from the official **Release**  
2. Extract anywhere  
3. Run `Launch-Hub-Securite.exe` (UAC admin)

Windows may show “potentially unwanted”: binaries are **not** Authenticode-signed. That is **SmartScreen** (reputation), not an antivirus verdict.

## Disclaimer — official builds only

The **only** sources and binaries I stand behind are those published at:

**https://github.com/Mr-Aurevo-X/Hub-Securite** (this repository’s Releases / tags).

Any **fork**, copy, rebuild, or third-party modified redistribution is **not** an official Mr-Aurevo-X build, is **not** reviewed, and may include changes (including URLs or network behavior) **outside my control**.

I accept **no liability** for damage, data loss, or incidents arising from unofficial builds, misuse, or a compromised machine.

Software provided **as is**, without warranty — see `LICENSE` (PolyForm Noncommercial 1.0.0). Use at your own risk.

## Legal

`PRIVACY.md` · `LICENSE`

## Support (optional)

If you like the work, a coffee — otherwise just enjoy.

[![Discord](https://img.shields.io/badge/Discord-Mr--Aurevo--X-5865F2?style=for-the-badge&logo=discord&logoColor=white&labelColor=050807)](https://discord.com/users/406891052516114442)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-39ff14?style=for-the-badge&logo=paypal&logoColor=00f0ff&labelColor=050807)](https://www.paypal.com/paypalme/aurevo1)
[![Revolut](https://img.shields.io/badge/Revolut-mr__aurevo__x-00f0ff?style=for-the-badge&logo=revolut&logoColor=39ff14&labelColor=050807)](https://revolut.me/mr_aurevo_x)

---

Dreamed by **Mr-Aurevo-X**. Cursor made the dream real.
