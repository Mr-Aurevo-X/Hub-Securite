[Français](README.md) · [English](README.en.md)

# PC Command | Security

Hub **Sécurité** — fichiers, certificats, repos, audit Windows. Accueil posture (firewall / findings), modules natifs.  
**Gratuit à vie** · **autant local que possible** · PolyForm Noncommercial 1.0.0 · **Mr-Aurevo-X**

## Aperçu

| Accueil | WinAudit |
|---------|----------|
| ![Accueil](docs/screenshots/dashboard.png) | ![WinAudit](docs/screenshots/winaudit.png) |

## Modules

| Module | Rôle |
|--------|------|
| FileGuard | Garde-fichiers / intégrité |
| CertView | Certificats |
| RepoRadar | Repos locaux · inspect · Fetch git (si tu lances) |
| **WinAudit** | Audit Windows · score · findings |

## Pourquoi ce hub

- **Gratuit à vie** — pas d’abonnement, pas de compte
- **Autant local que possible** — FileGuard, CertView et WinAudit restent sur ta machine
- **Module pas utilisé = pas de sortie** ; seule sortie module volontaire : **RepoRadar → Fetch** vers les remotes git **de tes repos** (si tu cliques)
- Seule option « suite » : vérif. GitHub **désactivable** dans À propos
- Confirmation avant action système · FR | EN · Accueil posture lecture seule

## Sur ton PC

| Quoi | Où |
|------|-----|
| **App** (`Launch-Hub-Securite.zip`) | Dossier portable — extrais, lance `Launch-Hub-Securite.exe` |
| Métadonnées / version | `%LOCALAPPDATA%\PCCommand\` |
| Préférences (langue, maj…) | `%LOCALAPPDATA%\Mr-Aurevo-X\user-settings.json` (partagé entre apps) |

Téléchargement : [Releases Hub-Securite](https://github.com/Mr-Aurevo-X/Hub-Securite/releases) · tag **v2.0.0**

## Lancer

1. Télécharge le zip de la **Release** officielle  
2. Extrais où tu veux  
3. Lance `Launch-Hub-Securite.exe` (UAC admin)

Windows peut afficher « potentiellement dangereux » : binaires **non signés** Authenticode. C’est **SmartScreen** (réputation), pas un verdict antivirus.

## Avertissement — builds officiels uniquement

Les binaires et sources **faisant foi** sont uniquement ceux publiés sur :

**https://github.com/Mr-Aurevo-X/Hub-Securite** (Releases / tags de ce dépôt).

Tout **fork**, copie, rebuild ou redistribution **modifiée** par un tiers n’est **pas** une version Mr-Aurevo-X, n’est **pas** vérifiée, et peut contenir des changements (y compris des URL ou comportements réseau) **hors de mon contrôle**.

Je décline toute responsabilité quant aux dommages, pertes de données ou incidents liés à une version **non officielle**, à une mauvaise utilisation, ou à un environnement compromis.

Logiciel fourni **tel quel**, sans garantie — voir `LICENSE` (PolyForm Noncommercial 1.0.0). Utilisation à tes risques.

## Legal

`PRIVACY.md` · `LICENSE`

## Soutien (optionnel)

Si le boulot te plaît, un café — sinon profite.

[![Discord](https://img.shields.io/badge/Discord-Mr--Aurevo--X-5865F2?style=for-the-badge&logo=discord&logoColor=white&labelColor=050807)](https://discord.com/users/406891052516114442)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-39ff14?style=for-the-badge&logo=paypal&logoColor=00f0ff&labelColor=050807)](https://www.paypal.com/paypalme/aurevo1)
[![Revolut](https://img.shields.io/badge/Revolut-mr__aurevo__x-00f0ff?style=for-the-badge&logo=revolut&logoColor=39ff14&labelColor=050807)](https://revolut.me/mr_aurevo_x)

---

Rêvée par **Mr-Aurevo-X**. Cursor a réalisé le rêve.
