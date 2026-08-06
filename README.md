# Hub-Securite — L'Atelier PC Command

Hub catégorie **Sécurité** — **Vague H6-A Couche B** (fusion in-process).

## Modules

| Module | Source fusionnée | ConfirmGate |
|--------|------------------|-------------|
| FileGuard | FileGuard | take_ownership |
| CertView | CertView | — (lecture seule) |
| RepoRadar | RepoRadar | — (fetch git local) |
| WinAudit | WinAudit | — (audit lecture seule) |

Dashboard = KPIs lecture seule. Fallback « Fenêtre dédiée » via `suite_launch`.

## Lancer

```bat
Lancer.cmd
```

Nécessite `pywebview`.
