/**
 * Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X
 */
/**
 * Hub-Securite FR/EN dictionaries + helpers.
 * Persist via suite user-settings (`language`: fr|en), not localStorage-only.
 */
const DICT = {
  fr: {
    langSwitchAria: "Langue",
    navHome: "Accueil",
    navFileGuard: "FileGuard",
    navCertView: "CertView",
    navRepoRadar: "RepoRadar",
    navWinAudit: "WinAudit",
    collapse: "Réduire",
    expand: "Étendre",
    collapseTitle: "Réduire la barre",
    expandTitle: "Étendre la barre",
    privacy:
      "100 % local-first. Seule connexion hors machine : vérif. version GitHub (si activée dans À propos). Sinon zéro réseau hors actions explicites des modules.",
    supportAria: "Soutien optionnel",
    supportNote: "Si le boulot te plaît, un café — sinon profite.",
    aboutBtn: "À propos",
    aboutTitle: "À propos — Hub Security",
    aboutIntro:
      "PC Command Security (Mr-Aurevo-X). FileGuard · CertView · RepoRadar · WinAudit. Gratuit, sans compte. Accueil lecture seule ; mutators ConfirmGate.",
    aboutLegalLocal: "100 % local-first — pas de télémétrie",
    aboutLegalGh: "Seule connexion hors machine : vérif. version GitHub (option ci-dessous)",
    aboutLegalOff: "Si vérif. désactivée : zéro réseau hors actions utilisateur (modules)",
    aboutToggle: "Vérifier les nouvelles versions sur GitHub",
    aboutHintOn:
      "Quand activé : un appel API GitHub au démarrage (lecture seule, pas de téléchargement).",
    aboutHintOff: "Désactivé : aucune requête GitHub. Local-first strict hors actions modules.",
    aboutRepoLabel: "Repo GitHub (releases)",
    aboutCopy: "Copier",
    aboutCopyUrlTitle: "Copier l’URL",
    aboutCopyPathTitle: "Copier le chemin",
    aboutCopiedLink: "Lien copié.",
    aboutCopiedPath: "Chemin copié.",
    aboutCopyFallback: "Sélectionne et Ctrl+C.",
    aboutCopied: "Copié.",
    aboutPathsTitle: "Chemins locaux (désinstall / ménage)",
    aboutPathsIntro:
      "Identifie clairement quoi supprimer. Les préférences Mr-Aurevo-X sont partagées entre apps.",
    aboutPathsAria: "Chemins locaux",
    aboutLegalAria: "Documents légaux",
    aboutLegalTerms: "CGU",
    aboutLegalPrivacy: "Confidentialité",
    aboutLegalMentions: "Mentions",
    aboutLegalNotices: "Notices",
    aboutCopyright: "Copyright © 2026 Mr-Aurevo-X — tous droits réservés",
    aboutRedistrib:
      "Redistribution, reverse engineering ou suppression du copyright interdits sans accord écrit.",
    aboutClose: "Fermer",
    aboutOptional: "(optionnel)",
    aboutPathFallback: "Chemin",
    aboutPathVersion: "Métadonnées / version",
    aboutPathSettings: "Préférences (accent, langue, vérif. maj)",
    aboutPathInstall: "Install (dossier de l’exe)",
    aboutPathVersionHint: "version.json et métadonnées suite.",
    aboutPathSettingsHint: "Fichier partagé Mr-Aurevo-X — à garder si d’autres apps l’utilisent.",
    aboutPathInstallHint: "Dossier réel de l’exe lancé (Bureau, USB, Downloads…) — à supprimer pour désinstaller.",
    aboutPathInstallHintMissing:
      "Emplacement typique après extraction du zip Releases (absent en mode Lancer.cmd / SoT).",
    aboutLegalLoadFail: "Impossible de charger {file}",
    releaseNew: "Nouvelle version",
    releaseOpen: "Ouvrir la release",
    releaseClose: "Fermer",
    releaseMsg: "Nouvelle version {ver} disponible",
    bootError: "Erreur au démarrage",
    dashTitle: "Accueil",
    dashBlurb: "PC Command — lecture seule · zéro mutator",
    dashLive: "LIVE",
    dashOff: "OFF",
    dashFirewall: "Firewall",
    dashFindings: "Findings",
    dashAudit: "Audit",
    dashGaugesAria: "Posture sécurité",
    dashMidAria: "Certificats et contexte",
    dashBottomAria: "État audit",
    dashQuickAria: "Accès rapide",
    dashModules: "Modules",
    dashOpen: "Ouvrir →",
    dashStatus:
      "100 % local-first · Accueil lecture seule · vérif. GitHub optionnelle (À propos) · zéro mutator · aucun scan auto.",
    dashCertsSoon: "Certs · expire <30j",
    dashCertsHint: "CurrentUser\\My",
    dashCertsOf: "sur {n} dans CurrentUser\\My",
    dashContext: "Contexte",
    dashContextEm: "UAC hérité · lecture seule",
    dashAuditState: "État audit",
    dashFwProfiles: "{on} / {total} profils",
    dashFwProfilesShort: "profils",
    dashFwDomain: "Domain · Private · Public",
    dashFindingsLast: "dernier audit",
    dashFindingsNone: "pas de cache",
    dashFindingsSub: "lecture seule · pas de scan",
    dashAuditLast: "dernier WinAudit",
    dashAuditNone: "aucun audit",
    dashAuditSub: "pas de scan au load",
    dashAuditAgeLt1: "<1j",
    dashAuditAgeDays: "{n}j",
    dashCachePresent: "Cache présent · {n} findings",
    dashCacheAge: " · il y a {n} j",
    dashCacheHint: "L’Accueil n’exécute aucun scan — ouvre WinAudit pour rafraîchir.",
    dashNoCache: "Aucun audit en cache",
    dashNoCacheHint: "Ouvre WinAudit pour un premier scan. L’Accueil n’exécute aucun scan.",
    dashChipFw: "Firewall {state}",
    dashChipFindings: "{n} findings",
    dashChipCerts: "{n} certs bientôt",
    modFileGuardDesc: "Verrous de fichiers, audit ACL NTFS, prise de possession",
    modCertViewDesc: "Certificats locaux — sujets, émetteurs, expirations",
    modRepoRadarDesc: "Scan repos Git locaux : branches, dirty, ahead/behind",
    modWinAuditDesc: "Audit OS heuristique lecture seule — score, findings",
    // ── WinAudit ──────────────────────────────────────────────────────────────
    waSegOverview: "Aperçu OS",
    waSegFindings: "Heuristique",
    waSegNetwork: "Réseau",
    waSegChains: "Chaînes",
    waSubtitle: "Audit OS heuristique — lecture seule",
    waScan: "Lancer le scan",
    waCancel: "Annuler le scan",
    waExport: "Exporter rapport",
    waExportTitle: "JSON · TXT · HTML",
    waPrint: "Rapport A4",
    waWlHint: "Un motif par ligne. Ex\u00a0: *\\Chrome\\* ou chrome|*\\chrome.exe — actif au prochain scan.",
    waWlClose: "Fermer",
    waWlSave: "Sauver",
    waWlSaved: "Whitelist sauvée ({n}) — {path}",
    waOverviewEmpty: "Lancez un scan pour cartographier les anomalies.",
    waScoreSain: "Sain",
    waScoreAcceptable: "Acceptable",
    waScoreSuspect: "Suspect",
    waScoreCritique: "Critique",
    waHealthLabel: "Santé machine",
    waKpiChains: "Chaînes",
    waKpiDuration: "Durée",
    waDiffNone: "Premier scan / pas de baseline.",
    waDiffSince: "{findings} finding(s), {conns} connexion(s) depuis {date}",
    waChartSeverity: "Sévérité",
    waChartCategories: "Catégories",
    waCatOther: "Autre",
    waChecklistTitle: "Checklist espionnage",
    waPrioritiesTitle: "Priorités",
    waChecklistUnavailable: "Checklist indisponible.",
    waNoCriticalChains: "Aucune chaîne critique.",
    waFindAllSev: "Toutes sévérités",
    waFindFilterPh: "Filtrer titre / chemin / catégorie\u2026",
    waFindThSev: "Sév.",
    waFindThCat: "Catégorie",
    waFindThTitle: "Titre",
    waFindThPath: "Chemin",
    waFindThWhy: "Pourquoi",
    waFindEmptyFilter: "Aucun finding correspondant.",
    waFindEmptyScan: "Lancez un scan.",
    waNetAll: "Toutes",
    waNetOutbound: "Sortantes",
    waNetListen: "Écoute",
    waNetSuspect: "Suspectes",
    waNetSearchPh: "Processus / IP / estimation\u2026",
    waNetRefresh: "Actualiser connexions",
    waNetOpenMap: "Voir en live (NetMap)",
    waNetThDir: "Dir.",
    waNetThProcess: "Processus",
    waNetThLocal: "Local",
    waNetThRemote: "Distant",
    waNetThEstimate: "Estimation",
    waNetThRisk: "Risque",
    waNetEmpty: "Aucune connexion.",
    waNetStats: "{n} connexions · {risk} à risque · affiché {shown}",
    waNetRefreshing: "Actualisation connexions\u2026",
    waNetRefreshed: "Connexions actualisées\u00a0: {n}",
    waNetMapApiMissing: "API open_suite_app indisponible.",
    waNetMapOpenFail: "Impossible d'ouvrir NetMap",
    waNetMapLaunchFail: "Échec ouverture NetMap",
    waNetMapUnavailable: "NetMap indisponible",
    waNetMapLaunched: "NetMap lancé.",
    waChainsEmpty: "Aucune chaîne — lancez un scan.",
    waTimelineTitle: "Timeline / diff baseline",
    waTimelineIntro: "Comparatif depuis le dernier scan (baseline).",
    waTimelineNeedScan: "Le comparatif apparaîtra après un scan.",
    waTimelineNoSummary: "Pas de résumé diff.",
    waTimelineNoNew: "Aucun nouveau finding depuis la baseline.",
    waLogClear: "Effacer",
    waReadyReadonly: "Prêt — lecture seule",
    waReady: "Prêt",
    waApiMissing: "API winaudit indisponible",
    waApiStartMissing: "API winaudit.start_scan indisponible",
    waApiRunMissing: "winaudit.run indisponible",
    waApiError: "Erreur API",
    waScanStarting: "Démarrage\u2026",
    waScanStartLog: "Démarrage du scan complet\u2026",
    waScanRunning: "Scan en cours\u2026",
    waScanStartDenied: "Démarrage refusé",
    waScanProgress: "{pct}% · {phase}{detail}",
    waScanCancelledLog: "Scan annulé — dernier scan conservé.",
    waScanCancelled: "Annulé",
    waScanLoading: "Chargement du résultat\u2026",
    waScanResultMissing: "Résultat indisponible",
    waScanOkLog: "Scan OK — score {score}/100 ({label}) · {n} findings · {dur}s",
    waHtmlReportLog: "Rapport HTML\u00a0: {path}",
    waReadyScore: "Prêt — score {score}/100",
    waErrorPrefix: "Erreur\u00a0: {msg}",
    waCancelRequested: "Annulation demandée\u2026",
    waExportNone: "Aucun scan à exporter",
    waExportA4Busy: "Génération rapport A4\u2026",
    waExportBusy: "Export rapport\u2026",
    waExportA4Log: "Rapport A4\u00a0: {path}",
    waExportHtmlLog: "Export HTML\u00a0: {path}",
    waExportJsonLog: "Export JSON\u00a0: {path}",
    waExportTxtLog: "Export TXT\u00a0: {path}",
    waExportDone: "Prêt — rapport généré",
    waExportFail: "Export échoué",
    waAdminRights: "droits admin",
    waLimitedRights: "droits limités",
    waReadyAdmin: "Prêt — {rights}",
    waLastReloadLog: "Dernier scan rechargé — score {score}/100 ({label}).",
    waLastScanStatus: "Dernier scan — score {score}/100",
    waChartJsMissing: "Chart.js introuvable (ui/vendor/chart.umd.min.js)",
    // ── Common ────────────────────────────────────────────────────────────────
    confirmTitle: "Confirmer",
    confirmOk: "Confirmer",
    confirmCancel: "Annuler",
    commonLoading: "Chargement\u2026",
    commonReady: "Prêt",
    commonFail: "Échec",
    commonError: "Erreur\u00a0: {err}",
    commonYes: "Oui",
    commonNo: "Non",
    commonPathRequired: "Chemin requis.",
    commonAnalyzing: "Analyse\u2026",
    commonPreparing: "Préparation\u2026",
    // ── FileGuard ─────────────────────────────────────────────────────────────
    fgSubtitle: "Verrous · ACL NTFS · ownership",
    fgSegLocks: "Verrous",
    fgSegPerms: "Permissions",
    fgFilePh: "C:\\…\\fichier",
    fgFolderPh: "C:\\…\\dossier",
    fgBrowse: "Parcourir",
    fgAnalyze: "Analyser",
    fgThProcess: "Processus",
    fgThSource: "Source",
    fgLockEmpty: "Aucun verrou détecté.",
    fgLockMeta: "{n} processus · {method}",
    fgTakeown: "Prendre possession",
    fgThIdentity: "Identité",
    fgThRights: "Droits",
    fgThType: "Type",
    fgThInherited: "Hérité",
    fgPermEmpty: "Aucune entrée ACL.",
    fgOwner: "Propriétaire : {owner}",
    fgApiMissing: "API fileguard indisponible.",
    fgTakeownConfirm:
      "Prendre possession récursivement ? Cette opération remplace les ACL actuelles par votre compte.",
    fgConfirmDenied: "Confirmation refusée",
    fgTakeownOk: "Possession prise.",
    // ── CertView ──────────────────────────────────────────────────────────────
    cvSubtitle: "Certificats CurrentUser\\My — lecture seule",
    cvFilterPh: "Filtrer sujet / émetteur / empreinte…",
    cvRefresh: "Rafraîchir",
    cvThSubject: "Sujet",
    cvThIssuer: "Émetteur",
    cvThExpiry: "Expiration",
    cvThThumb: "Empreinte",
    cvEmpty: "Aucun certificat.",
    cvMeta: "{shown} / {total} certificat(s)",
    cvApiMissing: "API certview indisponible.",
    // ── RepoRadar ─────────────────────────────────────────────────────────────
    rrSubtitle: "Repos Git locaux — branches, dirty, ahead/behind",
    rrFilterPh: "Filtrer nom / branche / chemin…",
    rrDirtyOnly: "Dirty seulement",
    rrScan: "Scanner",
    rrRootsLabel: "Racines (une par ligne) :",
    rrThName: "Nom / Chemin",
    rrThBranch: "Branche",
    rrThStatus: "Statut",
    rrThSync: "Sync",
    rrThLast: "Dernier commit",
    rrThActions: "Actions",
    rrEmpty: "Aucun repo trouvé — lancez un scan.",
    rrApiMissing: "API reporadar indisponible.",
    rrScanning: "Scan en cours…",
    rrReady: "Prêt — {n} repos · {dirty} dirty",
    rrOpen: "Ouvrir",
    rrFetchBusy: "fetch…",
    rrFetchOk: "fetch OK",
    rrFetchFail: "fetch fail",
    // ── WinAudit checklist (backend Ids) ──────────────────────────────────────
    waCkStatusOK: "OK",
    waCkStatusAttention: "Attention",
    waCkStatusCritique: "Critique",
    waCkVerdictHigh: "Risque élevé — investiguer les points Critical.",
    waCkVerdictWarn: "Points d'attention — vérifier les éléments marqués.",
    waCkVerdictOk: "Aucun signal fort d'espionnage sur les checks automatiques.",
    waCkQremote: "Outils de prise de contrôle à distance ?",
    waCkQrdp: "Bureau à distance (RDP) ouvert ?",
    waCkQdivert: "Trafic web détourné (hosts / proxy) ?",
    waCkQlisten: "Ports en écoute inhabituels ?",
    waCkQtempnet: "Exécutable sensible + connexion réseau ?",
    waCkQdefender: "Exclusions Windows Defender douteuses ?",
    waCkQwmi: "Persistance WMI furtive ?",
    waCkQifeo: "Hijack IFEO / AppInit_DLLs ?",
  },
  en: {
    langSwitchAria: "Language",
    navHome: "Home",
    navFileGuard: "FileGuard",
    navCertView: "CertView",
    navRepoRadar: "RepoRadar",
    navWinAudit: "WinAudit",
    collapse: "Collapse",
    expand: "Expand",
    collapseTitle: "Collapse sidebar",
    expandTitle: "Expand sidebar",
    privacy:
      "100% local-first. Only outbound connection: optional GitHub version check (About). Otherwise no network except explicit module actions.",
    supportAria: "Optional support",
    supportNote: "If you like the work, a coffee — otherwise just enjoy.",
    aboutBtn: "About",
    aboutTitle: "About — Hub Security",
    aboutIntro:
      "PC Command Security (Mr-Aurevo-X). FileGuard · CertView · RepoRadar · WinAudit. Free, no account. Home is read-only; mutators use ConfirmGate.",
    aboutLegalLocal: "100% local-first — no telemetry",
    aboutLegalGh: "Only outbound connection: GitHub version check (option below)",
    aboutLegalOff: "If check is off: zero network except user module actions",
    aboutToggle: "Check for new versions on GitHub",
    aboutHintOn:
      "When on: one GitHub API call at startup (read-only, no download).",
    aboutHintOff: "Off: no GitHub requests. Strict local-first outside module actions.",
    aboutRepoLabel: "GitHub repo (releases)",
    aboutCopy: "Copy",
    aboutCopyUrlTitle: "Copy URL",
    aboutCopyPathTitle: "Copy path",
    aboutCopiedLink: "Link copied.",
    aboutCopiedPath: "Path copied.",
    aboutCopyFallback: "Select and Ctrl+C.",
    aboutCopied: "Copied.",
    aboutPathsTitle: "Local paths (uninstall / cleanup)",
    aboutPathsIntro: "Clear labels for what to remove. Mr-Aurevo-X prefs are shared across apps.",
    aboutPathsAria: "Local paths",
    aboutLegalAria: "Legal documents",
    aboutLegalTerms: "Terms",
    aboutLegalPrivacy: "Privacy",
    aboutLegalMentions: "Legal notice",
    aboutLegalNotices: "Notices",
    aboutCopyright: "Copyright © 2026 Mr-Aurevo-X — all rights reserved",
    aboutRedistrib:
      "Redistribution, reverse engineering, or copyright removal forbidden without written consent.",
    aboutClose: "Close",
    aboutOptional: "(optional)",
    aboutPathFallback: "Path",
    aboutPathVersion: "Metadata / version",
    aboutPathSettings: "Preferences (accent, language, update check)",
    aboutPathInstall: "Install (exe folder)",
    aboutPathVersionHint: "version.json and suite metadata.",
    aboutPathSettingsHint: "Shared Mr-Aurevo-X file — keep if other apps still use it.",
    aboutPathInstallHint: "Real folder of the running exe (Desktop, USB, Downloads…) — delete to uninstall.",
    aboutPathInstallHintMissing:
      "Typical location after extracting the Releases zip (missing in Lancer.cmd / SoT mode).",
    aboutLegalLoadFail: "Could not load {file}",
    releaseNew: "New version",
    releaseOpen: "Open release",
    releaseClose: "Close",
    releaseMsg: "New version {ver} available",
    bootError: "Startup error",
    dashTitle: "Home",
    dashBlurb: "PC Command — read-only · zero mutators",
    dashLive: "LIVE",
    dashOff: "OFF",
    dashFirewall: "Firewall",
    dashFindings: "Findings",
    dashAudit: "Audit",
    dashGaugesAria: "Security posture",
    dashMidAria: "Certificates and context",
    dashBottomAria: "Audit state",
    dashQuickAria: "Quick access",
    dashModules: "Modules",
    dashOpen: "Open →",
    dashStatus:
      "100% local-first · Home read-only · optional GitHub check (About) · zero mutators · no auto scan.",
    dashCertsSoon: "Certs · expire <30d",
    dashCertsHint: "CurrentUser\\My",
    dashCertsOf: "of {n} in CurrentUser\\My",
    dashContext: "Context",
    dashContextEm: "Inherited UAC · read-only",
    dashAuditState: "Audit state",
    dashFwProfiles: "{on} / {total} profiles",
    dashFwProfilesShort: "profiles",
    dashFwDomain: "Domain · Private · Public",
    dashFindingsLast: "last audit",
    dashFindingsNone: "no cache",
    dashFindingsSub: "read-only · no scan",
    dashAuditLast: "last WinAudit",
    dashAuditNone: "no audit",
    dashAuditSub: "no scan on load",
    dashAuditAgeLt1: "<1d",
    dashAuditAgeDays: "{n}d",
    dashCachePresent: "Cache present · {n} findings",
    dashCacheAge: " · {n} d ago",
    dashCacheHint: "Home never scans — open WinAudit to refresh.",
    dashNoCache: "No audit in cache",
    dashNoCacheHint: "Open WinAudit for a first scan. Home never runs a scan.",
    dashChipFw: "Firewall {state}",
    dashChipFindings: "{n} findings",
    dashChipCerts: "{n} certs soon",
    modFileGuardDesc: "File locks, NTFS ACL audit, take ownership",
    modCertViewDesc: "Local certificates — subjects, issuers, expirations",
    modRepoRadarDesc: "Local Git repos: branches, dirty, ahead/behind",
    modWinAuditDesc: "Read-only OS heuristic audit — score, findings",
    // ── WinAudit ──────────────────────────────────────────────────────────────
    waSegOverview: "OS overview",
    waSegFindings: "Heuristics",
    waSegNetwork: "Network",
    waSegChains: "Chains",
    waSubtitle: "Heuristic OS audit — read-only",
    waScan: "Start scan",
    waCancel: "Cancel scan",
    waExport: "Export report",
    waExportTitle: "JSON · TXT · HTML",
    waPrint: "A4 report",
    waWlHint: "One pattern per line. E.g. *\\Chrome\\* or chrome|*\\chrome.exe — applies on the next scan.",
    waWlClose: "Close",
    waWlSave: "Save",
    waWlSaved: "Whitelist saved ({n}) — {path}",
    waOverviewEmpty: "Run a scan to map anomalies.",
    waScoreSain: "Healthy",
    waScoreAcceptable: "Acceptable",
    waScoreSuspect: "Suspicious",
    waScoreCritique: "Critical",
    waHealthLabel: "Machine health",
    waKpiChains: "Chains",
    waKpiDuration: "Duration",
    waDiffNone: "First scan / no baseline.",
    waDiffSince: "{findings} finding(s), {conns} connection(s) since {date}",
    waChartSeverity: "Severity",
    waChartCategories: "Categories",
    waCatOther: "Other",
    waChecklistTitle: "Spyware checklist",
    waPrioritiesTitle: "Priorities",
    waChecklistUnavailable: "Checklist unavailable.",
    waNoCriticalChains: "No critical chains.",
    waFindAllSev: "All severities",
    waFindFilterPh: "Filter title / path / category\u2026",
    waFindThSev: "Sev.",
    waFindThCat: "Category",
    waFindThTitle: "Title",
    waFindThPath: "Path",
    waFindThWhy: "Why",
    waFindEmptyFilter: "No matching finding.",
    waFindEmptyScan: "Run a scan.",
    waNetAll: "All",
    waNetOutbound: "Outbound",
    waNetListen: "Listen",
    waNetSuspect: "Suspicious",
    waNetSearchPh: "Process / IP / estimate\u2026",
    waNetRefresh: "Refresh connections",
    waNetOpenMap: "View live (NetMap)",
    waNetThDir: "Dir.",
    waNetThProcess: "Process",
    waNetThLocal: "Local",
    waNetThRemote: "Remote",
    waNetThEstimate: "Estimate",
    waNetThRisk: "Risk",
    waNetEmpty: "No connections.",
    waNetStats: "{n} connections · {risk} at risk · showing {shown}",
    waNetRefreshing: "Refreshing connections\u2026",
    waNetRefreshed: "Connections refreshed: {n}",
    waNetMapApiMissing: "open_suite_app API unavailable.",
    waNetMapOpenFail: "Unable to open NetMap",
    waNetMapLaunchFail: "Failed to open NetMap",
    waNetMapUnavailable: "NetMap unavailable",
    waNetMapLaunched: "NetMap launched.",
    waChainsEmpty: "No chains — run a scan.",
    waTimelineTitle: "Timeline / baseline diff",
    waTimelineIntro: "Comparison since the last scan (baseline).",
    waTimelineNeedScan: "The comparison will appear after a scan.",
    waTimelineNoSummary: "No diff summary.",
    waTimelineNoNew: "No new findings since baseline.",
    waLogClear: "Clear",
    waReadyReadonly: "Ready — read-only",
    waReady: "Ready",
    waApiMissing: "winaudit API unavailable",
    waApiStartMissing: "winaudit.start_scan API unavailable",
    waApiRunMissing: "winaudit.run unavailable",
    waApiError: "API error",
    waScanStarting: "Starting\u2026",
    waScanStartLog: "Starting full scan\u2026",
    waScanRunning: "Scan in progress\u2026",
    waScanStartDenied: "Start refused",
    waScanProgress: "{pct}% · {phase}{detail}",
    waScanCancelledLog: "Scan cancelled — last scan kept.",
    waScanCancelled: "Cancelled",
    waScanLoading: "Loading result\u2026",
    waScanResultMissing: "Result unavailable",
    waScanOkLog: "Scan OK — score {score}/100 ({label}) · {n} findings · {dur}s",
    waHtmlReportLog: "HTML report: {path}",
    waReadyScore: "Ready — score {score}/100",
    waErrorPrefix: "Error: {msg}",
    waCancelRequested: "Cancellation requested\u2026",
    waExportNone: "No scan to export",
    waExportA4Busy: "Generating A4 report\u2026",
    waExportBusy: "Exporting report\u2026",
    waExportA4Log: "A4 report: {path}",
    waExportHtmlLog: "HTML export: {path}",
    waExportJsonLog: "JSON export: {path}",
    waExportTxtLog: "TXT export: {path}",
    waExportDone: "Ready — report generated",
    waExportFail: "Export failed",
    waAdminRights: "admin rights",
    waLimitedRights: "limited rights",
    waReadyAdmin: "Ready — {rights}",
    waLastReloadLog: "Last scan reloaded — score {score}/100 ({label}).",
    waLastScanStatus: "Last scan — score {score}/100",
    waChartJsMissing: "Chart.js not found (ui/vendor/chart.umd.min.js)",
    // ── Common ────────────────────────────────────────────────────────────────
    confirmTitle: "Confirm",
    confirmOk: "Confirm",
    confirmCancel: "Cancel",
    commonLoading: "Loading\u2026",
    commonReady: "Ready",
    commonFail: "Failed",
    commonError: "Error: {err}",
    commonYes: "Yes",
    commonNo: "No",
    commonPathRequired: "Path required.",
    commonAnalyzing: "Analyzing\u2026",
    commonPreparing: "Preparing\u2026",
    // ── FileGuard ─────────────────────────────────────────────────────────────
    fgSubtitle: "Locks · NTFS ACL · ownership",
    fgSegLocks: "Locks",
    fgSegPerms: "Permissions",
    fgFilePh: "C:\\…\\file",
    fgFolderPh: "C:\\…\\folder",
    fgBrowse: "Browse",
    fgAnalyze: "Analyze",
    fgThProcess: "Process",
    fgThSource: "Source",
    fgLockEmpty: "No lock detected.",
    fgLockMeta: "{n} processes · {method}",
    fgTakeown: "Take ownership",
    fgThIdentity: "Identity",
    fgThRights: "Rights",
    fgThType: "Type",
    fgThInherited: "Inherited",
    fgPermEmpty: "No ACL entry.",
    fgOwner: "Owner: {owner}",
    fgApiMissing: "fileguard API unavailable.",
    fgTakeownConfirm:
      "Take ownership recursively? This replaces current ACLs with your account.",
    fgConfirmDenied: "Confirmation denied",
    fgTakeownOk: "Ownership taken.",
    // ── CertView ──────────────────────────────────────────────────────────────
    cvSubtitle: "Certificates CurrentUser\\My — read-only",
    cvFilterPh: "Filter subject / issuer / thumbprint…",
    cvRefresh: "Refresh",
    cvThSubject: "Subject",
    cvThIssuer: "Issuer",
    cvThExpiry: "Expiration",
    cvThThumb: "Thumbprint",
    cvEmpty: "No certificate.",
    cvMeta: "{shown} / {total} certificate(s)",
    cvApiMissing: "certview API unavailable.",
    // ── RepoRadar ─────────────────────────────────────────────────────────────
    rrSubtitle: "Local Git repos — branches, dirty, ahead/behind",
    rrFilterPh: "Filter name / branch / path…",
    rrDirtyOnly: "Dirty only",
    rrScan: "Scan",
    rrRootsLabel: "Roots (one per line):",
    rrThName: "Name / Path",
    rrThBranch: "Branch",
    rrThStatus: "Status",
    rrThSync: "Sync",
    rrThLast: "Last commit",
    rrThActions: "Actions",
    rrEmpty: "No repo found — run a scan.",
    rrApiMissing: "reporadar API unavailable.",
    rrScanning: "Scan in progress…",
    rrReady: "Ready — {n} repos · {dirty} dirty",
    rrOpen: "Open",
    rrFetchBusy: "fetch…",
    rrFetchOk: "fetch OK",
    rrFetchFail: "fetch fail",
    // ── WinAudit checklist (backend Ids) ──────────────────────────────────────
    waCkStatusOK: "OK",
    waCkStatusAttention: "Warning",
    waCkStatusCritique: "Critical",
    waCkVerdictHigh: "Elevated risk — investigate Critical items.",
    waCkVerdictWarn: "Attention points — review marked items.",
    waCkVerdictOk: "No strong spyware signal on automatic checks.",
    waCkQremote: "Remote-control tools present?",
    waCkQrdp: "Remote Desktop (RDP) open?",
    waCkQdivert: "Web traffic diverted (hosts / proxy)?",
    waCkQlisten: "Unusual listening ports?",
    waCkQtempnet: "Sensitive executable + network connection?",
    waCkQdefender: "Suspicious Windows Defender exclusions?",
    waCkQwmi: "Stealthy WMI persistence?",
    waCkQifeo: "IFEO / AppInit_DLLs hijack?",
  },
};

let lang = "fr";
const listeners = new Set();

function pack() {
  return DICT[lang] || DICT.fr;
}

export function getLang() {
  return lang === "en" ? "en" : "fr";
}

export function locale() {
  return getLang() === "en" ? "en-US" : "fr-FR";
}

export function t(key, vars) {
  const p = pack();
  let s = p[key];
  if (s == null) s = DICT.fr[key];
  if (s == null) return key;
  if (vars && typeof vars === "object") {
    for (const [k, v] of Object.entries(vars)) {
      s = String(s).split(`{${k}}`).join(String(v));
    }
  }
  return s;
}

export function applyDom(root) {
  if (typeof document === "undefined") return;
  const scope = root || document;
  const p = pack();
  document.documentElement.lang = getLang() === "en" ? "en" : "fr";
  scope.querySelectorAll("[data-i18n]").forEach((node) => {
    const key = node.getAttribute("data-i18n");
    if (key && p[key] != null) node.textContent = p[key];
  });
  scope.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    const key = node.getAttribute("data-i18n-placeholder");
    if (key && p[key] != null) node.setAttribute("placeholder", p[key]);
  });
  scope.querySelectorAll("[data-i18n-title]").forEach((node) => {
    const key = node.getAttribute("data-i18n-title");
    if (key && p[key] != null) node.setAttribute("title", p[key]);
  });
  scope.querySelectorAll("[data-i18n-aria]").forEach((node) => {
    const key = node.getAttribute("data-i18n-aria");
    if (key && p[key] != null) node.setAttribute("aria-label", p[key]);
  });
  if (window.MrAurevoXSuite && typeof window.MrAurevoXSuite.applyI18n === "function") {
    try {
      window.MrAurevoXSuite.applyI18n(getLang(), DICT);
    } catch (_) {}
  }
}

export function setLang(next, { silent = false } = {}) {
  const n = next === "en" ? "en" : "fr";
  if (n === lang && silent) {
    applyDom();
    return lang;
  }
  lang = n;
  applyDom();
  if (!silent) {
    listeners.forEach((fn) => {
      try {
        fn(lang);
      } catch (_) {}
    });
  }
  return lang;
}

export function onLangChange(fn) {
  if (typeof fn !== "function") return () => {};
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function legalFile(base) {
  const b = String(base || "")
    .replace(/\.fr\.md$/i, "")
    .replace(/\.en\.md$/i, "")
    .replace(/\.md$/i, "");
  return `${b}.${getLang() === "en" ? "en" : "fr"}.md`;
}

export function pathLabelFor(entry) {
  const id = entry?.id || "";
  const map = {
    version: "aboutPathVersion",
    settings: "aboutPathSettings",
    app: "aboutPathInstall",
  };
  const key = map[id];
  if (key) return t(key);
  return entry?.label || t("aboutPathFallback");
}

export function pathHintFor(entry) {
  const id = entry?.id || "";
  if (id === "app" && entry?.optional) {
    return t("aboutPathInstallHintMissing");
  }
  const map = {
    version: "aboutPathVersionHint",
    settings: "aboutPathSettingsHint",
    app: "aboutPathInstallHint",
  };
  const key = map[id];
  if (key) return t(key);
  return entry?.hint || "";
}

export { DICT };

if (typeof window !== "undefined") {
  window.HubI18n = { t, getLang, setLang, locale, applyDom, onLangChange, legalFile, DICT };
}
