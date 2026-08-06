/* WinAudit UI — bridge pywebview + Chart.js (style WinCleaner) */
(function () {
  "use strict";

  const SUITE_I18N = {
    fr: {
      tagline: "Scan only",
      copyright: "© 2026 Mr-Aurevo-X · local · CGU dans L'Atelier PC Command",
      featuresTitle: "Fonctions",
      features: "Audit heuristique local en lecture seule : score, findings, réseau, chaînes et timeline.",
      privacy: "Mr-Aurevo-X ne collecte aucune donnée. Analyse locale en lecture seule. Aucun envoi de résultats.",
      ready: "Prêt — lecture seule",
      navOverview: "Overview",
      navFindings: "Findings",
      navNetwork: "Réseau",
      navChains: "Chaînes",
      navTimeline: "Timeline",
      pageOverviewSub: "Score, checklist espionnage et priorités",
      pageFindingsSub: "Tous les signaux heuristiques (lecture seule)",
      pageNetworkSub: "Connexions TCP/UDP — actualisation live",
      pageChainsSub: "Corrélations multi-vecteurs",
      pageTimelineSub: "Diff depuis le dernier scan (baseline)",
      btnScan: "Lancer le scan",
      btnCancel: "Annuler le scan",
      btnExport: "Exporter rapport",
      btnPrint: "Rapport A4",
      btnWhitelist: "Whitelist",
      btnRefreshNet: "Actualiser connexions",
      btnOpenNetMap: "Voir en live (NetMap)",
      btnClear: "Effacer",
      btnSave: "Sauver",
      btnClose: "Fermer",
      lblScore: "Score",
      waiting: "En attente",
      subFindings: "signaux détectés",
      subChains: "corrélations",
      subDuration: "dernier scan",
      machineHealth: "Santé machine",
      scanHint: "Lancez un scan pour cartographier les anomalies.",
      checklistTitle: "Checklist espionnage",
      prioTitle: "Priorités",
      emptyChecklist: "Lancez un scan.",
      emptyPrio: "Les chaînes critiques apparaîtront ici.",
      emptyChecklistMissing: "Checklist indisponible.",
      emptyPrioNone: "Aucune chaîne critique — voir Findings.",
      emptyChains: "Aucune chaîne — lancez un scan.",
      emptyTimeline: "Le comparatif apparaîtra après un scan.",
      emptyDiffNew: "Aucun nouveau finding depuis la baseline.",
      noDiffSummary: "Pas de résumé diff.",
      statusScan: "Démarrage…",
      statusNet: "Actualisation connexions…",
      logScanStart: "Démarrage du scan complet…",
      logScanCancel: "Scan annulé — aucun résultat partiel. Dernier scan conservé si présent.",
      logCancelReq: "Annulation demandée…",
      logNetRefresh: "Refresh inventaire TCP/UDP…",
      logNetOk: "Connexions actualisées",
      logWlSaved: "Whitelist sauvée ({n})",
      logReady: "Prêt",
      logAdmin: "droits admin",
      logLimited: "droits limités",
      logLast: "Dernier scan rechargé.",
      done: "Terminé",
      loadingResult: "Chargement résultat…",
      firstScan: "Premier scan / pas de baseline.",
      btnCancelScan: "Annuler le scan",
      statScore: "Score",
      statFindings: "Findings",
      statChains: "Chaînes",
      statDuration: "Durée",
      scoreTitle: "Santé machine",
      diffHint: "Lancez un scan pour cartographier les anomalies.",
      emptyScan: "Lancez un scan.",
      sevAll: "Toutes sévérités",
      findPh: "Filtrer titre / chemin / catégorie…",
      thSev: "Sev.",
      thCat: "Cat.",
      thTitle: "Titre",
      thPath: "Chemin",
      thWhy: "Pourquoi",
      netAll: "Toutes",
      netOut: "Sortantes",
      netListen: "Écoute",
      netSuspect: "Suspectes",
      netPh: "Processus / IP / estimation…",
      thDir: "Dir.",
      thProcess: "Processus",
      thLocal: "Local",
      thRemote: "Distant",
      thEstimate: "Estimation",
      thRisk: "Risque",
      chainsTitle: "Chaînes déduites",
      timelineTitle: "Timeline / diff baseline",
      consoleTitle: "Console / journal",
      wlTitle: "Whitelist",
      wlHelp: "Un motif par ligne. Exemple : *\\MyApp\\* ou chrome|*\\Chrome\\*. Active au prochain scan.",
      hostApiMissing: "API host indisponible",
      logNetMapOk: "NetMap lancé",
      logNetMapFail: "Impossible d’ouvrir NetMap",
      netStats: "{n} connexions · {sus} à risque · affiché {shown}",
      other: "Autre",
      about: "WinAudit — audit heuristique local (lecture seule)\nPas un antivirus / EDR.\n\nMr-Aurevo-X ne collecte aucune donnée. Analyse sur cette machine. Aucun envoi de résultats en ligne. Pas de mise à jour automatique. Polices embarquées localement.\n\n© 2026 Mr-Aurevo-X",
    },
    en: {
      tagline: "Scan only",
      copyright: "© 2026 Mr-Aurevo-X · local · Terms in Atelier",
      featuresTitle: "Features",
      features: "Local read-only heuristic audit: score, findings, network, chains, and timeline.",
      privacy: "Mr-Aurevo-X does not collect your data. Local read-only analysis. Results are never uploaded.",
      ready: "Ready — read-only",
      navOverview: "Overview",
      navFindings: "Findings",
      navNetwork: "Network",
      navChains: "Chains",
      navTimeline: "Timeline",
      pageOverviewSub: "Score, spyware checklist and priorities",
      pageFindingsSub: "All heuristic signals (read-only)",
      pageNetworkSub: "TCP/UDP connections — live refresh",
      pageChainsSub: "Multi-vector correlations",
      pageTimelineSub: "Diff since last scan (baseline)",
      btnScan: "Run scan",
      btnCancel: "Cancel scan",
      btnExport: "Export report",
      btnPrint: "A4 report",
      btnWhitelist: "Whitelist",
      btnRefreshNet: "Refresh connections",
      btnOpenNetMap: "Live view (NetMap)",
      btnClear: "Clear",
      btnSave: "Save",
      btnClose: "Close",
      lblScore: "Score",
      waiting: "Waiting",
      subFindings: "signals detected",
      subChains: "correlations",
      subDuration: "last scan",
      machineHealth: "Machine health",
      scanHint: "Run a scan to map anomalies.",
      checklistTitle: "Spyware checklist",
      prioTitle: "Priorities",
      emptyChecklist: "Run a scan.",
      emptyPrio: "Critical chains will appear here.",
      emptyChecklistMissing: "Checklist unavailable.",
      emptyPrioNone: "No critical chains — see Findings.",
      emptyChains: "No chains — run a scan.",
      emptyTimeline: "Diff appears after a scan.",
      emptyDiffNew: "No new findings since baseline.",
      noDiffSummary: "No diff summary.",
      statusScan: "Starting…",
      statusNet: "Refreshing connections…",
      logScanStart: "Starting full scan…",
      logScanCancel: "Scan cancelled — no partial result. Last scan kept if present.",
      logCancelReq: "Cancel requested…",
      logNetRefresh: "Refreshing TCP/UDP inventory…",
      logNetOk: "Connections refreshed",
      logWlSaved: "Whitelist saved ({n})",
      logReady: "Ready",
      logAdmin: "admin rights",
      logLimited: "limited rights",
      logLast: "Last scan reloaded.",
      done: "Done",
      loadingResult: "Loading result…",
      firstScan: "First scan / no baseline.",
      btnCancelScan: "Cancel scan",
      statScore: "Score",
      statFindings: "Findings",
      statChains: "Chains",
      statDuration: "Duration",
      scoreTitle: "Machine health",
      diffHint: "Run a scan to map anomalies.",
      emptyScan: "Run a scan.",
      sevAll: "All severities",
      findPh: "Filter title / path / category…",
      thSev: "Sev.",
      thCat: "Cat.",
      thTitle: "Title",
      thPath: "Path",
      thWhy: "Why",
      netAll: "All",
      netOut: "Outbound",
      netListen: "Listen",
      netSuspect: "Suspect",
      netPh: "Process / IP / estimate…",
      thDir: "Dir.",
      thProcess: "Process",
      thLocal: "Local",
      thRemote: "Remote",
      thEstimate: "Estimate",
      thRisk: "Risk",
      chainsTitle: "Inferred chains",
      timelineTitle: "Timeline / baseline diff",
      consoleTitle: "Console / log",
      wlTitle: "Whitelist",
      wlHelp: "One pattern per line. Example: *\\MyApp\\* or chrome|*\\Chrome\\*. Applied on next scan.",
      hostApiMissing: "Host API unavailable",
      logNetMapOk: "NetMap launched",
      logNetMapFail: "Could not open NetMap",
      netStats: "{n} connections · {sus} at risk · shown {shown}",
      other: "Other",
      about: "WinAudit — local heuristic audit (read-only)\nNot an antivirus / EDR.\n\nMr-Aurevo-X does not collect your data. Analysis stays on this PC. Results are never uploaded. No automatic updates. Fonts are bundled locally.\n\n© 2026 Mr-Aurevo-X",
    },
  };

  let suiteLang = "fr";
  const t = (key, vars) => {
    let s = (SUITE_I18N[suiteLang] && SUITE_I18N[suiteLang][key]) || SUITE_I18N.fr[key] || key;
    if (vars) Object.keys(vars).forEach((k) => { s = s.split("{" + k + "}").join(String(vars[k])); });
    return s;
  };

  function pagesMeta() {
    return {
      overview: { title: t("navOverview"), sub: t("pageOverviewSub") },
      findings: { title: t("navFindings"), sub: t("pageFindingsSub") },
      reseau: { title: t("navNetwork"), sub: t("pageNetworkSub") },
      chains: { title: t("navChains"), sub: t("pageChainsSub") },
      timeline: { title: t("navTimeline"), sub: t("pageTimelineSub") },
    };
  }


  const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const SEV_COLORS = {
    Critical: "#e03545",
    High: "#fb923c",
    Medium: "#e0a84a",
    Low: "#e03545",
    Info: "#9a9aa3",
  };

  let result = null;
  let connections = [];
  let chartSev = null;
  let chartCat = null;
  let busy = false;
  let scanStartedAt = 0;
  let lastLoggedPhase = "";


  function applyAccent(hex) {
    const accent = String(hex || "#e03545").trim();
    if (!(accent.startsWith("#") && (accent.length === 4 || accent.length === 7))) return;
    let h = accent.slice(1);
    if (h.length === 3) h = h.split("").map((c) => c + c).join("");
    const r = parseInt(h.slice(0, 2), 16);
    const g = parseInt(h.slice(2, 4), 16);
    const b = parseInt(h.slice(4, 6), 16);
    const root = document.documentElement;
    root.style.setProperty("--accent", accent);
    root.style.setProperty("--accent-dim", `rgba(${r}, ${g}, ${b}, 0.2)`);
    root.style.setProperty("--accent-glow", `rgba(${r}, ${g}, ${b}, 0.4)`);
  }

  async function bootSuite(api) {
    const suite = window.MrAurevoXSuite;
    if (!suite) {
      if (api && api.get_suite_settings) {
        try {
          const s = await api.get_suite_settings();
          if (s && s.ok) {
            if (s.language === "en" || s.language === "fr") suiteLang = s.language;
            if (s.accent) applyAccent(s.accent);
          }
        } catch (_) {}
      }
      return suiteLang;
    }
    const settings = await suite.loadSuiteSettings(api);
    suiteLang = settings.language === "en" ? "en" : "fr";
    suite.applyAccent(settings.accent);
    suite.applyI18n(suiteLang, SUITE_I18N);
    return suiteLang;
  }

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/'/g, "&#39;");
  }

  function log(msg, level) {
    const el = $("#log");
    const line = document.createElement("div");
    if (level) line.className = level;
    const ts = new Date().toLocaleTimeString(suiteLang === "en" ? "en-US" : "fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    line.textContent = `[${ts}] ${msg}`;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
  }

  function fmtElapsed(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    const m = Math.floor(s / 60);
    const r = s % 60;
    return m + ":" + String(r).padStart(2, "0");
  }

  function setProgressUI(pct, phase, detail, elapsedMs) {
    const bar = $("#progressBar") || $("#progress > i");
    const wrap = $("#progress");
    const label = $("#progressLabel");
    const n = Math.max(0, Math.min(100, Number(pct) || 0));
    wrap.classList.remove("busy");
    wrap.classList.add("determinate");
    if (bar) bar.style.width = n + "%";
    const short = phase ? n + "% · " + phase : n + "%";
    const parts = [n + "%"];
    if (phase) parts.push(phase);
    if (detail) parts.push(detail);
    if (elapsedMs != null) parts.push(fmtElapsed(elapsedMs));
    const text = parts.join(" · ");
    if (label) label.textContent = short;
    $("#sideStatus").textContent = text;
    if (phase && phase !== lastLoggedPhase) {
      lastLoggedPhase = phase;
      log("Phase: " + phase + (detail ? " — " + detail : "") + " (" + n + "%)");
    }
  }

  function clearProgressUI() {
    const bar = $("#progressBar") || $("#progress > i");
    const wrap = $("#progress");
    const label = $("#progressLabel");
    wrap.classList.remove("busy", "determinate");
    if (bar) bar.style.width = "0%";
    if (label) label.textContent = "";
  }

  function setCancelVisible(on) {
    const b = $("#btnCancelScan");
    if (!b) return;
    b.style.display = on ? "" : "none";
    b.disabled = !on;
  }

  function setBusy(on, status, opts) {
    busy = on;
    const indeterminate = !!(opts && opts.indeterminate);
    const wrap = $("#progress");
    if (on && indeterminate) {
      wrap.classList.add("busy");
      wrap.classList.remove("determinate");
      const bar = $("#progressBar") || $("#progress > i");
      if (bar) bar.style.width = "";
    } else if (!on) {
      clearProgressUI();
      setCancelVisible(false);
    }
    if (status != null) $("#sideStatus").textContent = status;
    const keep = new Set(["btnClearLog", "btnWlClose", "btnCancelScan"]);
    $$(".btn").forEach((b) => {
      if (keep.has(b.id)) return;
      if (on) {
        b.dataset.wasDisabled = b.disabled ? "1" : "0";
        b.disabled = true;
      } else if (b.dataset.wasDisabled === "0") {
        b.disabled = false;
      }
    });
    if (!on) syncExportButtons();
  }

  function syncExportButtons() {
    const has = !!result;
    $("#btnExport").disabled = !has || busy;
    $("#btnPrint").disabled = !has || busy;
  }

  async function api(action, payload) {
    if (!window.pywebview || !window.pywebview.api) {
      throw new Error("Bridge pywebview indisponible (lance via host Python)");
    }
    const res = await window.pywebview.api.run(action, payload || {});
    if (!res || !res.ok) {
      throw new Error((res && res.error) || "Erreur API");
    }
    return res.data;
  }

  async function hostCall(method, ...args) {
    if (!window.pywebview || !window.pywebview.api || typeof window.pywebview.api[method] !== "function") {
      throw new Error("Methode host indisponible: " + method);
    }
    const res = await window.pywebview.api[method](...args);
    if (!res || !res.ok) {
      throw new Error((res && res.error) || "Erreur host");
    }
    return res.data;
  }

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  function setPage(id) {
    $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.page === id));
    $$(".page").forEach((p) => p.classList.toggle("active", p.id === "page-" + id));
    const meta = pagesMeta()[id] || { title: id, sub: "" };
    $("#pageTitle").textContent = meta.title;
    $("#pageSub").textContent = meta.sub;
  }

  function ensureCharts() {
    if (typeof Chart === "undefined") return;
    Chart.defaults.color = "#9a9aa3";
    Chart.defaults.borderColor = "rgba(255,255,255,0.07)";
    Chart.defaults.font.family = "Outfit";
  }

  function countSev(findings) {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    (findings || []).forEach((f) => {
      if (c[f.Severity] != null) c[f.Severity]++;
      else c.Info++;
    });
    return c;
  }

  function renderOverview() {
    if (!result) return;
    const score = result.Score || {};
    const pct = Math.max(0, Math.min(100, Number(score.Score) || 0));
    $("#stScore").textContent = String(pct);
    $("#stScoreLbl").textContent = score.Label || "Score";
    $("#stFindings").textContent = String((result.Findings || []).length);
    $("#stChains").textContent = String((result.Chains || []).length);
    $("#stTime").textContent = (result.DurationSec != null ? result.DurationSec + "s" : "—");
    $("#scoreNum").textContent = String(pct);
    $("#scoreRing").style.setProperty("--pct", String(pct));
    $("#scoreTitle").textContent = score.Label || t("machineHealth");
    $("#diffSummary").textContent =
      (result.Diff && result.Diff.Summary) || t("firstScan");

    const sev = countSev(result.Findings);
    ensureCharts();
    const sevLabels = Object.keys(sev);
    const sevData = sevLabels.map((k) => sev[k]);
    if (chartSev) chartSev.destroy();
    chartSev = new Chart($("#chartSev"), {
      type: "doughnut",
      data: {
        labels: sevLabels,
        datasets: [{
          data: sevData,
          backgroundColor: sevLabels.map((k) => SEV_COLORS[k] || "#9a9aa3"),
          borderWidth: 0,
        }],
      },
      options: {
        plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } },
        cutout: "62%",
      },
    });

    const cats = {};
    (result.Findings || []).forEach((f) => {
      const k = f.Category || t("other");
      cats[k] = (cats[k] || 0) + 1;
    });
    const catEntries = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (chartCat) chartCat.destroy();
    chartCat = new Chart($("#chartCat"), {
      type: "bar",
      data: {
        labels: catEntries.map((e) => e[0]),
        datasets: [{
          label: "Findings",
          data: catEntries.map((e) => e[1]),
          backgroundColor: "rgba(61,214,198,0.55)",
          borderRadius: 6,
        }],
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { precision: 0 } },
          y: { grid: { display: false } },
        },
      },
    });

    const ck = $("#checklistList");
    ck.innerHTML = "";
    if (result.Checklist) {
      const head = document.createElement("li");
      head.className = "check-li";
      head.innerHTML = "<strong>" + escapeHtml(result.Checklist.Verdict || "") + "</strong>";
      ck.appendChild(head);
      (result.Checklist.Items || []).forEach((it) => {
        const li = document.createElement("li");
        li.className = "check-li";
        const mark = it.Status === "OK" ? "OK" : it.Status === "Critique" ? "CRIT" : "ATT";
        li.textContent = "[" + mark + "] " + it.Question + (it.Detail ? " — " + it.Detail : "");
        ck.appendChild(li);
      });
    } else {
      ck.innerHTML = '<li class="muted check-li">' + escapeHtml(t("emptyChecklistMissing")) + '</li>';
    }

    const pr = $("#prioList");
    pr.innerHTML = "";
    const top = (result.Chains || [])
      .slice()
      .sort((a, b) => (SEV_ORDER[a.Severity] ?? 9) - (SEV_ORDER[b.Severity] ?? 9))
      .slice(0, 8);
    if (!top.length) {
      pr.innerHTML = '<li class="muted check-li">' + escapeHtml(t("emptyPrioNone")) + '</li>';
    } else {
      top.forEach((c) => {
        const li = document.createElement("li");
        li.className = "check-li";
        li.innerHTML =
          '<span class="sev sev-' + escapeAttr(c.Severity) + '">' + escapeHtml(c.Severity) + "</span> " +
          escapeHtml(c.Title) + " (" + escapeHtml(c.Confidence) + "%)";
        pr.appendChild(li);
      });
    }
  }

  function renderFindings() {
    const body = $("#findingsBody");
    body.innerHTML = "";
    if (!result) return;
    const sevF = $("#sevFilter").value;
    const q = ($("#findFilter").value || "").toLowerCase().trim();
    let rows = (result.Findings || []).slice().sort(
      (a, b) => (SEV_ORDER[a.Severity] ?? 9) - (SEV_ORDER[b.Severity] ?? 9)
    );
    if (sevF && sevF !== "all") {
      rows = rows.filter((f) => f.Severity === sevF);
    }
    if (q) {
      rows = rows.filter((f) =>
        ((f.Title || "") + " " + (f.Path || "") + " " + (f.Category || "") + " " + (f.WhySuspicious || ""))
          .toLowerCase()
          .includes(q)
      );
    }
    $("#findCount").textContent = rows.length + " / " + (result.Findings || []).length;
    rows.slice(0, 400).forEach((f) => {
      const tr = document.createElement("tr");
      tr.innerHTML =
        '<td><span class="sev sev-' + escapeAttr(f.Severity) + '">' + escapeHtml(f.Severity) + "</span></td>" +
        "<td>" + escapeHtml(f.Category || "") + "</td>" +
        "<td>" + escapeHtml(f.Title || "") + "</td>" +
        '<td class="path-cell">' + escapeHtml(f.Path || f.Evidence || "") + "</td>" +
        "<td>" + escapeHtml(f.WhySuspicious || "") + "</td>";
      body.appendChild(tr);
    });
  }

  function renderNetwork() {
    const body = $("#netBody");
    body.innerHTML = "";
    const mode = $("#netFilter").value;
    const q = ($("#netSearch").value || "").toLowerCase().trim();
    let rows = connections.slice();
    if (mode === "outbound") rows = rows.filter((c) => c.Direction === "Outbound");
    if (mode === "listen") rows = rows.filter((c) => c.Direction === "Listen");
    if (mode === "suspect") {
      rows = rows.filter((c) => ["Medium", "High", "Critical"].includes(c.Risk));
    }
    if (q) {
      rows = rows.filter((c) =>
        ((c.ProcessName || "") + " " + (c.RemoteAddress || "") + " " + (c.Estimate || "") + " " + (c.Path || ""))
          .toLowerCase()
          .includes(q)
      );
    }
    const sus = connections.filter((c) => ["Medium", "High", "Critical"].includes(c.Risk)).length;
    $("#netStats").textContent =
      t("netStats", { n: connections.length, sus, shown: rows.length });
    rows.slice(0, 500).forEach((c) => {
      const local = (c.LocalAddress || "") + ":" + (c.LocalPort || "");
      const remote =
        c.Direction === "Listen" ? "—" : (c.RemoteAddress || "") + ":" + (c.RemotePort || "");
      const tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + escapeHtml(c.Direction || "") + "</td>" +
        "<td>" + escapeHtml(c.ProcessName || "") + "</td>" +
        "<td>" + escapeHtml(local) + "</td>" +
        "<td>" + escapeHtml(remote) + "</td>" +
        "<td>" + escapeHtml(c.Estimate || "") + "</td>" +
        '<td><span class="sev sev-' + escapeAttr(c.Risk || "Info") + '">' + escapeHtml(c.Risk || "") + "</span></td>";
      body.appendChild(tr);
    });
  }

  function renderChains() {
    const host = $("#chainsHost");
    host.innerHTML = "";
    const chains = result && result.Chains ? result.Chains : [];
    if (!chains.length) {
      host.innerHTML = '<p class="muted" style="color:var(--muted);margin:0">' + escapeHtml(t("emptyChains")) + '</p>';
      return;
    }
    chains.forEach((c) => {
      const d = document.createElement("div");
      d.className = "chain-card";
      d.innerHTML =
        "<h4><span class=\"sev sev-" + escapeAttr(c.Severity) + '">' + escapeHtml(c.Severity) + "</span> " +
        escapeHtml(c.Title) +
        ' <span style="color:var(--muted);font-weight:500">(' +
        escapeHtml(c.Confidence) +
        "%)</span></h4>" +
        "<p>" +
        escapeHtml(c.Narrative || "") +
        "</p>";
      host.appendChild(d);
    });
  }

  function renderTimeline() {
    const ul = $("#timelineList");
    ul.innerHTML = "";
    if (!result) {
      ul.innerHTML = '<li class="muted check-li">' + escapeHtml(t("emptyTimeline")) + '</li>';
      return;
    }
    const diff = result.Diff || {};
    const li0 = document.createElement("li");
    li0.className = "check-li";
    li0.textContent = diff.Summary || t("noDiffSummary");
    ul.appendChild(li0);

    (diff.NewFindings || []).slice(0, 40).forEach((f) => {
      const li = document.createElement("li");
      li.className = "check-li";
      li.innerHTML =
        '<span class="sev sev-' + escapeAttr(f.Severity) + '">NEW</span> [' +
        escapeHtml(f.Severity) +
        "] " +
        escapeHtml(f.Title || "");
      ul.appendChild(li);
    });
    if (!(diff.NewFindings || []).length && diff.HasPrevious) {
      const li = document.createElement("li");
      li.className = "muted check-li";
      li.textContent = t("emptyDiffNew");
      ul.appendChild(li);
    }
  }

  function applyResult(data) {
    result = data;
    connections = (data && data.Connections) || [];
    renderOverview();
    renderFindings();
    renderNetwork();
    renderChains();
    renderTimeline();
    syncExportButtons();
  }

  async function runScan() {
    if (busy) return;
    lastLoggedPhase = "";
    scanStartedAt = Date.now();
    setBusy(true, "0% · " + t("statusScan"));
    setCancelVisible(true);
    setProgressUI(0, "Persistence", t("statusScan"), 0);
    log(t("logScanStart"));
    try {
      await hostCall("start_scan");
      let finalErr = null;
      let cancelled = false;
      for (;;) {
        await sleep(300);
        const p = await hostCall("get_scan_progress");
        const elapsed = Date.now() - scanStartedAt;
        setProgressUI(p.percent || 0, p.phase || "", p.detail || "", elapsed);
        if (p.cancelled && (p.done || !p.running)) {
          cancelled = true;
          break;
        }
        if (p.error && (p.done || !p.running)) {
          finalErr = p.error;
          break;
        }
        if (p.done && !p.running) break;
      }
      if (cancelled) {
        log(t("logScanCancel"), "warn");
        return;
      }
      if (finalErr) throw new Error(finalErr);
      setProgressUI(100, t("done"), t("loadingResult"), Date.now() - scanStartedAt);
      const data = await hostCall("get_scan_result");
      applyResult(data.result);
      log(
        "Scan OK — score " +
          (data.result.Score && data.result.Score.Score) +
          "/100 · " +
          (data.result.Findings || []).length +
          " findings · " +
          (data.result.DurationSec || "?") +
          "s",
        "ok"
      );
      if (data.export && data.export.Html) log("Rapport: " + data.export.Html);
      setPage("overview");
    } catch (e) {
      const msg = String(e.message || e);
      if (msg === "cancelled") {
        log(t("logScanCancel"), "warn");
      } else {
        log(msg, "err");
      }
    } finally {
      setCancelVisible(false);
      setBusy(false, t("ready"));
    }
  }

  async function cancelScan() {
    const b = $("#btnCancelScan");
    if (b) b.disabled = true;
    log(t("logCancelReq"), "warn");
    try {
      await hostCall("cancel_scan");
    } catch (e) {
      log(String(e.message || e), "err");
      if (b) b.disabled = false;
    }
  }

  async function refreshNet() {
    if (busy) return;
    setBusy(true, t("statusNet"), { indeterminate: true });
    log(t("logNetRefresh"));
    try {
      const data = await api("refreshConnections");
      connections = data.connections || [];
      if (result) result.Connections = connections;
      renderNetwork();
      log(t("logNetOk") + ": " + (data.count || connections.length), "ok");
      setPage("reseau");
    } catch (e) {
      log(String(e.message || e), "err");
    } finally {
      setBusy(false, t("ready"));
    }
  }

  async function exportReport() {
    try {
      const data = await api("exportReport");
      log("Export: " + data.Html, "ok");
      if (window.pywebview.api.open_path) await window.pywebview.api.open_path(data.Html);
    } catch (e) {
      log(String(e.message || e), "err");
    }
  }

  async function exportPrint() {
    try {
      const data = await api("exportPrint");
      log("Rapport A4: " + data.Html, "ok");
      if (window.pywebview.api.open_path) await window.pywebview.api.open_path(data.Html);
    } catch (e) {
      log(String(e.message || e), "err");
    }
  }

  async function openWhitelist() {
    try {
      const data = await api("getWhitelist");
      $("#wlText").value = (data.patterns || []).join("\n");
      $("#wlModal").classList.add("open");
    } catch (e) {
      log(String(e.message || e), "err");
    }
  }

  async function saveWhitelist() {
    const patterns = ($("#wlText").value || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s && !s.startsWith("#"));
    try {
      const data = await api("saveWhitelist", { patterns });
      log(t("logWlSaved", { n: data.count }) + " — " + data.path, "ok");
      $("#wlModal").classList.remove("open");
    } catch (e) {
      log(String(e.message || e), "err");
    }
  }

  function wire() {
    $$(".nav-btn").forEach((b) => b.addEventListener("click", () => setPage(b.dataset.page)));
    $("#btnScan").addEventListener("click", runScan);
    $("#btnCancelScan").addEventListener("click", cancelScan);
    $("#btnExport").addEventListener("click", exportReport);
    $("#btnPrint").addEventListener("click", exportPrint);
    $("#btnRefreshNet").addEventListener("click", refreshNet);
    const btnNetMap = $("#btnOpenNetMap");
    if (btnNetMap) {
      btnNetMap.addEventListener("click", async () => {
        try {
          const bridge = window.pywebview && window.pywebview.api;
          if (!bridge || typeof bridge.open_suite_app !== "function") {
            log(t("hostApiMissing"), "err");
            return;
          }
          const res = await bridge.open_suite_app("NetMap");
          if (!res || !res.ok) {
            log((res && res.error) || t("logNetMapFail"), "err");
          } else {
            log(t("logNetMapOk"), "ok");
          }
        } catch (e) {
          log(String(e.message || e), "err");
        }
      });
    }
    $("#btnWhitelist").addEventListener("click", openWhitelist);
    $("#btnWlSave").addEventListener("click", saveWhitelist);
    $("#btnWlClose").addEventListener("click", () => $("#wlModal").classList.remove("open"));
    $("#wlModal").addEventListener("click", (e) => {
      if (e.target === $("#wlModal")) $("#wlModal").classList.remove("open");
    });
    $("#btnClearLog").addEventListener("click", () => {
      $("#log").innerHTML = "";
    });
    $("#sevFilter").addEventListener("change", renderFindings);
    $("#findFilter").addEventListener("input", renderFindings);
    $("#netFilter").addEventListener("change", renderNetwork);
    $("#netSearch").addEventListener("input", renderNetwork);
  }

  async function boot() {
    wire();
    setPage("overview");
    syncExportButtons();
    const ready = () =>
      new Promise((resolve) => {
        if (window.pywebview && window.pywebview.api) resolve();
        else window.addEventListener("pywebviewready", resolve, { once: true });
      });
    await ready();
    await bootSuite(window.pywebview && window.pywebview.api);
    try {
      const ping = await api("ping");
      log(t("logReady") + " — " + (ping.admin ? t("logAdmin") : t("logLimited")), "ok");
      if (ping.hasLast) {
        try {
          const last = await api("getLastResult");
          applyResult(last.result);
          log(t("logLast"), "ok");
        } catch (_) {}
      }
    } catch (e) {
      log(String(e.message || e), "err");
    }
  }

  boot();
})();
