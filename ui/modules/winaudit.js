/**
 * Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X
 */
/**
 * WinAudit — native in-hub (no iframe).
 * Bridge: pywebview.api.winaudit.*
 * Segments: Overview / Heuristics / Network / Chains / Timeline / Logs
 *
 * Action bar lives OUTSIDE hub-inhub-body so segment swaps never wipe
 * Start scan / Export / A4 report / Whitelist (SoT parity).
 */
import { mountModuleShell, waitNs, esc, unwrapData, pollUntil } from "./_in_hub.js";
import { t, locale } from "../i18n.js";

const SEV_ORDER  = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
const SEV_COLORS = {
  Critical: "#e03545", High: "#fb923c", Medium: "#e0a84a", Low: "#3dd68c", Info: "#9a9aa3",
};

let chartJsPromise = null;
function ensureChartJs() {
  if (typeof window.Chart !== "undefined") return Promise.resolve(window.Chart);
  if (chartJsPromise) return chartJsPromise;
  chartJsPromise = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "./vendor/chart.umd.min.js";
    s.async = true;
    s.onload = () => (window.Chart ? resolve(window.Chart) : reject(new Error(t("waChartJsMissing"))));
    s.onerror = () => reject(new Error(t("waChartJsMissing")));
    document.head.appendChild(s);
  });
  return chartJsPromise;
}

/** Translate internal score labels (Sain/Acceptable/Suspect/Critique) to current locale. */
function scoreLabel(l) {
  const map = { Sain: "waScoreSain", Acceptable: "waScoreAcceptable", Suspect: "waScoreSuspect", Critique: "waScoreCritique" };
  return map[l] ? t(map[l]) : (l || t("waHealthLabel"));
}

export async function mount(root) {
  const SEGS = [
    { id: "overview",  label: t("waSegOverview") },
    { id: "findings",  label: t("waSegFindings") },
    { id: "reseau",    label: t("waSegNetwork") },
    { id: "chains",    label: t("waSegChains") },
    { id: "timeline",  label: "Timeline" },
    { id: "logs",      label: "Logs" },
  ];

  const {
    shell,
    body,
    setStatus,
    setProgress: setShellProgress,
    setSegment,
    getSegment,
  } = mountModuleShell(root, {
    title: "WinAudit",
    subtitle: t("waSubtitle"),
    segments: SEGS,
    initialSegment: "overview",
    onSegment: renderSegment,
    fill: true,
  });

  const api = await waitNs("winaudit", "start_scan");

  // ── State ───────────────────────────────────────────────────────────────────
  let result      = null;
  let connections = [];
  let busy        = false;
  let logLines    = [];
  let chartSev    = null;
  let chartCat    = null;

  // Persistent action bar — sibling ABOVE body (survives body.innerHTML clears)
  const toolbar = document.createElement("div");
  toolbar.className = "panel hub-inhub-actions";
  toolbar.setAttribute("data-role", "wa-actions");
  toolbar.innerHTML = `
    <div class="toolbar-row">
      <button type="button" class="btn accent" id="waScan">${esc(t("waScan"))}</button>
      <button type="button" class="btn danger" id="waCancel" hidden>${esc(t("waCancel"))}</button>
      <button type="button" class="btn ghost" id="waExport" disabled title="${esc(t("waExportTitle"))}">${esc(t("waExport"))}</button>
      <button type="button" class="btn ghost" id="waPrint" disabled>${esc(t("waPrint"))}</button>
      <button type="button" class="btn ghost" id="waWl">Whitelist</button>
    </div>
    <div class="progress-bar" id="waProgress" style="margin-top:8px"><i id="waProgressBar" style="width:0%"></i></div>
    <p class="meta" id="waProgressLabel" style="margin-top:4px"></p>`;
  body.parentNode.insertBefore(toolbar, body);

  // Whitelist modal (local allow-list config — not a system mutator / no ConfirmGate)
  const wlModal = document.createElement("div");
  wlModal.className = "wl-modal";
  wlModal.hidden = true;
  wlModal.innerHTML = `
    <div class="wl-box">
      <h3 style="font-size:.95rem;font-weight:650">Whitelist</h3>
      <p class="meta">${esc(t("waWlHint"))}</p>
      <textarea id="waWlText" rows="8"></textarea>
      <div class="btn-row">
        <button type="button" class="btn ghost" id="waWlClose">${esc(t("waWlClose"))}</button>
        <button type="button" class="btn accent" id="waWlSave">${esc(t("waWlSave"))}</button>
      </div>
    </div>`;
  shell.appendChild(wlModal);

  // ── DOM refs ────────────────────────────────────────────────────────────────
  const btnScan     = toolbar.querySelector("#waScan");
  const btnCancel   = toolbar.querySelector("#waCancel");
  const btnExport   = toolbar.querySelector("#waExport");
  const btnPrint    = toolbar.querySelector("#waPrint");
  const btnWl       = toolbar.querySelector("#waWl");
  const progressBar = toolbar.querySelector("#waProgressBar");
  const progressLabel = toolbar.querySelector("#waProgressLabel");

  function destroyCharts() {
    try { if (chartSev) chartSev.destroy(); } catch (_) {}
    try { if (chartCat) chartCat.destroy(); } catch (_) {}
    chartSev = null;
    chartCat = null;
  }

  // ── Log helper ──────────────────────────────────────────────────────────────
  function addLog(msg, level) {
    const ts = new Date().toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    logLines.push({ ts, msg, level });
    if (getSegment() === "logs") renderLogsContent(body);
  }

  function setProgress(pct, label) {
    const n = Math.max(0, Math.min(100, Number(pct) || 0));
    progressBar.style.width = n + "%";
    progressLabel.textContent = label || "";
    if (setShellProgress) {
      if (!label && n <= 0) setShellProgress(0, "");
      else setShellProgress(n, label || "");
    }
  }

  /** Mirror Get-AuditScore (capped penalties) so Overview stays meaningful on noisy scans. */
  function computeScore(res) {
    const findings = res?.Findings || res?.findings || [];
    const chains   = res?.Chains   || res?.chains   || [];
    const bySev = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    findings.forEach((f) => {
      const k = f?.Severity || f?.severity || "Info";
      if (bySev[k] != null) bySev[k]++;
      else bySev.Info++;
    });
    /* Softened vs Critical*20 (pinned real noisy PCs at 0 forever). */
    let penalty =
      Math.min(35, bySev.Critical * 10) +
      Math.min(22, bySev.High * 2) +
      Math.min(12, bySev.Medium * 0.2) +
      Math.min(5,  bySev.Low * 0.03);
    let chainPenalty = 0;
    chains.forEach((c) => {
      const conf = Number(c?.Confidence ?? c?.confidence) || 0;
      if (conf >= 70) chainPenalty += Math.min(5, conf / 18);
    });
    penalty += Math.min(8, chainPenalty);
    const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
    let label =
      score >= 85 ? "Sain" : score >= 65 ? "Acceptable" : score >= 40 ? "Suspect" : "Critique";
    if (bySev.Critical >= 3) label = "Critique";
    else if (bySev.Critical >= 1 && (label === "Sain" || label === "Acceptable")) label = "Suspect";
    else if (bySev.High >= 5 && label === "Sain") label = "Acceptable";
    return { Score: score, Label: label, BySeverity: bySev, Total: findings.length, Penalty: Math.round(penalty * 10) / 10 };
  }

  function scoreOf(res) {
    if (!res) return 0;
    const findings = res.Findings || res.findings || [];
    if (findings.length) return computeScore(res).Score;
    const s = res.Score || res.score || {};
    const n = Number(s.Score ?? s.score ?? res.scoreValue);
    return Number.isFinite(n) ? n : 0;
  }

  function scoreMeta(res) {
    if (!res) return { Score: 0, Label: "" };
    const findings = res.Findings || res.findings || [];
    if (findings.length) return computeScore(res);
    const s = res.Score || res.score || {};
    const n = Number(s.Score ?? s.score);
    return {
      Score: Number.isFinite(n) ? n : 0,
      Label: s.Label || s.label || "",
      BySeverity: s.BySeverity || {},
      Total: s.Total || 0,
    };
  }

  function countSev(findings) {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    (findings || []).forEach((f) => {
      if (c[f.Severity] != null) c[f.Severity]++;
      else c.Info++;
    });
    return c;
  }

  function syncExportButtons() {
    const has = !!result && !busy;
    btnExport.disabled = !has;
    btnPrint.disabled  = !has;
  }

  function setBusy(on) {
    busy = on;
    btnScan.disabled   = on;
    btnCancel.hidden   = !on;
    btnCancel.disabled = false;
    btnWl.disabled     = on;
    syncExportButtons();
  }

  // ── API helpers ─────────────────────────────────────────────────────────────
  async function apiRun(action, payload) {
    if (!api?.run) throw new Error(t("waApiRunMissing"));
    const res = await api.run(action, payload || {});
    if (!res?.ok) throw new Error((res?.error) || t("waApiError"));
    return res.data;
  }

  async function paintOverviewCharts(el, findings) {
    const sevCanvas = el.querySelector("#waChartSev");
    const catCanvas = el.querySelector("#waChartCat");
    if (!sevCanvas || !catCanvas) return;
    try {
      const Chart = await ensureChartJs();
      Chart.defaults.color       = "#9a9aa3";
      Chart.defaults.borderColor = "rgba(255,255,255,0.07)";
      destroyCharts();

      const sev = countSev(findings);
      const sevLabels = Object.keys(sev);
      chartSev = new Chart(sevCanvas, {
        type: "doughnut",
        data: {
          labels: sevLabels,
          datasets: [{
            data: sevLabels.map((k) => sev[k]),
            backgroundColor: sevLabels.map((k) => SEV_COLORS[k] || "#9a9aa3"),
            borderWidth: 0,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: "bottom", labels: { boxWidth: 8, font: { size: 10 }, padding: 8 } } },
          cutout: "62%",
        },
      });

      const cats = {};
      (findings || []).forEach((f) => {
        const k = f.Category || t("waCatOther");
        cats[k] = (cats[k] || 0) + 1;
      });
      const catEntries = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 8);
      chartCat = new Chart(catCanvas, {
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
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: "y",
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { precision: 0, font: { size: 10 } } },
            y: { grid: { display: false }, ticks: { font: { size: 10 } } },
          },
        },
      });
    } catch (e) {
      addLog(String(e.message || e), "warn");
    }
  }

  // ── Segment renderers ───────────────────────────────────────────────────────
  function renderOverviewContent(el) {
    destroyCharts();
    if (!result) {
      el.innerHTML = `<div class="panel"><p class="empty-state">${esc(t("waOverviewEmpty"))}</p></div>`;
      return;
    }
    const score = scoreMeta(result);
    const pct   = Math.max(0, Math.min(100, Number(score.Score) || 0));
    const sev   = countSev(result.Findings);

    el.innerHTML = `
      <div class="panel">
        <div class="score-ring-wrap">
          <div class="score-ring" style="--pct:${pct}">
            <span class="score-num">${pct}</span>
          </div>
          <div style="flex:1;min-width:180px">
            <div style="font-size:.75rem;color:var(--muted);margin-bottom:.3rem">${esc(scoreLabel(score.Label))}</div>
            <div class="card-grid" style="grid-template-columns:repeat(4,minmax(90px,1fr))">
              <div class="card"><span class="label">Score</span><span class="value">${pct}/100</span></div>
              <div class="card"><span class="label">Findings</span><span class="value">${(result.Findings || []).length}</span></div>
              <div class="card"><span class="label">${esc(t("waKpiChains"))}</span><span class="value">${(result.Chains || []).length}</span></div>
              <div class="card"><span class="label">${esc(t("waKpiDuration"))}</span><span class="value">${result.DurationSec != null ? result.DurationSec + "s" : "—"}</span></div>
            </div>
            <p class="meta" style="margin-top:8px">${esc((result.Diff && result.Diff.Summary) || t("waDiffNone"))}</p>
          </div>
        </div>
        <div class="wa-charts">
          <div class="wa-chart-box"><h4>${esc(t("waChartSeverity"))}</h4><div class="wa-chart-canvas"><canvas id="waChartSev"></canvas></div></div>
          <div class="wa-chart-box"><h4>${esc(t("waChartCategories"))}</h4><div class="wa-chart-canvas"><canvas id="waChartCat"></canvas></div></div>
        </div>
      </div>
      <div class="panel" style="flex-shrink:0">
        <div class="toolbar-row" style="gap:.5rem;flex-wrap:wrap">
          ${Object.entries(sev).map(([k, v]) =>
            `<span class="sev sev-${esc(k)}">${esc(k)}: ${v}</span>`
          ).join("")}
        </div>
      </div>
      <div class="panel" style="flex:1;min-height:0;overflow:auto">
        <h4 style="font-size:.8rem;font-weight:700;color:var(--muted);margin-bottom:.6rem">${esc(t("waChecklistTitle"))}</h4>
        <ul id="waChecklist" style="list-style:none;display:flex;flex-direction:column;gap:.35rem"></ul>
        <h4 style="font-size:.8rem;font-weight:700;color:var(--muted);margin:.9rem 0 .5rem">${esc(t("waPrioritiesTitle"))}</h4>
        <ul id="waPrioList" style="list-style:none;display:flex;flex-direction:column;gap:.35rem"></ul>
      </div>`;

    void paintOverviewCharts(el, result.Findings);

    const ck = el.querySelector("#waChecklist");
    if (result.Checklist) {
      const head = document.createElement("li");
      const cri = Number(result.Checklist.Critique || 0);
      const att = Number(result.Checklist.Attention || 0);
      const verdictKey =
        cri > 0 ? "waCkVerdictHigh" : att > 0 ? "waCkVerdictWarn" : "waCkVerdictOk";
      head.innerHTML = `<strong>${esc(t(verdictKey))}</strong>`;
      ck.appendChild(head);
      (result.Checklist.Items || []).slice(0, 30).forEach((it) => {
        const li = document.createElement("li");
        li.style.cssText = "font-size:.8rem";
        const st = String(it.Status || "");
        const mark = st === "OK" ? "✓" : st === "Critique" ? "✗" : "!";
        const stKey =
          st === "OK"
            ? "waCkStatusOK"
            : st === "Critique"
              ? "waCkStatusCritique"
              : "waCkStatusAttention";
        const qKey = it.Id ? `waCkQ${it.Id}` : "";
        const question = qKey && t(qKey) !== qKey ? t(qKey) : it.Question || "";
        li.textContent = `[${mark} ${t(stKey)}] ${question}${
          it.Detail ? " — " + it.Detail : ""
        }`;
        ck.appendChild(li);
      });
    } else {
      ck.innerHTML = `<li style="color:var(--muted);font-size:.8rem">${esc(t("waChecklistUnavailable"))}</li>`;
    }

    const pr  = el.querySelector("#waPrioList");
    const top = (result.Chains || [])
      .slice().sort((a, b) => (SEV_ORDER[a.Severity] ?? 9) - (SEV_ORDER[b.Severity] ?? 9))
      .slice(0, 8);
    if (!top.length) {
      pr.innerHTML = `<li style="color:var(--muted);font-size:.8rem">${esc(t("waNoCriticalChains"))}</li>`;
    } else {
      top.forEach((c) => {
        const li = document.createElement("li");
        li.style.cssText = "font-size:.8rem";
        li.innerHTML =
          `<span class="sev sev-${esc(c.Severity)}">${esc(c.Severity)}</span> ${esc(c.Title)} ` +
          `<span style="color:var(--muted);font-weight:500">(${esc(c.Confidence)}%)</span>`;
        pr.appendChild(li);
      });
    }
  }

  function renderFindingsContent(el) {
    el.innerHTML = `
      <div class="panel" style="flex-shrink:0">
        <div class="toolbar-row">
          <select id="waFindSev" style="height:40px;padding:0 10px;border-radius:12px;border:1px solid var(--border);background:var(--bg1);color:var(--text);font:inherit;font-size:.84rem">
            <option value="">${esc(t("waFindAllSev"))}</option>
            <option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option>
          </select>
          <div class="search-wrap">
            <input type="search" id="waFindFilter" placeholder="${esc(t("waFindFilterPh"))}" autocomplete="off" />
          </div>
        </div>
        <p class="meta" id="waFindCount"></p>
      </div>
      <div class="panel flex-fill">
        <div class="table-wrap">
          <table class="data">
            <thead><tr>
              <th>${esc(t("waFindThSev"))}</th>
              <th>${esc(t("waFindThCat"))}</th>
              <th>${esc(t("waFindThTitle"))}</th>
              <th>${esc(t("waFindThPath"))}</th>
              <th>${esc(t("waFindThWhy"))}</th>
            </tr></thead>
            <tbody id="waFindBody"></tbody>
          </table>
          <p class="empty-state" id="waFindEmpty" hidden>${esc(result ? t("waFindEmptyFilter") : t("waFindEmptyScan"))}</p>
        </div>
      </div>`;

    const sevSel     = el.querySelector("#waFindSev");
    const findFilter = el.querySelector("#waFindFilter");
    const tbody      = el.querySelector("#waFindBody");
    const empty      = el.querySelector("#waFindEmpty");
    const count      = el.querySelector("#waFindCount");

    function render() {
      if (!result) { empty.hidden = false; return; }
      const sevF = sevSel.value;
      const q    = (findFilter.value || "").toLowerCase().trim();
      let rows   = (result.Findings || []).slice().sort(
        (a, b) => (SEV_ORDER[a.Severity] ?? 9) - (SEV_ORDER[b.Severity] ?? 9)
      );
      if (sevF) rows = rows.filter((f) => f.Severity === sevF);
      if (q) rows = rows.filter((f) =>
        ((f.Title || "") + " " + (f.Path || "") + " " + (f.Category || "") + " " + (f.WhySuspicious || ""))
          .toLowerCase().includes(q)
      );
      count.textContent = `${rows.length} / ${(result.Findings || []).length}`;
      tbody.innerHTML = "";
      empty.hidden = rows.length > 0;
      rows.slice(0, 500).forEach((f) => {
        const tr = document.createElement("tr");
        tr.innerHTML =
          `<td><span class="sev sev-${esc(f.Severity)}">${esc(f.Severity)}</span></td>` +
          `<td>${esc(f.Category || "")}</td>` +
          `<td>${esc(f.Title || "")}</td>` +
          `<td class="path">${esc(f.Path || f.Evidence || "")}</td>` +
          `<td style="font-size:.78rem;color:var(--muted)">${esc(f.WhySuspicious || "")}</td>`;
        tbody.appendChild(tr);
      });
    }

    sevSel.addEventListener("change", render);
    findFilter.addEventListener("input", render);
    render();
  }

  function renderReseauContent(el) {
    el.innerHTML = `
      <div class="panel" style="flex-shrink:0">
        <div class="toolbar-row">
          <select id="waNetDir" style="height:40px;padding:0 10px;border-radius:12px;border:1px solid var(--border);background:var(--bg1);color:var(--text);font:inherit;font-size:.84rem">
            <option value="">${esc(t("waNetAll"))}</option>
            <option value="outbound">${esc(t("waNetOutbound"))}</option>
            <option value="listen">${esc(t("waNetListen"))}</option>
            <option value="suspect">${esc(t("waNetSuspect"))}</option>
          </select>
          <div class="search-wrap">
            <input type="search" id="waNetSearch" placeholder="${esc(t("waNetSearchPh"))}" autocomplete="off" />
          </div>
          <button type="button" class="btn ghost" id="waRefreshNet">${esc(t("waNetRefresh"))}</button>
          <button type="button" class="btn ghost" id="waOpenNetMap">${esc(t("waNetOpenMap"))}</button>
        </div>
        <p class="meta" id="waNetStats"></p>
      </div>
      <div class="panel flex-fill">
        <div class="table-wrap">
          <table class="data">
            <thead><tr>
              <th>${esc(t("waNetThDir"))}</th>
              <th>${esc(t("waNetThProcess"))}</th>
              <th>${esc(t("waNetThLocal"))}</th>
              <th>${esc(t("waNetThRemote"))}</th>
              <th>${esc(t("waNetThEstimate"))}</th>
              <th>${esc(t("waNetThRisk"))}</th>
            </tr></thead>
            <tbody id="waNetBody"></tbody>
          </table>
          <p class="empty-state" id="waNetEmpty" hidden>${esc(t("waNetEmpty"))}</p>
        </div>
      </div>`;

    const dirSel    = el.querySelector("#waNetDir");
    const search    = el.querySelector("#waNetSearch");
    const btnRef    = el.querySelector("#waRefreshNet");
    const btnNetMap = el.querySelector("#waOpenNetMap");
    const tbody     = el.querySelector("#waNetBody");
    const empty     = el.querySelector("#waNetEmpty");
    const stats     = el.querySelector("#waNetStats");

    function render() {
      const mode = dirSel.value;
      const q    = (search.value || "").toLowerCase().trim();
      let rows   = connections.slice();
      if (mode === "outbound") rows = rows.filter((c) => c.Direction === "Outbound");
      else if (mode === "listen")  rows = rows.filter((c) => c.Direction === "Listen");
      else if (mode === "suspect") rows = rows.filter((c) => ["Medium", "High", "Critical"].includes(c.Risk));
      if (q) rows = rows.filter((c) =>
        ((c.ProcessName || "") + " " + (c.RemoteAddress || "") + " " + (c.Estimate || "") + " " + (c.Path || ""))
          .toLowerCase().includes(q)
      );
      const sus = connections.filter((c) => ["Medium", "High", "Critical"].includes(c.Risk)).length;
      stats.textContent = t("waNetStats", { n: connections.length, risk: sus, shown: rows.length });
      tbody.innerHTML = "";
      empty.hidden = rows.length > 0;
      rows.slice(0, 500).forEach((c) => {
        const local  = (c.LocalAddress  || "") + ":" + (c.LocalPort  || "");
        const remote = c.Direction === "Listen" ? "—" : (c.RemoteAddress || "") + ":" + (c.RemotePort || "");
        const tr = document.createElement("tr");
        tr.innerHTML =
          `<td>${esc(c.Direction || "")}</td>` +
          `<td>${esc(c.ProcessName || "")}</td>` +
          `<td class="meta">${esc(local)}</td>` +
          `<td class="meta">${esc(remote)}</td>` +
          `<td style="font-size:.78rem">${esc(c.Estimate || "")}</td>` +
          `<td><span class="sev sev-${esc(c.Risk || "Info")}">${esc(c.Risk || "")}</span></td>`;
        tbody.appendChild(tr);
      });
    }

    async function refreshNet() {
      if (!api?.run) return;
      setStatus(t("waNetRefreshing"));
      btnRef.disabled = true;
      try {
        const data = await apiRun("refreshConnections");
        connections = data.connections || [];
        if (result) result.Connections = connections;
        render();
        addLog(t("waNetRefreshed", { n: connections.length }), "ok");
        setStatus(t("waReady"));
      } catch (e) {
        setStatus(String(e), "error");
        addLog(String(e), "err");
      } finally {
        btnRef.disabled = false;
      }
    }

    dirSel.addEventListener("change", render);
    search.addEventListener("input", render);
    btnRef.addEventListener("click", refreshNet);
    if (btnNetMap) {
      btnNetMap.addEventListener("click", async () => {
        try {
          const bridge = window.pywebview && window.pywebview.api;
          if (!bridge || typeof bridge.open_suite_app !== "function") {
            addLog(t("waNetMapApiMissing"), "err");
            setStatus(t("waNetMapOpenFail"), "error");
            return;
          }
          const res = await bridge.open_suite_app("NetMap");
          if (!res || !res.ok) {
            addLog((res && res.error) || t("waNetMapLaunchFail"), "err");
            setStatus(t("waNetMapUnavailable"), "error");
          } else {
            addLog(t("waNetMapLaunched"), "ok");
          }
        } catch (e) {
          addLog(String(e.message || e), "err");
        }
      });
    }
    render();
  }

  function renderChainsContent(el) {
    el.innerHTML = `<div class="panel" style="flex:1;min-height:0;overflow:auto"><div id="waChainsHost"></div></div>`;
    const host   = el.querySelector("#waChainsHost");
    const chains = result?.Chains || [];
    if (!chains.length) {
      host.innerHTML = `<p class="empty-state">${esc(t("waChainsEmpty"))}</p>`;
      return;
    }
    chains.forEach((c) => {
      const d = document.createElement("div");
      d.className = "chain-card";
      d.innerHTML =
        `<h4><span class="sev sev-${esc(c.Severity)}">${esc(c.Severity)}</span> ${esc(c.Title)} ` +
        `<span style="color:var(--muted);font-weight:500">(${esc(c.Confidence)}%)</span></h4>` +
        `<p>${esc(c.Narrative || "")}</p>`;
      host.appendChild(d);
    });
  }

  function renderTimelineContent(el) {
    el.innerHTML = `
      <div class="panel" style="flex:1;min-height:0;overflow:auto">
        <h4 style="font-size:.85rem;font-weight:700;margin:0 0 .65rem">${esc(t("waTimelineTitle"))}</h4>
        <p class="meta" style="margin:0 0 .75rem">${esc(t("waTimelineIntro"))}</p>
        <ul id="waTimelineList" style="list-style:none;display:flex;flex-direction:column;gap:.4rem;margin:0;padding:0"></ul>
      </div>`;
    const ul = el.querySelector("#waTimelineList");
    if (!result) {
      ul.innerHTML = `<li class="meta">${esc(t("waTimelineNeedScan"))}</li>`;
      return;
    }
    const diff = result.Diff || {};
    const li0  = document.createElement("li");
    li0.style.cssText = "font-size:.85rem";
    li0.textContent   = diff.Summary || t("waTimelineNoSummary");
    ul.appendChild(li0);

    (diff.NewFindings || []).slice(0, 40).forEach((f) => {
      const li = document.createElement("li");
      li.style.cssText = "font-size:.82rem";
      li.innerHTML =
        `<span class="sev sev-${esc(f.Severity || "Info")}">NEW</span> [` +
        `${esc(f.Severity || "")}] ${esc(f.Title || "")}`;
      ul.appendChild(li);
    });
    if (!(diff.NewFindings || []).length && diff.HasPrevious) {
      const li = document.createElement("li");
      li.className  = "meta";
      li.textContent = t("waTimelineNoNew");
      ul.appendChild(li);
    }
  }

  function renderLogsContent(el) {
    el.innerHTML = `
      <div style="display:flex;gap:8px;flex-shrink:0">
        <button type="button" class="btn ghost" id="waLogClear">${esc(t("waLogClear"))}</button>
      </div>
      <div class="log-area" id="waLog"></div>`;
    const logEl = el.querySelector("#waLog");
    logLines.forEach(({ ts, msg, level }) => {
      const line = document.createElement("div");
      if (level) line.className = level;
      line.textContent = `[${ts}] ${msg}`;
      logEl.appendChild(line);
    });
    logEl.scrollTop = logEl.scrollHeight;
    el.querySelector("#waLogClear").addEventListener("click", () => {
      logLines = [];
      logEl.innerHTML = "";
    });
  }

  async function renderSegment(segId, el) {
    // Segment content only — action bar is outside body and must not be cleared.
    const host = el || body;
    if (segId !== "overview") destroyCharts();
    host.innerHTML = "";
    if (segId === "overview")      renderOverviewContent(host);
    else if (segId === "findings") renderFindingsContent(host);
    else if (segId === "reseau")   renderReseauContent(host);
    else if (segId === "chains")   renderChainsContent(host);
    else if (segId === "timeline") renderTimelineContent(host);
    else if (segId === "logs")     renderLogsContent(host);
  }

  function refreshCurrentSeg() {
    renderSegment(getSegment(), body);
  }

  // ── Scan lifecycle ──────────────────────────────────────────────────────────
  async function runScan() {
    if (busy || !api) return;
    if (typeof api.start_scan !== "function") {
      setStatus(t("waApiStartMissing"), "error");
      return;
    }
    setBusy(true);
    setProgress(2, t("waScanStarting"));
    addLog(t("waScanStartLog"));
    setStatus(t("waScanRunning"));
    try {
      const started = await api.start_scan();
      if (started && started.ok === false) throw new Error(started.error || t("waScanStartDenied"));
      const prog = await pollUntil(
        () => api.get_scan_progress(),
        {
          intervalMs: 350,
          timeoutMs:  600000,
          onTick: ({ percent, phase, detail }) => {
            const pct = Math.max(percent || 0, 2);
            setProgress(pct, t("waScanProgress", { pct, phase: phase || "", detail: detail ? " \u2014 " + detail : "" }));
          },
        }
      );
      if (prog.cancelled) {
        addLog(t("waScanCancelledLog"), "warn");
        setStatus(t("waScanCancelled"));
        return;
      }
      if (prog.error) throw new Error(prog.error);
      setProgress(100, t("waScanLoading"));
      const raw = unwrapData(await api.get_scan_result());
      if (!raw || raw.ok === false) throw new Error(raw?.error || t("waScanResultMissing"));
      result = raw.result || raw.data || raw;
      if (result && result.result) result = result.result;
      connections = result.Connections || result.connections || [];
      const meta = scoreMeta(result);
      if (result && typeof result === "object") result.Score = meta;
      const sc = meta.Score;
      addLog(
        t("waScanOkLog", {
          score: sc,
          label: scoreLabel(meta.Label),
          n:     (result.Findings || result.findings || []).length,
          dur:   result.DurationSec ?? result.durationSec ?? "?",
        }),
        "ok"
      );
      const exp = raw.export || result.export;
      if (exp?.Html) addLog(t("waHtmlReportLog", { path: exp.Html }));
      setStatus(t("waReadyScore", { score: sc }), "ok");
      refreshCurrentSeg();
    } catch (e) {
      addLog(String(e.message || e), "err");
      setStatus(t("waErrorPrefix", { msg: String(e.message || e) }), "error");
    } finally {
      setBusy(false);
      setProgress(0, "");
    }
  }

  async function cancelScan() {
    if (!api?.cancel_scan) return;
    addLog(t("waCancelRequested"), "warn");
    btnCancel.disabled = true;
    try { await api.cancel_scan(); } catch (e) {
      addLog(String(e), "err");
      btnCancel.disabled = false;
    }
  }

  // ── Export (read-only — JSON / TXT / HTML via bridge.run) ───────────────────
  async function openExportedPath(path) {
    if (!path) return;
    try {
      if (api?.open_path) {
        await api.open_path(path);
        return;
      }
      const bridge = window.pywebview && window.pywebview.api;
      if (bridge?.open_path) await bridge.open_path(path);
    } catch (_) { /* log path only */ }
  }

  async function exportReport(print) {
    if (!api?.run || !result) {
      setStatus(t("waExportNone"), "error");
      return;
    }
    setStatus(print ? t("waExportA4Busy") : t("waExportBusy"));
    try {
      const data = await apiRun(print ? "exportPrint" : "exportReport");
      if (print) {
        addLog(t("waExportA4Log", { path: data.Html || "" }), "ok");
        await openExportedPath(data.Html);
      } else {
        if (data.Html) addLog(t("waExportHtmlLog", { path: data.Html }), "ok");
        if (data.Json) addLog(t("waExportJsonLog", { path: data.Json }), "ok");
        if (data.Txt)  addLog(t("waExportTxtLog",  { path: data.Txt  }), "ok");
        await openExportedPath(data.Html || data.Json || data.Txt);
      }
      setStatus(t("waExportDone"), "ok");
    } catch (e) {
      addLog(String(e.message || e), "err");
      setStatus(t("waExportFail"), "error");
    }
  }

  // ── Whitelist ───────────────────────────────────────────────────────────────
  async function openWl() {
    if (!api?.run) return;
    try {
      const data = await apiRun("getWhitelist");
      wlModal.querySelector("#waWlText").value = (data.patterns || []).join("\n");
      wlModal.hidden = false;
    } catch (e) { addLog(String(e), "err"); }
  }

  async function saveWl() {
    const patterns = (wlModal.querySelector("#waWlText").value || "")
      .split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
    try {
      const data = await apiRun("saveWhitelist", { patterns });
      addLog(t("waWlSaved", { n: data.count, path: data.path }), "ok");
      wlModal.hidden = true;
    } catch (e) { addLog(String(e), "err"); }
  }

  // ── Wire top-level buttons ──────────────────────────────────────────────────
  btnScan.addEventListener("click",   runScan);
  btnCancel.addEventListener("click", cancelScan);
  btnExport.addEventListener("click", () => exportReport(false));
  btnPrint.addEventListener("click",  () => exportReport(true));
  btnWl.addEventListener("click",     openWl);
  wlModal.querySelector("#waWlClose").addEventListener("click", () => { wlModal.hidden = true; });
  wlModal.querySelector("#waWlSave").addEventListener("click",  saveWl);
  wlModal.addEventListener("click", (e) => { if (e.target === wlModal) wlModal.hidden = true; });

  // ── Initial boot ────────────────────────────────────────────────────────────
  setStatus(t("waReadyReadonly"));
  syncExportButtons();
  void ensureChartJs().catch(() => {});

  if (api) {
    try {
      const ping     = await apiRun("ping");
      const adminLbl = ping.admin ? t("waAdminRights") : t("waLimitedRights");
      addLog(t("waReadyAdmin", { rights: adminLbl }), "ok");
      if (ping.hasLast) {
        try {
          const last = await apiRun("getLastResult");
          result     = last?.result || last;
          connections = (result?.Connections) || [];
          const meta = scoreMeta(result);
          if (result && typeof result === "object") result.Score = meta;
          const sc = meta.Score;
          addLog(t("waLastReloadLog", { score: sc, label: scoreLabel(meta.Label) }), "ok");
          setStatus(t("waLastScanStatus", { score: sc }));
          syncExportButtons();
        } catch (_) {}
      }
    } catch (e) {
      addLog(String(e), "err");
    }
  } else {
    addLog(t("waApiMissing"), "err");
    setStatus(t("waApiMissing"), "error");
    btnScan.disabled = true;
  }

  await setSegment("overview", { silent: false });
}
