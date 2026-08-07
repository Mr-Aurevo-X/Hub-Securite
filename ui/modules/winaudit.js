/**
 * WinAudit — native in-hub (no iframe).
 * Bridge: pywebview.api.winaudit.*
 * Segments: Aperçu OS / Heuristique / Réseau / Chaînes / Logs
 *
 * Action bar lives OUTSIDE hub-inhub-body so segment swaps never wipe
 * Lancer le scan / Exporter / Rapport A4 / Whitelist (SoT parity).
 */
import { mountModuleShell, waitNs, esc, unwrapData, pollUntil } from "./_in_hub.js";

const SEV_ORDER  = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
const SEV_COLORS = {
  Critical: "#e03545", High: "#fb923c", Medium: "#e0a84a", Low: "#3dd68c", Info: "#9a9aa3",
};

export async function mount(root) {
  const SEGS = [
    { id: "overview",  label: "Aperçu OS" },
    { id: "findings",  label: "Heuristique" },
    { id: "reseau",    label: "Réseau" },
    { id: "chains",    label: "Chaînes" },
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
    subtitle: "Audit OS heuristique — lecture seule",
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

  // Persistent action bar — sibling ABOVE body (survives body.innerHTML clears)
  const toolbar = document.createElement("div");
  toolbar.className = "panel hub-inhub-actions";
  toolbar.setAttribute("data-role", "wa-actions");
  toolbar.innerHTML = `
    <div class="toolbar-row">
      <button type="button" class="btn accent" id="waScan">Lancer le scan</button>
      <button type="button" class="btn danger" id="waCancel" hidden>Annuler le scan</button>
      <button type="button" class="btn ghost" id="waExport" disabled title="JSON · TXT · HTML">Exporter rapport</button>
      <button type="button" class="btn ghost" id="waPrint" disabled>Rapport A4</button>
      <button type="button" class="btn ghost" id="waWl">Whitelist</button>
    </div>
    <div class="progress-bar" id="waProgress" style="margin-top:8px"><i id="waProgressBar" style="width:0%"></i></div>
    <p class="meta" id="waProgressLabel" style="margin-top:4px"></p>`;
  body.parentNode.insertBefore(toolbar, body);

  // Whitelist modal
  const wlModal = document.createElement("div");
  wlModal.className = "wl-modal";
  wlModal.hidden = true;
  wlModal.innerHTML = `
    <div class="wl-box">
      <h3 style="font-size:.95rem;font-weight:650">Whitelist</h3>
      <p class="meta">Un motif par ligne. Ex: *\\Chrome\\* ou chrome|*\\chrome.exe — actif au prochain scan.</p>
      <textarea id="waWlText" rows="8"></textarea>
      <div class="btn-row">
        <button type="button" class="btn ghost" id="waWlClose">Fermer</button>
        <button type="button" class="btn accent" id="waWlSave">Sauver</button>
      </div>
    </div>`;
  shell.appendChild(wlModal);

  // ── DOM refs ────────────────────────────────────────────────────────────────
  const btnScan    = toolbar.querySelector("#waScan");
  const btnCancel  = toolbar.querySelector("#waCancel");
  const btnExport  = toolbar.querySelector("#waExport");
  const btnPrint   = toolbar.querySelector("#waPrint");
  const btnWl      = toolbar.querySelector("#waWl");
  const progressBar = toolbar.querySelector("#waProgressBar");
  const progressLabel = toolbar.querySelector("#waProgressLabel");

  // ── Log helper ──────────────────────────────────────────────────────────────
  function addLog(msg, level) {
    const ts = new Date().toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
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

  function scoreOf(res) {
    if (!res) return 0;
    const s = res.Score || res.score || {};
    return Number(s.Score ?? s.score ?? res.scoreValue ?? 0) || 0;
  }

  function syncExportButtons() {
    const has = !!result && !busy;
    btnExport.disabled = !has;
    btnPrint.disabled = !has;
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
    if (!api?.run) throw new Error("winaudit.run indisponible");
    const res = await api.run(action, payload || {});
    if (!res?.ok) throw new Error((res?.error) || "Erreur API");
    return res.data;
  }

  // ── Segment renderers ───────────────────────────────────────────────────────
  function renderOverviewContent(el) {
    if (!result) {
      el.innerHTML = `<div class="panel"><p class="empty-state">Lancez un scan pour cartographier les anomalies.</p></div>`;
      return;
    }
    const score = result.Score || result.score || {};
    const pct   = Math.max(0, Math.min(100, scoreOf(result)));
    const sev   = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    (result.Findings || []).forEach((f) => { if (sev[f.Severity] != null) sev[f.Severity]++; else sev.Info++; });

    el.innerHTML = `
      <div class="panel">
        <div class="score-ring-wrap">
          <div class="score-ring" style="--pct:${pct}">
            <span class="score-num">${pct}</span>
          </div>
          <div>
            <div style="font-size:.75rem;color:var(--muted);margin-bottom:.3rem">${esc(score.Label || "Santé machine")}</div>
            <div class="card-grid" style="grid-template-columns:repeat(4,minmax(90px,1fr))">
              <div class="card"><span class="label">Score</span><span class="value">${pct}/100</span></div>
              <div class="card"><span class="label">Findings</span><span class="value">${(result.Findings || []).length}</span></div>
              <div class="card"><span class="label">Chaînes</span><span class="value">${(result.Chains || []).length}</span></div>
              <div class="card"><span class="label">Durée</span><span class="value">${result.DurationSec != null ? result.DurationSec + "s" : "—"}</span></div>
            </div>
          </div>
        </div>
      </div>
      <div class="panel" style="flex-shrink:0">
        <div class="toolbar-row" style="gap:.5rem;flex-wrap:wrap">
          ${Object.entries(sev).map(([k, v]) =>
            `<span class="sev sev-${esc(k)}">${esc(k)}: ${v}</span>`
          ).join("")}
        </div>
        ${result.Diff ? `<p class="meta" style="margin-top:8px">${esc(result.Diff.Summary || "Premier scan / pas de baseline.")}</p>` : ""}
      </div>
      <div class="panel" style="flex:1;min-height:0;overflow:auto">
        <h4 style="font-size:.8rem;font-weight:700;color:var(--muted);margin-bottom:.6rem">Checklist espionnage</h4>
        <ul id="waChecklist" style="list-style:none;display:flex;flex-direction:column;gap:.35rem"></ul>
        <h4 style="font-size:.8rem;font-weight:700;color:var(--muted);margin:.9rem 0 .5rem">Priorités</h4>
        <ul id="waPrioList" style="list-style:none;display:flex;flex-direction:column;gap:.35rem"></ul>
      </div>`;

    const ck = el.querySelector("#waChecklist");
    if (result.Checklist) {
      const head = document.createElement("li");
      head.innerHTML = `<strong>${esc(result.Checklist.Verdict || "")}</strong>`;
      ck.appendChild(head);
      (result.Checklist.Items || []).slice(0, 30).forEach((it) => {
        const li = document.createElement("li");
        li.style.cssText = "font-size:.8rem";
        const mark = it.Status === "OK" ? "✓" : it.Status === "Critique" ? "✗" : "!";
        li.textContent = `[${mark}] ${it.Question}${it.Detail ? " — " + it.Detail : ""}`;
        ck.appendChild(li);
      });
    } else {
      ck.innerHTML = '<li style="color:var(--muted);font-size:.8rem">Checklist indisponible.</li>';
    }

    const pr = el.querySelector("#waPrioList");
    const top = (result.Chains || [])
      .slice().sort((a, b) => (SEV_ORDER[a.Severity] ?? 9) - (SEV_ORDER[b.Severity] ?? 9))
      .slice(0, 8);
    if (!top.length) {
      pr.innerHTML = '<li style="color:var(--muted);font-size:.8rem">Aucune chaîne critique.</li>';
    } else {
      top.forEach((c) => {
        const li = document.createElement("li");
        li.style.cssText = "font-size:.8rem";
        li.innerHTML = `<span class="sev sev-${esc(c.Severity)}">${esc(c.Severity)}</span> ${esc(c.Title)} (${esc(c.Confidence)}%)`;
        pr.appendChild(li);
      });
    }
  }

  function renderFindingsContent(el) {
    el.innerHTML = `
      <div class="panel" style="flex-shrink:0">
        <div class="toolbar-row">
          <select id="waFindSev" style="height:40px;padding:0 10px;border-radius:12px;border:1px solid var(--border);background:var(--bg1);color:var(--text);font:inherit;font-size:.84rem">
            <option value="">Toutes sévérités</option>
            <option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option>
          </select>
          <div class="search-wrap">
            <input type="search" id="waFindFilter" placeholder="Filtrer titre / chemin / catégorie…" autocomplete="off" />
          </div>
        </div>
        <p class="meta" id="waFindCount"></p>
      </div>
      <div class="panel flex-fill">
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Sév.</th><th>Catégorie</th><th>Titre</th><th>Chemin</th><th>Pourquoi</th></tr></thead>
            <tbody id="waFindBody"></tbody>
          </table>
          <p class="empty-state" id="waFindEmpty" hidden>${result ? "Aucun finding correspondant." : "Lancez un scan."}</p>
        </div>
      </div>`;

    const sevSel = el.querySelector("#waFindSev");
    const findFilter = el.querySelector("#waFindFilter");
    const tbody  = el.querySelector("#waFindBody");
    const empty  = el.querySelector("#waFindEmpty");
    const count  = el.querySelector("#waFindCount");

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
            <option value="">Toutes</option>
            <option value="outbound">Sortantes</option>
            <option value="listen">Écoute</option>
            <option value="suspect">Suspectes</option>
          </select>
          <div class="search-wrap">
            <input type="search" id="waNetSearch" placeholder="Processus / IP / estimation…" autocomplete="off" />
          </div>
          <button type="button" class="btn ghost" id="waRefreshNet">Actualiser connexions</button>
          <button type="button" class="btn ghost" id="waOpenNetMap">Voir en live (NetMap)</button>
        </div>
        <p class="meta" id="waNetStats"></p>
      </div>
      <div class="panel flex-fill">
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Dir.</th><th>Processus</th><th>Local</th><th>Distant</th><th>Estimation</th><th>Risque</th></tr></thead>
            <tbody id="waNetBody"></tbody>
          </table>
          <p class="empty-state" id="waNetEmpty" hidden>Aucune connexion.</p>
        </div>
      </div>`;

    const dirSel  = el.querySelector("#waNetDir");
    const search  = el.querySelector("#waNetSearch");
    const btnRef  = el.querySelector("#waRefreshNet");
    const btnNetMap = el.querySelector("#waOpenNetMap");
    const tbody   = el.querySelector("#waNetBody");
    const empty   = el.querySelector("#waNetEmpty");
    const stats   = el.querySelector("#waNetStats");

    function render() {
      const mode = dirSel.value;
      const q    = (search.value || "").toLowerCase().trim();
      let rows   = connections.slice();
      if (mode === "outbound") rows = rows.filter((c) => c.Direction === "Outbound");
      else if (mode === "listen") rows = rows.filter((c) => c.Direction === "Listen");
      else if (mode === "suspect") rows = rows.filter((c) => ["Medium", "High", "Critical"].includes(c.Risk));
      if (q) rows = rows.filter((c) =>
        ((c.ProcessName || "") + " " + (c.RemoteAddress || "") + " " + (c.Estimate || "") + " " + (c.Path || ""))
          .toLowerCase().includes(q)
      );
      const sus = connections.filter((c) => ["Medium", "High", "Critical"].includes(c.Risk)).length;
      stats.textContent = `${connections.length} connexions · ${sus} à risque · affiché ${rows.length}`;
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
      setStatus("Actualisation connexions…");
      btnRef.disabled = true;
      try {
        const data = await apiRun("refreshConnections");
        connections = data.connections || [];
        if (result) result.Connections = connections;
        render();
        addLog(`Connexions actualisées: ${connections.length}`, "ok");
        setStatus("Prêt");
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
            addLog("API open_suite_app indisponible.", "err");
            setStatus("Impossible d'ouvrir NetMap", "error");
            return;
          }
          const res = await bridge.open_suite_app("NetMap");
          if (!res || !res.ok) {
            addLog((res && res.error) || "Échec ouverture NetMap", "err");
            setStatus("NetMap indisponible", "error");
          } else {
            addLog("NetMap lancé.", "ok");
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
    const host = el.querySelector("#waChainsHost");
    const chains = result?.Chains || [];
    if (!chains.length) {
      host.innerHTML = `<p class="empty-state">Aucune chaîne — lancez un scan.</p>`;
      return;
    }
    chains.forEach((c) => {
      const d = document.createElement("div");
      d.className = "chain-card";
      d.innerHTML =
        `<h4><span class="sev sev-${esc(c.Severity)}">${esc(c.Severity)}</span> ${esc(c.Title)} <span style="color:var(--muted);font-weight:500">(${esc(c.Confidence)}%)</span></h4>` +
        `<p>${esc(c.Narrative || "")}</p>`;
      host.appendChild(d);
    });
  }

  function renderLogsContent(el) {
    el.innerHTML = `
      <div style="display:flex;gap:8px;flex-shrink:0">
        <button type="button" class="btn ghost" id="waLogClear">Effacer</button>
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
    host.innerHTML = "";
    if (segId === "overview")  renderOverviewContent(host);
    else if (segId === "findings") renderFindingsContent(host);
    else if (segId === "reseau")   renderReseauContent(host);
    else if (segId === "chains")   renderChainsContent(host);
    else if (segId === "logs")     renderLogsContent(host);
  }

  function refreshCurrentSeg() {
    renderSegment(getSegment(), body);
  }

  // ── Scan lifecycle ──────────────────────────────────────────────────────────
  async function runScan() {
    if (busy || !api) return;
    if (typeof api.start_scan !== "function") {
      setStatus("API winaudit.start_scan indisponible", "error");
      return;
    }
    setBusy(true);
    setProgress(2, "Démarrage…");
    addLog("Démarrage du scan complet…");
    setStatus("Scan en cours…");
    try {
      const started = await api.start_scan();
      if (started && started.ok === false) throw new Error(started.error || "Démarrage refusé");
      const prog = await pollUntil(
        () => api.get_scan_progress(),
        {
          intervalMs: 350,
          timeoutMs: 600000,
          onTick: ({ percent, phase, detail }) => {
            const pct = Math.max(percent || 0, 2);
            setProgress(pct, `${pct}% · ${phase || ""}${detail ? " — " + detail : ""}`);
          },
        }
      );
      if (prog.cancelled) {
        addLog("Scan annulé — dernier scan conservé.", "warn");
        setStatus("Annulé");
        return;
      }
      if (prog.error) throw new Error(prog.error);
      setProgress(100, "Chargement du résultat…");
      const raw = unwrapData(await api.get_scan_result());
      if (!raw || raw.ok === false) throw new Error(raw?.error || "Résultat indisponible");
      result = raw.result || raw.data || raw;
      if (result && result.result) result = result.result;
      connections = result.Connections || result.connections || [];
      const sc = scoreOf(result);
      addLog(
        `Scan OK — score ${sc}/100 · ${(result.Findings || result.findings || []).length} findings · ${
          result.DurationSec ?? result.durationSec ?? "?"
        }s`,
        "ok"
      );
      const exp = raw.export || result.export;
      if (exp?.Html) addLog("Rapport HTML: " + exp.Html);
      setStatus(sc ? `Prêt — score ${sc}/100` : "Prêt — lecture seule", "ok");
      refreshCurrentSeg();
    } catch (e) {
      addLog(String(e.message || e), "err");
      setStatus("Erreur : " + String(e.message || e), "error");
    } finally {
      setBusy(false);
      setProgress(0, "");
    }
  }

  async function cancelScan() {
    if (!api?.cancel_scan) return;
    addLog("Annulation demandée…", "warn");
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
      setStatus("Aucun scan à exporter", "error");
      return;
    }
    setStatus(print ? "Génération rapport A4…" : "Export rapport…");
    try {
      const data = await apiRun(print ? "exportPrint" : "exportReport");
      if (print) {
        addLog("Rapport A4: " + (data.Html || ""), "ok");
        await openExportedPath(data.Html);
      } else {
        if (data.Html) addLog("Export HTML: " + data.Html, "ok");
        if (data.Json) addLog("Export JSON: " + data.Json, "ok");
        if (data.Txt)  addLog("Export TXT: " + data.Txt, "ok");
        await openExportedPath(data.Html || data.Json || data.Txt);
      }
      setStatus("Prêt — rapport généré", "ok");
    } catch (e) {
      addLog(String(e.message || e), "err");
      setStatus("Export échoué", "error");
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
      addLog(`Whitelist sauvée (${data.count}) — ${data.path}`, "ok");
      wlModal.hidden = true;
    } catch (e) { addLog(String(e), "err"); }
  }

  // ── Wire top-level buttons ──────────────────────────────────────────────────
  btnScan.addEventListener("click", runScan);
  btnCancel.addEventListener("click", cancelScan);
  btnExport.addEventListener("click", () => exportReport(false));
  btnPrint.addEventListener("click",  () => exportReport(true));
  btnWl.addEventListener("click",     openWl);
  wlModal.querySelector("#waWlClose").addEventListener("click", () => { wlModal.hidden = true; });
  wlModal.querySelector("#waWlSave").addEventListener("click",  saveWl);
  wlModal.addEventListener("click", (e) => { if (e.target === wlModal) wlModal.hidden = true; });

  // ── Initial boot ────────────────────────────────────────────────────────────
  setStatus("Prêt — lecture seule");
  syncExportButtons();

  if (api) {
    try {
      const ping = await apiRun("ping");
      const adminLbl = ping.admin ? "droits admin" : "droits limités";
      addLog(`Prêt — ${adminLbl}`, "ok");
      if (ping.hasLast) {
        try {
          const last = await apiRun("getLastResult");
          result = last?.result || last;
          connections = (result?.Connections) || [];
          const sc = scoreOf(result);
          addLog(sc ? `Dernier scan rechargé — score ${sc}/100.` : "Dernier scan rechargé.", "ok");
          setStatus(sc ? `Dernier scan — score ${sc}/100` : "Dernier scan chargé");
          syncExportButtons();
        } catch (_) {}
      }
    } catch (e) {
      addLog(String(e), "err");
    }
  } else {
    addLog("API winaudit indisponible.", "err");
    setStatus("API winaudit indisponible", "error");
    btnScan.disabled = true;
  }

  await setSegment("overview", { silent: false });
}
