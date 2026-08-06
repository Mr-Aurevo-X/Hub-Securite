/**
 * WinAudit — native in-hub (no iframe).
 * Bridge: pywebview.api.winaudit.*
 * Segments: Aperçu OS / Heuristique / Réseau / Chaînes / Logs
 */
import { mountModuleShell, waitNs, esc } from "./_in_hub.js";

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

  const { body, setStatus, setSegment, getSegment } = mountModuleShell(root, {
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

  // ── Persistent toolbar (injected before body content) ───────────────────────
  const toolbar = document.createElement("div");
  toolbar.className = "panel";
  toolbar.style.flexShrink = "0";
  toolbar.innerHTML = `
    <div class="toolbar-row">
      <button type="button" class="btn accent" id="waScan">Lancer le scan</button>
      <button type="button" class="btn ghost" id="waCancel" hidden>Annuler</button>
      <button type="button" class="btn ghost" id="waExport" disabled>Exporter rapport</button>
      <button type="button" class="btn ghost" id="waPrint" disabled>Rapport A4</button>
      <button type="button" class="btn ghost" id="waWl">Whitelist</button>
    </div>
    <div class="progress-bar" id="waProgress" style="margin-top:8px"><i id="waProgressBar" style="width:0%"></i></div>
    <p class="meta" id="waProgressLabel" style="margin-top:4px"></p>`;

  // Segment content area
  const segArea = document.createElement("div");
  segArea.style.cssText = "flex:1;min-height:0;display:flex;flex-direction:column;gap:.65rem;overflow:hidden";
  segArea.id = "waSegArea";

  body.style.overflow = "hidden";
  body.appendChild(toolbar);
  body.appendChild(segArea);

  // Whitelist modal
  const wlModal = document.createElement("div");
  wlModal.className = "wl-modal";
  wlModal.hidden = true;
  wlModal.innerHTML = `
    <div class="wl-box">
      <h3 style="font-size:.95rem;font-weight:650">Whitelist</h3>
      <p class="meta">Un motif par ligne. Ex: *\\Chrome\\* ou chrome|*\\chrome.exe</p>
      <textarea id="waWlText" rows="8"></textarea>
      <div class="btn-row">
        <button type="button" class="btn ghost" id="waWlClose">Fermer</button>
        <button type="button" class="btn accent" id="waWlSave">Sauvegarder</button>
      </div>
    </div>`;
  root.querySelector(".hub-inhub").appendChild(wlModal);

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
    if (getSegment() === "logs") renderLogsContent(segArea);
  }

  function setProgress(pct, label) {
    progressBar.style.width = Math.max(0, Math.min(100, pct)) + "%";
    progressLabel.textContent = label || "";
  }

  function setBusy(on) {
    busy = on;
    btnScan.disabled   = on;
    btnCancel.hidden   = !on;
    btnExport.disabled = on || !result;
    btnPrint.disabled  = on || !result;
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
    const score = result.Score || {};
    const pct   = Math.max(0, Math.min(100, Number(score.Score) || 0));
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
          <button type="button" class="btn ghost" id="waRefreshNet">Actualiser</button>
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
    el.innerHTML = "";
    if (segId === "overview")  renderOverviewContent(el);
    else if (segId === "findings") renderFindingsContent(el);
    else if (segId === "reseau")   renderReseauContent(el);
    else if (segId === "chains")   renderChainsContent(el);
    else if (segId === "logs")     renderLogsContent(el);
  }

  function refreshCurrentSeg() {
    renderSegment(getSegment(), segArea);
  }

  // ── Scan lifecycle ──────────────────────────────────────────────────────────
  async function runScan() {
    if (busy || !api) return;
    setBusy(true);
    setProgress(0, "Démarrage…");
    addLog("Démarrage du scan complet…");
    setStatus("Scan en cours…");
    try {
      await api.start_scan();
      let cancelled = false;
      for (;;) {
        await new Promise((r) => setTimeout(r, 300));
        const p = await api.get_scan_progress();
        setProgress(p.percent || 0, `${p.percent || 0}% · ${p.phase || ""}${p.detail ? " — " + p.detail : ""}`);
        if (p.cancelled && (p.done || !p.running)) { cancelled = true; break; }
        if (p.error && (p.done || !p.running)) throw new Error(p.error);
        if (p.done && !p.running) break;
      }
      if (cancelled) {
        addLog("Scan annulé — dernier scan conservé.", "warn");
        setStatus("Annulé");
        return;
      }
      setProgress(100, "Chargement du résultat…");
      const data = await api.get_scan_result();
      result      = data.result || data;
      connections = (result.Connections) || [];
      addLog(`Scan OK — score ${result.Score?.Score}/100 · ${(result.Findings || []).length} findings · ${result.DurationSec || "?"}s`, "ok");
      if (data.export?.Html) addLog("Rapport HTML: " + data.export.Html);
      setStatus("Prêt — lecture seule");
      refreshCurrentSeg();
    } catch (e) {
      addLog(String(e.message || e), "err");
      setStatus("Erreur", "error");
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

  // ── Export ──────────────────────────────────────────────────────────────────
  async function exportReport(print) {
    if (!api?.run) return;
    try {
      const data = await apiRun(print ? "exportPrint" : "exportReport");
      addLog((print ? "A4: " : "Export: ") + data.Html, "ok");
      if (api.open_path) await api.open_path(data.Html);
    } catch (e) {
      addLog(String(e), "err");
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
  if (api) {
    try {
      const ping = await apiRun("ping");
      const adminLbl = ping.admin ? "droits admin" : "droits limités";
      addLog(`Prêt — ${adminLbl}`, "ok");
      if (ping.hasLast) {
        try {
          const last = await apiRun("getLastResult");
          result      = last.result;
          connections = (result?.Connections) || [];
          addLog("Dernier scan rechargé.", "ok");
        } catch (_) {}
      }
    } catch (e) {
      addLog(String(e), "err");
    }
  } else {
    addLog("API winaudit indisponible.", "err");
  }

  await setSegment("overview", { silent: false });
}
