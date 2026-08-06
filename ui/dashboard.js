/**
 * Dashboard home — KPIs lecture seule + tuiles modules (zéro mutator).
 */

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmt(v) {
  if (v == null || v === "") return "—";
  return String(v);
}

function api() {
  return window.pywebview && window.pywebview.api;
}

export async function mount(root) {
  root.innerHTML = `
    <header class="hub-page-header">
      <h1>Sécurité</h1>
      <p>Dashboard lecture seule · hub sécurité</p>
    </header>
    <div class="hub-kpi-grid" id="kpiGrid" aria-busy="true">
      <div class="hub-skel kpi"></div>
      <div class="hub-skel kpi"></div>
      <div class="hub-skel kpi"></div>
      <div class="hub-skel kpi"></div>
    </div>
    <h2 class="hub-note" style="margin-bottom:.65rem;font-size:.92rem;color:var(--text);font-weight:600;">Accès rapide</h2>
    <div class="hub-tile-grid" id="tileGrid"></div>
    <p class="hub-status" id="dashStatus"></p>
  `;

  const a = api();
  let modules = [];
  try {
    if (a?.dashboard?.list_modules) {
      const res = await a.dashboard.list_modules();
      modules = (res && res.modules) || [];
    }
  } catch (_) {}

  if (!modules.length) {
    modules = [
      { id: "fileguard", label: "FileGuard", desc: "Ownership / garde fichiers" },
      { id: "certview", label: "CertView", desc: "Certificats locaux" },
      { id: "reporadar", label: "RepoRadar", desc: "Scan repos" },
      { id: "winaudit", label: "WinAudit", desc: "Audit OS lecture seule" }
    ];
  }

  const tiles = document.getElementById("tileGrid");
  tiles.innerHTML = modules
    .map(
      (m) => `
      <button type="button" class="hub-tile" data-open="${esc(m.id)}">
        <strong>${esc(m.label)}</strong>
        <span>${esc(m.desc || "")}</span>
      </button>`
    )
    .join("");

  tiles.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-open]");
    if (!btn) return;
    const id = btn.getAttribute("data-open");
    if (id && window.HubShell?.showView) window.HubShell.showView(id);
  });

  const grid = document.getElementById("kpiGrid");
  const status = document.getElementById("dashStatus");
  try {
    let kpis = { ok: true, admin: false };
    if (a?.dashboard?.get_kpis) {
      kpis = await a.dashboard.get_kpis();
    }
    grid.setAttribute("aria-busy", "false");
    grid.innerHTML = `
      <div class="hub-kpi"><span class="label">Statut</span><span class="value">${esc(fmt(kpis.status))}</span></div>
      <div class="hub-kpi"><span class="label">Audit</span><span class="value">${esc(fmt(kpis.note))}</span></div>
      <div class="hub-kpi"><span class="label">Admin</span><span class="value">${kpis.admin ? "Oui" : "Non"}</span></div>
      <div class="hub-kpi"><span class="label">Hub</span><span class="value">OK</span></div>
    `;
    if (kpis.partial && kpis.error) {
      status.textContent = "KPIs partiels : " + kpis.error;
    } else {
      status.textContent = "";
    }
  } catch (e) {
    grid.setAttribute("aria-busy", "false");
    grid.innerHTML = `<div class="hub-kpi"><span class="label">KPIs</span><span class="value">—</span></div>`;
    status.textContent = "KPIs indisponibles (API ou bridge).";
  }
}
