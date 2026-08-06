/**
 * Hub-Securite Dashboard — KPIs lecture seule + tuiles modules (zéro mutator).
 */

const MODULES = [
  {
    id: "fileguard",
    label: "FileGuard",
    icon: "🔒",
    desc: "Verrous de fichiers, audit ACL NTFS, prise de possession.",
  },
  {
    id: "certview",
    label: "CertView",
    icon: "📋",
    desc: "Certificats CurrentUser\\My — sujets, émetteurs, expirations.",
  },
  {
    id: "reporadar",
    label: "RepoRadar",
    icon: "📡",
    desc: "Scan repos Git locaux : branches, dirty, ahead/behind.",
  },
  {
    id: "winaudit",
    label: "WinAudit",
    icon: "🔍",
    desc: "Audit OS heuristique lecture seule — score, findings, réseau, chaînes.",
  },
];

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
      <p>Hub sécurité — lecture seule · L'Atelier PC Command</p>
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

  // ── Tiles ──────────────────────────────────────────────────────────────────
  const tiles = document.getElementById("tileGrid");
  tiles.innerHTML = MODULES.map(
    (m) => `
      <button type="button" class="hub-tile" data-open="${esc(m.id)}">
        <span style="font-size:1.5rem;margin-bottom:.15rem">${m.icon}</span>
        <strong>${esc(m.label)}</strong>
        <span>${esc(m.desc)}</span>
      </button>`
  ).join("");

  tiles.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-open]");
    if (!btn) return;
    const id = btn.getAttribute("data-open");
    if (id && window.HubShell?.showView) window.HubShell.showView(id);
  });

  // ── KPIs ───────────────────────────────────────────────────────────────────
  const grid   = document.getElementById("kpiGrid");
  const status = document.getElementById("dashStatus");

  try {
    let kpis = { ok: true, admin: false, modules: 4, status: "ready" };
    if (a?.dashboard?.get_kpis) {
      kpis = await a.dashboard.get_kpis();
    }

    const adminLabel = kpis.admin ? "✓ Admin" : "Limité";
    const lastAudit  = kpis.last_audit || kpis.lastAudit || null;
    const findings   = kpis.findings_count ?? kpis.findingsCount ?? null;

    grid.setAttribute("aria-busy", "false");
    grid.innerHTML = `
      <div class="hub-kpi">
        <span class="label">Statut</span>
        <span class="value" style="font-size:.95rem">${esc(fmt(kpis.status || "ready"))}</span>
      </div>
      <div class="hub-kpi">
        <span class="label">Modules</span>
        <span class="value">${esc(fmt(kpis.modules || 4))}</span>
      </div>
      <div class="hub-kpi">
        <span class="label">Droits</span>
        <span class="value" style="font-size:.95rem;color:${kpis.admin ? "var(--ok,#3dd68c)" : "var(--muted)"}">${esc(adminLabel)}</span>
      </div>
      <div class="hub-kpi">
        <span class="label">${lastAudit ? "Dernier audit" : findings != null ? "Findings" : "Couche"}</span>
        <span class="value" style="font-size:.95rem">${esc(lastAudit ? fmt(lastAudit) : findings != null ? fmt(findings) : "H7")}</span>
      </div>
    `;

    if (kpis.partial && kpis.error) {
      status.textContent = "KPIs partiels : " + kpis.error;
    }
  } catch (e) {
    grid.setAttribute("aria-busy", "false");
    grid.innerHTML = `
      <div class="hub-kpi"><span class="label">Sécurité</span><span class="value">—</span></div>`;
    status.textContent = "KPIs indisponibles.";
  }
}
