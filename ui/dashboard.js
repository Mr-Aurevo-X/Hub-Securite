/**
 * Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X
 */
/**
 * Hub Accueil Sécurité — Filament Void Glow (dash-prop · gauge-card).
 * Firewall · findings · âge audit — lecture seule, zéro scan auto.
 * Pas de kicker « · Void Glow » (chrome only).
 */
import { locale, t } from "./i18n.js";

const SHOW_VIEW = () => window.HubSecurite?.showView || window.HubShell?.showView;

function moduleCatalog() {
  return [
    { id: "fileguard", label: "FileGuard", desc: t("modFileGuardDesc"), ico: "FG" },
    { id: "certview", label: "CertView", desc: t("modCertViewDesc"), ico: "CV" },
    { id: "reporadar", label: "RepoRadar", desc: t("modRepoRadarDesc"), ico: "RR" },
    { id: "winaudit", label: "WinAudit", desc: t("modWinAuditDesc"), ico: "WA" },
  ];
}

const ICO = Object.fromEntries(moduleCatalog().map((m) => [m.id, m.ico]));

const HISTORY = 60;
const ARC_LEN = 141.37;
const KPI_MS = 6000;

let tickTimer = null;
let clockTimer = null;
const hist = { firewall: [], findings: [], audit: [] };

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function api() {
  return window.pywebview && window.pywebview.api;
}

function el(id) {
  return document.getElementById(id);
}

function gaugeCard(kind, lab) {
  return `
  <article class="gauge-card" id="g-${kind}" style="--gc:var(--ok,#3dd68c)">
    <div class="arc-wrap">
      <svg viewBox="0 0 120 70" aria-hidden="true">
        <path class="trk" d="M15 58 A45 45 0 0 1 105 58"/>
        <path class="arc" id="${kind}Arc" d="M15 58 A45 45 0 0 1 105 58"
          stroke-dasharray="${ARC_LEN}" stroke-dashoffset="${ARC_LEN}"/>
      </svg>
      <span class="val" id="${kind}Val">—</span>
    </div>
    <div class="g-meta">
      <p class="lab">${lab}</p>
      <p class="name" id="${kind}Name">—</p>
      <p class="sub" id="${kind}Sub">—</p>
      <p class="temp" id="${kind}Temp" hidden><span class="t-dot"></span><span class="t-txt"></span></p>
      <svg class="spark-mini" id="${kind}Spark" viewBox="0 0 120 32" aria-hidden="true">
        <path class="area" d=""/>
        <polyline class="ln" points=""/>
      </svg>
    </div>
  </article>`;
}

function metricsMarkup() {
  return `
  <div class="hub-dash-root">
    <header class="hub-page-header hub-dash-head">
      <div>
        <h1>${esc(t("dashTitle"))}</h1>
        <p>${esc(t("dashBlurb"))}</p>
      </div>
      <div class="hub-dash-live">
        <time id="clock">—</time>
        <span class="live-pill off" id="livePill"><i></i> ${esc(t("dashOff"))}</span>
      </div>
    </header>

    <div class="dash-prop">
      <section class="gauges-block" aria-label="${esc(t("dashGaugesAria"))}">
        <div class="gauges">
          ${gaugeCard("firewall", esc(t("dashFirewall")))}
          ${gaugeCard("findings", esc(t("dashFindings")))}
          ${gaugeCard("audit", esc(t("dashAudit")))}
        </div>
      </section>
      <section class="mid-row" aria-label="${esc(t("dashMidAria"))}">
        <article class="kpi">
          <small>${esc(t("dashCertsSoon"))}</small>
          <b id="certsSoon">—</b>
          <em id="certsHint">${esc(t("dashCertsHint"))}</em>
        </article>
        <article class="kpi">
          <small>${esc(t("dashContext"))}</small>
          <b id="adminCtx">—</b>
          <em>${esc(t("dashContextEm"))}</em>
        </article>
      </section>
      <section class="bottom-row" aria-label="${esc(t("dashBottomAria"))}">
        <article class="kpi status-banner" id="auditBanner">
          <small>${esc(t("dashAuditState"))}</small>
          <b id="auditTitle">—</b>
          <em id="auditHint">—</em>
          <div class="chip-row" id="auditChips"></div>
        </article>
      </section>
    </div>

    <section class="hub-dash-modules" aria-label="${esc(t("dashQuickAria"))}">
      <h2 class="hub-section-title sec">${esc(t("dashModules"))}</h2>
      <div class="mods" id="tileGrid"></div>
      <p class="hub-status" id="dashStatus"></p>
    </section>
  </div>`;
}

function push(key, val) {
  hist[key].push(val == null || Number.isNaN(val) ? 0 : Number(val));
  while (hist[key].length > HISTORY) hist[key].shift();
}

function levelTone(pct) {
  if (pct < 45) return { cls: "ok", color: "#3dd68c" };
  if (pct < 75) return { cls: "warn", color: "#e0a84a" };
  if (pct < 90) return { cls: "hot", color: "#e07020" };
  return { cls: "crit", color: "#e03545" };
}

function setGauge(kind, pct, name, sub, tempC, valText) {
  const tone = levelTone(pct);
  const card = el(`g-${kind}`);
  if (card) {
    card.className = `gauge-card ${tone.cls}`;
    card.style.setProperty("--gc", tone.color);
  }
  const arc = el(`${kind}Arc`);
  if (arc) {
    const offset = ARC_LEN * (1 - Math.min(100, Math.max(0, pct)) / 100);
    arc.style.stroke = tone.color;
    arc.setAttribute("stroke-dashoffset", String(offset));
  }
  if (el(`${kind}Val`)) {
    el(`${kind}Val`).textContent = valText != null ? String(valText) : `${Math.round(pct)}%`;
  }
  if (el(`${kind}Name`)) el(`${kind}Name`).textContent = name || "—";
  if (el(`${kind}Sub`)) el(`${kind}Sub`).textContent = sub || "—";
  const temp = el(`${kind}Temp`);
  if (temp) temp.hidden = true;
  drawSpark(kind, hist[kind], tone.color);
}

function drawSpark(kind, data, color) {
  const svg = el(`${kind}Spark`);
  if (!svg || !data || data.length < 2) return;
  const w = 120;
  const h = 32;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - (Math.min(100, v) / 100) * (h - 4) - 2;
    return [x, y];
  });
  const ln = pts.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  const area =
    `M0,${h} ` +
    pts.map((p) => `L${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ") +
    ` L${w},${h} Z`;
  const path = svg.querySelector(".area");
  const poly = svg.querySelector(".ln");
  if (path) {
    path.setAttribute("d", area);
    path.style.fill = color;
  }
  if (poly) {
    poly.setAttribute("points", ln);
    poly.style.stroke = color;
  }
}

function setLive(on) {
  const pill = el("livePill");
  if (!pill) return;
  if (on) {
    pill.classList.remove("off");
    pill.innerHTML = `<i></i> ${esc(t("dashLive"))}`;
  } else {
    pill.classList.add("off");
    pill.innerHTML = `<i></i> ${esc(t("dashOff"))}`;
  }
}

function applyKpis(k) {
  if (!k) {
    setLive(false);
    return;
  }
  setLive(!!k.ok);

  const fwOn = !!k.firewallOn;
  const fwProfiles = Number(k.firewallProfiles ?? 0);
  const fwEnabled = Number(k.firewallEnabled ?? (fwOn ? fwProfiles : 0));
  const fwPct = fwOn ? 100 : fwProfiles > 0 ? Math.round((fwEnabled / fwProfiles) * 100) : 0;
  push("firewall", fwPct);
  setGauge(
    "firewall",
    fwPct,
    fwProfiles
      ? t("dashFwProfiles", { on: fwEnabled, total: fwProfiles })
      : t("dashFwProfilesShort"),
    t("dashFwDomain"),
    null,
    fwOn ? "On" : "Off"
  );

  const hasAudit = !!k.hasAudit;
  const findings = hasAudit ? Number(k.findingsCount ?? 0) : null;
  const findPct = findings == null ? 0 : Math.min(100, findings * 8);
  push("findings", findPct);
  setGauge(
    "findings",
    findPct,
    hasAudit ? t("dashFindingsLast") : t("dashFindingsNone"),
    t("dashFindingsSub"),
    null,
    findings == null ? "—" : String(findings)
  );

  const age = k.auditAgeDays;
  let auditPct = 0;
  let auditVal = "—";
  if (hasAudit && age != null && Number.isFinite(Number(age))) {
    const days = Math.max(0, Math.round(Number(age)));
    auditVal = days === 0 ? t("dashAuditAgeLt1") : t("dashAuditAgeDays", { n: days });
    auditPct = Math.min(100, Math.max(8, days * 12));
  }
  push("audit", auditPct);
  setGauge(
    "audit",
    auditPct,
    hasAudit ? t("dashAuditLast") : t("dashAuditNone"),
    t("dashAuditSub"),
    null,
    auditVal
  );

  const soon = k.certsExpiringSoon;
  const certCount = k.certCount;
  const soonEl = el("certsSoon");
  if (soonEl) {
    soonEl.textContent = soon != null ? String(soon) : "—";
    soonEl.className = "";
    if (soon != null && Number(soon) > 0) soonEl.classList.add("warn");
    else if (soon != null) soonEl.classList.add("ok");
  }
  if (el("certsHint")) {
    el("certsHint").textContent =
      certCount != null ? t("dashCertsOf", { n: certCount }) : t("dashCertsHint");
  }

  const adminEl = el("adminCtx");
  if (adminEl) {
    const admin = !!k.admin;
    adminEl.textContent = admin ? "Admin" : "User";
    adminEl.className = admin ? "ok" : "warn";
  }

  const title = el("auditTitle");
  const hint = el("auditHint");
  const chips = el("auditChips");
  if (hasAudit) {
    if (title) {
      let line = t("dashCachePresent", { n: findings ?? 0 });
      if (age != null) line += t("dashCacheAge", { n: Math.round(Number(age)) });
      title.textContent = line;
    }
    if (hint) hint.textContent = t("dashCacheHint");
    if (chips) {
      const parts = [];
      parts.push(
        `<span class="mini-chip ${fwOn ? "on" : "warn"}">${esc(
          t("dashChipFw", { state: fwOn ? "On" : "Off" })
        )}</span>`
      );
      if (findings != null) {
        parts.push(
          `<span class="mini-chip ${findings > 0 ? "warn" : "on"}">${esc(
            t("dashChipFindings", { n: findings })
          )}</span>`
        );
      }
      if (soon != null && Number(soon) > 0) {
        parts.push(
          `<span class="mini-chip warn">${esc(t("dashChipCerts", { n: soon }))}</span>`
        );
      }
      chips.innerHTML = parts.join("");
    }
  } else {
    if (title) title.textContent = t("dashNoCache");
    if (hint) hint.textContent = t("dashNoCacheHint");
    if (chips) {
      chips.innerHTML = `<span class="mini-chip ${fwOn ? "on" : "warn"}">${esc(
        t("dashChipFw", { state: fwOn ? "On" : "Off" })
      )}</span>`;
    }
  }
}

async function tick() {
  const a = api();
  try {
    if (a?.dashboard?.get_kpis) {
      applyKpis(await a.dashboard.get_kpis());
      return;
    }
  } catch (_) {}
  setLive(false);
}

function clock() {
  const c = el("clock");
  if (c) c.textContent = new Date().toLocaleTimeString(locale(), { hour12: false });
}

async function mountTiles() {
  const a = api();
  const fallback = moduleCatalog();
  let modules = [];
  try {
    if (a?.dashboard?.list_modules) {
      const res = await a.dashboard.list_modules();
      modules = (res && res.modules) || [];
    }
  } catch (_) {}
  if (!modules.length) modules = fallback;
  else {
    modules = modules.map((m) => ({
      ...m,
      ico: ICO[m.id] || m.ico || "▪",
      desc: fallback.find((f) => f.id === m.id)?.desc || m.desc || "",
      label: fallback.find((f) => f.id === m.id)?.label || m.label,
    }));
  }
  const tiles = el("tileGrid");
  if (!tiles) return;
  tiles.innerHTML = modules
    .map(
      (m) => `
      <button type="button" class="tile" data-open="${esc(m.id)}">
        <span class="tile-k">${esc(m.ico || "▪")}</span>
        <strong>${esc(m.label)}</strong>
        <span class="tile-b">${esc(m.desc || "")}</span>
        <span class="go">${esc(t("dashOpen"))}</span>
        <span class="fil"></span>
      </button>`
    )
    .join("");
  tiles.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-open]");
    if (!btn) return;
    const id = btn.getAttribute("data-open");
    const open = SHOW_VIEW();
    if (id && typeof open === "function") open(id);
  });
}

export function unmount() {
  if (tickTimer) {
    clearInterval(tickTimer);
    tickTimer = null;
  }
  if (clockTimer) {
    clearInterval(clockTimer);
    clockTimer = null;
  }
  for (const k of Object.keys(hist)) hist[k] = [];
}

export async function mount(root) {
  unmount();
  root.innerHTML = metricsMarkup();
  const status = el("dashStatus");
  if (status) status.textContent = t("dashStatus");
  await mountTiles();
  clock();
  clockTimer = setInterval(clock, 1000);
  /* Non-blocking KPI fetch — awaiting PowerShell/bridge must not stall i18n remount */
  void tick();
  tickTimer = setInterval(tick, KPI_MS);
}
