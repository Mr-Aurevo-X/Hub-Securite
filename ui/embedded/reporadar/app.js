(() => {
  "use strict";
  const SUITE_I18N = {
    fr: {
      tagline: "Tableau Git multi-repo",
      featuresTitle: "Fonctions",
      features: "Scan L'Atelier + Dev Central Tree : branche, dirty, ahead/behind, remote.",
      privacy: "100 % local ? git status uniquement, aucune collecte.",
      copyright: "? 2026 Mr-Aurevo-X",
      title: "Repos Git",
      rootsLabel: "Racines (une par ligne)",
      btnScan: "Scanner",
      filterPh: "Filtrer?",
      dirtyOnly: "Dirty seulement",
      colName: "Nom",
      colBranch: "Branche",
      colStatus: "Statut",
      colSync: "Sync",
      colLast: "Dernier commit",
      hostMissing: "Host indisponible",
      scanning: "Scan en cours?",
      ready: "Pr?t",
      open: "Ouvrir",
      fetch: "Fetch",
    },
    en: {
      tagline: "Multi-repo Git board",
      featuresTitle: "Features",
      features: "Scan L'Atelier + Dev Central Tree: branch, dirty, ahead/behind, remote.",
      privacy: "100% local ? git status only, no collection.",
      copyright: "? 2026 Mr-Aurevo-X",
      title: "Git repos",
      rootsLabel: "Roots (one per line)",
      btnScan: "Scan",
      filterPh: "Filter?",
      dirtyOnly: "Dirty only",
      colName: "Name",
      colBranch: "Branch",
      colStatus: "Status",
      colSync: "Sync",
      colLast: "Last commit",
      hostMissing: "Host unavailable",
      scanning: "Scanning?",
      ready: "Ready",
      open: "Open",
      fetch: "Fetch",
    },
  };

  let suiteLang = "fr";
  let repos = [];
  const t = (k) => (SUITE_I18N[suiteLang] && SUITE_I18N[suiteLang][k]) || SUITE_I18N.fr[k] || k;
  const $ = (id) => document.getElementById(id);

  function api() {
    return window.pywebview && window.pywebview.api ? window.pywebview.api : null;
  }

  async function bootSuite(a) {
    const suite = window.MrAurevoXSuite;
    if (suite) {
      const settings = await suite.loadSuiteSettings(a);
      suiteLang = settings.language === "en" ? "en" : "fr";
      suite.applyAccent(settings.accent);
      suite.applyI18n(suiteLang, SUITE_I18N);
      return;
    }
    if (a && a.get_suite_settings) {
      try {
        const s = await a.get_suite_settings();
        if (s && s.language === "en") suiteLang = "en";
      } catch (_) {}
    }
  }

  function render() {
    const q = ($("filter").value || "").trim().toLowerCase();
    const dirtyOnly = $("dirtyOnly").checked;
    const tbody = $("tbody");
    tbody.innerHTML = "";
    let shown = 0;
    for (const r of repos) {
      if (dirtyOnly && !r.dirty) continue;
      const blob = `${r.name || ""} ${r.path || ""} ${r.branch || ""} ${r.remote || ""}`.toLowerCase();
      if (q && !blob.includes(q)) continue;
      shown += 1;
      const tr = document.createElement("tr");
      const status = !r.ok
        ? `<span class="pill err">err</span>`
        : r.dirty
          ? `<span class="pill dirty">dirty</span>`
          : `<span class="pill clean">clean</span>`;
      const sync =
        r.ahead || r.behind
          ? `?${r.ahead || 0} ?${r.behind || 0}`
          : "?";
      tr.innerHTML = `
        <td><strong>${escapeHtml(r.name || "")}</strong><div class="path">${escapeHtml(r.path || "")}</div></td>
        <td>${escapeHtml(r.branch || "?")}</td>
        <td>${status}${r.error ? `<div class="path">${escapeHtml(r.error)}</div>` : ""}</td>
        <td>${sync}</td>
        <td>${escapeHtml(r.last || "?")}</td>
        <td>
          <button type="button" class="btn tiny" data-open="${escapeAttr(r.path || "")}">${t("open")}</button>
          <button type="button" class="btn tiny" data-fetch="${escapeAttr(r.path || "")}">${t("fetch")}</button>
        </td>`;
      tbody.appendChild(tr);
    }
    $("meta").textContent = `${shown} / ${repos.length}`;
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/'/g, "&#39;");
  }

  async function scan() {
    const a = api();
    if (!a) {
      $("status").textContent = t("hostMissing");
      return;
    }
    $("status").textContent = t("scanning");
    $("btnScan").disabled = true;
    try {
      const roots = ($("roots").value || "")
        .split(/\r?\n/)
        .map((x) => x.trim())
        .filter(Boolean);
      const res = await a.scan_repos(roots, 3);
      if (!res || !res.ok) {
        $("status").textContent = (res && res.error) || t("hostMissing");
        return;
      }
      repos = res.repos || [];
      render();
      $("status").textContent = `${t("ready")} ? ${res.count} repos ? ${res.dirtyCount} dirty`;
    } catch (e) {
      $("status").textContent = String(e);
    } finally {
      $("btnScan").disabled = false;
    }
  }

  async function init() {
    const a = api();
    await bootSuite(a);
    if (window.MrAurevoXSuite) window.MrAurevoXSuite.applyI18n(suiteLang, SUITE_I18N);
    if (a && a.get_default_roots) {
      try {
        const r = await a.get_default_roots();
        if (r && r.ok && r.roots) $("roots").value = r.roots.join("\n");
      } catch (_) {}
    }
    $("btnScan").addEventListener("click", scan);
    $("filter").addEventListener("input", render);
    $("dirtyOnly").addEventListener("change", render);
    $("tbody").addEventListener("click", async (ev) => {
      const open = ev.target.closest("[data-open]");
      const fetchBtn = ev.target.closest("[data-fetch]");
      const host = api();
      if (!host) return;
      if (open) {
        await host.open_folder(open.getAttribute("data-open"));
      }
      if (fetchBtn) {
        $("status").textContent = "fetch?";
        const res = await host.fetch_repo(fetchBtn.getAttribute("data-fetch"));
        if (res && res.repo) {
          const idx = repos.findIndex((x) => x.path === res.repo.path);
          if (idx >= 0) repos[idx] = res.repo;
          else repos.push(res.repo);
          render();
        }
        $("status").textContent = res && res.ok ? "fetch OK" : (res && res.error) || "fetch fail";
      }
    });
    await scan();
  }

  window.addEventListener("pywebviewready", init);
  if (window.pywebview && window.pywebview.api) init();
})();
