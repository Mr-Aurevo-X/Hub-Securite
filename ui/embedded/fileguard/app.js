(function () {
  "use strict";

  const SUITE_I18N = {
    fr: {
      tagline: "Fichiers · verrous",
      featuresTitle: "Fonctions",
      features: "Verrous de fichiers et audit ACL NTFS.",
      privacy: "Mr-Aurevo-X ne collecte aucune donnée. Outils locaux uniquement.",
      copyright: "© 2026 Mr-Aurevo-X · local · CGU dans L'Atelier PC Command",
      title: "FileGuard",
      subtitle: "Verrous et permissions — local",
      tabLocks: "Verrous",
      tabPerms: "Permissions",
      fileLabel: "Fichier",
      filePh: "C:\\...\\fichier",
      folderLabel: "Dossier",
      folderPh: "C:\\...\\dossier",
      browse: "Parcourir",
      btnScan: "Analyser",
      btnTakeown: "Prendre possession",
      thPid: "PID",
      thName: "Processus",
      thSource: "Source",
      thIdentity: "Identité",
      thRights: "Droits",
      thType: "Type",
      thInherited: "Hérité",
      emptyLocks: "Aucun verrou détecté.",
      emptyPerms: "Aucune entrée ACL.",
      metaCount: "{count} processus · {method}",
      owner: "Propriétaire : {owner}",
      hostMissing: "Host indisponible",
      ready: "Prêt",
      fail: "Échec",
      scanning: "Analyse…",
      confirmTakeown: "Prendre possession récursivement ? Opération destructive des ACL actuelles pour votre compte.",
      taken: "Possession prise",
      yes: "Oui",
      no: "Non",
    },
    en: {
      tagline: "Files · locks",
      featuresTitle: "Features",
      features: "File locks and NTFS ACL audit.",
      privacy: "Mr-Aurevo-X does not collect your data. Local tools only.",
      copyright: "© 2026 Mr-Aurevo-X · local · Terms in Atelier",
      title: "FileGuard",
      subtitle: "Locks and permissions — local",
      tabLocks: "Locks",
      tabPerms: "Permissions",
      fileLabel: "File",
      filePh: "C:\\...\\file",
      folderLabel: "Folder",
      folderPh: "C:\\...\\folder",
      browse: "Browse",
      btnScan: "Scan",
      btnTakeown: "Take ownership",
      thPid: "PID",
      thName: "Process",
      thSource: "Source",
      thIdentity: "Identity",
      thRights: "Rights",
      thType: "Type",
      thInherited: "Inherited",
      emptyLocks: "No lock detected.",
      emptyPerms: "No ACL entries.",
      metaCount: "{count} process(es) · {method}",
      owner: "Owner: {owner}",
      hostMissing: "Host unavailable",
      ready: "Ready",
      fail: "Failed",
      scanning: "Scanning…",
      confirmTakeown: "Take recursive ownership? This grants your account full control.",
      taken: "Ownership taken",
      yes: "Yes",
      no: "No",
    },
  };

  const state = { booted: false, lang: "fr" };
  const t = (k) => (SUITE_I18N[state.lang] && SUITE_I18N[state.lang][k]) || SUITE_I18N.fr[k] || k;

  function escapeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function fmt(key, vars) {
    let s = t(key);
    Object.entries(vars || {}).forEach(([k, v]) => {
      s = s.replace(new RegExp(`\\{${k}\\}`, "g"), String(v));
    });
    return s;
  }

  function setStatus(text, isError) {
    const el = document.getElementById("status");
    if (!el) return;
    el.textContent = text || "";
    el.classList.toggle("error", !!isError);
    el.classList.toggle("ok", !isError && !!text);
    if (window.SuiteProgress && /^(prêt|ready)$/i.test(String(text || ""))) window.SuiteProgress.forceClear();
  }

  async function setStatusBusy(text) {
    setStatus(text);
    if (window.SuiteProgress) window.SuiteProgress.setBusy(text || "…");
    await new Promise((r) => setTimeout(r, 40));
  }

  function apiReady() {
    return new Promise((resolve) => {
      if (window.pywebview && window.pywebview.api) return resolve(window.pywebview.api);
      window.addEventListener("pywebviewready", () => resolve(window.pywebview && window.pywebview.api), { once: true });
      setTimeout(() => resolve(window.pywebview && window.pywebview.api), 3000);
    });
  }

  function switchTab(name) {
    document.querySelectorAll(".hub-tab").forEach((btn) => {
      const on = btn.getAttribute("data-tab") === name;
      btn.classList.toggle("active", on);
      btn.setAttribute("aria-selected", on ? "true" : "false");
    });
    document.querySelectorAll(".hub-panel").forEach((panel) => {
      const on = panel.getAttribute("data-panel") === name;
      panel.classList.toggle("active", on);
      panel.hidden = !on;
    });
  }

  function renderLocks(processes, method) {
    const tbody = document.getElementById("lockBody");
    const empty = document.getElementById("lockEmpty");
    const meta = document.getElementById("lockMeta");
    tbody.innerHTML = "";
    meta.textContent = fmt("metaCount", { count: (processes || []).length, method: method || "—" });
    empty.hidden = (processes || []).length > 0;
    (processes || []).forEach((p) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${escapeHtml(p.pid)}</td>
        <td>${escapeHtml(p.name || "")}</td>
        <td class="mono">${escapeHtml(p.source || "")}</td>`;
      tbody.appendChild(tr);
    });
  }

  function renderPerms(entries, owner) {
    const tbody = document.getElementById("permBody");
    const empty = document.getElementById("permEmpty");
    const ownerMeta = document.getElementById("ownerMeta");
    tbody.innerHTML = "";
    ownerMeta.textContent = owner ? fmt("owner", { owner }) : "—";
    empty.hidden = (entries || []).length > 0;
    (entries || []).forEach((e) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${escapeHtml(e.identity || "")}</td>
        <td class="mono">${escapeHtml(e.rights || "")}</td>
        <td>${escapeHtml(e.type || "")}</td>
        <td>${e.inherited ? t("yes") : t("no")}</td>`;
      tbody.appendChild(tr);
    });
  }

  async function bootSuite(api) {
    const suite = window.MrAurevoXSuite;
    if (suite) {
      const s = await suite.loadSuiteSettings(api);
      state.lang = s.language === "en" ? "en" : "fr";
      suite.applyAccent(s.accent);
      if (suite.applyTheme) suite.applyTheme(s.theme);
      suite.applyI18n(state.lang, SUITE_I18N);
    } else if (api && api.get_suite_settings) {
      try {
        const s = await api.get_suite_settings();
        if (s && s.language === "en") state.lang = "en";
      } catch (_) {}
    }
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const k = el.getAttribute("data-i18n");
      if (SUITE_I18N.fr[k]) el.textContent = t(k);
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      const k = el.getAttribute("data-i18n-placeholder");
      if (SUITE_I18N.fr[k]) el.setAttribute("placeholder", t(k));
    });
  }

  function wire(api) {
    document.getElementById("hubTabs").addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-tab]");
      if (btn) switchTab(btn.getAttribute("data-tab"));
    });

    document.getElementById("btnLockBrowse").addEventListener("click", async () => {
      if (!api || !api.pick_file) return;
      const res = await api.pick_file();
      if (res && res.ok && res.path) document.getElementById("filePath").value = res.path;
    });

    document.getElementById("btnLockScan").addEventListener("click", async () => {
      if (!api || !api.find_locks) return setStatus(t("hostMissing"), true);
      const path = document.getElementById("filePath").value.trim();
      if (!path) return setStatus(t("fail"), true);
      await setStatusBusy(t("scanning"));
      const res = await api.find_locks(path);
      if (!res || !res.ok) {
        renderLocks([], "");
        return setStatus((res && res.error) || t("fail"), true);
      }
      renderLocks(res.processes || [], res.method || "");
      setStatus(t("ready"));
    });


    document.getElementById("btnPermBrowse").addEventListener("click", async () => {
      if (!api || !api.pick_folder) return;
      const res = await api.pick_folder();
      if (res && res.ok && res.path) document.getElementById("folderPath").value = res.path;
    });

    async function scanPerms() {
      if (!api || !api.get_acl) return setStatus(t("hostMissing"), true);
      const path = document.getElementById("folderPath").value.trim();
      if (!path) return setStatus(t("fail"), true);
      await setStatusBusy(t("scanning"));
      const res = await api.get_acl(path);
      if (!res || !res.ok) {
        renderPerms([], "");
        return setStatus((res && res.error) || t("fail"), true);
      }
      renderPerms(res.entries || [], res.owner || "");
      setStatus(t("ready"));
    }

    document.getElementById("btnPermScan").addEventListener("click", scanPerms);

    document.getElementById("btnTakeown").addEventListener("click", async () => {
      if (!window.confirm(t("confirmTakeown"))) return;
      if (!api || !api.take_ownership || !api.prepare_take_ownership) return setStatus(t("hostMissing"), true);
      const path = document.getElementById("folderPath").value.trim();
      if (!path) return setStatus(t("fail"), true);
      await setStatusBusy(t("scanning"));
      const prep = await api.prepare_take_ownership(path);
      if (!prep || !prep.ok || !prep.token) return setStatus((prep && prep.error) || t("fail"), true);
      const res = await api.take_ownership(path, prep.token);
      if (!res || !res.ok) return setStatus((res && res.error) || t("fail"), true);
      setStatus(t("taken"));
      await scanPerms();
    });

  }

  async function boot() {
    if (state.booted) return;
    state.booted = true;
    try {
      const api = await apiReady();
      await bootSuite(api);
      wire(api);
      setStatus(api ? t("ready") : t("hostMissing"), !api);
    } catch (e) {
      setStatus(String(e.message || e), true);
    }
  }

  window.addEventListener("pywebviewready", boot);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
