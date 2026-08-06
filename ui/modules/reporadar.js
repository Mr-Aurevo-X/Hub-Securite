import { apiNs, esc } from "./_hub_util.js";

export async function mount(root) {
  const api = apiNs("reporadar");
  root.innerHTML = `
    <div class="hub-module-panel">
      <header class="hub-page-header">
        <h1>RepoRadar</h1>
        <p>Scan Git multi-repo — 100 % local</p>
      </header>
      <label class="hub-note" style="display:block;margin-bottom:.35rem">Racines (une par ligne)</label>
      <textarea id="rrRoots" class="hub-note" style="width:100%;min-height:4rem;padding:.5rem;margin-bottom:.5rem;font-family:var(--font-mono,monospace);font-size:.8rem"></textarea>
      <div class="hub-module-apps" style="margin-bottom:.75rem;display:flex;flex-wrap:wrap;gap:.5rem;align-items:center">
        <button type="button" class="hub-btn accent" id="rrScan">Scanner</button>
        <input id="rrFilter" class="hub-note" style="flex:1;min-width:8rem;padding:.4rem .6rem" placeholder="Filtrer…" />
        <label class="hub-note" style="display:flex;gap:.35rem;align-items:center"><input type="checkbox" id="rrDirty" /> Dirty seulement</label>
        <button type="button" class="hub-btn" id="rrDedicated">Fenêtre dédiée</button>
      </div>
      <p class="hub-note" id="rrMeta"></p>
      <div class="hub-skel kpi" id="rrSkel" style="min-height:8rem;display:none"></div>
      <div style="max-height:22rem;overflow:auto">
        <table class="hub-note" style="width:100%;border-collapse:collapse;font-size:.8rem">
          <thead><tr><th>Nom</th><th>Branche</th><th>Statut</th><th>Sync</th><th>Dernier</th><th></th></tr></thead>
          <tbody id="rrBody"></tbody>
        </table>
      </div>
      <p class="hub-status" id="rrStatus"></p>
    </div>`;
  const status = root.querySelector("#rrStatus");
  const meta = root.querySelector("#rrMeta");
  const skel = root.querySelector("#rrSkel");
  const tbody = root.querySelector("#rrBody");
  let repos = [];

  function render() {
    const q = (root.querySelector("#rrFilter").value || "").trim().toLowerCase();
    const dirtyOnly = root.querySelector("#rrDirty").checked;
    tbody.innerHTML = "";
    let shown = 0;
    for (const r of repos) {
      if (dirtyOnly && !r.dirty) continue;
      const blob = `${r.name || ""} ${r.path || ""} ${r.branch || ""} ${r.remote || ""}`.toLowerCase();
      if (q && !blob.includes(q)) continue;
      shown += 1;
      const statusHtml = !r.ok
        ? `<span style="color:var(--danger,#e03545)">err</span>`
        : r.dirty
          ? `<span style="color:var(--warn,#e0a035)">dirty</span>`
          : `<span style="color:var(--ok,#3dd68c)">clean</span>`;
      const sync = r.ahead || r.behind ? `↑${r.ahead || 0} ↓${r.behind || 0}` : "—";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${esc(r.name || "")}</strong><div style="opacity:.7;font-size:.75rem">${esc(r.path || "")}</div></td>
        <td>${esc(r.branch || "?")}</td>
        <td>${statusHtml}${r.error ? `<div style="opacity:.7">${esc(r.error)}</div>` : ""}</td>
        <td>${sync}</td>
        <td>${esc(r.last || "—")}</td>
        <td>
          <button type="button" class="hub-btn" data-open="${esc(r.path || "")}">Ouvrir</button>
          <button type="button" class="hub-btn" data-fetch="${esc(r.path || "")}">Fetch</button>
        </td>`;
      tbody.appendChild(tr);
    }
    meta.textContent = `${shown} / ${repos.length}`;
  }

  async function scan() {
    status.textContent = "Scan en cours…";
    skel.style.display = "block";
    root.querySelector("#rrScan").disabled = true;
    try {
      const roots = (root.querySelector("#rrRoots").value || "")
        .split(/\r?\n/)
        .map((x) => x.trim())
        .filter(Boolean);
      const res = await api.scan_repos(roots, 3);
      if (!res?.ok) {
        status.textContent = res?.error || "Échec";
        return;
      }
      repos = res.repos || [];
      render();
      status.textContent = `Prêt · ${res.count} repos · ${res.dirtyCount} dirty`;
    } catch (e) {
      status.textContent = String(e);
    } finally {
      skel.style.display = "none";
      root.querySelector("#rrScan").disabled = false;
    }
  }

  try {
    const r = await api.get_default_roots();
    if (r?.ok && r.roots) root.querySelector("#rrRoots").value = r.roots.join("\n");
  } catch (_) {}

  root.querySelector("#rrScan")?.addEventListener("click", scan);
  root.querySelector("#rrFilter")?.addEventListener("input", render);
  root.querySelector("#rrDirty")?.addEventListener("change", render);
  root.querySelector("#rrDedicated")?.addEventListener("click", async () => {
    const r = await api.open_dedicated();
    status.textContent = r?.ok ? "Lancé RepoRadar" : r?.error || "Échec";
  });
  tbody.addEventListener("click", async (ev) => {
    const open = ev.target.closest("[data-open]");
    const fetchBtn = ev.target.closest("[data-fetch]");
    if (open) await api.open_folder(open.getAttribute("data-open"));
    if (fetchBtn) {
      status.textContent = "fetch…";
      const res = await api.fetch_repo(fetchBtn.getAttribute("data-fetch"));
      if (res?.repo) {
        const idx = repos.findIndex((x) => x.path === res.repo.path);
        if (idx >= 0) repos[idx] = res.repo;
        else repos.push(res.repo);
        render();
      }
      status.textContent = res?.ok ? "fetch OK" : res?.error || "fetch fail";
    }
  });
  await scan();
}
