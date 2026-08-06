/**
 * RepoRadar — native in-hub (no iframe).
 * Bridge: pywebview.api.reporadar.*
 */
import { mountModuleShell, waitNs, esc } from "./_in_hub.js";

export async function mount(root) {
  const { body, setStatus } = mountModuleShell(root, {
    title: "RepoRadar",
    subtitle: "Repos Git locaux — branches, dirty, ahead/behind",
    fill: true,
  });

  body.innerHTML = `
    <div class="panel">
      <div class="toolbar-row">
        <div class="search-wrap">
          <input type="search" id="rrFilter" placeholder="Filtrer nom / branche / chemin…" autocomplete="off" />
        </div>
        <label style="display:flex;align-items:center;gap:6px;font-size:.82rem;color:var(--muted);cursor:pointer;white-space:nowrap">
          <input type="checkbox" id="rrDirty" /> Dirty seulement
        </label>
        <button type="button" class="btn accent" id="rrScan">Scanner</button>
      </div>
      <p class="meta" id="rrMeta"></p>
    </div>
    <div class="panel">
      <p style="font-size:.78rem;color:var(--muted);margin-bottom:6px">Racines (une par ligne) :</p>
      <textarea id="rrRoots" rows="3"
        style="width:100%;background:var(--bg0);border:1px solid var(--border);border-radius:8px;color:var(--text);font:inherit;font-size:.8rem;padding:8px 10px;resize:vertical;outline:none"></textarea>
    </div>
    <div class="panel flex-fill">
      <div class="table-wrap">
        <table class="data">
          <thead>
            <tr>
              <th>Nom / Chemin</th>
              <th>Branche</th>
              <th>Statut</th>
              <th>Sync</th>
              <th>Dernier commit</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="rrBody"></tbody>
        </table>
        <p class="empty-state" id="rrEmpty" hidden>Aucun repo trouvé — lancez un scan.</p>
      </div>
    </div>`;

  const filterEl  = body.querySelector("#rrFilter");
  const dirtyEl   = body.querySelector("#rrDirty");
  const btnScan   = body.querySelector("#rrScan");
  const rootsEl   = body.querySelector("#rrRoots");
  const tbody     = body.querySelector("#rrBody");
  const empty     = body.querySelector("#rrEmpty");
  const meta      = body.querySelector("#rrMeta");

  const api = await waitNs("reporadar");
  let repos = [];

  if (api?.get_default_roots) {
    try {
      const r = await api.get_default_roots();
      if (r?.ok && r.roots) rootsEl.value = r.roots.join("\n");
    } catch (_) {}
  }

  function render() {
    const q = (filterEl.value || "").toLowerCase().trim();
    const dirtyOnly = dirtyEl.checked;
    tbody.innerHTML = "";
    let shown = 0;
    const frag = document.createDocumentFragment();
    for (const r of repos) {
      if (dirtyOnly && !r.dirty) continue;
      const blob = `${r.name || ""} ${r.path || ""} ${r.branch || ""} ${r.remote || ""}`.toLowerCase();
      if (q && !blob.includes(q)) continue;
      shown++;
      const statusBadge = !r.ok
        ? `<span class="pill err">err</span>`
        : r.dirty
          ? `<span class="pill dirty">dirty</span>`
          : `<span class="pill clean">clean</span>`;
      const sync = r.ahead || r.behind ? `↑${r.ahead || 0} ↓${r.behind || 0}` : "✓";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${esc(r.name || "")}</strong><div class="path">${esc(r.path || "")}</div></td>
        <td>${esc(r.branch || "?")}</td>
        <td>${statusBadge}${r.error ? `<div class="path">${esc(r.error)}</div>` : ""}</td>
        <td>${esc(sync)}</td>
        <td style="font-size:.75rem">${esc(r.last || "—")}</td>
        <td>
          <button type="button" class="action-btn" data-open="${esc(r.path || "")}">Ouvrir</button>
          <button type="button" class="action-btn" data-fetch="${esc(r.path || "")}">Fetch</button>
        </td>`;
      frag.appendChild(tr);
    }
    tbody.appendChild(frag);
    empty.hidden = shown > 0 || repos.length === 0;
    meta.textContent = repos.length ? `${shown} / ${repos.length}` : "";
  }

  async function scan() {
    if (!api?.scan_repos) { setStatus("API reporadar indisponible.", "error"); return; }
    setStatus("Scan en cours…");
    btnScan.disabled = true;
    try {
      const roots = (rootsEl.value || "").split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
      const res = await api.scan_repos(roots, 3);
      if (!res?.ok) { setStatus((res?.error) || "Échec", "error"); return; }
      repos = res.repos || [];
      render();
      setStatus(`Prêt — ${res.count ?? repos.length} repos · ${res.dirtyCount ?? 0} dirty`);
    } catch (e) {
      setStatus(String(e), "error");
    } finally {
      btnScan.disabled = false;
    }
  }

  filterEl.addEventListener("input", render);
  dirtyEl.addEventListener("change", render);
  btnScan.addEventListener("click", scan);

  tbody.addEventListener("click", async (ev) => {
    const openBtn  = ev.target.closest("[data-open]");
    const fetchBtn = ev.target.closest("[data-fetch]");
    if (!api) return;
    if (openBtn) {
      api.open_folder(openBtn.getAttribute("data-open")).catch(() => {});
    }
    if (fetchBtn) {
      const path = fetchBtn.getAttribute("data-fetch");
      setStatus("fetch…");
      try {
        const res = await api.fetch_repo(path);
        if (res?.repo) {
          const idx = repos.findIndex((x) => x.path === res.repo.path);
          if (idx >= 0) repos[idx] = res.repo;
          else repos.push(res.repo);
          render();
        }
        setStatus(res?.ok ? "fetch OK" : (res?.error) || "fetch fail");
      } catch (e) {
        setStatus(String(e), "error");
      }
    }
  });

  await scan();
}
