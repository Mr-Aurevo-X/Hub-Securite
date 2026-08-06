import { apiNs, esc } from "./_hub_util.js";

export async function mount(root) {
  const api = apiNs("fileguard");
  root.innerHTML = `
    <div class="hub-module-panel">
      <header class="hub-page-header">
        <h1>FileGuard</h1>
        <p>Verrous · ACL NTFS — ConfirmGate sur possession</p>
      </header>
      <div class="hub-module-apps" style="margin-bottom:.75rem;display:flex;flex-wrap:wrap;gap:.5rem">
        <button type="button" class="hub-btn" data-tab="locks">Verrous</button>
        <button type="button" class="hub-btn accent" data-tab="perms">Permissions</button>
        <button type="button" class="hub-btn" id="btnDedicated">Fenêtre dédiée</button>
      </div>
      <div id="fgBody"></div>
      <p class="hub-status" id="fgStatus"></p>
    </div>`;
  const body = root.querySelector("#fgBody");
  const status = root.querySelector("#fgStatus");

  function showLocks() {
    body.innerHTML = `
      <div class="hub-module-apps" style="flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem">
        <input id="fgFile" class="hub-note" style="flex:1;min-width:12rem;padding:.4rem .6rem" placeholder="C:\\...\\fichier" />
        <button type="button" class="hub-btn" id="fgBrowseFile">Parcourir</button>
        <button type="button" class="hub-btn accent" id="fgScanLocks">Analyser</button>
      </div>
      <p class="hub-note" id="fgLockMeta"></p>
      <div style="max-height:16rem;overflow:auto">
        <table class="hub-note" style="width:100%;border-collapse:collapse;font-size:.8rem">
          <thead><tr><th>PID</th><th>Processus</th><th>Source</th></tr></thead>
          <tbody id="fgLockBody"></tbody>
        </table>
      </div>`;
    body.querySelector("#fgBrowseFile")?.addEventListener("click", async () => {
      const r = await api.pick_file();
      if (r?.ok && r.path) body.querySelector("#fgFile").value = r.path;
    });
    body.querySelector("#fgScanLocks")?.addEventListener("click", async () => {
      const path = (body.querySelector("#fgFile").value || "").trim();
      if (!path) {
        status.textContent = "Chemin requis";
        return;
      }
      status.textContent = "Analyse…";
      body.classList.add("hub-skel", "kpi");
      const r = await api.find_locks(path);
      body.classList.remove("hub-skel", "kpi");
      const tbody = body.querySelector("#fgLockBody");
      tbody.innerHTML = "";
      const procs = r?.processes || [];
      body.querySelector("#fgLockMeta").textContent = r?.ok
        ? `${procs.length} processus · ${r.method || "—"}`
        : r?.error || "Échec";
      procs.forEach((p) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${esc(p.pid)}</td><td>${esc(p.name || "")}</td><td class="mono">${esc(p.source || "")}</td>`;
        tbody.appendChild(tr);
      });
      status.textContent = r?.ok ? "Prêt" : r?.error || "Échec";
    });
  }

  function showPerms() {
    body.innerHTML = `
      <div class="hub-module-apps" style="flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem">
        <input id="fgFolder" class="hub-note" style="flex:1;min-width:12rem;padding:.4rem .6rem" placeholder="C:\\...\\dossier" />
        <button type="button" class="hub-btn" id="fgBrowseFolder">Parcourir</button>
        <button type="button" class="hub-btn accent" id="fgScanAcl">Analyser ACL</button>
        <button type="button" class="hub-btn" id="fgTakeown">Prendre possession</button>
      </div>
      <p class="hub-note" id="fgOwner"></p>
      <div style="max-height:16rem;overflow:auto">
        <table class="hub-note" style="width:100%;border-collapse:collapse;font-size:.8rem">
          <thead><tr><th>Identité</th><th>Droits</th><th>Type</th><th>Hérité</th></tr></thead>
          <tbody id="fgAclBody"></tbody>
        </table>
      </div>`;

    async function scanAcl() {
      const path = (body.querySelector("#fgFolder").value || "").trim();
      if (!path) {
        status.textContent = "Chemin requis";
        return;
      }
      status.textContent = "Analyse ACL…";
      const r = await api.get_acl(path);
      const tbody = body.querySelector("#fgAclBody");
      tbody.innerHTML = "";
      body.querySelector("#fgOwner").textContent = r?.owner ? `Propriétaire : ${r.owner}` : "—";
      (r?.entries || []).forEach((e) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${esc(e.identity || "")}</td><td class="mono">${esc(e.rights || "")}</td>
          <td>${esc(e.type || "")}</td><td>${e.inherited ? "Oui" : "Non"}</td>`;
        tbody.appendChild(tr);
      });
      status.textContent = r?.ok ? "Prêt" : r?.error || "Échec";
    }

    body.querySelector("#fgBrowseFolder")?.addEventListener("click", async () => {
      const r = await api.pick_folder();
      if (r?.ok && r.path) body.querySelector("#fgFolder").value = r.path;
    });
    body.querySelector("#fgScanAcl")?.addEventListener("click", scanAcl);
    body.querySelector("#fgTakeown")?.addEventListener("click", async () => {
      if (!window.confirm("Prendre possession récursivement ? Opération destructive des ACL actuelles pour votre compte.")) {
        return;
      }
      const path = (body.querySelector("#fgFolder").value || "").trim();
      if (!path) {
        status.textContent = "Chemin requis";
        return;
      }
      status.textContent = "Confirmation…";
      const prep = await api.prepare_take_ownership(path);
      if (!prep?.ok || !prep.token) {
        status.textContent = prep?.error || "Confirmation refusée";
        return;
      }
      const r = await api.take_ownership(path, prep.token);
      status.textContent = r?.ok ? "Possession prise" : r?.error || "Échec";
      if (r?.ok) await scanAcl();
    });
  }

  root.querySelectorAll("[data-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.dataset.tab === "locks") showLocks();
      else showPerms();
    });
  });
  root.querySelector("#btnDedicated")?.addEventListener("click", async () => {
    const r = await api.open_dedicated();
    status.textContent = r?.ok ? "Lancé FileGuard" : r?.error || "Échec";
  });
  showLocks();
}
