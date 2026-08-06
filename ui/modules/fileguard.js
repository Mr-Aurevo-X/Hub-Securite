/**
 * FileGuard — native in-hub (no iframe).
 * Bridge: pywebview.api.fileguard.*
 * Segments: Verrous / Permissions
 */
import { mountModuleShell, waitNs, esc } from "./_in_hub.js";

export async function mount(root) {
  const { body, setStatus, setSegment, askConfirm } = mountModuleShell(root, {
    title: "FileGuard",
    subtitle: "Verrous · ACL NTFS · ownership",
    segments: [
      { id: "locks", label: "Verrous" },
      { id: "perms", label: "Permissions" },
    ],
    initialSegment: "locks",
    onSegment: renderSeg,
  });

  const api = await waitNs("fileguard", "find_locks");

  // ── Shared state ────────────────────────────────────────────────────────────
  let locksData = { processes: [], method: "" };
  let permsData  = { entries: [], owner: "" };

  // ── Render helpers ──────────────────────────────────────────────────────────
  function renderLocks(b) {
    b.innerHTML = `
      <div class="panel">
        <div class="toolbar-row">
          <div class="search-wrap">
            <input type="text" id="fgFilePath" placeholder="C:\\…\\fichier" autocomplete="off" />
          </div>
          <button type="button" class="btn ghost" id="fgFileBrowse">Parcourir</button>
          <button type="button" class="btn accent" id="fgLockScan">Analyser</button>
        </div>
        <p class="meta" id="fgLockMeta"></p>
      </div>
      <div class="panel flex-fill">
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>PID</th><th>Processus</th><th>Source</th></tr></thead>
            <tbody id="fgLockBody"></tbody>
          </table>
          <p class="empty-state" id="fgLockEmpty" hidden>Aucun verrou détecté.</p>
        </div>
      </div>`;

    const fileInput = b.querySelector("#fgFilePath");
    const btnBrowse = b.querySelector("#fgFileBrowse");
    const btnScan   = b.querySelector("#fgLockScan");
    const tbody     = b.querySelector("#fgLockBody");
    const empty     = b.querySelector("#fgLockEmpty");
    const meta      = b.querySelector("#fgLockMeta");

    function renderTable() {
      const { processes, method } = locksData;
      tbody.innerHTML = "";
      empty.hidden = processes.length > 0;
      meta.textContent = processes.length
        ? `${processes.length} processus · ${method || "—"}`
        : "";
      processes.forEach((p) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${esc(p.pid)}</td><td>${esc(p.name || "")}</td><td class="meta">${esc(p.source || "")}</td>`;
        tbody.appendChild(tr);
      });
    }
    renderTable();

    btnBrowse.addEventListener("click", async () => {
      if (!api?.pick_file) return;
      const res = await api.pick_file();
      if (res?.ok && res.path) fileInput.value = res.path;
    });

    btnScan.addEventListener("click", async () => {
      const path = fileInput.value.trim();
      if (!path) { setStatus("Chemin requis.", "error"); return; }
      if (!api?.find_locks) { setStatus("API fileguard indisponible.", "error"); return; }
      setStatus("Analyse…");
      btnScan.disabled = true;
      try {
        const res = await api.find_locks(path);
        if (!res?.ok) { setStatus((res?.error) || "Échec", "error"); return; }
        locksData = { processes: res.processes || [], method: res.method || "" };
        renderTable();
        setStatus("Prêt");
      } catch (e) {
        setStatus(String(e), "error");
      } finally {
        btnScan.disabled = false;
      }
    });
  }

  function renderPerms(b) {
    b.innerHTML = `
      <div class="panel">
        <div class="toolbar-row">
          <div class="search-wrap">
            <input type="text" id="fgFolderPath" placeholder="C:\\…\\dossier" autocomplete="off" />
          </div>
          <button type="button" class="btn ghost" id="fgFolderBrowse">Parcourir</button>
          <button type="button" class="btn accent" id="fgPermScan">Analyser</button>
          <button type="button" class="btn danger" id="fgTakeown">Prendre possession</button>
        </div>
        <p class="meta" id="fgOwnerMeta"></p>
      </div>
      <div class="panel flex-fill">
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>Identité</th><th>Droits</th><th>Type</th><th>Hérité</th></tr></thead>
            <tbody id="fgPermBody"></tbody>
          </table>
          <p class="empty-state" id="fgPermEmpty" hidden>Aucune entrée ACL.</p>
        </div>
      </div>`;

    const folderInput = b.querySelector("#fgFolderPath");
    const btnBrowse   = b.querySelector("#fgFolderBrowse");
    const btnScan     = b.querySelector("#fgPermScan");
    const btnTakeown  = b.querySelector("#fgTakeown");
    const tbody       = b.querySelector("#fgPermBody");
    const empty       = b.querySelector("#fgPermEmpty");
    const ownerMeta   = b.querySelector("#fgOwnerMeta");

    function renderTable() {
      const { entries, owner } = permsData;
      tbody.innerHTML = "";
      empty.hidden = entries.length > 0;
      ownerMeta.textContent = owner ? `Propriétaire : ${owner}` : "—";
      entries.forEach((e) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${esc(e.identity || "")}</td>
          <td class="meta">${esc(e.rights || "")}</td>
          <td>${esc(e.type || "")}</td>
          <td>${e.inherited ? "Oui" : "Non"}</td>`;
        tbody.appendChild(tr);
      });
    }
    renderTable();

    async function doScan() {
      const path = folderInput.value.trim();
      if (!path) { setStatus("Chemin requis.", "error"); return; }
      if (!api?.get_acl) { setStatus("API fileguard indisponible.", "error"); return; }
      setStatus("Analyse…");
      btnScan.disabled = true;
      try {
        const res = await api.get_acl(path);
        if (!res?.ok) { setStatus((res?.error) || "Échec", "error"); return; }
        permsData = { entries: res.entries || [], owner: res.owner || "" };
        renderTable();
        setStatus("Prêt");
      } catch (e) {
        setStatus(String(e), "error");
      } finally {
        btnScan.disabled = false;
      }
    }

    btnBrowse.addEventListener("click", async () => {
      if (!api?.pick_folder) return;
      const res = await api.pick_folder();
      if (res?.ok && res.path) folderInput.value = res.path;
    });

    btnScan.addEventListener("click", doScan);

    btnTakeown.addEventListener("click", async () => {
      const path = folderInput.value.trim();
      if (!path) { setStatus("Chemin requis.", "error"); return; }
      if (!api?.prepare_take_ownership || !api?.take_ownership) {
        setStatus("API fileguard indisponible.", "error");
        return;
      }
      const ok = await askConfirm(
        "Prendre possession récursivement ? Cette opération remplace les ACL actuelles par votre compte.",
        "Prendre possession"
      );
      if (!ok) return;
      setStatus("Préparation…");
      btnTakeown.disabled = true;
      try {
        const prep = await api.prepare_take_ownership(path);
        if (!prep?.ok || !prep.token) {
          setStatus((prep?.error) || "Confirmation refusée", "error");
          return;
        }
        const res = await api.take_ownership(path, prep.token);
        if (!res?.ok) { setStatus((res?.error) || "Échec", "error"); return; }
        setStatus("Possession prise.", "ok");
        await doScan();
      } catch (e) {
        setStatus(String(e), "error");
      } finally {
        btnTakeown.disabled = false;
      }
    });
  }

  async function renderSeg(segId, b) {
    b.innerHTML = "";
    if (segId === "locks") renderLocks(b);
    else renderPerms(b);
  }

  await setSegment("locks", { silent: false });
}
