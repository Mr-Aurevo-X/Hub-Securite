/**
 * Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X
 */
/**
 * FileGuard — native in-hub (no iframe).
 * Bridge: pywebview.api.fileguard.*
 * Segments: Locks / Permissions
 */
import { mountModuleShell, waitNs, esc } from "./_in_hub.js";
import { t } from "../i18n.js";

export async function mount(root) {
  const { body, setStatus, setSegment, askConfirm } = mountModuleShell(root, {
    title: "FileGuard",
    subtitle: t("fgSubtitle"),
    segments: [
      { id: "locks", label: t("fgSegLocks") },
      { id: "perms", label: t("fgSegPerms") },
    ],
    initialSegment: "locks",
    onSegment: renderSeg,
  });

  const api = await waitNs("fileguard", "find_locks");

  let locksData = { processes: [], method: "" };
  let permsData = { entries: [], owner: "" };

  function renderLocks(b) {
    b.innerHTML = `
      <div class="panel">
        <div class="toolbar-row">
          <div class="search-wrap">
            <input type="text" id="fgFilePath" placeholder="${esc(t("fgFilePh"))}" autocomplete="off" />
          </div>
          <button type="button" class="btn ghost" id="fgFileBrowse">${esc(t("fgBrowse"))}</button>
          <button type="button" class="btn accent" id="fgLockScan">${esc(t("fgAnalyze"))}</button>
        </div>
        <p class="meta" id="fgLockMeta"></p>
      </div>
      <div class="panel flex-fill">
        <div class="table-wrap">
          <table class="data">
            <thead><tr><th>PID</th><th>${esc(t("fgThProcess"))}</th><th>${esc(t("fgThSource"))}</th></tr></thead>
            <tbody id="fgLockBody"></tbody>
          </table>
          <p class="empty-state" id="fgLockEmpty" hidden>${esc(t("fgLockEmpty"))}</p>
        </div>
      </div>`;

    const fileInput = b.querySelector("#fgFilePath");
    const btnBrowse = b.querySelector("#fgFileBrowse");
    const btnScan = b.querySelector("#fgLockScan");
    const tbody = b.querySelector("#fgLockBody");
    const empty = b.querySelector("#fgLockEmpty");
    const meta = b.querySelector("#fgLockMeta");

    function renderTable() {
      const { processes, method } = locksData;
      tbody.innerHTML = "";
      empty.hidden = processes.length > 0;
      meta.textContent = processes.length
        ? t("fgLockMeta", { n: processes.length, method: method || "—" })
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
      if (!path) {
        setStatus(t("commonPathRequired"), "error");
        return;
      }
      if (!api?.find_locks) {
        setStatus(t("fgApiMissing"), "error");
        return;
      }
      setStatus(t("commonAnalyzing"));
      btnScan.disabled = true;
      try {
        const res = await api.find_locks(path);
        if (!res?.ok) {
          setStatus(res?.error || t("commonFail"), "error");
          return;
        }
        locksData = { processes: res.processes || [], method: res.method || "" };
        renderTable();
        setStatus(t("commonReady"));
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
            <input type="text" id="fgFolderPath" placeholder="${esc(t("fgFolderPh"))}" autocomplete="off" />
          </div>
          <button type="button" class="btn ghost" id="fgFolderBrowse">${esc(t("fgBrowse"))}</button>
          <button type="button" class="btn accent" id="fgPermScan">${esc(t("fgAnalyze"))}</button>
          <button type="button" class="btn danger" id="fgTakeown">${esc(t("fgTakeown"))}</button>
        </div>
        <p class="meta" id="fgOwnerMeta"></p>
      </div>
      <div class="panel flex-fill">
        <div class="table-wrap">
          <table class="data">
            <thead><tr>
              <th>${esc(t("fgThIdentity"))}</th>
              <th>${esc(t("fgThRights"))}</th>
              <th>${esc(t("fgThType"))}</th>
              <th>${esc(t("fgThInherited"))}</th>
            </tr></thead>
            <tbody id="fgPermBody"></tbody>
          </table>
          <p class="empty-state" id="fgPermEmpty" hidden>${esc(t("fgPermEmpty"))}</p>
        </div>
      </div>`;

    const folderInput = b.querySelector("#fgFolderPath");
    const btnBrowse = b.querySelector("#fgFolderBrowse");
    const btnScan = b.querySelector("#fgPermScan");
    const btnTakeown = b.querySelector("#fgTakeown");
    const tbody = b.querySelector("#fgPermBody");
    const empty = b.querySelector("#fgPermEmpty");
    const ownerMeta = b.querySelector("#fgOwnerMeta");

    function renderTable() {
      const { entries, owner } = permsData;
      tbody.innerHTML = "";
      empty.hidden = entries.length > 0;
      ownerMeta.textContent = owner ? t("fgOwner", { owner }) : "—";
      entries.forEach((e) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${esc(e.identity || "")}</td>
          <td class="meta">${esc(e.rights || "")}</td>
          <td>${esc(e.type || "")}</td>
          <td>${e.inherited ? esc(t("commonYes")) : esc(t("commonNo"))}</td>`;
        tbody.appendChild(tr);
      });
    }
    renderTable();

    async function doScan() {
      const path = folderInput.value.trim();
      if (!path) {
        setStatus(t("commonPathRequired"), "error");
        return;
      }
      if (!api?.get_acl) {
        setStatus(t("fgApiMissing"), "error");
        return;
      }
      setStatus(t("commonAnalyzing"));
      btnScan.disabled = true;
      try {
        const res = await api.get_acl(path);
        if (!res?.ok) {
          setStatus(res?.error || t("commonFail"), "error");
          return;
        }
        permsData = { entries: res.entries || [], owner: res.owner || "" };
        renderTable();
        setStatus(t("commonReady"));
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
      if (!path) {
        setStatus(t("commonPathRequired"), "error");
        return;
      }
      if (!api?.prepare_take_ownership || !api?.take_ownership) {
        setStatus(t("fgApiMissing"), "error");
        return;
      }
      const ok = await askConfirm(t("fgTakeownConfirm"), t("fgTakeown"));
      if (!ok) return;
      setStatus(t("commonPreparing"));
      btnTakeown.disabled = true;
      try {
        const prep = await api.prepare_take_ownership(path);
        if (!prep?.ok || !prep.token) {
          setStatus(prep?.error || t("fgConfirmDenied"), "error");
          return;
        }
        const res = await api.take_ownership(path, prep.token);
        if (!res?.ok) {
          setStatus(res?.error || t("commonFail"), "error");
          return;
        }
        setStatus(t("fgTakeownOk"), "ok");
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
