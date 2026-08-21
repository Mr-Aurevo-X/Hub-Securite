/**
 * Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X
 */
/**
 * CertView — native in-hub (no iframe).
 * Bridge: pywebview.api.certview.*
 */
import { mountModuleShell, waitNs, esc } from "./_in_hub.js";
import { t } from "../i18n.js";

export async function mount(root) {
  const { body, setStatus } = mountModuleShell(root, {
    title: "CertView",
    subtitle: t("cvSubtitle"),
    fill: true,
  });

  body.innerHTML = `
    <div class="panel">
      <div class="toolbar-row">
        <div class="search-wrap">
          <input type="search" id="cvFilter" placeholder="${esc(t("cvFilterPh"))}" autocomplete="off" />
        </div>
        <button type="button" class="btn accent" id="cvRefresh">${esc(t("cvRefresh"))}</button>
      </div>
      <p class="meta" id="cvMeta"></p>
    </div>
    <div class="panel flex-fill">
      <div class="table-wrap">
        <table class="data">
          <thead>
            <tr>
              <th>${esc(t("cvThSubject"))}</th>
              <th>${esc(t("cvThIssuer"))}</th>
              <th>${esc(t("cvThExpiry"))}</th>
              <th>${esc(t("cvThThumb"))}</th>
            </tr>
          </thead>
          <tbody id="cvBody"></tbody>
        </table>
        <p class="empty-state" id="cvEmpty" hidden>${esc(t("cvEmpty"))}</p>
      </div>
    </div>`;

  const filterEl = body.querySelector("#cvFilter");
  const btnRefresh = body.querySelector("#cvRefresh");
  const tbody = body.querySelector("#cvBody");
  const empty = body.querySelector("#cvEmpty");
  const meta = body.querySelector("#cvMeta");

  const api = await waitNs("certview", "list_certs");
  let rows = [];

  function render() {
    const q = (filterEl.value || "").toLowerCase().trim();
    const shown = q
      ? rows.filter(
          (r) =>
            (r.Subject || "").toLowerCase().includes(q) ||
            (r.Issuer || "").toLowerCase().includes(q) ||
            (r.Thumbprint || "").toLowerCase().includes(q)
        )
      : rows;
    tbody.innerHTML = "";
    empty.hidden = shown.length > 0;
    meta.textContent = t("cvMeta", { shown: shown.length, total: rows.length });
    shown.forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="wrap">${esc(r.Subject || "")}</td>
        <td class="wrap">${esc(r.Issuer || "")}</td>
        <td>${esc(r.NotAfter || "")}</td>
        <td class="meta">${esc(r.Thumbprint || "")}</td>`;
      tbody.appendChild(tr);
    });
  }

  async function refresh() {
    if (!api?.list_certs) {
      setStatus(t("cvApiMissing"), "error");
      return;
    }
    setStatus(t("commonLoading"));
    btnRefresh.disabled = true;
    try {
      const res = await api.list_certs();
      if (!res?.ok) {
        setStatus(res?.error || t("commonFail"), "error");
        return;
      }
      rows = res.certs || [];
      render();
      setStatus(t("commonReady"));
    } catch (e) {
      setStatus(String(e), "error");
    } finally {
      btnRefresh.disabled = false;
    }
  }

  filterEl.addEventListener("input", render);
  btnRefresh.addEventListener("click", refresh);
  await refresh();
}
