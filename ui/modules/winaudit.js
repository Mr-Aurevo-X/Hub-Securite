import { apiNs, esc } from "./_hub_util.js";

export async function mount(root) {
  const api = apiNs("winaudit");
  root.innerHTML = `
    <div class="hub-module-panel">
      <header class="hub-page-header">
        <h1>WinAudit</h1>
        <p>Audit OS heuristique — lecture seule (zéro mutator)</p>
      </header>
      <div class="hub-module-apps" style="margin-bottom:.75rem;display:flex;flex-wrap:wrap;gap:.5rem">
        <button type="button" class="hub-btn accent" id="waScan">Lancer le scan</button>
        <button type="button" class="hub-btn" id="waCancel" disabled>Annuler</button>
        <button type="button" class="hub-btn" id="waReload">Dernier résultat</button>
        <button type="button" class="hub-btn" id="waDedicated">Fenêtre dédiée</button>
      </div>
      <div class="hub-kpi-grid" id="waKpis" style="margin-bottom:.75rem">
        <div class="hub-skel kpi"></div>
        <div class="hub-skel kpi"></div>
        <div class="hub-skel kpi"></div>
        <div class="hub-skel kpi"></div>
      </div>
      <p class="hub-note" id="waProg"></p>
      <div style="max-height:18rem;overflow:auto">
        <table class="hub-note" style="width:100%;border-collapse:collapse;font-size:.8rem">
          <thead><tr><th>Sev.</th><th>Cat.</th><th>Titre</th><th>Chemin</th></tr></thead>
          <tbody id="waBody"><tr><td colspan="4">Lancez un scan ou rechargez le dernier résultat.</td></tr></tbody>
        </table>
      </div>
      <p class="hub-status" id="waStatus"></p>
    </div>`;
  const status = root.querySelector("#waStatus");
  const prog = root.querySelector("#waProg");
  const kpis = root.querySelector("#waKpis");
  const tbody = root.querySelector("#waBody");
  const btnScan = root.querySelector("#waScan");
  const btnCancel = root.querySelector("#waCancel");

  function setKpis(data) {
    const score = data?.Score ?? data?.score ?? "—";
    const findings = data?.Findings || data?.findings || [];
    const chains = data?.Chains || data?.chains || [];
    const dur = data?.DurationLabel || data?.duration || data?.Duration || "—";
    kpis.innerHTML = `
      <div class="hub-kpi"><span class="label">Score</span><span class="value">${esc(score)}</span></div>
      <div class="hub-kpi"><span class="label">Findings</span><span class="value">${esc(findings.length)}</span></div>
      <div class="hub-kpi"><span class="label">Chaînes</span><span class="value">${esc(chains.length)}</span></div>
      <div class="hub-kpi"><span class="label">Durée</span><span class="value">${esc(dur)}</span></div>`;
  }

  function renderFindings(data) {
    const findings = data?.Findings || data?.findings || [];
    setKpis(data || {});
    if (!findings.length) {
      tbody.innerHTML = `<tr><td colspan="4">Aucun finding.</td></tr>`;
      return;
    }
    tbody.innerHTML = findings
      .slice(0, 200)
      .map((f) => {
        const sev = f.Severity || f.severity || f.Sev || "";
        const cat = f.Category || f.category || "";
        const title = f.Title || f.title || f.Name || "";
        const path = f.Path || f.path || f.Target || "";
        return `<tr>
          <td>${esc(sev)}</td><td>${esc(cat)}</td>
          <td>${esc(title)}</td><td class="wrap">${esc(path)}</td></tr>`;
      })
      .join("");
  }

  async function pollUntilDone() {
    btnCancel.disabled = false;
    btnScan.disabled = true;
    for (;;) {
      const p = await api.get_scan_progress();
      const d = p?.data || {};
      prog.textContent = `${d.percent || 0}% · ${d.phase || ""} · ${d.detail || ""}`;
      if (d.done) {
        btnCancel.disabled = true;
        btnScan.disabled = false;
        if (d.cancelled) {
          status.textContent = "Scan annulé";
          return;
        }
        if (d.error) {
          status.textContent = d.error;
          return;
        }
        const res = await api.get_scan_result();
        if (res?.ok) {
          renderFindings(res.data);
          status.textContent = "Scan terminé";
        } else {
          status.textContent = res?.error || "Échec résultat";
        }
        return;
      }
      await new Promise((r) => setTimeout(r, 400));
    }
  }

  root.querySelector("#waScan")?.addEventListener("click", async () => {
    status.textContent = "Démarrage…";
    kpis.innerHTML = `<div class="hub-skel kpi"></div><div class="hub-skel kpi"></div><div class="hub-skel kpi"></div><div class="hub-skel kpi"></div>`;
    const r = await api.start_scan();
    if (!r?.ok) {
      status.textContent = r?.error || "Échec démarrage";
      return;
    }
    await pollUntilDone();
  });
  root.querySelector("#waCancel")?.addEventListener("click", async () => {
    await api.cancel_scan();
    status.textContent = "Annulation…";
  });
  root.querySelector("#waReload")?.addEventListener("click", async () => {
    status.textContent = "Chargement…";
    const res = await api.get_scan_result();
    if (res?.ok) {
      renderFindings(res.data);
      status.textContent = "Dernier résultat";
    } else {
      status.textContent = res?.error || "Aucun résultat";
    }
  });
  root.querySelector("#waDedicated")?.addEventListener("click", async () => {
    const r = await api.open_dedicated();
    status.textContent = r?.ok ? "Lancé WinAudit" : r?.error || "Échec";
  });

  try {
    const admin = await api.is_admin();
    status.textContent = admin ? "Prêt — droits admin" : "Prêt — droits limités";
  } catch (_) {
    status.textContent = "Prêt";
  }
}
