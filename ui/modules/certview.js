import { apiNs, esc } from "./_hub_util.js";

export async function mount(root) {
  const api = apiNs("certview");
  root.innerHTML = `
    <div class="hub-module-panel">
      <header class="hub-page-header">
        <h1>CertView</h1>
        <p>Certificats CurrentUser\\My — lecture seule</p>
      </header>
      <div class="hub-module-apps" style="margin-bottom:.75rem;display:flex;flex-wrap:wrap;gap:.5rem">
        <input id="cvFilter" class="hub-note" style="flex:1;min-width:10rem;padding:.4rem .6rem" placeholder="Filtrer…" />
        <button type="button" class="hub-btn accent" id="cvRefresh">Rafraîchir</button>
        <button type="button" class="hub-btn" id="cvDedicated">Fenêtre dédiée</button>
      </div>
      <p class="hub-note" id="cvMeta"></p>
      <div class="hub-skel kpi" id="cvSkel" style="min-height:8rem"></div>
      <div style="max-height:22rem;overflow:auto;display:none" id="cvTableWrap">
        <table class="hub-note" style="width:100%;border-collapse:collapse;font-size:.8rem">
          <thead><tr><th>Sujet</th><th>Émetteur</th><th>Expire</th><th>Thumbprint</th></tr></thead>
          <tbody id="cvBody"></tbody>
        </table>
      </div>
      <p class="hub-status" id="cvStatus"></p>
    </div>`;
  const status = root.querySelector("#cvStatus");
  const meta = root.querySelector("#cvMeta");
  const skel = root.querySelector("#cvSkel");
  const wrap = root.querySelector("#cvTableWrap");
  const tbody = root.querySelector("#cvBody");
  let rows = [];

  function render() {
    const q = (root.querySelector("#cvFilter").value || "").toLowerCase();
    const shown = rows.filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q));
    if (!shown.length) {
      tbody.innerHTML = `<tr><td colspan="4">Aucun certificat</td></tr>`;
    } else {
      tbody.innerHTML = shown
        .map(
          (r) => `<tr>
          <td class="wrap">${esc(r.Subject || "")}</td>
          <td class="wrap">${esc(r.Issuer || "")}</td>
          <td>${esc(r.NotAfter || "")}</td>
          <td class="wrap">${esc(r.Thumbprint || "")}</td></tr>`
        )
        .join("");
    }
    meta.textContent = `${shown.length} certificats`;
  }

  async function refresh() {
    status.textContent = "Chargement…";
    skel.style.display = "block";
    wrap.style.display = "none";
    const r = await api.list_certs();
    skel.style.display = "none";
    wrap.style.display = "block";
    if (!r?.ok) {
      status.textContent = r?.error || "Échec";
      rows = [];
      render();
      return;
    }
    rows = r.certs || [];
    render();
    status.textContent = "Prêt";
  }

  root.querySelector("#cvRefresh")?.addEventListener("click", refresh);
  root.querySelector("#cvFilter")?.addEventListener("input", render);
  root.querySelector("#cvDedicated")?.addEventListener("click", async () => {
    const r = await api.open_dedicated();
    status.textContent = r?.ok ? "Lancé CertView" : r?.error || "Échec";
  });
  await refresh();
}
