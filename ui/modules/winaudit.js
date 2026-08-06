import { mountEmbeddedApp } from "./_hub_util.js";

export async function mount(root) {
  await mountEmbeddedApp(root, {
    ns: 'winaudit',
    src: './embedded/winaudit/index.html',
    title: 'WinAudit',
    subtitle: 'Audit OS heuristique — lecture seule',
    segments: [
    { id: "overview", label: "Aperçu OS" },
    { id: "findings", label: "Heuristique" },
    { id: "reseau", label: "Réseau" },
    { id: "chains", label: "Chaînes" },
    { id: "timeline", label: "Logs / Timeline" }
  ],
  });
}
