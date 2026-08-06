import { mountEmbeddedApp } from "./_hub_util.js";

export async function mount(root) {
  await mountEmbeddedApp(root, {
    ns: 'reporadar',
    src: './embedded/reporadar/index.html',
    title: 'RepoRadar',
    subtitle: 'Repos Git locaux',
    segments: null,
  });
}
