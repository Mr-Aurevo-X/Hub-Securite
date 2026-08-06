import { mountEmbeddedApp } from "./_hub_util.js";

export async function mount(root) {
  await mountEmbeddedApp(root, {
    ns: 'fileguard',
    src: './embedded/fileguard/index.html',
    title: 'FileGuard',
    subtitle: 'Verrous · ACL · ownership',
    segments: null,
  });
}
