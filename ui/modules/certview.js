import { mountEmbeddedApp } from "./_hub_util.js";

export async function mount(root) {
  await mountEmbeddedApp(root, {
    ns: 'certview',
    src: './embedded/certview/index.html',
    title: 'CertView',
    subtitle: 'Certificats locaux',
    segments: null,
  });
}
