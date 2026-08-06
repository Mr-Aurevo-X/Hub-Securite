import { createLaunchModule } from "./_launch.js";

const mod = createLaunchModule({
  id: "certview",
  title: "CertView",
  blurb: "Certificats locaux",
});

export const mount = mod.mount;
