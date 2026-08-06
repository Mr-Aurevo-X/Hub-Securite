import { createLaunchModule } from "./_launch.js";

const mod = createLaunchModule({
  id: "fileguard",
  title: "FileGuard",
  blurb: "Ownership / garde fichiers",
});

export const mount = mod.mount;
