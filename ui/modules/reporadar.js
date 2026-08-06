import { createLaunchModule } from "./_launch.js";

const mod = createLaunchModule({
  id: "reporadar",
  title: "RepoRadar",
  blurb: "Scan repos",
});

export const mount = mod.mount;
