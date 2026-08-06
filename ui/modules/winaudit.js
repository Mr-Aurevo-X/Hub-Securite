import { createLaunchModule } from "./_launch.js";

const mod = createLaunchModule({
  id: "winaudit",
  title: "WinAudit",
  blurb: "Audit OS lecture seule",
});

export const mount = mod.mount;
