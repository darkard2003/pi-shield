import shellGuard from "./shell-guard";
import pathGuard from "./path-guard";
import { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createDefaultConfig, loadConfig } from "./config";

export default function register(pi: ExtensionAPI) {
  const config = createDefaultConfig();

  pi.on("session_start", async (_event, ctx) => {
    await loadConfig(config, (msg) => ctx.ui.notify(msg));
    
    const shellStatus = config.shell.enabled ? "enabled" : "disabled";
    const pathStatus = config.path.enabled ? "enabled" : "disabled";
    ctx.ui.notify(`Pi-Shield: Config loaded (Shell Guard: ${shellStatus}, Path Guard: ${pathStatus})`);
  });

  shellGuard(pi, config);
  pathGuard(pi, config);
}
