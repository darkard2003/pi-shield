import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { parse } from "shell-quote";
import * as fs from "fs/promises";
import * as path from "path";

// 1. GLOBAL DEFAULTS
const GLOBAL_BLOCKLIST = new Map<string, string>([
  ["cat", "Do not use 'cat' to read files. Use your specialized 'read' tool instead."],
  ["nano", "Interactive text editors freeze the terminal. Use native file editing tools."],
  ["vim", "Interactive text editors freeze the terminal. Use native file editing tools."],
  ["less", "Interactive pagers lock up the execution pipeline. Use your 'read' tool."],
  ["rm", "Destructive file deletions are forbidden. Ask the user."],
  ["ssh", "Outbound remote connections are disabled."],
  ["bash", "Nesting shell environments is forbidden. Run commands top-level."]
  // ... (Add the rest of your exhaustive blocklist here) ...
]);

const GLOBAL_ALLOWLIST = new Set([
  "ls", "pwd", "grep", "find", "git", "npm", "echo"
]);

// 2. PROJECT STATE MEMORY
// We store project rules here so we only read the JSON file once on startup
let projectAllowed = new Set<string>();
let projectBlocked = new Map<string, string>();

export default function bashSecureAllowlist(pi: ExtensionAPI) {

  // ==========================================
  // Hook 1: Load Config on Startup
  // ==========================================
  pi.on("session_start", async (_event, ctx) => {
    // Clear previous state in case the agent session restarts
    projectAllowed.clear();
    projectBlocked.clear();

    // Look for pi-security.json in the current working directory
    const configPath = path.join(process.cwd(), "pi-security.json");

    try {
      const fileStats = await fs.stat(configPath);

      if (fileStats.isFile()) {
        const configData = await fs.readFile(configPath, "utf-8");
        const config = JSON.parse(configData);

        // Load project allows
        if (Array.isArray(config.allow)) {
          config.allow.forEach((cmd: string) => projectAllowed.add(cmd));
        }

        // Load project blocks
        if (typeof config.block === "object" && config.block !== null) {
          for (const [cmd, reason] of Object.entries(config.block)) {
            projectBlocked.set(cmd, reason as string);
          }
        }

        ctx.ui.notify(`🛡️ Guardrail: Loaded project config (+${projectAllowed.size} allowed, +${projectBlocked.size} blocked)`);
      }
    } catch (error: any) {
      if (error.code === "ENOENT") {
        // File doesn't exist, just use defaults silently
        ctx.ui.notify("🛡️ Security Guardrail enabled (Default rules)");
      } else {
        // File exists but has bad JSON or permissions issues
        ctx.ui.notify(`⚠️ Failed to parse pi-security.json: ${error.message}`);
      }
    }
  });

  // ==========================================
  // Hook 2: Validate Commands
  // ==========================================
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return;

    const args = event.input as { command?: string };
    const commandStr = args.command || "";

    if (!commandStr.trim()) {
      return { block: true, reason: "Security Guardrail: Empty bash command provided." };
    }

    try {
      const tokens = parse(commandStr);

      if (tokens.length === 0) {
        return { block: true, reason: "Security Guardrail: No executable tokens found." };
      }

      // Step A: Check Blocklists (Project blocks override global blocks)
      const blockedToken = tokens.find(token => {
        if (typeof token !== "string") return false;
        return projectBlocked.has(token) || GLOBAL_BLOCKLIST.has(token);
      }) as string | undefined;

      if (blockedToken) {
        ctx.ui.notify(`Blocked forbidden keyword: '${blockedToken}'`);

        // Fetch the specific reason, prioritizing the project config
        const specificFeedback = projectBlocked.get(blockedToken) || GLOBAL_BLOCKLIST.get(blockedToken);

        return {
          block: true,
          reason: `Security Guardrail: Execution denied. ${specificFeedback}`
        };
      }

      // Step B: Block Operators
      const hasOperators = tokens.some(token => typeof token !== "string");
      if (hasOperators) {
        ctx.ui.notify("Blocked shell injection attempt");
        return {
          block: true,
          reason: "Security Guardrail: Shell operators (;, &&, ||, >, etc.) are forbidden. Run commands one at a time."
        };
      }

      // Step C: Extract Base Command
      const baseCommand = tokens[0];
      if (typeof baseCommand !== "string") {
        return { block: true, reason: "Security Guardrail: Invalid command structure." };
      }

      // Step D: Check Allowlists (Must be in Project OR Global)
      const isAllowed = projectAllowed.has(baseCommand) || GLOBAL_ALLOWLIST.has(baseCommand);

      if (!isAllowed) {
        ctx.ui.notify(`Blocked unauthorized command: ${baseCommand}`);
        return {
          block: true,
          reason: `Security Guardrail: The command '${baseCommand}' is not on the global or project allowlist.`
        };
      }

      // Command is safe to execute
      return;

    } catch (error) {
      ctx.ui.notify("Blocked malformed bash string");
      return {
        block: true,
        reason: `Security Guardrail: Failed to parse command string securely. Error: ${(error as Error).message}`
      };
    }
  });
}
