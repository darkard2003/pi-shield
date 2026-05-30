import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { GLOBAL_ALLOWLIST, GLOBAL_BLOCKLIST } from "./global_constants";
import { parse } from "shell-quote";
import * as fs from "fs/promises";
import * as path from "path";


let projectAllowed = new Set<string>();
let projectBlocked = new Map<string, string>();

export default function bashSecureAllowlist(pi: ExtensionAPI, enabled: boolean = true) {

  // Hook 1: Load Project Config on Startup
  pi.on("session_start", async (_event, ctx) => {
    if (!enabled) {
      ctx.ui.notify('Security Guardrail is disabled');
      return;
    }

    projectAllowed.clear();
    projectBlocked.clear();

    const configPath = path.join(process.cwd(), "pi-security.json");

    try {
      const fileStats = await fs.stat(configPath);

      if (fileStats.isFile()) {
        const configData = await fs.readFile(configPath, "utf-8");
        const config = JSON.parse(configData);

        if (Array.isArray(config.allow)) {
          config.allow.forEach((cmd: string) => projectAllowed.add(cmd));
        }

        if (typeof config.block === "object" && config.block !== null) {
          for (const [cmd, reason] of Object.entries(config.block)) {
            projectBlocked.set(cmd, reason as string);
          }
        }

        ctx.ui.notify(`Guardrail: Loaded config (+${projectAllowed.size} allowed, +${projectBlocked.size} blocked)`);
      }
    } catch (error: any) {
      if (error.code === "ENOENT") {
        ctx.ui.notify("Security Guardrail enabled (Default rules)");
      } else {
        ctx.ui.notify(`Failed to parse pi-security.json: ${error.message}`);
      }
    }
  });

  // Hook 2: Validate Commands
  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return;
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

      // Step A: Check Blocklists
      const blockedToken = tokens.find(token => {
        if (typeof token !== "string") return false;
        // Check exact match or basename (to catch /bin/rm)
        const baseName = path.basename(token);
        return projectBlocked.has(token) || GLOBAL_BLOCKLIST.has(token) ||
          projectBlocked.has(baseName) || GLOBAL_BLOCKLIST.has(baseName);
      }) as string | undefined;

      if (blockedToken) {
        const matchedToken = path.basename(blockedToken);
        ctx.ui.notify(`Blocked forbidden keyword: '${matchedToken}'`);
        const specificFeedback = projectBlocked.get(matchedToken) || GLOBAL_BLOCKLIST.get(matchedToken);
        return {
          block: true,
          reason: `Security Guardrail: ${specificFeedback}`
        };
      }

      // Step B: Block Dangerous Operators (Allow safe globbing like *.ts)
      let hasDangerousOperators = false;

      for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];

        // 1. Standard strings are safe to skip
        if (typeof token === "string") continue;

        // 2. Check Objects (Operators)
        if ('op' in token) {
          // Allow wildcard globbing (e.g., *.ts)
          if (token.op === "glob") continue;

          // Allow output redirection ONLY to /dev/null
          const redirectOps = [">", ">>", "2>", "&>", "1>"];
          if (redirectOps.includes(token.op as string)) {
            const nextToken = tokens[i + 1];

            // Validate the target is exactly /dev/null
            if (typeof nextToken === "string" && nextToken === "/dev/null") {
              i++; // Fast-forward the loop past '/dev/null' so we don't evaluate it again
              continue;
            }
          }

          // If we reach this line, it's a dangerous operator (like ; or &&) 
          // OR it's a redirect to an unauthorized file (like > hack.txt)
          hasDangerousOperators = true;
          break;
        }
      }

      if (hasDangerousOperators) {
        ctx.ui.notify("Blocked shell injection or file redirect");
        return {
          block: true,
          reason: "ACTION BLOCKED. Shell operators (;, &&, ||) and file redirections are disabled. You may only redirect output to /dev/null."
        };
      }
      // Step C: Extract Base Command (Skipping inline ENV variables like NODE_ENV=test)
      const execToken = tokens.find(t => typeof t === "string" && !t.includes("="));
      if (!execToken) {
        return { block: true, reason: "Security Guardrail: No executable command found." };
      }

      // Strip absolute paths so "/usr/bin/git" becomes "git" for the allowlist check
      const baseCommand = path.basename(execToken as string);

      // Step D: Check Allowlists
      const isAllowed = projectAllowed.has(baseCommand) || GLOBAL_ALLOWLIST.has(baseCommand);

      if (!isAllowed) {
        ctx.ui.notify(`Blocked unauthorized command: ${baseCommand}`);
        return {
          block: true,
          reason: `ACTION BLOCKED. The command '${baseCommand}' is not explicitly allowed in this project. Ask user to add it in project allow list via py-security.json, or run it manually`
        };
      }

      return;

    } catch (error) {
      ctx.ui.notify("Blocked malformed bash string");
      return {
        block: true,
        reason: `Security Guardrail: Failed to parse command. Error: ${(error as Error).message}`
      };
    }
  });
}
