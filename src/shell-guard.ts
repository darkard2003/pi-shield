import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { GLOBAL_ALLOWLIST, GLOBAL_BLOCKLIST } from "./global_constants";
import { parse } from "shell-quote";
import * as fs from "fs/promises";
import * as path from "path";


let projectAllowed = new Set<string>();
let projectBlocked = new Map<string, string>();

/**
 * Hooks into the ExtensionAPI to implement the bash command secure allowlist and blocklist checks,
 * including strict command substitution blocks and configurable override precedence.
 *
 * @param pi The active ExtensionAPI instance.
 * @param enabled Whether the security guardrail is enabled (default: true).
 */
export default function bashSecureAllowlist(pi: ExtensionAPI, enabled: boolean = true) {

  // Load Project-Specific Config on Startup
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

  // Validate and intercept bash tool calls
  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return;
    if (event.toolName !== "bash") return;

    const args = event.input as { command?: string };
    const commandStr = args.command || "";

    if (!commandStr.trim()) {
      return { block: true, reason: "Security Guardrail: Empty bash command provided." };
    }

    // Pre-parse check for backticks and command substitutions in raw string
    if (commandStr.includes("$(") || commandStr.includes("`")) {
      ctx.ui.notify("Blocked command substitution");
      return {
        block: true,
        reason: "Security Guardrail: Command substitution using '$()' or backticks '`...`' is strictly prohibited."
      };
    }

    try {
      const tokens = parse(commandStr);

      if (tokens.length === 0) {
        return { block: true, reason: "Security Guardrail: No executable tokens found." };
      }

      // Check parsed string tokens for any backticks or substitutions
      const hasSubstitutionToken = tokens.some(token => {
        if (typeof token !== "string") return false;
        return token.includes("$(") || token.includes("`");
      });

      if (hasSubstitutionToken) {
        ctx.ui.notify("Blocked command substitution");
        return {
          block: true,
          reason: "Security Guardrail: Command substitution using '$()' or backticks '`...`' is strictly prohibited."
        };
      }

      // Extract Base Command (Skipping inline ENV variables like NODE_ENV=test)
      const execToken = tokens.find(t => typeof t === "string" && !t.includes("=")) as string | undefined;
      if (!execToken) {
        return { block: true, reason: "Security Guardrail: No executable command found." };
      }

      const baseCommand = path.basename(execToken);

      // Overriding Precedence & Allow/Block lists validation:
      // 1. Project-specific blocklist overrides everything else
      if (projectBlocked.has(execToken) || projectBlocked.has(baseCommand)) {
        const specificFeedback = projectBlocked.get(execToken) || projectBlocked.get(baseCommand);
        ctx.ui.notify(`Blocked by project config: '${baseCommand}'`);
        return {
          block: true,
          reason: `Security Guardrail (Project Block): ${specificFeedback}`
        };
      }

      // 2. Project-specific allowlist overrides global blocklist
      const isProjectAllowed = projectAllowed.has(execToken) || projectAllowed.has(baseCommand);

      if (!isProjectAllowed) {
        // 3. Global blocklist
        const isGloballyBlocked = GLOBAL_BLOCKLIST.has(execToken) || GLOBAL_BLOCKLIST.has(baseCommand);
        if (isGloballyBlocked) {
          const specificFeedback = GLOBAL_BLOCKLIST.get(execToken) || GLOBAL_BLOCKLIST.get(baseCommand);
          ctx.ui.notify(`Blocked forbidden keyword: '${baseCommand}'`);
          return {
            block: true,
            reason: `Security Guardrail: ${specificFeedback}`
          };
        }

        // 4. Global allowlist
        const isGloballyAllowed = GLOBAL_ALLOWLIST.has(execToken) || GLOBAL_ALLOWLIST.has(baseCommand);
        if (!isGloballyAllowed) {
          ctx.ui.notify(`Blocked unauthorized command: ${baseCommand}`);
          return {
            block: true,
            reason: `ACTION BLOCKED. The command '${baseCommand}' is not explicitly allowed in this project. Ask user to add it in project allow list via pi-security.json, or run it manually`
          };
        }
      }

      // Check for and block dangerous shell operators (allowing safe globbing like *.ts)
      let hasDangerousOperators = false;

      for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];

        if (typeof token === "string") continue;

        if ('op' in token) {
          if (token.op === "glob") continue;

          // Allow output redirection ONLY to /dev/null
          const redirectOps = [">", ">>", "2>", "&>", "1>"];
          if (redirectOps.includes(token.op as string)) {
            const nextToken = tokens[i + 1];

            if (typeof nextToken === "string" && nextToken === "/dev/null") {
              i++; // Skip '/dev/null' target
              continue;
            }
          }

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
