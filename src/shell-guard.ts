import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { parse } from "shell-quote";
import * as path from "path";
import { ShieldConfig } from "./config";

const EXTENSION_NAME = "Pi-Shield";

/**
 * Hooks into the ExtensionAPI to implement the bash command secure allowlist and blocklist checks,
 * including strict command substitution blocks and configurable override precedence.
 *
 * @param pi The active ExtensionAPI instance.
 * @param config The shared extension configuration state.
 * @param enabled Whether the security guardrail is enabled (default: true).
 */
export default function shellGuard(pi: ExtensionAPI, config: ShieldConfig, enabled: boolean = true) {

  // Validate and intercept bash tool calls
  pi.on("tool_call", async (event, ctx) => {
    if (!enabled || !config.shell.enabled) return;
    if (event.toolName !== "bash") return;

    const args = event.input as { command?: string };
    const commandStr = args.command || "";

    if (!commandStr.trim()) {
      return { block: true, reason: `${EXTENSION_NAME}: Empty bash command provided.` };
    }

    // Pre-parse check for backticks and command substitutions in raw string
    if (commandStr.includes("$(") || commandStr.includes("`")) {
      const policy = config.shell.projectCommandSubstitution || config.shell.globalCommandSubstitution || "block";
      if (policy === "block") {
        ctx.ui.notify(`${EXTENSION_NAME}: Blocked command substitution`);
        return {
          block: true,
          reason: `${EXTENSION_NAME}: Command substitution using '$()' or backticks '\`...\`' is strictly prohibited.`
        };
      }
      if (policy === "warn") {
        const confirmed = await ctx.ui.confirm(
          `${EXTENSION_NAME}: Substitution Warning`,
          `Agent is trying to run a command containing command substitution: ${commandStr}. Proceed or Reject?`
        );
        if (confirmed) {
          return { block: true, reason: `${EXTENSION_NAME}: User rejected command substitution.` };
        }
      }
    }

    try {
      const tokens = parse(commandStr);

      if (tokens.length === 0) {
        return { block: true, reason: `${EXTENSION_NAME}: No executable tokens found.` };
      }

      // Check for dangerous shell operators and file redirections
      for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];
        if (typeof token === "object" && token !== null && "op" in token) {
          const op = (token as { op: string }).op;
          
          // Check if it's a redirection to /dev/null
          const isRedirection = [">", ">>", "2>", "1>", "2>>"].includes(op);
          const nextToken = tokens[i + 1];
          if (isRedirection && typeof nextToken === "string" && nextToken === "/dev/null") {
            // Safe redirection, skip to next token after target
            i++; 
            continue;
          }

          // Check if it's a command chaining operator
          const isChaining = ["&&", "||", ";", "|", "&"].includes(op);
          if (isChaining) {
            const chaining = config.shell.projectChaining || config.shell.globalChaining || "block";
            
            if (chaining === "allow") {
              continue;
            }
            
            if (chaining === "warn") {
              const confirmed = await ctx.ui.confirm(
                `${EXTENSION_NAME}: Chaining Warning`,
                `Agent is trying to run a chained command containing the operator '${op}'. Proceed or Reject?`
              );
              if (confirmed) {
                return { block: true, reason: `${EXTENSION_NAME}: User rejected command chaining.` };
              }
              continue;
            }
            
            ctx.ui.notify(`${EXTENSION_NAME}: Blocked command chaining: '${op}'`);
            return {
              block: true,
              reason: `${EXTENSION_NAME}: Command chaining using '${op}' is prohibited.`
            };
          }

          // Otherwise (other redirections, etc.), block it
          ctx.ui.notify(`${EXTENSION_NAME}: Blocked dangerous shell operator/redirection: '${op}'`);
          return {
            block: true,
            reason: `${EXTENSION_NAME}: The shell operator or file redirection '${op}' is prohibited.`
          };
        }
      }

      // Extract all executable command names from the tokens to validate each segment
      const commandTokens: string[] = [];
      let isNextCommand = true;
      for (const token of tokens) {
        if (typeof token === "string") {
          if (isNextCommand && !token.includes("=")) {
            commandTokens.push(token);
            isNextCommand = false;
          }
        } else if (typeof token === "object" && token !== null && "op" in token) {
          const op = (token as { op: string }).op;
          if (["&&", "||", ";", "|", "&"].includes(op)) {
            isNextCommand = true;
          }
        }
      }

      if (commandTokens.length === 0) {
        return { block: true, reason: `${EXTENSION_NAME}: No executable command found.` };
      }

      // Validate each command in the chain sequentially
      for (const execToken of commandTokens) {
        const baseCommand = path.basename(execToken);

        // Helper checks for pipeline logic
        const getBlockedReason = (blockedMap: Map<string, string>) => blockedMap.get(execToken) || blockedMap.get(baseCommand);
        const isAllowed = (allowedSet: Set<string>) => allowedSet.has(execToken) || allowedSet.has(baseCommand);
        const isWarned = (warnedSet: Set<string>) => warnedSet.has(execToken) || warnedSet.has(baseCommand);

        // --- SECURITY PRECEDENCE PIPELINE FOR EACH COMMAND ---

        // 1. Project Block -> HARD BLOCK
        const projectBlockReason = getBlockedReason(config.shell.projectBlocked);
        if (projectBlockReason !== undefined) {
          ctx.ui.notify(`${EXTENSION_NAME}: Blocked by project config: '${baseCommand}'`);
          return { block: true, reason: `${EXTENSION_NAME} (Project Block): ${projectBlockReason}` };
        }

        // 2. Project Allow -> ALLOW
        if (isAllowed(config.shell.projectAllowed)) {
          continue;
        }

        // 3. Project Warn -> WARN & ALLOW (Bypasses Global Block)
        if (isWarned(config.shell.projectWarned)) {
          const confirmed = await ctx.ui.confirm(
            `${EXTENSION_NAME}: Project Warning`,
            `Agent is trying to run '${baseCommand}', which is flagged as a warning in this project. Proceed or Reject?`
          );
          if (confirmed) return { block: true, reason: `${EXTENSION_NAME}: User rejected warned command.` };
          continue;
        }

        // 4. File Execution Policy Check
        const isFileExec = execToken.startsWith("./") || execToken.startsWith("../") || path.isAbsolute(execToken);
        if (isFileExec) {
          const fileExecPolicy = config.shell.projectFileExecution || config.shell.globalFileExecution || "block";
          if (fileExecPolicy === "block") {
            ctx.ui.notify(`${EXTENSION_NAME}: Blocked file execution: '${baseCommand}'`);
            return {
              block: true,
              reason: `${EXTENSION_NAME}: Direct execution of file paths is prohibited.`
            };
          }
          if (fileExecPolicy === "warn") {
            const confirmed = await ctx.ui.confirm(
              `${EXTENSION_NAME}: File Execution Warning`,
              `Agent is trying to execute the file path '${execToken}'. Proceed or Reject?`
            );
            if (confirmed) {
              return { block: true, reason: `${EXTENSION_NAME}: User rejected file execution.` };
            }
            continue; // Allowed via warning, skip further checks for this command segment
          }
          if (fileExecPolicy === "allow") {
            continue; // Allowed, skip further checks for this command segment
          }
        }

        // 5. Global Block -> HARD BLOCK
        const globalBlockReason = getBlockedReason(config.shell.globalBlocked);
        if (globalBlockReason !== undefined) {
          ctx.ui.notify(`${EXTENSION_NAME}: Blocked: '${baseCommand}'`);
          return { block: true, reason: `${EXTENSION_NAME}: ${globalBlockReason}` };
        }

        // 6. Global Allow -> ALLOW
        if (isAllowed(config.shell.globalAllowed)) {
          continue;
        }

        // 7. Fallback
        const fallback = config.shell.projectFallback || config.shell.globalFallback;

        if (fallback === "block") {
          ctx.ui.notify(`${EXTENSION_NAME}: Blocked unknown command: '${baseCommand}'`);
          return {
            block: true,
            reason: `${EXTENSION_NAME}: The command '${baseCommand}' is not explicitly allowed. Add it to pi-security.json or change the fallback setting.`
          };
        }

        if (fallback === "warn") {
          const confirmed = await ctx.ui.confirm(
            `${EXTENSION_NAME}: Security Warning`,
            `Agent is trying to run '${baseCommand}', which is not in the allow list. Proceed or Reject?`
          );
          if (confirmed) return { block: true, reason: `${EXTENSION_NAME}: User rejected unknown command.` };
        }
      }

      return;

    } catch (error) {
      ctx.ui.notify(`${EXTENSION_NAME}: Blocked malformed bash string`);
      return {
        block: true,
        reason: `${EXTENSION_NAME}: Failed to parse command. Error: ${(error as Error).message}`
      };
    }
  });
}
