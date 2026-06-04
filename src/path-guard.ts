import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import * as path from "path";
import { ALLOWED_PATH_SUFFIXES } from "./config";
import { ShieldConfig } from "./config";

const FILE_TOOLS = new Set(["read", "write", "edit", "grep", "find", "ls", "create_file", "delete_file"]);
const EXTENSION_NAME = "Pi-Shield";

/**
 * Hooks into the ExtensionAPI to implement the path traversal guardrail,
 * blocking access to files outside the workspace root directory, /tmp, or allowed suffixes.
 * Also protects against Git internals modifications.
 *
 * @param pi The active ExtensionAPI instance.
 * @param config The shared extension configuration state.
 * @param enabled Whether the path traversal guard is enabled (default: true).
 */
export default function pathGuard(pi: ExtensionAPI, config: ShieldConfig, enabled: boolean = true) {

  pi.on("tool_call", async (event, ctx) => {
    if (!enabled || !config.path.enabled) return;

    if (!FILE_TOOLS.has(event.toolName)) {
      return;
    }

    const args = event.input as { path?: string; file?: string };
    const targetPath = args.path || args.file;

    if (!targetPath) {
      return;
    }

    const projectRoot = path.resolve(process.cwd());
    const absoluteTargetPath = path.resolve(projectRoot, targetPath);

    // Git internals check (applies to any path segment that is exactly .git)
    if (absoluteTargetPath.split(path.sep).includes(".git")) {
      const gitAccessPolicy = config.path.projectGitAccess || config.path.globalGitAccess || "block";
      
      if (gitAccessPolicy === "allow") {
        // Permit access, fall through to next checks
      } else if (gitAccessPolicy === "warn") {
        const confirmed = await ctx.ui.confirm(
          `${EXTENSION_NAME}: Git Internals Warning`,
          `Agent is trying to access Git internals at '${targetPath}'. Proceed or Reject?`
        );
        if (!confirmed) {
          return {
            block: true,
            reason: `${EXTENSION_NAME}: User rejected access to Git internals.`
          };
        }
      } else {
        ctx.ui.notify(`Blocked access to Git internals: ${targetPath}`);
        return {
          block: true,
          reason: "SECURITY GUARDRAIL: Accessing or modifying .git internals is forbidden."
        };
      }
    }

    // Config Protection check
    if (["write", "edit", "delete_file", "create_file"].includes(event.toolName) && absoluteTargetPath === path.join(projectRoot, "pi-security.json")) {
      const fallback = config.path.projectPathFallback || config.path.globalPathFallback;

      if (fallback === "allow") {
        return;
      }

      if (fallback === "warn") {
        const confirmed = await ctx.ui.confirm(
          `${EXTENSION_NAME}: Config Protection`,
          `Agent is trying to modify the security config file 'pi-security.json'. This will change the safety rules. Proceed or Reject?`
        );
        if (confirmed) return;
        ctx.ui.notify(`🚨 Blocked modification of pi-security.json`);
        return {
          block: true,
          reason: `${EXTENSION_NAME}: User rejected modification of security configuration.`
        };
      }

      return {
        block: true,
        reason: `SECURITY GUARDRAIL: you cannot edit pi-security.json, ask user to edit it for you.`,
      };
    }

    // Restricted Paths check
    const restrictedPaths = [
      ...config.path.projectRestrictedPaths,
      ...config.path.globalRestrictedPaths
    ];

    const isRestricted = restrictedPaths.some(restPath => {
      const absoluteRestPath = path.resolve(projectRoot, restPath);
      const relative = path.relative(absoluteRestPath, absoluteTargetPath);
      return !relative.startsWith("..") && !path.isAbsolute(relative);
    });

    if (isRestricted) {
      ctx.ui.notify(`🚨 Blocked restricted path access: ${targetPath}`);
      return {
        block: true,
        reason: `SECURITY GUARDRAIL: Access to restricted path "${targetPath}" is forbidden.`
      };
    }

    const relativeToProject = path.relative(projectRoot, absoluteTargetPath);
    const isOutsideProject = relativeToProject.startsWith("..") || path.isAbsolute(relativeToProject);

    const allowedTmpDir = path.resolve("/tmp");
    const relativeToTmp = path.relative(allowedTmpDir, absoluteTargetPath);
    const isInsideTmp = !relativeToTmp.startsWith("..") && !path.isAbsolute(relativeToTmp);

    const allSuffixes = [
      ...ALLOWED_PATH_SUFFIXES,
      ...config.path.projectAllowedPathSuffixes,
      ...config.path.globalAllowedPathSuffixes
    ];

    const normalizedTarget = path.normalize(absoluteTargetPath);
    const isAllowedSuffix = allSuffixes.some(suffix => {
      const normalizedSuffix = path.normalize(suffix);
      const paddedInside = path.sep + normalizedSuffix + path.sep;
      const paddedEnd = path.sep + normalizedSuffix;

      const isExactMatch = normalizedTarget === normalizedSuffix;
      const endsWithSuffix = normalizedTarget.endsWith(paddedEnd);
      const isInsideSuffix = normalizedTarget.includes(paddedInside);

      return isExactMatch || endsWithSuffix || isInsideSuffix;
    });

    if (isOutsideProject && !isInsideTmp && !isAllowedSuffix) {
      const fallback = config.path.projectPathFallback || config.path.globalPathFallback;

      if (fallback === "allow") {
        return;
      }

      if (fallback === "warn") {
        const confirmed = await ctx.ui.confirm(
          `${EXTENSION_NAME}: Path Warning`,
          `Agent is trying to access '${targetPath}', which is outside the project boundaries. Proceed or Reject?`
        );
        if (!confirmed) return;
        ctx.ui.notify(`🚨 Blocked file access: ${targetPath}`);
        return {
          block: true,
          reason: `${EXTENSION_NAME}: User rejected access to path outside project boundary.`
        };
      }

      ctx.ui.notify(`🚨 Blocked file access: ${targetPath}`);
      return {
        block: true,
        reason: `SECURITY GUARDRAIL: Directory traversal blocked. You cannot access '${targetPath}'. You may only access files inside the current working directory, '/tmp', or explicitly allowed paths.`
      };
    }

    return;
  });
}
