import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import * as path from "path";
import { ALLOWED_PATH_SUFFIXES } from "./global_constants";

const FILE_TOOLS = new Set(["read", "write", "edit", "grep", "find", "ls", "create_file", "delete_file"]);

/**
 * Hooks into the ExtensionAPI to implement the path traversal guardrail,
 * blocking access to files outside the workspace root directory, /tmp, or allowed suffixes.
 * Also protects against Git internals modifications.
 *
 * @param pi The active ExtensionAPI instance.
 * @param enabled Whether the path traversal guard is enabled (default: true).
 */
export default function pathTraversalGuard(pi: ExtensionAPI, enabled: boolean = true) {

  pi.on("session_start", async (_event, ctx) => {
    if (enabled) {
      ctx.ui.notify(`🔒 Path Guard enabled (with ${ALLOWED_PATH_SUFFIXES.length} baked-in paths)`);
    } else {
      ctx.ui.notify(`🔒 Path Guard disabled`);
    }
  });

  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return;

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

    const relativeToProject = path.relative(projectRoot, absoluteTargetPath);
    const isOutsideProject = relativeToProject.startsWith("..") || path.isAbsolute(relativeToProject);

    const allowedTmpDir = path.resolve("/tmp");
    const relativeToTmp = path.relative(allowedTmpDir, absoluteTargetPath);
    const isInsideTmp = !relativeToTmp.startsWith("..") && !path.isAbsolute(relativeToTmp);

    const isAllowedSuffix = ALLOWED_PATH_SUFFIXES.some(suffix => {
      const normalizedTarget = path.normalize(absoluteTargetPath);
      const normalizedSuffix = path.normalize(suffix);

      const paddedInside = path.sep + normalizedSuffix + path.sep;
      const paddedEnd = path.sep + normalizedSuffix;

      const isExactMatch = normalizedTarget === normalizedSuffix;
      const endsWithSuffix = normalizedTarget.endsWith(paddedEnd);
      const isInsideSuffix = normalizedTarget.includes(paddedInside);

      return isExactMatch || endsWithSuffix || isInsideSuffix;
    });

    if (isOutsideProject && !isInsideTmp && !isAllowedSuffix) {
      ctx.ui.notify(`🚨 Blocked file access: ${targetPath}`);

      return {
        block: true,
        reason: `SECURITY GUARDRAIL: Directory traversal blocked. You cannot access '${targetPath}'. You may only access files inside the current working directory, '/tmp', or explicitly allowed paths.`
      };
    }

    if (!isOutsideProject && (relativeToProject.includes(".git" + path.sep) || relativeToProject === ".git")) {
      ctx.ui.notify(`Blocked access to Git internals: ${targetPath}`);
      return {
        block: true,
        reason: "SECURITY GUARDRAIL: Accessing or modifying .git internals is forbidden."
      };
    }

    return;
  });
}
