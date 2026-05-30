import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import * as path from "path";
import { ALLOWED_PATH_SUFFIXES } from "./global_constants";

const FILE_TOOLS = new Set(["read", "write", "edit", "create_file", "delete_file"]);

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

    // Resolve paths
    const projectRoot = path.resolve(process.cwd());
    const absoluteTargetPath = path.resolve(projectRoot, targetPath);

    // 1. Check Project Root
    const relativeToProject = path.relative(projectRoot, absoluteTargetPath);
    const isOutsideProject = relativeToProject.startsWith("..") || path.isAbsolute(relativeToProject);

    // 2. Check /tmp Directory
    const allowedTmpDir = path.resolve("/tmp");
    const relativeToTmp = path.relative(allowedTmpDir, absoluteTargetPath);
    const isInsideTmp = !relativeToTmp.startsWith("..") && !path.isAbsolute(relativeToTmp);

    // 3. Check Hardcoded Suffixes (Allow exact match, or any file inside the suffix directory)
    const isAllowedSuffix = ALLOWED_PATH_SUFFIXES.some(suffix => {
      const normalizedTarget = path.normalize(absoluteTargetPath);
      const normalizedSuffix = path.normalize(suffix);

      // Pad the suffix with path separators (e.g., /docs/ and /docs)
      // This ensures we only match exact folder names, not partial words.
      const paddedInside = path.sep + normalizedSuffix + path.sep;
      const paddedEnd = path.sep + normalizedSuffix;

      // Check 1: The target is exactly the suffix
      const isExactMatch = normalizedTarget === normalizedSuffix;

      // Check 2: The target ends exactly at the suffix directory (e.g. /usr/lib/docs)
      const endsWithSuffix = normalizedTarget.endsWith(paddedEnd);

      // Check 3: The target is INSIDE the suffix directory (e.g. /usr/lib/docs/api/sdk.md)
      const isInsideSuffix = normalizedTarget.includes(paddedInside);

      return isExactMatch || endsWithSuffix || isInsideSuffix;
    });
    // 4. Final Block Check
    if (isOutsideProject && !isInsideTmp && !isAllowedSuffix) {
      ctx.ui.notify(`🚨 Blocked file access: ${targetPath}`);

      return {
        block: true,
        reason: `SECURITY GUARDRAIL: Directory traversal blocked. You cannot access '${targetPath}'. You may only access files inside the current working directory, '/tmp', or explicitly allowed paths.`
      };
    }

    // 5. Strict block for Git internals (only inside the project)
    if (!isOutsideProject && (relativeToProject.includes(".git" + path.sep) || relativeToProject === ".git")) {
      ctx.ui.notify(`Blocked access to Git internals: ${targetPath}`);
      return {
        block: true,
        reason: "SECURITY GUARDRAIL: Accessing or modifying .git internals is forbidden."
      };
    }

    // Path is safe! Let Pi execute the tool.
    return;
  });
}
