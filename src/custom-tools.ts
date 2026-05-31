import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { ALLOWED_PATH_SUFFIXES } from "./global_constants";
import * as path from "path";
import * as fs from "fs/promises";
import * as crypto from "crypto";
import { Type } from "typebox";
import ignore from "ignore";

/**
 * Resolves and validates a target path against the secure sandbox boundaries.
 * Enforces that paths must be situated within the project root directory, the
 * system /tmp directory, or match explicitly allowed documentation suffixes.
 * Also blocks access to Git internals.
 *
 * @param targetPath The raw target path to validate.
 * @param projectRoot The absolute path to the project root directory.
 * @returns An object indicating whether access is allowed and the resolved absolute path.
 */
export function validatePath(targetPath: string, projectRoot: string): { allowed: boolean; absolutePath: string } {
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
    return normalizedTarget === normalizedSuffix || normalizedTarget.endsWith(paddedEnd) || normalizedTarget.includes(paddedInside);
  });

  if (isOutsideProject && !isInsideTmp && !isAllowedSuffix) {
    return { allowed: false, absolutePath: absoluteTargetPath };
  }

  if (!isOutsideProject && (relativeToProject.includes(".git" + path.sep) || relativeToProject === ".git")) {
    return { allowed: false, absolutePath: absoluteTargetPath };
  }

  return { allowed: true, absolutePath: absoluteTargetPath };
}

/**
 * Loads and compiles .gitignore rules from the project root.
 * Always includes baseline ignores like .git and node_modules.
 *
 * @param projectRoot The absolute path to the project root directory.
 * @returns A compiled ignore instance.
 */
export async function getIgnoreRules(projectRoot: string): Promise<any> {
  const ig = ignore();
  
  // Always ignore .git and node_modules by default
  ig.add([".git", "node_modules", ".git/", "node_modules/"]);

  const gitignorePath = path.join(projectRoot, ".gitignore");
  try {
    const content = await fs.readFile(gitignorePath, "utf-8");
    ig.add(content);
  } catch (error: any) {
    if (error.code !== "ENOENT") {
      console.warn(`Warning: Failed to read .gitignore: ${error.message}`);
    }
  }

  return ig;
}

/**
 * Checks the size and line count of a tool's output content. If the output exceeds
 * the security threshold (5 KB or 200 lines), writes the full content to a secure
 * scratch file inside the /tmp directory and returns a redirection notice.
 *
 * @param toolName The name of the custom tool generating the output.
 * @param content The raw string content of the tool's output.
 * @returns A promise resolving to either the original content or the redirection notice.
 */
async function processOutput(toolName: string, content: string): Promise<string> {
  const maxBytes = 5 * 1024;
  const maxLines = 200;

  const bytes = Buffer.byteLength(content, "utf-8");
  const lines = content.split("\n");

  if (bytes > maxBytes || lines.length > maxLines) {
    const hash = crypto.randomBytes(8).toString("hex");
    const scratchPath = `/tmp/pi-shield-${toolName}-${hash}.txt`;
    await fs.writeFile(scratchPath, content, "utf-8");
    return `[SECURITY NOTICE: Output truncated to fit context limits. Total output size was ${lines.length} lines (${(bytes / 1024).toFixed(2)} KB). The complete, un-truncated output has been securely written to the scratch file: ${scratchPath}. You can view its contents using the native 'read' tool.]`;
  }

  return content;
}

/**
 * Converts a standard file glob pattern (e.g. '*.ts' or '**\/*.js') into a
 * regular expression to safely match path names.
 *
 * @param glob The raw glob pattern.
 * @returns A regular expression corresponding to the glob pattern.
 */
function globToRegex(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const regexStr = escaped.replace(/\*\*(?:\/)?|\*|\?/g, (m) => {
    if (m === "**/") return "(?:.*/)?";
    if (m === "**") return ".*";
    if (m === "*") return "[^/]*";
    if (m === "?") return "[^/]";
    return m;
  });
  return new RegExp('^' + regexStr + '$');
}

/**
 * Recursively walks a directory, collecting all relative file paths while
 * explicitly skipping specified ignored directories (e.g. .git and node_modules).
 *
 * @param dir The current absolute directory path.
 * @param baseDir The base search directory path (used to resolve relative paths).
 * @param projectRoot The absolute path to the project root directory.
 * @param results The array in which matching relative paths are collected.
 * @param ig The compiled ignore instance containing .gitignore rules.
 */
async function walk(dir: string, baseDir: string, projectRoot: string, results: string[], ig: any) {
  let entries;
  try {
    entries = await fs.readdir(dir);
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    
    // Resolve relative path from projectRoot for JGit ignore matching
    const relativeToRoot = path.relative(projectRoot, fullPath).replace(/\\/g, "/");

    if (ig.ignores(relativeToRoot) || ig.ignores(relativeToRoot + "/")) {
      continue;
    }

    let stats;
    try {
      stats = await fs.stat(fullPath);
    } catch {
      continue;
    }

    if (stats.isDirectory()) {
      await walk(fullPath, baseDir, projectRoot, results, ig);
    } else if (stats.isFile()) {
      const relativeToBase = path.relative(baseDir, fullPath).replace(/\\/g, "/");
      results.push(relativeToBase);
    }
  }
}

/**
 * Searches a single file line-by-line for a specific RegExp pattern.
 * Collects matching lines formatted with standard file and line prefixes.
 *
 * @param filePath The absolute path to the file to search.
 * @param relativePath The relative path to display in the output.
 * @param patternRegex The regular expression pattern to match.
 * @param matches The array in which matching lines are collected.
 * @param context The number of context lines to display before and after matches.
 * @param limit The maximum number of total matches to collect.
 */
async function searchFile(filePath: string, relativePath: string, patternRegex: RegExp, matches: string[], context: number, limit: number) {
  let content;
  try {
    content = await fs.readFile(filePath, "utf-8");
  } catch {
    return;
  }

  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (matches.length >= limit) break;
    const line = lines[i];
    if (patternRegex.test(line)) {
      const start = Math.max(0, i - context);
      const end = Math.min(lines.length - 1, i + context);
      for (let c = start; c <= end; c++) {
        const prefix = c === i ? ":" : "-";
        matches.push(`${relativePath}${prefix}${c + 1}${prefix} ${lines[c]}`);
      }
    }
  }
}

// 6. Schema Definitions
const lsSchema = Type.Object({
  path: Type.Optional(Type.String({ description: "Directory to list (default: current directory)" })),
  limit: Type.Optional(Type.Number({ description: "Maximum number of entries to return" })),
});

const findSchema = Type.Object({
  pattern: Type.String({ description: "Glob pattern to match files, e.g. '*.ts' or 'src/**/*.json'" }),
  path: Type.Optional(Type.String({ description: "Directory to search in (default: current directory)" })),
  limit: Type.Optional(Type.Number({ description: "Maximum number of results" })),
});

const grepSchema = Type.Object({
  pattern: Type.String({ description: "Search pattern (regex or literal string)" }),
  path: Type.Optional(Type.String({ description: "Directory or file to search (default: current directory)" })),
  glob: Type.Optional(Type.String({ description: "Filter files by glob pattern, e.g. '*.ts'" })),
  ignoreCase: Type.Optional(Type.Boolean({ description: "Case-insensitive search (default: false)" })),
  literal: Type.Optional(Type.Boolean({ description: "Treat pattern as literal string instead of regex (default: false)" })),
  context: Type.Optional(Type.Number({ description: "Number of lines to show before and after each match (default: 0)" })),
  limit: Type.Optional(Type.Number({ description: "Maximum number of matches to return (default: 100)" })),
});

/**
 * Registers custom overridden implementations of the secure ls, find, and grep tools.
 *
 * @param pi The active ExtensionAPI instance.
 */
export default function registerCustomTools(pi: ExtensionAPI) {
  // --- CUSTOM LS TOOL ---
  pi.registerTool({
    name: "ls",
    label: "ls (secure)",
    description: "List directory contents securely with output size restrictions.",
    parameters: lsSchema,
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const target = params.path || ".";
      const projectRoot = path.resolve(ctx.cwd || process.cwd());
      const { allowed, absolutePath } = validatePath(target, projectRoot);

      if (!allowed) {
        return {
          content: [{ type: "text", text: `SECURITY GUARDRAIL: Access denied to path "${target}". Directory traversal blocked.` }],
          details: { blocked: true },
        };
      }

      try {
        const stats = await fs.stat(absolutePath);
        if (!stats.isDirectory()) {
          return {
            content: [{ type: "text", text: `Error: Path "${target}" is not a directory.` }],
            details: { error: true },
          };
        }

        const entries = await fs.readdir(absolutePath);
        entries.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));

        const formatted: string[] = [];
        const limit = params.limit || 500;
        const displayedEntries = entries.slice(0, limit);

        for (const entry of displayedEntries) {
          const entryPath = path.join(absolutePath, entry);
          let suffix = "";
          try {
             const entryStat = await fs.stat(entryPath);
             if (entryStat.isDirectory()) {
               suffix = "/";
             }
          } catch {
             // Ignore stat errors
          }
          formatted.push(entry + suffix);
        }

        let resultText = formatted.join("\n");
        if (entries.length > limit) {
          resultText += `\n\n[Warning: Listed ${limit} of ${entries.length} total entries.]`;
        }

        const finalOutput = await processOutput("ls", resultText);

        return {
          content: [{ type: "text", text: finalOutput }],
          details: { count: entries.length },
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error listing directory: ${error.message}` }],
          details: { error: true },
        };
      }
    }
  });

  // --- CUSTOM FIND TOOL ---
  pi.registerTool({
    name: "find",
    label: "find (secure)",
    description: "Search for files by glob pattern securely with output size restrictions.",
    parameters: findSchema,
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const target = params.path || ".";
      const projectRoot = path.resolve(ctx.cwd || process.cwd());
      const { allowed, absolutePath } = validatePath(target, projectRoot);

      if (!allowed) {
        return {
          content: [{ type: "text", text: `SECURITY GUARDRAIL: Access denied to path "${target}". Directory traversal blocked.` }],
          details: { blocked: true },
        };
      }

      try {
        const stats = await fs.stat(absolutePath);
        if (!stats.isDirectory()) {
          return {
            content: [{ type: "text", text: `Error: Path "${target}" is not a directory.` }],
            details: { error: true },
          };
        }

        const ig = await getIgnoreRules(projectRoot);
        const allFiles: string[] = [];
        await walk(absolutePath, absolutePath, projectRoot, allFiles, ig);

        const globPattern = params.pattern;
        const regex = globToRegex(globPattern);
        const matchedFiles = allFiles.filter(f => regex.test(f));

        const limit = params.limit || 1000;
        const displayedFiles = matchedFiles.slice(0, limit);

        let resultText = displayedFiles.join("\n");
        if (matchedFiles.length === 0) {
          resultText = "No files found matching pattern.";
        } else if (matchedFiles.length > limit) {
          resultText += `\n\n[Warning: Found ${matchedFiles.length} matches, showing first ${limit}.]`;
        }

        const finalOutput = await processOutput("find", resultText);

        return {
          content: [{ type: "text", text: finalOutput }],
          details: { totalMatches: matchedFiles.length },
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error finding files: ${error.message}` }],
          details: { error: true },
        };
      }
    }
  });

  // --- CUSTOM GREP TOOL ---
  pi.registerTool({
    name: "grep",
    label: "grep (secure)",
    description: "Search file contents securely with output size restrictions.",
    parameters: grepSchema,
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const target = params.path || ".";
      const projectRoot = path.resolve(ctx.cwd || process.cwd());
      const { allowed, absolutePath } = validatePath(target, projectRoot);

      if (!allowed) {
        return {
          content: [{ type: "text", text: `SECURITY GUARDRAIL: Access denied to path "${target}". Directory traversal blocked.` }],
          details: { blocked: true },
        };
      }

      try {
        const stats = await fs.stat(absolutePath);
        let targetFiles: string[] = [];

        if (stats.isFile()) {
          targetFiles = [absolutePath];
        } else if (stats.isDirectory()) {
          const ig = await getIgnoreRules(projectRoot);
          await walk(absolutePath, absolutePath, projectRoot, targetFiles, ig);
          targetFiles = targetFiles.map(f => path.join(absolutePath, f));
        } else {
          return {
            content: [{ type: "text", text: `Error: Path "${target}" is not a file or directory.` }],
            details: { error: true },
          };
        }

        if (params.glob) {
          const globRegex = globToRegex(params.glob);
          targetFiles = targetFiles.filter(f => {
            const relative = path.relative(absolutePath, f).replace(/\\/g, "/");
            return globRegex.test(relative);
          });
        }

        let patternStr = params.pattern;
        if (params.literal) {
          patternStr = patternStr.replace(/[|\\{}()[\]^$+*?.]/g, "\\$&");
        }
        let flags = "";
        if (params.ignoreCase) {
          flags += "i";
        }
        const patternRegex = new RegExp(patternStr, flags);

        const matches: string[] = [];
        const context = params.context || 0;
        const limit = params.limit || 100;

        for (const file of targetFiles) {
          if (matches.length >= limit) break;
          const relative = path.relative(absolutePath, file).replace(/\\/g, "/");
          await searchFile(file, relative, patternRegex, matches, context, limit);
        }

        let resultText = matches.join("\n");
        if (matches.length === 0) {
          resultText = "No matches found.";
        } else if (matches.length >= limit) {
          resultText += `\n\n[Warning: Found maximum matches limit of ${limit}.]`;
        }

        const finalOutput = await processOutput("grep", resultText);

        return {
          content: [{ type: "text", text: finalOutput }],
          details: { matchesCount: matches.length },
        };
      } catch (error: any) {
        return {
          content: [{ type: "text", text: `Error searching files: ${error.message}` }],
          details: { error: true },
        };
      }
    }
  });

  /**
   * Hooks into 'before_agent_start' to inject instructions to the agent's system prompt.
   * Tells the agent that custom secure implementations of ls, find, and grep are available,
   * that using bash for these tools is strictly disabled, and how to read large outputs.
   */
  pi.on("before_agent_start", async (event, _ctx) => {
    const extraInstructions = `
[SECURITY ENVIRONMENT INSTRUCTIONS]
1. Custom secure filesystem tools are registered: 'ls', 'find', and 'grep'.
2. Execution of 'ls', 'grep', or 'find' via the 'bash' tool is STRICTLY PROHIBITED and will be blocked by the security guardrail.
3. You MUST always call the native 'ls', 'find', and 'grep' tools directly instead of running them via bash.
4. If a custom tool's output is very large, it is automatically saved to a scratch file (e.g. '/tmp/pi-shield-*.txt'). When this happens, you will receive a security redirection notice, and you must call the native 'read' tool to view its full contents.
`;
    return {
      systemPrompt: event.systemPrompt + "\n\n" + extraInstructions
    };
  });
}
