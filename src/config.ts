import * as fs from "fs/promises";
import * as path from "path";
import * as os from "os";

export const ALLOWED_PATH_SUFFIXES = [
  "@earendil-works/pi-coding-agent/docs",
  "@earendil-works/pi-coding-agent/README.md",
];

export interface ShieldConfig {
  shell: {
    enabled: boolean;
    projectAllowed: Set<string>;
    projectBlocked: Map<string, string>;
    projectWarned: Set<string>;
    projectFallback: string;
    projectChaining: string;
    projectCommandSubstitution: string;
    projectFileExecution: string;

    globalAllowed: Set<string>;
    globalBlocked: Map<string, string>;
    globalFallback: string;
    globalChaining: string;
    globalCommandSubstitution: string;
    globalFileExecution: string;
  };
  path: {
    enabled: boolean;
    projectPathFallback: string;
    globalPathFallback: string;
    projectAllowedPathSuffixes: string[];
    globalAllowedPathSuffixes: string[];
    projectRestrictedPaths: string[];
    globalRestrictedPaths: string[];
    projectGitAccess: string;
    globalGitAccess: string;
  };
}

export function createDefaultConfig(): ShieldConfig {
  return {
    shell: {
      enabled: true,
      projectAllowed: new Set(),
      projectBlocked: new Map(),
      projectWarned: new Set(),
      projectFallback: "warn",
      projectChaining: "warn",
      projectCommandSubstitution: "warn",
      projectFileExecution: "block",

      globalAllowed: new Set(),
      globalBlocked: new Map(),
      globalFallback: "warn",
      globalChaining: "warn",
      globalCommandSubstitution: "warn",
      globalFileExecution: "block",
    },
    path: {
      enabled: true,
      projectPathFallback: "block",
      globalPathFallback: "block",
      projectAllowedPathSuffixes: [],
      globalAllowedPathSuffixes: [],
      projectRestrictedPaths: [],
      globalRestrictedPaths: [],
      projectGitAccess: "block",
      globalGitAccess: "block",
    }
  };
}

export async function loadConfig(shieldConfig: ShieldConfig, notify: (msg: string) => void) {
  // Clear previous configurations
  shieldConfig.shell.projectAllowed.clear();
  shieldConfig.shell.projectBlocked.clear();
  shieldConfig.shell.projectWarned.clear();

  shieldConfig.shell.globalAllowed.clear();
  shieldConfig.shell.globalBlocked.clear();

  // Default fallbacks and configs
  shieldConfig.shell.enabled = true;
  shieldConfig.shell.globalFallback = "warn";
  shieldConfig.shell.projectFallback = "warn";
  shieldConfig.shell.globalChaining = "warn";
  shieldConfig.shell.projectChaining = "warn";
  shieldConfig.shell.globalCommandSubstitution = "warn";
  shieldConfig.shell.projectCommandSubstitution = "warn";
  shieldConfig.shell.globalFileExecution = "block";
  shieldConfig.shell.projectFileExecution = "block";

  shieldConfig.path.enabled = true;
  shieldConfig.path.globalPathFallback = "warn";
  shieldConfig.path.projectPathFallback = "warn";
  shieldConfig.path.globalGitAccess = "block";
  shieldConfig.path.projectGitAccess = "block";
  shieldConfig.path.globalAllowedPathSuffixes = [];
  shieldConfig.path.projectAllowedPathSuffixes = [];
  shieldConfig.path.globalRestrictedPaths = [];
  shieldConfig.path.projectRestrictedPaths = [];

  const globalConfigPath = path.join(os.homedir(), ".pi", "agent", "pi-security.json");
  const projectConfigPath = path.join(process.cwd(), "pi-security.json");

  async function readFileConfig(filePath: string, type: "global" | "project") {
    try {
      const fileStats = await fs.stat(filePath);
      if (!fileStats.isFile()) return;

      const configData = await fs.readFile(filePath, "utf-8");
      const config = JSON.parse(configData);

      if (type === "global") {
        if (config.shellGuard !== undefined) shieldConfig.shell.enabled = config.shellGuard;
        if (config.pathGuard !== undefined) shieldConfig.path.enabled = config.pathGuard;

        if (Array.isArray(config.allow)) {
          config.allow.forEach((cmd: string) => shieldConfig.shell.globalAllowed.add(cmd));
        }
        if (typeof config.block === "object" && config.block !== null) {
          for (const [cmd, reason] of Object.entries(config.block)) {
            shieldConfig.shell.globalBlocked.set(cmd, reason as string);
          }
        }
        if (config.fallback) shieldConfig.shell.globalFallback = config.fallback;
        if (config.chaining) shieldConfig.shell.globalChaining = config.chaining;
        if (config.commandSubstitution) shieldConfig.shell.globalCommandSubstitution = config.commandSubstitution;
        if (config.fileExecution) shieldConfig.shell.globalFileExecution = config.fileExecution;

        if (config.pathFallback) shieldConfig.path.globalPathFallback = config.pathFallback;
        if (config.gitAccess) shieldConfig.path.globalGitAccess = config.gitAccess;
        if (Array.isArray(config.allowedPathSuffixes)) {
          shieldConfig.path.globalAllowedPathSuffixes = config.allowedPathSuffixes;
        }
        if (Array.isArray(config.restrictedPaths)) {
          shieldConfig.path.globalRestrictedPaths = config.restrictedPaths;
        }
      } else {
        if (config.shellGuard !== undefined) shieldConfig.shell.enabled = config.shellGuard;
        if (config.pathGuard !== undefined) shieldConfig.path.enabled = config.pathGuard;

        if (Array.isArray(config.allow)) {
          config.allow.forEach((cmd: string) => shieldConfig.shell.projectAllowed.add(cmd));
        }
        if (Array.isArray(config.warn)) {
          config.warn.forEach((cmd: string) => shieldConfig.shell.projectWarned.add(cmd));
        }
        if (typeof config.block === "object" && config.block !== null) {
          for (const [cmd, reason] of Object.entries(config.block)) {
            shieldConfig.shell.projectBlocked.set(cmd, reason as string);
          }
        }
        if (config.fallback) shieldConfig.shell.projectFallback = config.fallback;
        if (config.chaining) shieldConfig.shell.projectChaining = config.chaining;
        if (config.commandSubstitution) shieldConfig.shell.projectCommandSubstitution = config.commandSubstitution;
        if (config.fileExecution) shieldConfig.shell.projectFileExecution = config.fileExecution;

        if (config.pathFallback) shieldConfig.path.projectPathFallback = config.pathFallback;
        if (config.gitAccess) shieldConfig.path.projectGitAccess = config.gitAccess;
        if (Array.isArray(config.allowedPathSuffixes)) {
          shieldConfig.path.projectAllowedPathSuffixes = config.allowedPathSuffixes;
        }
        if (Array.isArray(config.restrictedPaths)) {
          shieldConfig.path.projectRestrictedPaths = config.restrictedPaths;
        }
      }
    } catch (error: any) {
      if (error.code !== "ENOENT") {
        notify(`Pi-Shield: Failed to parse ${path.basename(filePath)}: ${error.message}`);
      }
    }
  }

  await readFileConfig(globalConfigPath, "global");
  await readFileConfig(projectConfigPath, "project");
}
