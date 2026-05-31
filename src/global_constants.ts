// 1. GLOBAL EXHAUSTIVE BLOCKLIST
// Normally any command other than that in allow list will be blocked, but these will give a clear reasn on why it was blocked and what to do insted
export const GLOBAL_BLOCKLIST = new Map<string, string>([
  // --- FILE READING ALTERNATIVES (Force the native 'read' tool) ---
  ["cat", "ACTION BLOCKED. Reading files via bash is disabled. You MUST use your native 'read' tool. Do not retry with bash."],
  ["head", "ACTION BLOCKED. Reading files via bash is disabled. You MUST use your native 'read' tool. Do not retry with bash."],
  ["tail", "ACTION BLOCKED. Reading files via bash is disabled. You MUST use your native 'read' tool. Do not retry with bash."],
  ["sed", "ACTION BLOCKED. Using sed to view file contents is disabled. Use your native 'read' or 'edit' tools."],
  ["awk", "ACTION BLOCKED. Using awk to view file contents is disabled. Use your native 'read' tool."],
  ["strings", "ACTION BLOCKED. Binary reading via bash is disabled. Use your native 'read' tool."],
  ["hexdump", "ACTION BLOCKED. Hexdump is restricted. Use your native 'read' tool."],
  ["xxd", "ACTION BLOCKED. Hexdump is restricted. Use your native 'read' tool."],
  ["od", "ACTION BLOCKED. Octal dumps are restricted. Use your native 'read' tool."],

  // --- INTERACTIVE APPS & PAGERS (Freeze protection) ---
  ["vim", "ACTION BLOCKED. Interactive editors freeze the environment. Use your native 'edit' tool. Do not retry."],
  ["vi", "ACTION BLOCKED. Interactive editors freeze the environment. Use your native 'edit' tool. Do not retry."],
  ["nano", "ACTION BLOCKED. Interactive editors freeze the environment. Use your native 'edit' tool. Do not retry."],
  ["pico", "ACTION BLOCKED. Interactive editors freeze the environment. Use your native 'edit' tool. Do not retry."],
  ["emacs", "ACTION BLOCKED. Interactive editors freeze the environment. Use your native 'edit' tool. Do not retry."],
  ["ed", "ACTION BLOCKED. Line editors are disabled. Use your native 'edit' tool."],
  ["less", "ACTION BLOCKED. Interactive pagers lock up the execution pipeline. Use your native 'read' tool."],
  ["more", "ACTION BLOCKED. Interactive pagers lock up the execution pipeline. Use your native 'read' tool."],
  ["man", "ACTION BLOCKED. The manual viewer hangs the agent. Look up syntax internally or skip this step."],
  ["top", "ACTION BLOCKED. Infinite monitoring tools are permanently disabled."],
  ["htop", "ACTION BLOCKED. Infinite monitoring tools are permanently disabled."],
  ["btop", "ACTION BLOCKED. Infinite monitoring tools are permanently disabled."],
  ["watch", "ACTION BLOCKED. The watch command executes indefinitely and is disabled."],

  // --- DESTRUCTIVE OPERATIONS (Kill the action completely) ---
  ["rm", "ACTION BLOCKED. You do not have privileges to delete files. This is a hard limit. Do not ask for permission. Skip the deletion and proceed with other tasks."],
  ["shred", "ACTION BLOCKED. File wiping utilities are strictly prohibited. Skip this step."],
  ["wipe", "ACTION BLOCKED. File wiping utilities are strictly prohibited. Skip this step."],
  ["srm", "ACTION BLOCKED. Secure removal tools are strictly prohibited. Skip this step."],
  ["dd", "ACTION BLOCKED. Low-level disk writing utilities are restricted to prevent data loss. Abort plan."],
  ["mkfs", "ACTION BLOCKED. System formatting is permanently disabled. Abort this plan immediately."],
  ["fdisk", "ACTION BLOCKED. Partitioning utilities are strictly blocked. Abort plan."],
  ["parted", "ACTION BLOCKED. Partitioning utilities are strictly blocked. Abort plan."],
  ["sfdisk", "ACTION BLOCKED. Partitioning utilities are strictly blocked. Abort plan."],

  // --- NETWORK EXFILTRATION & REMOTE ACCESS ---
  ["ssh", "ACTION BLOCKED. Outbound SSH is permanently disabled in this sandbox."],
  ["scp", "ACTION BLOCKED. Outbound secure file copy is disabled to prevent data leakage."],
  ["sftp", "ACTION BLOCKED. Outbound file transfers are disabled to prevent data leakage."],
  ["ftp", "ACTION BLOCKED. File transfer protocols are disabled."],
  ["telnet", "ACTION BLOCKED. Unencrypted remote login utilities are disabled."],
  ["nc", "ACTION BLOCKED. Arbitrary network connections via Netcat are strictly blocked."],
  ["netcat", "ACTION BLOCKED. Arbitrary network connections via Netcat are strictly blocked."],
  ["ncat", "ACTION BLOCKED. Arbitrary network connections via Ncat are strictly blocked."],
  ["socat", "ACTION BLOCKED. Socket relay utilities are blocked to prevent unauthorized data routing."],
  ["curl", "ACTION BLOCKED. Raw web requests via curl are disabled to ensure environment isolation."],
  ["wget", "ACTION BLOCKED. Raw web requests via wget are disabled to ensure environment isolation."],
  ["rsync", "ACTION BLOCKED. Remote synchronization is disabled."],
  ["nmap", "ACTION BLOCKED. Network scanning utilities are strictly prohibited."],

  // --- SHELL ESCAPING / NESTING ---
  ["bash", "ACTION BLOCKED. Nesting shell environments is disabled. Execute commands top-level only."],
  ["sh", "ACTION BLOCKED. Nesting shell environments is disabled. Execute commands top-level only."],
  ["zsh", "ACTION BLOCKED. Nesting shell environments is disabled. Execute commands top-level only."],
  ["csh", "ACTION BLOCKED. Nesting shell environments is disabled. Execute commands top-level only."],
  ["tcsh", "ACTION BLOCKED. Nesting shell environments is disabled. Execute commands top-level only."],
  ["fish", "ACTION BLOCKED. Nesting shell environments is disabled. Execute commands top-level only."],
  ["dash", "ACTION BLOCKED. Nesting shell environments is disabled. Execute commands top-level only."],
  ["tmux", "ACTION BLOCKED. Terminal multiplexers are disabled. Do not spin up background sessions."],
  ["screen", "ACTION BLOCKED. Terminal multiplexers are disabled. Do not spin up background sessions."],

  // --- SYSTEM MANIPULATION / RESOURCE KILLERS ---
  ["reboot", "ACTION BLOCKED. System state changes are disabled. Abort plan."],
  ["shutdown", "ACTION BLOCKED. System state changes are disabled. Abort plan."],
  ["halt", "ACTION BLOCKED. System state changes are disabled. Abort plan."],
  ["poweroff", "ACTION BLOCKED. System state changes are disabled. Abort plan."],
  ["init", "ACTION BLOCKED. System state changes are disabled. Abort plan."],
  ["systemctl", "ACTION BLOCKED. Service control utilities are disabled."],
  ["service", "ACTION BLOCKED. Service control utilities are disabled."],
  ["kill", "ACTION BLOCKED. Process termination via bash is disabled. Let processes exit naturally."],
  ["killall", "ACTION BLOCKED. Mass process termination is disabled."],
  ["pkill", "ACTION BLOCKED. Process termination utilities are disabled."],
  ["ulimit", "ACTION BLOCKED. Modifying system resource limits is restricted."],

  // --- TURING-COMPLETE SHELLS & INTERPRETERS ---
  ["python", "ACTION BLOCKED. Turing-complete languages/interpreters are globally restricted to maintain sandbox boundaries. If needed, please explicitly enable 'python' in your project's 'pi-security.json' allowlist."],
  ["python3", "ACTION BLOCKED. Turing-complete languages/interpreters are globally restricted to maintain sandbox boundaries. If needed, please explicitly enable 'python3' in your project's 'pi-security.json' allowlist."],
  ["node", "ACTION BLOCKED. Turing-complete languages/interpreters are globally restricted to maintain sandbox boundaries. If needed, please explicitly enable 'node' in your project's 'pi-security.json' allowlist."],
  ["perl", "ACTION BLOCKED. Turing-complete languages/interpreters are globally restricted. Explicitly allow 'perl' in 'pi-security.json' if needed."],
  ["ruby", "ACTION BLOCKED. Turing-complete languages/interpreters are globally restricted. Explicitly allow 'ruby' in 'pi-security.json' if needed."],
  ["php", "ACTION BLOCKED. Turing-complete languages/interpreters are globally restricted. Explicitly allow 'php' in 'pi-security.json' if needed."],
  ["deno", "ACTION BLOCKED. Turing-complete languages/interpreters are globally restricted. Explicitly allow 'deno' in 'pi-security.json' if needed."],
  ["bun", "ACTION BLOCKED. Turing-complete languages/interpreters are globally restricted. Explicitly allow 'bun' in 'pi-security.json' if needed."],

  // --- DEVELOPER UTILITIES (Blocked in bash to force secure native tools) ---
  ["ls", "ACTION BLOCKED. Running 'ls' via bash is disabled for security. Please use your native 'ls' tool."],
  ["grep", "ACTION BLOCKED. Running 'grep' via bash is disabled for security. Please use your native 'grep' tool."],
  ["find", "ACTION BLOCKED. Running 'find' via bash is disabled for security. Please use your native 'find' tool."],
  ["git", "ACTION BLOCKED. Git commands via bash are disabled. Please perform git operations manually outside the agent environment or use native version control features if available."],
  ["sudo", "ACTION BLOCKED. Sudo/privilege escalation is strictly prohibited in this sandboxed environment."],
  ["gh", "ACTION BLOCKED. GitHub CLI commands are disabled to prevent unauthorized remote operations."],
  ["apt", "ACTION BLOCKED. Package installation via apt is disabled in this environment to maintain stability."],
  ["apt-get", "ACTION BLOCKED. Package installation via apt-get is disabled in this environment to maintain stability."],
  ["pip", "ACTION BLOCKED. Package installations are restricted. Please ask the user to install dependencies if required."],
  ["pip3", "ACTION BLOCKED. Package installations are restricted. Please ask the user to install dependencies if required."],
  ["cargo", "ACTION BLOCKED. Cargo command execution is restricted. Explicitly allow 'cargo' in 'pi-security.json' if needed."]
]);

// 2. GLOBAL ALLOWLIST
export const GLOBAL_ALLOWLIST = new Set([
  "pwd",
  "npm",
  "pnpm",
  "yarn",
  "echo",
  "pytest",
  "vitest"
]);

export const ALLOWED_PATH_SUFFIXES = [
  "@earendil-works/pi-coding-agent/docs",
  "@earendil-works/pi-coding-agent/README.md",
];

