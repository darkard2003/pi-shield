import registerCustomTools, { validatePath } from "./custom-tools";
import bashSecureAllowlist from "./shell-guard";
import { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import * as path from "path";
import * as fs from "fs/promises";

// Mock ExtensionAPI
class MockExtensionAPI {
  events: { [key: string]: Function[] } = {};
  tools: { [key: string]: any } = {};

  on(event: string, handler: Function): any {
    if (!this.events[event]) {
      this.events[event] = [];
    }
    this.events[event].push(handler);
  }

  registerTool(definition: any): any {
    this.tools[definition.name] = definition;
  }

  async emit(event: string, ...args: any[]) {
    if (this.events[event]) {
      for (const handler of this.events[event]) {
        const res = await handler(...args);
        if (res) return res;
      }
    }
  }
}

async function runTests() {
  console.log("=== STARTING PI SHIELD VERIFICATION TESTS ===");
  const projectRoot = path.resolve(__dirname, "../mock-project");
  await fs.mkdir(projectRoot, { recursive: true });
  
  // Save process.cwd so we can restore it
  const originalCwd = process.cwd();
  process.chdir(projectRoot);

  const mockCtx = {
    cwd: projectRoot,
    ui: {
      notify: (msg: string) => console.log(`[Notification] ${msg}`),
      setStatus: () => {},
      setWidget: () => {},
    }
  };

  // --- TEST 1: Path Traversal helper ---
  console.log("\n--- Test 1: validatePath ---");
  const testPath1 = validatePath("src/main.ts", projectRoot);
  console.log("src/main.ts relative:", testPath1.allowed ? "ALLOWED" : "BLOCKED");

  const testPath2 = validatePath("../sensitive.txt", projectRoot);
  console.log("../sensitive.txt (traverse out):", testPath2.allowed ? "ALLOWED" : "BLOCKED");

  const testPath3 = validatePath("/tmp/pi-test.txt", projectRoot);
  console.log("/tmp/pi-test.txt:", testPath3.allowed ? "ALLOWED" : "BLOCKED");

  const testPath4 = validatePath(".git/config", projectRoot);
  console.log(".git/config:", testPath4.allowed ? "ALLOWED" : "BLOCKED");

  // --- TEST 2: Shell Precedence overrides ---
  console.log("\n--- Test 2: Shell Precedence ---");
  const pi = new MockExtensionAPI() as any;
  bashSecureAllowlist(pi);

  // Setup project pi-security.json config
  const configContent = JSON.stringify({
    allow: ["python", "my-custom-command"],
    block: {
      "ls": "Use native ls"
    }
  });
  await fs.writeFile(path.join(projectRoot, "pi-security.json"), configContent);

  // Trigger session start to load config
  await pi.emit("session_start", {}, mockCtx);

  // Test blocklist overriding allowlist (project-level block)
  const resLs = await pi.emit("tool_call", { toolName: "bash", input: { command: "ls" } }, mockCtx);
  console.log("bash 'ls' (project block):", resLs?.block ? "BLOCKED" : "ALLOWED", resLs?.reason ? `(${resLs.reason})` : "");

  // Test project allowlist overriding global blocklist
  const resPython = await pi.emit("tool_call", { toolName: "bash", input: { command: "python script.py" } }, mockCtx);
  console.log("bash 'python' (project allow overrides global block):", resPython ? "BLOCKED" : "ALLOWED");

  // Test global blocklist
  const resGit = await pi.emit("tool_call", { toolName: "bash", input: { command: "git status" } }, mockCtx);
  console.log("bash 'git' (globally blocked):", resGit?.block ? "BLOCKED" : "ALLOWED", resGit?.reason ? `(${resGit.reason})` : "");

  // --- TEST 3: Command Substitutions ---
  console.log("\n--- Test 3: Command Substitutions ---");
  const resSub1 = await pi.emit("tool_call", { toolName: "bash", input: { command: "echo $(whoami)" } }, mockCtx);
  console.log("bash 'echo $(whoami)':", resSub1?.block ? "BLOCKED" : "ALLOWED", resSub1?.reason ? `(${resSub1.reason})` : "");

  const resSub2 = await pi.emit("tool_call", { toolName: "bash", input: { command: "echo `whoami`" } }, mockCtx);
  console.log("bash 'echo `whoami`':", resSub2?.block ? "BLOCKED" : "ALLOWED", resSub2?.reason ? `(${resSub2.reason})` : "");

  // --- TEST 4: Custom Overridden Tools ---
  console.log("\n--- Test 4: Custom ls, find, grep ---");
  registerCustomTools(pi);

  // Write some mock files in projectRoot to test custom tools
  await fs.mkdir(path.join(projectRoot, "src"), { recursive: true });
  await fs.writeFile(path.join(projectRoot, "src/hello.ts"), "console.log('hello world');\nconst x = 42;");
  await fs.writeFile(path.join(projectRoot, "src/world.ts"), "console.log('earth');");

  // A. Custom LS
  console.log("\n--- A. Custom ls tool execution ---");
  const lsTool = pi.tools["ls"];
  const lsRes = await lsTool.execute("1", { path: "src" }, undefined, undefined, mockCtx);
  console.log("ls src outcome:\n", lsRes.content[0].text);

  // B. Custom FIND
  console.log("\n--- B. Custom find tool execution ---");
  const findTool = pi.tools["find"];
  const findRes = await findTool.execute("2", { pattern: "**/*.ts" }, undefined, undefined, mockCtx);
  console.log("find outcome:\n", findRes.content[0].text);

  // C. Custom GREP
  console.log("\n--- C. Custom grep tool execution ---");
  const grepTool = pi.tools["grep"];
  const grepRes = await grepTool.execute("3", { pattern: "console\\.log", path: "src" }, undefined, undefined, mockCtx);
  console.log("grep outcome:\n", grepRes.content[0].text);

  // D. Large Output Truncation
  console.log("\n--- D. Truncation and Scratch File redirection ---");
  // Write a large mock file (more than 200 lines)
  const largeLines = Array.from({ length: 250 }, (_, i) => `Line ${i + 1} matching search term`).join("\n");
  await fs.writeFile(path.join(projectRoot, "src/large.ts"), largeLines);

  const grepLargeRes = await grepTool.execute("4", { pattern: "search term", path: "src/large.ts", limit: 250 }, undefined, undefined, mockCtx);
  console.log("Grep large output outcome:\n", grepLargeRes.content[0].text);

  // Clean up
  process.chdir(originalCwd);
  await fs.rm(projectRoot, { recursive: true, force: true });
  console.log("\n=== ALL VERIFICATION TESTS COMPLETED SUCCESSFULLY ===");
}

runTests().catch(err => {
  console.error("Test failed with error:", err);
  process.exit(1);
});
