import register from "./index";
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
      confirm: async (title: string, message: string) => {
        console.log(`[Confirm Prompt] ${title}: ${message}`);
        return true; // Auto-confirm for testing
      }
    }
  };

  const pi = new MockExtensionAPI() as any;
  register(pi);

  // Setup project pi-security.json config
  const configContent = JSON.stringify({
    allow: ["python", "my-custom-command"],
    block: {
      "ls": "Use native ls"
    },
    pathFallback: "block"
  });
  await fs.writeFile(path.join(projectRoot, "pi-security.json"), configContent);

  // Trigger session start to load config
  await pi.emit("session_start", {}, mockCtx);

  // --- TEST 1: Path Traversal Interception ---
  console.log("\n--- Test 1: Path Traversal ---");
  const pathRes1 = await pi.emit("tool_call", { toolName: "read", input: { path: "src/main.ts" } }, mockCtx);
  console.log("read 'src/main.ts':", pathRes1?.block ? "BLOCKED" : "ALLOWED", pathRes1?.reason ? `(${pathRes1.reason})` : "");

  const pathRes2 = await pi.emit("tool_call", { toolName: "read", input: { path: "../sensitive.txt" } }, mockCtx);
  console.log("read '../sensitive.txt':", pathRes2?.block ? "BLOCKED" : "ALLOWED", pathRes2?.reason ? `(${pathRes2.reason})` : "");

  const pathRes3 = await pi.emit("tool_call", { toolName: "read", input: { path: "/tmp/pi-test.txt" } }, mockCtx);
  console.log("read '/tmp/pi-test.txt':", pathRes3?.block ? "BLOCKED" : "ALLOWED", pathRes3?.reason ? `(${pathRes3.reason})` : "");

  const pathRes4 = await pi.emit("tool_call", { toolName: "read", input: { path: ".git/config" } }, mockCtx);
  console.log("read '.git/config':", pathRes4?.block ? "BLOCKED" : "ALLOWED", pathRes4?.reason ? `(${pathRes4.reason})` : "");

  // --- TEST 2: Shell Precedence overrides ---
  console.log("\n--- Test 2: Shell Precedence ---");

  // Test blocklist overriding allowlist (project-level block)
  const resLs = await pi.emit("tool_call", { toolName: "bash", input: { command: "ls" } }, mockCtx);
  console.log("bash 'ls' (project block):", resLs?.block ? "BLOCKED" : "ALLOWED", resLs?.reason ? `(${resLs.reason})` : "");

  // Test project allowlist overriding global blocklist
  const resPython = await pi.emit("tool_call", { toolName: "bash", input: { command: "python script.py" } }, mockCtx);
  console.log("bash 'python' (project allow overrides global block):", resPython ? "BLOCKED" : "ALLOWED");

  // Test global blocklist
  const resGit = await pi.emit("tool_call", { toolName: "bash", input: { command: "git status" } }, mockCtx);
  console.log("bash 'git' (globally blocked):", resGit?.block ? "BLOCKED" : "ALLOWED", resGit?.reason ? `(${resGit.reason})` : "");

  // --- TEST 3: Command Substitutions and Operators ---
  console.log("\n--- Test 3: Command Substitutions and Operators ---");
  const resSub1 = await pi.emit("tool_call", { toolName: "bash", input: { command: "echo $(whoami)" } }, mockCtx);
  console.log("bash 'echo $(whoami)':", resSub1?.block ? "BLOCKED" : "ALLOWED", resSub1?.reason ? `(${resSub1.reason})` : "");

  const resSub2 = await pi.emit("tool_call", { toolName: "bash", input: { command: "echo `whoami`" } }, mockCtx);
  console.log("bash 'echo `whoami`':", resSub2?.block ? "BLOCKED" : "ALLOWED", resSub2?.reason ? `(${resSub2.reason})` : "");

  const resOp1 = await pi.emit("tool_call", { toolName: "bash", input: { command: "echo hello && ls" } }, mockCtx);
  console.log("bash 'echo hello && ls':", resOp1?.block ? "BLOCKED" : "ALLOWED", resOp1?.reason ? `(${resOp1.reason})` : "");

  const resOp2 = await pi.emit("tool_call", { toolName: "bash", input: { command: "echo hello > file.txt" } }, mockCtx);
  console.log("bash 'echo hello > file.txt':", resOp2?.block ? "BLOCKED" : "ALLOWED", resOp2?.reason ? `(${resOp2.reason})` : "");

  const resOp3 = await pi.emit("tool_call", { toolName: "bash", input: { command: "echo hello > /dev/null" } }, mockCtx);
  console.log("bash 'echo hello > /dev/null':", resOp3?.block ? "BLOCKED" : "ALLOWED", resOp3?.reason ? `(${resOp3.reason})` : "");

  // Clean up
  process.chdir(originalCwd);
  await fs.rm(projectRoot, { recursive: true, force: true });
  console.log("\n=== ALL VERIFICATION TESTS COMPLETED SUCCESSFULLY ===");
}

runTests().catch(err => {
  console.error("Test failed with error:", err);
  process.exit(1);
});
