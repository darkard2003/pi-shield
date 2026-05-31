# pi-shield

Security guardrail and custom tool extension for the Pi Coding Agent (`@earendil-works/pi-coding-agent`).

## Features

### 1. Path Traversal Guardrail (`pathTraversalGuard`)
- Enforces strict security boundaries around the current working directory.
- Restricts filesystem tool access (`read`, `write`, `edit`, `grep`, `find`, `ls`, etc.) to files within the workspace directory, `/tmp`, or explicitly allowed path suffixes.
- Completely blocks access or modification to `.git` internals.

### 2. Bash Secure Allowlist & Blocklist (`bashSecureAllowlist`)
- Prohibits command substitution using `$()` or backticks.
- Restricts bash tool execution to a very narrow global allowlist (`pwd`, `npm`, `pnpm`, `yarn`, `echo`, `pytest`, `vitest`).
- Implements a strict blocklist with descriptive safety instructions (e.g. blocking `cat`, interactive pagers/editors like `less`/`vim`, dangerous disk utilities like `rm`/`dd`, network tools, and Turing-complete interpreters by default).
- Blocks dangerous shell operators (`;`, `&&`, `||`) and file redirections (except safe globbing and output redirection to `/dev/null`).

### 3. Custom Secure Tools (`registerCustomTools`)
- Replaces standard tools with safe TypeScript equivalents for `ls`, `find`, and `grep` to bypass shell hazards.
- Implements context window size protection: automatically truncates massive tool outputs (> 5 KB or 200 lines) and writes the full content to secure scratch files (e.g., `/tmp/pi-shield-*.txt`).
- Dynamically extends agent system instructions upon startup via `before_agent_start`.

## Configuration (`pi-security.json`)

Customize security rules for your project by creating a `pi-security.json` file in the project root:

```json
{
  "allow": ["python3", "my-custom-command"],
  "block": {
    "some-command": "Specific reason for blocking this command"
  }
}
```

### Precedence Hierarchy:
1. **Project-specific blocklist** (defined in `pi-security.json` `block` object) overrides everything.
2. **Project-specific allowlist** (defined in `pi-security.json` `allow` array) overrides the global blocklist (e.g., allowing `python` or `node`).
3. **Global blocklist** (defined in `global_constants.ts`) blocks forbidden commands.
4. **Global allowlist** (defined in `global_constants.ts`) permits safe commands.

## Installation

Clone the `pi-shield` repository from GitHub into either a global or local extensions directory:

### Option A: Global Installation
Clone into the global agent extensions directory:
```bash
# Create directory if it does not exist
mkdir -p ~/.pi/agent/extensions

# Clone the repository
git clone https://github.com/your-username/pi-shield.git ~/.pi/agent/extensions/pi-shield

# Navigate and install
cd ~/.pi/agent/extensions/pi-shield
npm install
```

### Option B: Local Installation
Clone into your specific project's `.pi/extensions` directory:
```bash
# Create directory if it does not exist
mkdir -p .pi/extensions

# Clone the repository
git clone https://github.com/your-username/pi-shield.git .pi/extensions/pi-shield

# Navigate and install
cd .pi/extensions/pi-shield
npm install
```

## Development and Verification

Run self-contained verification tests to validate all security behaviors:
```bash
npx ts-node src/test_pi_shield.ts
```
*(Runs validation for validatePath, shell overrides, command substitutions, custom tools, and output truncation/scratch file redirection)*
