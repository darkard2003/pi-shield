# pi-shield

Security guardrail extension for the Pi Coding Agent (`@earendil-works/pi-coding-agent`).

## Features

### 1. Path Traversal Guardrail (`pathGuard`)
- Enforces strict security boundaries around the current working directory.
- Restricts filesystem tool access (`read`, `write`, `edit`, `grep`, `find`, `ls`, etc.) to files within the workspace directory, `/tmp`, or explicitly configured path suffixes.
- Blocks access to custom configured restricted directory paths.
- Protects against Git internals modifications with configurable access levels.
- Can be enabled or disabled via configuration.

### 2. Shell Guardrail (`shellGuard`)
- Validates and intercepts bash tool command executions against allowlists, blocklists, and warning lists.
- Controls command substitution usage using `$()` or backticks with a configurable policy.
- Restricts dangerous command chaining (`;`, `&&`, `||`, `|`, `&`) with individual segment checks.
- Regulates direct file execution paths (relative and absolute script runs) using a dedicated policy.
- Can be enabled or disabled via configuration.

---

## Configuration (`pi-security.json`)

Customize security rules globally in `~/.pi/agent/pi-security.json` or at the project level by creating a `pi-security.json` file in the project root.

**Sane Default Template:**
```json
{
  "shellGuard": true,
  "pathGuard": true,
  "allow": [],
  "warn": [],
  "block": {},
  "fallback": "warn",
  "chaining": "warn",
  "commandSubstitution": "warn",
  "fileExecution": "block",
  "pathFallback": "block",
  "gitAccess": "block",
  "allowedPathSuffixes": [
    "@earendil-works/pi-coding-agent/docs",
    "@earendil-works/pi-coding-agent/README.md"
  ],
  "restrictedPaths": []
}
```

### Enablement Settings
- **`shellGuard`**: Enables (`true`, default) or disables (`false`) bash execution interception.
- **`pathGuard`**: Enables (`true`, default) or disables (`false`) filesystem path checks.

### Command Execution Control
- **`allow`**: Array of commands to trust explicitly (e.g. `["ls", "grep"]`).
- **`warn`**: Array of commands that should trigger a user confirmation prompt.
- **`block`**: Object mapping commands to specific block reasons.
- **`fallback`**: Defines behavior for commands not listed in any allow/block/warn list.
  - `warn` (default): Asks user "Proceed or Reject?".
  - `block`: Rejects unknown commands.
  - `allow`: Allows unknown commands silently.

### Advanced Shell Rules
- **`chaining`**: Defines how to handle command chaining operators (`&&`, `||`, `;`, `|`, `&`).
  - `warn` (default): Prompts for user confirmation.
  - `block`: Instantly blocks chaining.
  - `allow`: Allows chaining operators (all commands in the chain are still checked individually).
- **`commandSubstitution`**: Policy for command substitutions using `$()` or backticks.
  - `warn` (default): Prompts for user confirmation.
  - `block`: Instantly blocks substitutions.
  - `allow`: Allows substitutions.
- **`fileExecution`**: Policy for running direct file execution paths (e.g. `./build.sh` or `/usr/bin/python`).
  - `block` (default): Instantly blocks file executions.
  - `warn`: Prompts for user confirmation.
  - `allow`: Allows file executions.

### Path Access Control
- **`pathFallback`**: Defines behavior when the agent tries to access a file outside the project root, `/tmp`, or allowed suffixes.
  - `block` (default): Hard block on directory traversal.
  - `warn`: Asks user "Proceed or Reject?".
  - `allow`: Allows access to outside paths silently.
- **`gitAccess`**: Policy for accessing `.git/` internals.
  - `block` (default): Instantly blocks access.
  - `warn`: Prompts for user confirmation.
  - `allow`: Allows access.
- **`allowedPathSuffixes`**: Custom directory/file path suffixes outside the workspace that the agent is allowed to access.
- **`restrictedPaths`**: Workspace-relative paths that the agent is explicitly forbidden from reading or writing (e.g. `["secrets/", ".env"]`).

### Precedence Hierarchy:
1. **Project Blocklist** (`pi-security.json` : `block`): Hard block. Overrides all.
2. **Project Allowlist** (`pi-security.json` : `allow`): Explicit trust. Overrides global block.
3. **Project Warnlist** (`pi-security.json` : `warn`): Bypasses global block to trigger a user confirmation prompt.
4. **Global Blocklist** (`~/.pi/agent/pi-security.json` : `block`): Hard block for critical system hazards.
5. **Global Allowlist** (`~/.pi/agent/pi-security.json` : `allow`): System-wide safe tools.
6. **Command Fallback**: Resolved as `projectFallback` > `globalFallback` > `"warn"`.
7. **Path Fallback**: Resolved as `projectPathFallback` > `globalPathFallback` > `"block"`.

---

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

---

## Development and Verification

Run self-contained verification tests to validate all security behaviors:
```bash
npx ts-node src/test_pi_shield.ts
```
*(Runs validation for path traversal boundaries, shell precedence, command substitutions, command chaining operators, and redirection controls)*
