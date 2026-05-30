# PI Shield 🔒

A security guardrail extension for the PI coding agent that restricts dangerous bash commands, prevents directory traversal attacks, and blocks destructive operations.

## Overview

PI Shield intercepts and validates all tool calls and bash commands within the PI coding agent environment. It provides multiple layers of protection:

- **Bash Command Allowlisting**: Only explicitly allowed commands can execute
- **Path Traversal Prevention**: Restricts file access to the current project directory and `/tmp`
- **Destructive Operation Block**: Prevents file deletion, format, reboot, etc.
- **Network Isolation**: Blocks outbound connections, SSH, curl, wget, etc.
- **Shell Injection Protection**: Disables dangerous operators like `;`, `&&`, `||`

## How It Works

### 1. Global Blocklist

PI Shield ships with a comprehensive list of blocked commands, each with a helpful explanation of why they're restricted and what to do instead:

| Category | Example Commands |
|----------|------------------|
| File Reading | `cat`, `head`, `tail`, `sed`, `awk`, `strings`, `xxd` |
| Interactive Editors | `vim`, `vi`, `nano`, `emacs`, `ed` |
| Pagers & Monitors | `less`, `more`, `top`, `htop`, `btop`, `watch` |
| Destructive Commands | `rm`, `shred`, `wipe`, `dd`, `mkfs` |
| Network/Remote | `ssh`, `scp`, `curl`, `wget`, `nc`, `nmap` |
| System Control | `reboot`, `shutdown`, `systemctl`, `kill` |
| Shell Nesting | `bash`, `sh`, `zsh`, `tmux`, `screen` |

### 2. Global Allowlist

These commands are always allowed:

- `ls`, `pwd`, `grep`, `find`, `npm`, `echo`, `pytest`, `vitest`

### 3. Project Configuration

Create a `pi-security.json` file in your project root to customize allowed/blocked commands:

```json
{
  "allow": ["custom-cmd", "my-tool"],
  "block": {
    "git": "Use the native read/edit tools instead of git commands"
  }
}
```

## Using File Tools

The `read`, `write`, and `edit` native tools are **always available** and should be used instead of trying to execute `cat` or other file commands via bash.

### Path Restrictions

- [x] Files inside the current working directory (project root)
- [x] Files inside `/tmp`
- [x] Allowed documentation paths (e.g., `@earendil-works/pi-coding-agent/docs`)

### Blocked Paths

- [ ] Paths outside the project directory
- [ ] Access to `.git` internals
- [ ] Attempts to traverse `..` to escape the project

### Example Block Messages

When blocked, you'll see helpful messages like:

```
🚨 Blocked file access: /etc/passwd
SECURITY GUARDRAIL: Directory traversal blocked.

🚨 Blocked file access: ../sensitive.txt
SECURITY GUARDRAIL: Directory traversal blocked...

Blocked forbidden keyword: 'rm'
ACTION BLOCKED. You do not have privileges to delete files.
```

## Installation

There are two ways to use PI Shield:

### Option 1: Install Globally (System-wide)

Clone or copy the `pi-shield` directory directly to your global extensions folder:

The extension will be located at:
```
~/.pi/agent/extensions/pi-shield/
```

Once installed globally, security guards are active for all your PI sessions.

### Option 2: Install Locally (Project-specific)

Clone or copy the `pi-shield` directory to your project's `.pi/extensions` folder:

The extension will be located at:
```
/path/to/your/project/.pi/extensions/pi-shield/
```

This installs it per-project. Each project can have its own `pi-security.json` configuration.

### How It Works

When PI loads a project, it scans the `extensions` directory and automatically registers any TypeScript files. PI Shield hooks into:

- `session_start` - Loads configuration and shows status notifications
- `tool_call` - Validates file read/write/edit tools
- `bash` commands - Checks commands against blocklist/allowlist

### Customizing per-project

After installing locally, create a `pi-security.json` in your project root:

```json
{
  "allow": ["custom-tool"],
  "block": {
    "git": "Use git from terminal instead"
  }
}
```

This config is automatically loaded on session start.

## Usage

1. **Just start using PI** - security guards are active by default
2. **Create `pi-security.json`** to customize the rules in your project (optional)

### pi-security.json Example

```json
{
  "allow": [
    "npm",
    "pnpm",
    "my-custom-tool"
  ],
  "block": {
    "git": "Use git commands manually outside PI",
    "git commit": "Use git commit from terminal directly"
  }
}
```

## Notification System

PI Shield uses the built-in UI notification system to inform you when commands are blocked:

- 🔒 Green lock icon when guards are enabled
- 🚨 Warning when a command is blocked
- ℹ️ Informational messages when configuration is loaded

## Development

### TypeScript Dependencies

- `@earendil-works/pi-coding-agent` - PI agent SDK
- `shell-quote` - Command tokenization
- `@types/shell-quote` - Type definitions

