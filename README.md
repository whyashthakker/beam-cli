# AgentBeam

AgentBeam is a local security layer for AI agents. `beam` is the AgentBeam CLI. It installs hooks for the agents detected on your machine, captures agent and MCP activity, applies your AgentBeam policy locally, and sends approved telemetry to the AgentBeam dashboard.

## Install and setup

```bash
npm i @agent-beam/beam -g
beam setup
```

`beam setup` is the main command. It detects supported agents, installs their native AgentBeam hooks, inventories configured MCP servers, connects the device to the dashboard, downloads organization and user policy, and starts the persistent background service.

After setup, selected agents are protected automatically. You do not need to run `beam run` or manually start a collector.

## Useful commands

```bash
beam setup                 # install or repair AgentBeam and agent protection
beam service status        # check the background service
beam agent list            # see supported agents and hook status
beam studio                # open the local activity dashboard
beam sync                  # fetch the latest organization policy
```

Run `beam setup` again when adding an agent or repairing an installation. It preserves existing agent configuration.

## What AgentBeam protects

Depending on organization policy, AgentBeam can ask for approval, block, redact, or log:

- Environment variables and `.env` files
- API keys, tokens, passwords, private keys, and cloud credentials
- Files outside the current workspace
- Destructive commands and production changes
- MCP write or side-effect tools
- Attempts to modify AgentBeam policy/data, stop the AgentBeam service, or uninstall AgentBeam

MCP responses can be filtered locally before sensitive content reaches an agent. MCP inventory and activity are reported to the dashboard so administrators can review or block a server for one user or the entire organization.

## Multi-agent support

AgentBeam is not Claude-specific. Setup discovers the agents actually installed on the machine and installs the appropriate native hook for each selected agent.

| Agent | Hook support |
|---|---|
| Claude Code | Pre-tool protection and activity capture |
| Codex | Pre-tool protection and activity capture |
| Gemini CLI | Before-tool protection and activity capture |
| GitHub Copilot CLI | Pre-tool protection and activity capture |
| Cursor | Pre-tool protection and activity capture |
| OpenCode | Shim-based protection where supported |

Agent configuration is updated non-destructively, without replacing existing hooks.

## Dashboard

After enrollment, the AgentBeam dashboard shows agent activity, policy decisions, MCP inventory, users, installations, model usage, token counts, violations, blocked actions, and sensitive-data findings. Administrators can block MCP usage for an entire organization or an individual user.

## Privacy and local operation

AgentBeam's hook and policy decision run locally, so actions can be blocked even when the collector or dashboard is unavailable. Telemetry is redacted before storage or forwarding. The local service binds to loopback, and AgentBeam files are protected from modification or removal by agent hooks.

## Development

```bash
npm test
npm run typecheck
npm run build
```

## License

AGPL-3.0-only — see [LICENSE](./LICENSE).
