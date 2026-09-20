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
| Jev (TypeSafe AI) | Discovery only — config/artifact presence; ecosystem is too fragmented across third-party CLIs (`jev-cli`, `jev-axi`, `jev-guard`) for a single hook contract yet |

Agent configuration is updated non-destructively, without replacing existing hooks.

## Optional Jev action judging

Use TypeSafe Jev to review proposed actions with Noul (two independent risk questions), Score (a damage rubric), or both. This is separate from discovery of third-party Jev CLIs in the agent table above. The integration is **disabled by default**; enabling it sends selected, redacted action data to TypeSafe's remote API and can incur charges.

Supply `TYPESAFE_API_KEY` through your shell or secret manager, then run:

```bash
beam jev configure --mode observe --primitive both
beam jev status
```

For persistent hooks that do not inherit your shell environment, pipe a key from your secret manager to `beam jev configure --key-stdin`. Keys are stored in `~/.beam/jev.json` (or `BEAM_HOME/jev.json`) with mode 0600. Never pass a key as a command argument. The environment key takes precedence over a stored key. Run configuration directly as the operator; Beam's self-protection blocks agents from changing these settings.

For an explicit check, create `action.json`:

```json
{
  "action": { "tool": "Bash", "command": "git diff --stat" },
  "context": "Inspect workspace changes without modifying files."
}
```

```bash
beam jev judge action.json --dry-run  # inspect redacted request locally; no API call
beam jev judge action.json            # JSON result; 0 allow, 2 review/deny, 1 error
beam jev configure --mode enforce --primitive both
beam jev disable                      # stop checks and remove stored key
```

`configure` enables checks in existing pre-tool hooks; it does not install them. Observation prints judgments to stderr and preserves local policy. Enforcement blocks an eligible action on `review`, `deny`, or an evaluation error. Local deny, approval and redaction decisions take precedence and skip Jev. Prompt/post-tool events and offline `beam scan` skip Jev. The explicit `judge` command reports its own verdict regardless of hook mode; it never executes the action.

| Check | Pass | Deny | Review |
| --- | --- | --- | --- |
| Noul: data exposure and irreversible destruction | Both ≤ 0.2 | Either ≥ 0.8 | Otherwise |
| Score: four damage levels (0–3) | Score ≤ 0.5 and confidence ≥ 0.7 | Score ≥ 2 | Otherwise |
| Both | All checks pass | Any check denies | Any remaining uncertainty |

These initial thresholds are conservative defaults, not measured safety guarantees. Noul has no separate confidence. Score includes its distribution and confidence. A malformed config reports an error and skips the optional check, preserving local policy; repair it to restore Jev coverage. Requests use a fixed HTTPS endpoint, a two-second timeout, no automatic retries, a 32 KB input limit and a 64 KB response limit.

Hook requests include only agent, tool, tool input and command, with known credential patterns, sensitive field names and policy custom detectors redacted first. Tool arguments can still contain private source or data; redaction cannot guarantee removal of every secret. Hooks do not load transcripts, referenced file contents, the user's task or environment into Jev state. An explicit file may include a short `context` string. Hook enforcement depends on the installed client's support and does not cover uninstrumented actions or every MCP transport. `disable` does not revoke the provider key or unset external environment variables.

Use the bundled [Jev action judging skill](Skills/jev-action-judge/SKILL.md), read the [Beam walkthrough](https://agentbeam.com/blog/beam-cli-jev-action-judging), or explore the [Awesome Jev use-case collection](https://github.com/whyashthakker/awesome-jev-use-cases). API semantics: [Noul](https://docs.typesafe.ai/primitives/noul), [Score](https://docs.typesafe.ai/primitives/score), [HTTP reference](https://docs.typesafe.ai/api).

## Dashboard

After enrollment, the AgentBeam dashboard shows agent activity, policy decisions, MCP inventory, users, installations, model usage, token counts, violations, blocked actions, and sensitive-data findings. Administrators can block MCP usage for an entire organization or an individual user.

## Privacy and local operation

AgentBeam's hook and policy decision run locally, so actions can be blocked even when the collector or dashboard is unavailable. Optional Jev judgments use the remote TypeSafe API; local policy remains independent. Telemetry is redacted before storage or forwarding. The local service binds to loopback, and AgentBeam files are protected from modification or removal by agent hooks.

## Development

```bash
npm test
npm run typecheck
npm run build
```

## License

AGPL-3.0-only — see [LICENSE](./LICENSE).
