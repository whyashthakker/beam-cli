# Beam

Local observation and heuristic risk scanning for AI agent activity. Beam runs entirely on your machine: a loopback-only HTTP collector stores normalized events and scan reports in NDJSON files under `~/.beam`, and the `beam` CLI talks to it (or scans files completely offline).

Beam does not execute, block, or approve anything an agent does. It observes, redacts secrets before persisting, and flags risky patterns for human review.

## Install

```bash
npm run setup:global
```

This installs dependencies, builds, `npm link`s the `beam` binary globally, and starts a background watcher so the global command always reflects the current source — no manual rebuild needed after edits.

## Commands

```bash
beam serve                          # start the local collector (binds 127.0.0.1:4319)
beam serve --port 4400              # use a different port

beam token                          # print the collector's pairing token

beam import events.ndjson           # send normalized events to /ingest
beam scan SKILL.md                  # scan offline for risky instructions
beam scan mcp.json --mcp            # scan an MCP config (checks version pinning)
beam scan SKILL.md --save           # also persist the report to the collector

beam hook claude-code < payload.json # forward a hook payload for the given agent (stdin)

beam agent list                     # supported agents and payload verification status
beam agent install cursor           # wire beam's hook into that agent's own config, non-destructively
```

`scan` runs entirely offline unless `--save` is passed — no collector required. `hook` never throws or blocks the calling agent; capture failures are logged to stderr only. This mirrors Beam's core rule: **observation must never become enforcement.**

## Multi-agent coverage

Different agents send different JSON shapes to their hooks. `beam hook <agent>` picks the right adapter for the agent id you pass, and `beam agent install <agent>` writes beam's hook into that agent's real config file in its own native format, merging with (never overwriting) whatever hooks are already there.

| Agent id | Config file `agent install` writes | Payload |
|---|---|---|
| `claude-code` | `~/.claude/settings.json` (`hooks.PreToolUse`) | Verified against Claude Code's docs |
| `codex` | `~/.codex/hooks.json` (`hooks.PreToolUse`) | Same shape as Claude Code; verified |
| `cursor` | `~/.cursor/hooks.json` (`hooks.preToolUse`) | Verified against Cursor's docs |
| `copilot-cli` | `~/.copilot/hooks/beam.json` (`hooks.preToolUse`) | Verified (camelCase — translated internally) |
| `gemini` | `~/.gemini/settings.json` (`hooks.BeforeTool`) | **Not verified** — Gemini CLI's stdin schema isn't published; capture uses a generic best-effort field adapter |
| `opencode` | not built yet | discovery (config/artifact presence) only — OpenCode uses a generated TS plugin, not a JSON hook file |

Run `beam agent list` for the current status of each. Adding a new agent means one entry in `src/agents.ts` (config path + how to merge the hook block) and, if its stdin payload uses different field names than `tool_name`/`tool_input`/`session_id`/`cwd`/`hook_event_name`, one adapter function in `src/hook-adapters.ts`.

This is an intentionally small first slice of what a full multi-agent observer covers (see [Numbat](https://github.com/perplexityai/numbat) for the much larger prior art: 25+ agents, forensic on-disk artifact extraction without live hooks, a CEL rule engine, enforcement/blocking, and portable case bundles). Beam does not yet do artifact extraction, a real rule engine beyond flat regexes, or enforcement — those are tracked as future slices, not silently unsupported.

## Configuration

- `BEAM_HOME` — root config directory (default `~/.beam`).
- `BEAM_DATA_DIR` — where events/scans/token are stored (default `$BEAM_HOME/data`).
- `BEAM_TOKEN` — pairing token (skips reading the token file).
- `BEAM_COLLECTOR_URL` — collector origin the CLI talks to (default `http://127.0.0.1:4319`); must stay on HTTP loopback.
- `BEAM_PORT` — port `beam serve` binds to (default `4319`).
- `BEAM_ALLOWED_ORIGINS` — comma-separated browser origins allowed to call the collector (for a future local UI).

## Connect a Claude Code hook

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "beam hook claude-code"
      }]
    }]
  }
}
```

Choose `PreToolUse` to observe proposed actions before they run. `beam` must be on the agent's PATH (or use its absolute path).

## API

All routes require `Authorization: Bearer <token>` and are bound to loopback only.

- `GET /health` — collector version and retention.
- `GET /state` — retained events, scans, reviews, rule catalog.
- `GET /agents` — existence checks on common agent config/artifact locations, hook-install/payload-verification status; no contents are read.
- `POST /ingest` — one normalized JSON object, JSON array, or NDJSON (up to 2 MB / 2,000 records; 100 KB per record).
- `POST /v1/logs` — OTLP/HTTP **JSON** (not protobuf).
- `POST /scan` — `{ "name": "SKILL.md", "kind": "skill", "content": "..." }` (or `kind: "mcp"`; max 500 KB).
- `POST /review` — `{ "id": "...", "reviewed": true }`.
- `GET /export` — redacted event NDJSON.

## Limits and guarantees

- Retention: latest 10,000 events and 500 scan reports. Each accepted batch atomically replaces the bounded event file.
- Known credential formats, assignments, auth headers, URL query strings, and private keys are redacted before persistence. Other sensitive text may remain; inspect exports before sharing.
- Data directory mode `0700`, files `0600`. Token is generated once per data directory and reused across restarts.
- The heuristic scanner is pattern matching, not semantic malware analysis or a safety guarantee. Findings require human review.

## Development

```bash
npm test
npm run typecheck
npm run build
```
