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
beam start                          # start the local collector (binds 127.0.0.1:4319)
beam start --port 4400              # use a different port

beam studio                         # open the activity dashboard in your browser

beam token                          # print the collector's pairing token

beam import events.ndjson           # send normalized events to /ingest
beam scan SKILL.md                  # scan offline for risky instructions
beam scan mcp.json --mcp            # scan an MCP config (checks version pinning)
beam scan SKILL.md --save           # also persist the report to the collector

beam hook claude-code < payload.json # forward a hook payload for the given agent (stdin)

beam agent list                     # supported agents and payload verification status
beam agent install cursor           # wire beam's hook into that agent's own config, non-destructively
beam agent install-all              # detect every agent actually installed on this machine and wire them all

beam service install                # run the collector as a background service (starts on login)
beam service status                 # is it installed / running
beam service stop                   # stop it
beam service start                  # start it again
beam service uninstall              # remove it
beam service logs                   # where its log files are (or the command to follow them)
```

`scan` runs entirely offline unless `--save` is passed — no collector required. `hook` never throws or blocks the calling agent; capture failures are logged to stderr only. This mirrors Beam's core rule: **observation must never become enforcement.**

## Studio (activity dashboard)

`beam start` or `beam service install` also serves a dashboard at `GET /` and `GET /studio` on the collector itself — no separate app, no build step, no dependency added to the package (plain HTML/CSS/JS, no fonts or CDNs). `beam studio` opens it in your default browser for you.

- **Activity** — every captured event, searchable and filterable by agent/risk, with a detail drawer per action.
- **Findings** — the subset with heuristic matches, with a per-event "mark reviewed" (a record of your assessment, never an approval or block).
- **Skill & MCP scan** — paste or check a file's content and see findings live, same engine as `beam scan`.

The page itself carries no secret and needs no auth to load — only the API calls it makes do. `beam studio` reads the pairing token from disk and passes it once via a URL that's immediately scrubbed from the address bar (`history.replaceState`) after the page reads it. From there it's saved in that browser's `localStorage` (scoped to the collector's own origin, `127.0.0.1:4319` — no other site or app can read it), so reloading the tab or closing and reopening the browser stays connected without re-pairing. If the collector ever rejects the stored token (e.g. `beam service uninstall && beam service install` generates a new one), the page detects that and clears it automatically rather than looping silently. Use the **Disconnect** button to clear it yourself.

Sessions and Usage views from the original Sentinel console aren't ported yet — Activity/Findings/Scan cover the core loop first.

## Multi-agent coverage

Different agents send different JSON shapes to their hooks. `beam hook <agent>` picks the right adapter for the agent id you pass, and `beam agent install <agent>` writes beam's hook into that agent's real config file in its own native format, merging with (never overwriting) whatever hooks are already there.

`npm run setup:global` runs `beam agent install-all` automatically at the end, so every agent it can detect on your machine gets wired without you having to know which ones you have installed. Detection uses each agent's own real, pre-existing files (e.g. `~/.codex/config.toml`, `~/.copilot/config.json`) — never a file beam itself writes — so an agent that was never actually installed won't get a hook, and one that's already wired won't get a duplicate entry on a second run.

| Agent id | Config file `agent install` writes | Payload |
|---|---|---|
| `claude-code` | `~/.claude/settings.json` (`hooks.PreToolUse`) | Verified against Claude Code's docs |
| `codex` | `~/.codex/hooks.json` (`hooks.PreToolUse`) | Same shape as Claude Code; verified |
| `cursor` | `~/.cursor/hooks.json` (`hooks.preToolUse`) | Verified against Cursor's docs |
| `copilot-cli` | `~/.copilot/hooks/beam.json` (`hooks.preToolUse`) | Verified (camelCase — translated internally) |
| `gemini` | `~/.gemini/settings.json` (`hooks.BeforeTool`) | **Not verified** — Gemini CLI's stdin schema isn't published; capture uses a generic best-effort field adapter |
| `opencode` | not built yet | discovery (config/artifact presence) only — OpenCode uses a generated TS plugin, not a JSON hook file |

Run `beam agent list` for the current status of each. Adding a new agent means one entry in `src/agents.ts` (config path + how to merge the hook block) and, if its stdin payload uses different field names than `tool_name`/`tool_input`/`session_id`/`cwd`/`hook_event_name`, one adapter function in `src/hook-adapters.ts`.

This is an intentionally small first slice of what a full multi-agent observer covers (see [Numbat](https://github.com/perplexityai/numbat) for the much larger prior art: 25+ agents, a CEL rule engine, enforcement/blocking, and portable case bundles). Beam does not yet do a real rule engine beyond flat regexes, or enforcement — those are tracked as future slices, not silently unsupported.

## Forensic extraction (no hook required)

`beam agent extract <agent>` reads an agent's own existing session/transcript files directly — no hook needed, and it works for history from *before* Beam was ever installed:

```bash
beam agent extract claude-code              # preview: normalizes locally, prints JSON, nothing sent anywhere
beam agent extract claude-code --limit 20   # cap how many events the preview prints (default 200)
beam agent extract claude-code --save       # import into the running collector (dedupes by event_id)
beam agent extract codex --save
```

Supported today: **`claude-code`** (`~/.claude/projects/**/*.jsonl` — reads `tool_use` blocks out of assistant turns) and **`codex`** (`~/.codex/{sessions,archived_sessions}/**/*.jsonl` — reads `function_call` and `custom_tool_call` response items). Every extracted event gets `source: "extract"` and `phase: "observed"` so it's visibly distinct from a live hook capture (which is `"proposed"`/`"completed hook"`). Preview mode normalizes (and therefore redacts) locally without ever contacting the collector; `--save` sends the raw records through the same `/ingest` pipeline a live hook uses, batched under the collector's 2,000-record-per-request cap. Bounded like everything else in Beam: 50 MB max per transcript file, 20,000 parsed lines per file, 2,000 files walked per run.

Other agents aren't wired yet — `beam agent extract <agent>` fails clearly rather than silently returning nothing for one that isn't supported.

## Running as a background service

`beam start` in a terminal works, but closing that terminal stops the collector. `beam service install` instead registers it as a real background service:

- **macOS**: a `launchd` user agent at `~/Library/LaunchAgents/ai.beam.collector.plist` (`RunAtLoad` + `KeepAlive`, so it starts on login and restarts if it crashes).
- **Linux**: a `systemd --user` unit at `~/.config/systemd/user/beam.service` (`enable --now`, `Restart=always`).

Both embed the resolved `BEAM_DATA_DIR` directly into the service definition (launchd/systemd don't inherit your shell's environment), so `BEAM_DATA_DIR=/custom/path beam service install` keeps using that path even after a reboot. Logs go to `$BEAM_DATA_DIR/logs/`.

This is a userspace HTTP server, same as running `beam start` yourself — not kernel-level capture. Beam has nothing to observe at the kernel level: the actual signal comes from agents calling `beam hook <agent>` at the moment they're about to act, the same way whether run in a terminal or as a background service.

Windows isn't supported yet (`beam service *` will say so and tell you to run `beam start` directly).

## Configuration

- `BEAM_HOME` — root config directory (default `~/.beam`).
- `BEAM_DATA_DIR` — where events/scans/token are stored (default `$BEAM_HOME/data`).
- `BEAM_TOKEN` — pairing token (skips reading the token file).
- `BEAM_COLLECTOR_URL` — collector origin the CLI talks to (default `http://127.0.0.1:4319`); must stay on HTTP loopback.
- `BEAM_PORT` — port `beam start` binds to (default `4319`).
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
