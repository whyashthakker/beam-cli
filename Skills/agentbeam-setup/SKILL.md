---
name: agentbeam-setup
description: Install and set up AgentBeam on this machine - the Beam CLI, protection hooks for every AI coding agent it finds, the connection to the user's AgentBeam workspace, and the background service - then verify it works. Use when the user asks to install, set up, connect, update or repair AgentBeam or the beam CLI.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
  website: https://agentbeam.com
---

# Set up AgentBeam

AgentBeam is a local security layer for AI coding agents. The `beam` CLI installs hooks into the agents on this machine (Claude Code, Codex, Cursor, Gemini CLI, GitHub Copilot CLI, OpenCode), checks their tool calls against the user's AgentBeam policy, redacts secrets, and reports activity to the user's dashboard at https://app.agentbeam.com.

## Rules while you do this

- Run one command at a time and show the user what it printed.
- Never print, read or copy credentials: not `~/.beam/data/identity.json`, not tokens, not API keys. Never pass a key as a command argument.
- `beam setup` and `beam connect` are interactive and open a browser for the user to approve this device. Ask the user to run those themselves in a terminal, for example by typing `! beam setup` in Claude Code. Don't try to answer the prompts for them.
- Once installed, Beam blocks agents from changing its settings, stopping its service or uninstalling it. If a Beam command is blocked, that's working as intended: tell the user and ask them to run it themselves.
- Don't edit the agents' configuration files by hand; `beam setup` updates them without removing existing hooks.

## 1. Check what's here

```sh
beam --version
node --version
```

- If `beam --version` prints a version, Beam is installed; skip to step 3 (re-running setup is safe and repairs an installation).
- The npm install needs Node.js 20.17 or newer. Without it, use the standalone installer in step 2.

## 2. Install the Beam CLI

With Node.js 20.17+:

```sh
npm i -g @agent-beam/beam
```

Without Node.js, the user installs the standalone binary themselves: point them to https://docs.agentbeam.com/agent-cli/quickstart (macOS and Linux use a one-line installer script, Windows uses PowerShell). Don't run a downloaded install script yourself.

Confirm with `beam --version`. If the command isn't found, the install folder isn't on the user's PATH: for npm it's the `bin` folder under `npm prefix -g`; for the standalone installer it's `~/.local/bin`. Ask the user to add it to their shell profile and open a new terminal.

## 3. Run setup (the user runs this)

Ask the user to run:

```sh
beam setup
```

It walks through five steps:

1. Detects the AI agents on this machine and installs Beam's hook into each one.
2. Connects this device to the user's AgentBeam workspace. A browser opens; the user signs in at app.agentbeam.com and approves the device.
3. Downloads the workspace's policy.
4. Indexes installed agent skills and scores their risk.
5. Starts the background service, so protection keeps running after restarts.

It ends with a summary table. Every row should be green. Ask the user to paste it if you can't see it.

## 4. Verify

```sh
beam whoami
beam agent list
beam service status
```

- `beam whoami` shows this device and its workspace. "This device is not enrolled" means step 2 of setup didn't finish: have the user run `beam connect`.
- `beam agent list` should show "installed" for each agent the user uses. If an agent is missing, the user can run `beam agent install <agent>`, or install the agent and run `beam setup` again.
- `beam service status` should say the service is running. If not: `beam service start`, then `beam service logs`.

Finally, ask the user to open https://app.agentbeam.com: within a minute of using any agent, activity appears on the dashboard.

## 5. Optional extras

Offer these, don't run them unasked:

- `beam studio` opens a local activity view in the browser.
- `beam cve check .` checks the current project's dependencies for known vulnerabilities (needs App monitoring turned on in the dashboard).
- `beam monitor --file <log>` watches a running app's logs and traffic for attacks, on servers, after App monitoring is turned on in the dashboard.
- `beam jev --help` and `beam judge --help` add an optional second opinion on agent actions from a model of the user's choice. Both are off by default.

## If something goes wrong

- Re-running `beam setup` is safe; it keeps existing agent configuration.
- Full guide: https://docs.agentbeam.com/agent-cli/quickstart
- Troubleshooting: https://docs.agentbeam.com/agent-cli/troubleshooting
- Help: support@agentbeam.com
