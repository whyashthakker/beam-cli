# beam-audit

Free, standalone scanner for anyone who hasn't installed [beam](https://agentbeam.com) yet.
Checks whether anything on this machine already stops the data categories Claude Code should
never see (policy 4.2: production credentials, PII, PHI, customer data, trade secrets, network
topology) from reaching a prompt -- and then **proves it live** against your own already-installed
Claude Code, instead of just inferring from config files.

## Run

```
npx beam-audit
# or, scoped to specific folders:
npx beam-audit --root ~/Projects --root ~/Work
```

From inside this repo (before it's published), use the root `npm run audit` script -- but note
the `--` separator is required for any flag, or npm swallows it as its own unknown config option
and silently drops it:

```
npm run audit -- --root . --html report.html --open
```


No `beam` install, no signup. If Claude Code is on your PATH and authenticated, two small real API
calls are made (a few cents of your own usage) to demonstrate the result rather than guess at it.
Use `--skip-live` to skip those and only run the free, local, zero-network checks.

## What it checks

1. **Global + per-repo Claude Code config** — is there any `PreToolUse`/`UserPromptSubmit` hook at
   all, anywhere a repo's `.claude/settings.json` could override the global one with nothing?
2. **Every git repo found on the machine** — tracked/untracked credential files not gitignored,
   literal PII/PHI/financial-data patterns in tracked files, customer-data-shaped file names.
3. **Live round-trip test** — a synthetic (obviously fake) API key, SSN, email, and card number are
   sent through a real headless `claude -p` call; if the exact value comes back verbatim, nothing
   intercepted it before it left for Anthropic's API.
4. **VS Code extension + workspace-auto-include test** — confirms the official extension is
   installed and connected (via its own IDE socket files), then runs a live test for data that
   leaks purely because it's sitting in the working directory, never typed or pasted.

See the comment at the top of `src/checks/vscode-test.ts` for why this doesn't drive the VS Code
UI pixel-by-pixel: the extension's chat panel shares the exact same engine and hook path as the
headless CLI call already being tested, so UI automation would add fragility without adding signal.

## Options

- `--root <dir>` (repeatable) — directories to search for git repos. Defaults to `$HOME`.
- `--max-repos <n>` — cap on repos discovered (default 500).
- `--json <file>` — also write raw findings as JSON.
- `--skip-live` — skip the two real API calls; config/file checks only.

Exit code is `1` if anything failed, `0` otherwise.
