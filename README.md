# AgentBeam

AgentBeam is a local security layer for AI agents. `beam` is the AgentBeam CLI. It installs hooks for the agents detected on your machine, captures agent and MCP activity, applies your AgentBeam policy locally, and sends approved telemetry to the AgentBeam dashboard.

## WipeBench: coding agent safety benchmark

[WipeBench](https://github.com/whyashthakker/WipeBench) gives coding agents an
objective, captures the commands they choose, and evaluates task completion and
harmful effects in Docker. A benchmark by [AgentBeam](https://agentbeam.com), in
collaboration with [ExplainX.ai](https://explainx.ai).

The [local snapshot](safety-bench/README.md) includes 112 scored scenarios across
12 categories and a no-key smoke test:

```sh
python3 safety-bench/bench.py selftest --scenarios smoke-hello
```

Requires Python 3.11+ and a running Docker daemon. Scripted self-tests validate
the harness; they are not model rankings. The benchmark snapshot uses its own
[Apache-2.0 license](safety-bench/LICENSE). See the
[benchmark page](https://agentbeam.com/benchmarks/wipebench) for scope and usage.

## Install and setup

```bash
npm i @agent-beam/beam -g
beam setup
```

`beam setup` is the main command. It detects supported agents, installs their native AgentBeam hooks, inventories configured MCP servers, connects the device to the dashboard, downloads organization and user policy, and starts the persistent background service.

After setup, selected agents are protected automatically. You do not need to run `beam run` or manually start a collector.

### Or let your coding agent set it up

```bash
npx @agent-beam/beam add skill agentbeam-setup -g --all-agents
```

That installs the AgentBeam setup skill for Claude Code, Codex, Cursor, Gemini CLI, OpenCode and GitHub Copilot CLI. Then ask your agent to "set up AgentBeam". It installs the CLI, hands you `beam setup` for the parts that need a browser sign-in, and checks that everything is running.

## Useful commands

```bash
beam setup                 # install or repair AgentBeam and agent protection
beam service status        # check the background service
beam agent list            # see supported agents and hook status
beam studio                # open the local activity dashboard
beam sync                  # fetch the latest organization policy
beam monitor --file <log>  # watch a running app's logs and traffic (see App monitoring)
beam cve check .           # check an app's dependencies for known vulnerabilities
```

Run `beam setup` again when adding an agent or repairing an installation. It preserves existing agent configuration.

**Updates.** Like Claude Code, Beam keeps itself current. At most once a day, an interactive `beam` command checks for a new release and installs it in the background, so the command you ran never waits. The next command tells you it's done and what to restart.

- It never runs inside agent hooks, `beam run`, `beam monitor`, CI or non-interactive shells, and never asks for sudo. If the install needs elevated rights, it tells you to run `beam update`.
- Turn it off per user with `beam update --auto off`, or fleet-wide with `BEAM_DISABLE_AUTOUPDATE=1` (for example through MDM).
- Standalone binaries show a download link instead.

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

## Optional judging with any LLM or decision service

`beam judge` works like Jev but with a model you choose. It's disabled by default. Pick one provider:

- **`llm`:** any model behind an OpenAI-compatible chat completions endpoint, such as OpenAI, OpenRouter, a LiteLLM gateway, or a local Ollama or vLLM server. Beam asks it for an allow, review or deny verdict on the action.
- **`http`:** your own decision service: an internal policy engine, a classifier, or a fine-tuned model behind an API.

```bash
# General LLM. On OpenAI the default model is gpt-4.1-nano; key from your secret manager
op read op://vault/openai/key | beam judge configure --provider llm --key-stdin

# A local model: no key, nothing leaves the machine
beam judge configure --provider llm --url http://localhost:11434/v1 --model llama3.2

# Your own decision service, enforcing
beam judge configure --provider http --url https://decide.internal.example/v1/check --mode enforce

beam judge status
beam judge check action.json --dry-run   # print the redacted request; nothing is sent
beam judge check action.json             # 0 allow, 2 review/deny, 1 error
beam judge disable                       # stop checks and remove the stored key
```

A decision service receives `POST {"version":1,"action":{"agent","tool","input","command"},"context"?}` and must answer `{"verdict":"allow"|"review"|"deny","reason":"..."}`. A `decision` field is accepted in place of `verdict`. The key, if any, comes from `BEAM_JUDGE_API_KEY` or is stored in `~/.beam/judge.json` (mode 0600), and is sent as `Authorization: Bearer`.

The safety rules match Jev's:

- It runs only on pre-tool hooks, and only when local policy would let the action run.
- Inputs are redacted the same way.
- Observation mode is the default. Only `--mode enforce` blocks an action, on `review`, `deny` or an error.
- A refusal from a general model counts as `review`. Anything unreadable counts as an error, never as `allow`.
- Requests time out after 3 seconds by default (`--timeout-ms`, from 500 to 15000).
- Agents can't run `beam judge configure` or `beam judge disable`.

Jev and `beam judge` can run together. Each adds its own wait to every eligible tool call.

## App monitoring (optional)

`beam monitor` watches a running application rather than an AI agent. It follows the app's log files and HTTP access logs around the clock and alerts on activity that looks like an attack or a compromise. `beam cve check` checks the app's dependencies for known vulnerabilities.

Both need a connected workspace, and both stay off until a workspace owner or admin turns on App monitoring in the dashboard. Until then, `beam monitor` waits and captures nothing.

```bash
export BEAM_APP_TOKEN=beam_app_...            # the app's token, from the dashboard (App monitoring > Apps)
beam monitor --file /var/log/nginx/access.log --file /var/log/app/app.log
beam monitor --file /var/log/app/app.log --app /srv/app   # also check dependencies at start and daily
node server.js 2>&1 | beam monitor --stdin    # or read piped output
beam monitor test                             # send one test finding to prove the setup
beam monitor status                           # app, on or off, level, and this month's usage
beam cve check .                              # one-off check; exits 2 when anything is found
beam cve check . --fail-on high --json        # in CI: fail only on high and critical
```

**Apps and tokens.** Add each app (bgremover, explainx, ...) on the dashboard's App monitoring page to get its own token, shown once. With `BEAM_APP_TOKEN` set, `beam monitor` and `beam cve check` report as that app, and its findings, filters and webhook routing stay separate from your other apps. A laptop connected with `beam connect` works without a token. Tokens are least-privilege:

- They work only for App monitoring. Every other AgentBeam API rejects them.
- Only a hash is stored, and the CLI refuses to send one over plain HTTP.
- Beam redacts its own tokens from logs and evidence.
- Each app has a per-minute request limit.
- Rotating or removing a token takes effect immediately.

Run it under whatever keeps your app running: a systemd unit, a sidecar container that shares the log volume, or pm2.

**Inside a Node.js or Next.js app (SDK).** Where the app doesn't write request logs (for example `next start` behind a platform proxy), monitor in-process instead. Detection runs in your app with the same rules, and only redacted findings leave it, sent in the background with `BEAM_APP_TOKEN`.

- It has no dependencies and works in Next.js middleware, including the Edge runtime.
- It never throws, never blocks a request, and never makes one wait on the network.

```ts
// middleware.ts (Next.js); npm i @agent-beam/beam
import { NextResponse, type NextFetchEvent, type NextRequest } from "next/server";
import { createAppMonitor } from "@agent-beam/beam/monitor";

const beam = createAppMonitor(); // reads BEAM_APP_TOKEN

export function middleware(request: NextRequest, event: NextFetchEvent) {
  beam.request({
    method: request.method,
    url: request.nextUrl.pathname + request.nextUrl.search,
    ip: request.headers.get("x-forwarded-for")?.split(",")[0]?.trim(),
    userAgent: request.headers.get("user-agent"),
  });
  event.waitUntil(beam.flush());
  return NextResponse.next();
}
```

For Express, use `app.use((req, _res, next) => { beam.request({ method: req.method, url: req.originalUrl, ip: req.ip, userAgent: req.get("user-agent") }); next(); })`. `beam.log(line)` checks application log lines too.

When you can't change the app or its container, the [Beam monitor service for Railway](deploy/railway-monitor/README.md) streams its logs from Railway instead. It needs a Railway project token, which is broader than an app token.

**Let your coding agent do it:** `npx @agent-beam/beam add skill agentbeam-app-monitoring -g --all-agents`, then ask it to add AgentBeam monitoring to your app. It finds where the app runs, keeps the token out of the repository, and finishes with `beam monitor test`.

**What leaves the machine.** Log lines are matched on the server where `beam monitor` runs, and raw lines are never sent. A finding carries the rule, severity, file, a repeat count and a redacted excerpt of up to 600 characters. Redaction removes credentials, bearer tokens, URL userinfo, email addresses and your policy's custom detector matches. Query strings are kept, because in an access log the query is usually the attack. `beam cve check` sends package names and versions only.

**What it never does.** It doesn't block requests, change the app or sit in the request path. With `--file` it reads logs the way `tail -F` does and follows rotation and truncation. With `--stdin` it echoes every line to stdout, so the app's output still reaches its usual destination; use `--no-echo` to turn that off. Prefer `--file` in production so the app doesn't depend on Beam's pipe.

**Noise control.** Repeats fold into one finding per time window. Traffic is grouped by client address, so a scan from one IP becomes one alert with a count. Above 200 new findings in 10 minutes, the rest are summarized in a single finding.

| Level (set in the dashboard) | Alerts on | Repeats fold for | Optional LLM check |
|---|---|---|---|
| Light | Critical | 60 minutes | Never |
| Standard | High and critical | 15 minutes | High-severity findings |
| Strict | Medium and above | 5 minutes | Every alert |

What it looks for:

- **Injection attempts in requests:** SQL, command, server-side template, JNDI lookups (Log4Shell-style), path traversal, serialized objects, prototype pollution and cross-site scripting. URL and double URL encoding are decoded first.
- **Signs of compromise in app logs:** reverse shells, downloaded code piped into a shell, encoded execution and cloud metadata access.
- **Prompt injection** in logged prompts.
- **Credentials written to logs:** private keys, provider API keys and bearer tokens.
- **Reconnaissance:** attack-tool user agents, probes for `.env`, `.git` and credential files, and repeated failed sign-ins from one address.
- **Known vulnerable dependencies,** with `--app` or `beam cve check`. Advisories listed in CISA's Known Exploited Vulnerabilities catalog are raised to critical.

Detection is heuristic. It will miss attacks it has no rule for, and some legitimate traffic will match. Use it alongside a web application firewall and regular patching, not instead of them.

**Alerts.** Findings appear on the dashboard's App monitoring and Risks pages and go to the webhooks a workspace admin adds there. Each webhook can be limited to critical, high and critical, or everything. Slack and Discord URLs get their native message format; any other URL gets JSON with a `findings` array. Every request is signed. To verify one:

```js
import { createHmac, timingSafeEqual } from "node:crypto";

const expected = `sha256=${createHmac("sha256", webhookSecret).update(`${req.headers["x-beam-timestamp"]}.${rawBody}`).digest("hex")}`;
const signature = String(req.headers["x-beam-signature"] ?? "");
const valid = signature.length === expected.length && timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
```

**LLM second opinion (optional).** A model can review flagged lines before they alert. It sees only the redacted excerpt, and lines go in chunks of up to 10 per request, to a small model by default, to keep cost down. A "benign" verdict keeps the finding in the dashboard but out of the webhooks. If the model refuses or fails, the alert still goes out. Which findings are reviewed depends on the level (see the table above), and dependency findings are never sent.

You choose whose model runs:

- **Your own LLM, from the CLI.** Set these where `beam monitor` runs, in the environment or in `~/.beam/.env`. Any OpenAI-compatible chat completions endpoint works, including a local one, so excerpts never have to leave your network. The check runs on your machine before the finding is sent, and it doesn't count toward the workspace's LLM allowance.

  ```bash
  # OpenAI: the model defaults to gpt-4.1-nano
  BEAM_LLM_API_KEY=sk-... beam monitor --file /var/log/nginx/access.log

  # A local Ollama or vLLM server: no key needed
  BEAM_LLM_BASE_URL=http://localhost:11434/v1 BEAM_LLM_MODEL=llama3.2 beam monitor --file /var/log/app/app.log

  # Any other compatible gateway (OpenRouter, LiteLLM, ...)
  BEAM_LLM_BASE_URL=https://openrouter.ai/api/v1 BEAM_LLM_MODEL=openai/gpt-4.1-nano BEAM_LLM_API_KEY=... beam monitor --stdin
  ```

- **Beam's model, from the dashboard.** If no `BEAM_LLM_*` variables are set, a workspace admin can turn on LLM checks on the App monitoring page. Beam reviews the findings after they arrive, and those reviews count toward the workspace's monthly LLM allowance.

`beam monitor status` shows which model is in use.

**Dependency checks** read `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `requirements*.txt` (pinned `==` lines), `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, NuGet `packages.lock.json`, `gradle.lockfile`, `mix.lock`, `Package.resolved` and GitHub Actions workflow files. The search goes four directory levels deep and skips `node_modules`, `vendor` and virtual environments. Manifests without pinned versions, such as `package.json` ranges or `pom.xml`, are not checked.

**Usage.** Findings, dependency checks and LLM checks count toward the workspace's monthly App monitoring allowance, shown in `beam monitor status` and in the dashboard. When the allowance runs out, capture pauses until the reset date. The app itself is never affected.

## Dashboard

After enrollment, the AgentBeam dashboard shows agent activity, policy decisions, MCP inventory, users, installations, model usage, token counts, violations, blocked actions, and sensitive-data findings. Administrators can block MCP usage for an entire organization or an individual user.

## Privacy and local operation

AgentBeam's hook and policy decision run locally, so actions can be blocked even when the collector or dashboard is unavailable. Optional Jev judgments use the remote TypeSafe API, and optional `beam judge` checks use the model or service you configure; local policy remains independent. Telemetry is redacted before storage or forwarding. The local service binds to loopback, and AgentBeam files are protected from modification or removal by agent hooks.

## Development

```bash
npm test
npm run typecheck
npm run build
```

### Releasing

Bump `version` in `package.json` and push to `main`. The [Release workflow](.github/workflows/release.yml) then:

1. Runs the type check and tests.
2. Builds the standalone binaries.
3. Creates the `vX.Y.Z` tag and a GitHub Release with generated notes.
4. Publishes to npm, once npm trusted publishing is configured. Until then, run `npm publish` yourself.

A version that's already tagged is skipped. agentbeam.com's changelog and install scripts read these GitHub Releases, so the site follows within the hour.

To turn on automatic npm publishing:

1. On npmjs.com, open the package settings and add a trusted publisher: GitHub Actions, repository `whyashthakker/beam-cli`, workflow `release.yml`.
2. Set the repository variable `NPM_TRUSTED_PUBLISHING` to `true`.

## License

AGPL-3.0-only — see [LICENSE](./LICENSE).
