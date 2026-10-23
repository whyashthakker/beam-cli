---
name: agentbeam-app-monitoring
description: Add AgentBeam app monitoring to an application - check its dependencies for known vulnerabilities with beam cve check, watch its logs and traffic for attacks around the clock with beam monitor, and check what goes into and comes out of its LLM features for prompt injection and data exfiltration - without changing how the app runs. Use when the user asks to monitor an app, server or service with AgentBeam, add beam monitor, protect an LLM or chatbot feature from prompt injection, or check dependencies with beam cve check.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.1.0"
  website: https://agentbeam.com
---

# Add AgentBeam app monitoring

You'll set up two things for the user's app:

- `beam cve check` checks its dependencies against AgentBeam's vulnerability database.
- `beam monitor` watches its logs and HTTP traffic and sends redacted findings to the user's AgentBeam workspace and webhooks. It only watches: it never blocks requests, changes the app, or sits in its request path.

## Rules while you do this

- Never change how the app starts, builds or deploys. Monitoring runs next to the app.
- The app token (`BEAM_APP_TOKEN`) is a credential. Don't print it, commit it, or write it into a Dockerfile, a compose file, CI config or any other file in the repository. It belongs in the platform's credential store (Railway variables, CI repository variables, a root-only systemd EnvironmentFile). Ask the user to paste it there themselves.
- Never send log contents anywhere yourself. `beam monitor` redacts on the machine and sends findings only.
- Ask before creating cloud resources (services, workflows, units) and before committing.

## 1. Check the prerequisites with the user

- App monitoring is turned on for their workspace at https://app.agentbeam.com/dashboard/monitoring (an owner or admin does this).
- The app has been added there under Apps (named after the app, for example `bgremover`), and its token is in the environment where you'll run commands. `beam monitor status` confirms the token works without printing it.

## 2. Install the CLI

```sh
npm i -g @agent-beam/beam
beam --version
```

It needs Node.js 20.17 or newer. `npx -y @agent-beam/beam <command>` works without a global install.

## 3. Check the dependencies

From the app's directory:

```sh
beam cve check .
```

Exit code 2 means known vulnerabilities were found. For each one, tell the user the package, the installed version, the fixed version and the advisory link. Propose upgrades, but don't apply them without asking. To keep checking on every push, offer a CI step that runs `npx -y @agent-beam/beam cve check . --fail-on high`. The user stores the token in the CI provider's encrypted repository variables (in GitHub, Settings > Secrets and variables > Actions, named `BEAM_APP_TOKEN`), and the step exposes it to the command as an environment variable. The step fails the build only on high or critical findings.

## 4. Find where the app runs and what it logs

Look at the repository: a Dockerfile, docker-compose file, Railway config, fly.toml, vercel.json, Procfile, systemd units, nginx or Apache config. Then pick the matching step below. Monitoring needs a stream of the app's logs; for serverless platforms without one (such as Vercel functions), stop after the dependency check and tell the user.

### 4a. A Node.js or Next.js app (preferred when you can change the code)

Add the in-app SDK. It needs only the app token, no extra service or platform credentials. `npm i @agent-beam/beam`, then call it once per request, keeping the app's existing middleware logic unchanged:

- Next.js `middleware.ts`: `const beam = createAppMonitor()` from `@agent-beam/beam/monitor` at module level. In `middleware(request, event)`, call `beam.request({ method: request.method, url: request.nextUrl.pathname + request.nextUrl.search, ip, userAgent })`, with `ip` from the first value of the `x-forwarded-for` header and `userAgent` from the `user-agent` header. Then call `event.waitUntil(beam.flush())`. Add the `event: NextFetchEvent` parameter if the function doesn't have it.
- Express: an `app.use` middleware that calls `beam.request({ method: req.method, url: req.originalUrl, ip: req.ip, userAgent: req.get("user-agent") })` and then `next()`.

The SDK never throws or blocks requests. The user sets `BEAM_APP_TOKEN` in the app's environment on their platform.

#### If the app calls an LLM

Find where the app sends text to a model (the OpenAI, Anthropic or AI SDK call, a LangChain chain, an agent loop) and where it uses the reply. Use the same `beam` instance:

- Before the model call: `const check = beam.prompt(userMessage, { user: userId })`. Also pass content the model will read that a stranger could have written, like retrieved documents, web pages, emails and tool results, with a `label` such as `"retrieved web page"`. Pass an opaque user id or the client address, never an email.
- On the reply, before it's shown, rendered as markdown or HTML, or handed to tools or another agent: `beam.output(replyText)`.
- Suggest a canary: a random marker such as `canary-` plus 8 random hex characters. The user adds it to the model's instructions and to the app's configuration, and the app passes it as `createAppMonitor({ canaries: [marker] })`. If it ever shows up in a reply, the instructions leaked.

Both calls return `{ flagged, severity, matches }` and only report; they don't stop anything. Ask the user before you make the app act on them, for example by refusing a prompt when `check.severity` is `"high"` or `"critical"`, or by not rendering a reply flagged with `llm.output_exfiltration`. If the prompts may hold personal data, offer `createAppMonitor({ excerpts: false })`: findings then carry the rule and sender but no text.

### 4b. Railway, when the app can't be changed

Use the Beam monitor service from https://github.com/whyashthakker/beam-cli/tree/main/deploy/railway-monitor. It's a separate service in the same Railway project, which streams the app's HTTP and app logs into `beam monitor`. It needs a Railway project token, which can also read the project's variables, so tell the user that before they create one. Walk the user through its README:

1. The user creates a Railway project token (project Settings, then Tokens).
2. Add a service whose source is that repository, with `RAILWAY_DOCKERFILE_PATH=deploy/railway-monitor/Dockerfile`.
3. The user sets sealed variables `BEAM_APP_TOKEN` and `RAILWAY_TOKEN`, plus `MONITOR_SERVICE` (the app's service name).

### 4c. Docker Compose or Kubernetes

Run `beam monitor` as a sidecar that reads the app's log files from a shared volume, read-only. In Compose, pass the token through from the host environment by name, never by value:

```yaml
  beam-monitor:
    image: node:24-slim
    command: ["npx", "-y", "@agent-beam/beam", "monitor", "--file", "/logs/access.log", "--file", "/logs/app.log"]
    environment:
      - BEAM_APP_TOKEN
    volumes:
      - app-logs:/logs:ro
    restart: unless-stopped
```

If the app only logs to stdout, run `docker logs -f <container> | beam monitor --stdin --no-echo` on the host instead.

### 4d. A server with systemd

Create a unit that runs next to the app. Put the token in a root-owned EnvironmentFile (for example `/etc/beam/app-monitor.conf`) with mode 600, and make sure the service user can read the log files (for example, membership in the `adm` group). Use the path that `command -v beam` prints in `ExecStart`:

```ini
[Unit]
Description=AgentBeam app monitoring
After=network-online.target

[Service]
EnvironmentFile=/etc/beam/app-monitor.conf
ExecStart=/usr/local/bin/beam monitor --file /var/log/nginx/access.log --file /var/log/myapp/app.log
Restart=always
User=beam-monitor

[Install]
WantedBy=multi-user.target
```

## 5. Prove it works

From the same environment, with the token set:

```sh
beam monitor test
beam monitor status
```

The test finding should appear within seconds on https://app.agentbeam.com/dashboard/monitoring, and at the webhooks set for that app. `beam monitor status` shows the app name, level and this month's usage.

## Optional extras

- **LLM features outside Node.js:** if the app logs its prompts or model replies, point `beam monitor --file` at that log. The same prompt injection rules read it.
- **Review flagged lines with the user's own LLM:** set the `BEAM_LLM_*` variables (endpoint, model and, if the endpoint needs one, its key) where `beam monitor` runs.
- **Separate alert channels:** add webhooks on the dashboard and limit each one to particular apps.
- **Full guide:** https://docs.agentbeam.com/agent-cli/app-monitoring
