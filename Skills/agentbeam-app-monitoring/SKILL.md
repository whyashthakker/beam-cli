---
name: agentbeam-app-monitoring
description: Add AgentBeam app monitoring to an application - check its dependencies for known vulnerabilities with beam cve check, and watch its logs and traffic for attacks around the clock with beam monitor - without changing how the app runs. Use when the user asks to monitor an app, server or service with AgentBeam, add beam monitor, or check dependencies with beam cve check.
license: AGPL-3.0-only
metadata:
  author: Beam
  version: "1.0.0"
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

### 4a. Railway

Use the Beam monitor service from https://github.com/whyashthakker/beam-cli/tree/main/deploy/railway-monitor. It's a separate service in the same Railway project, which streams the app's HTTP and app logs into `beam monitor`. Walk the user through its README:

1. The user creates a Railway project token (project Settings, then Tokens).
2. Add a service whose source is that repository, with `RAILWAY_DOCKERFILE_PATH=deploy/railway-monitor/Dockerfile`.
3. The user sets sealed variables `BEAM_APP_TOKEN` and `RAILWAY_TOKEN`, plus `MONITOR_SERVICE` (the app's service name).

### 4b. Docker Compose or Kubernetes

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

### 4c. A server with systemd

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

- **Review flagged lines with the user's own LLM:** set the `BEAM_LLM_*` variables (endpoint, model and, if the endpoint needs one, its key) where `beam monitor` runs.
- **Separate alert channels:** add webhooks on the dashboard and limit each one to particular apps.
- **Full guide:** https://docs.agentbeam.com/agent-cli/app-monitoring
