# Beam monitor for a Railway service

Watches one Railway service around the clock without changing it. This small service streams the target's HTTP request logs and app logs from Railway into `beam monitor`. Detection runs here, and only redacted findings go to your AgentBeam workspace and its webhooks. The monitored app's code, image, start command and deploys are untouched. If this service stops, the app doesn't notice.

## Set up

1. **Create the app in AgentBeam.** On the dashboard, open App monitoring, turn it on, then add an app (for example `bgremover`). Copy its token; it's shown once.
2. **Create a Railway project token.** In the project that runs the app, go to Settings → Tokens and create a token for the environment you want to watch.
3. **Add a service to that project.** Set its source to this repository, and set the Dockerfile path variable `RAILWAY_DOCKERFILE_PATH=deploy/railway-monitor/Dockerfile`.
4. **Set the variables below,** and seal the two tokens:

| Variable | Value |
| --- | --- |
| `BEAM_APP_TOKEN` | The app token from step 1 (sealed) |
| `RAILWAY_TOKEN` | The project token from step 2 (sealed) |
| `MONITOR_SERVICE` | The service to watch, for example `BGR_PROD` |
| `MONITOR_ENVIRONMENT` | Optional; defaults to `production` |
| `BEAM_LLM_BASE_URL`, `BEAM_LLM_MODEL`, `BEAM_LLM_API_KEY` | Optional: review flagged lines with your own LLM |

5. **Deploy, then prove it works.** Open a shell on the service and run `node /app/dist/cli.js monitor test`. The test finding should show up on the App monitoring page within seconds, and at the webhooks for that app.

The service needs no public domain, volume or inbound port. It uses a few tens of MB of memory.

## Security

- **Least privilege.** The app token works only for App monitoring: sending findings and running dependency checks for that one app. Every other AgentBeam API rejects it. The Railway project token can read the logs of the one project and environment it was created for.
- **Rotation.** Rotate the app token from the dashboard (Apps → Rotate token), then update the variable here. Revoking takes effect immediately.
- **No root.** The container runs as an unprivileged user and never writes the tokens to disk.
