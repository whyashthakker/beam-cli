#!/bin/sh
# Pipes a Railway service's logs into `beam monitor`. Required variables (store them as sealed
# Railway variables):
#   BEAM_APP_TOKEN   the app's token from the AgentBeam dashboard (App monitoring > Apps)
#   RAILWAY_TOKEN    a project token for the monitored project, scoped to its environment
#   MONITOR_SERVICE  the Railway service to watch, e.g. BGR_PROD
# Optional: MONITOR_ENVIRONMENT (default production), BEAM_LLM_* for your own LLM review.
set -eu

: "${BEAM_APP_TOKEN:?Set BEAM_APP_TOKEN to the app token from the AgentBeam dashboard}"
: "${RAILWAY_TOKEN:?Set RAILWAY_TOKEN to a project token for the monitored project}"
: "${MONITOR_SERVICE:?Set MONITOR_SERVICE to the Railway service to watch}"
environment="${MONITOR_ENVIRONMENT:-production}"

# Each stream is restarted every 15 minutes and whenever it ends, so it follows new deployments of
# the service. A restart can repeat a few lines; beam monitor folds repeats into the same finding.
stream() {
  while :; do
    timeout 900 railway logs --service "$MONITOR_SERVICE" --environment "$environment" --json "$@" 2>/dev/null || true
    sleep 2
  done
}

echo "beam-railway-monitor: watching $MONITOR_SERVICE ($environment) HTTP and app logs" >&2
{ stream --http & stream & wait; } | exec node /app/dist/cli.js monitor --stdin --no-echo
