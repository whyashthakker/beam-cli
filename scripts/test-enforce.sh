#!/usr/bin/env bash
# End-to-end check of `beam hook` policy enforcement. Fully isolated — writes only
# to a temp BEAM_DATA_DIR, needs no collector and no network.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/dist/cli.js"
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

export BEAM_DATA_DIR="$DIR"
export BEAM_TOKEN="x"
export BEAM_COLLECTOR_URL="http://127.0.0.1:59999"   # deliberately dead: enforcement must not depend on it

[ -f "$CLI" ] || { echo "build first: npm run build"; exit 1; }

pass=0 fail=0
policy() { printf '%s\n' "$1" > "$DIR/policy.json"; }

# run <name> <agent> <payload-json> <expect: DENY|ALLOW|WARN>
run() {
  local name="$1" agent="$2" payload="$3" expect="$4"
  local out err
  out="$(printf '%s' "$payload" | node "$CLI" hook "$agent" 2>"$DIR/err")"
  err="$(cat "$DIR/err")"

  local got="ALLOW"
  echo "$out" | grep -q '"permissionDecision":"deny"' && got="DENY"
  [ "$got" = "ALLOW" ] && echo "$err" | grep -q "advisory" && got="WARN"

  if [ "$got" = "$expect" ]; then
    printf "  ✔ %-38s %s\n" "$name" "$got"; pass=$((pass+1))
  else
    printf "  x %-38s expected %s got %s\n" "$name" "$expect" "$got"; fail=$((fail+1))
    [ -n "$out$err" ] && printf "      out: %s\n      err: %s\n" "$out" "$err"
  fi
}

BASH='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}'
READ='{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"a.txt"}}'
PROD='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"kubectl apply -n prod"}}'

echo "== no policy file =="
rm -f "$DIR/policy.json"
run "no policy -> allow bash"        claude-code "$BASH" ALLOW

echo "== observe mode =="
policy '{"version":1,"notAfter":null,"rules":{"mode":"observe","blockedTools":["Bash"],"blockedCommandPatterns":[],"disabledAgents":[]}}'
run "observe never blocks"           claude-code "$BASH" ALLOW

echo "== enforce mode =="
policy '{"version":2,"notAfter":null,"rules":{"mode":"enforce","blockedTools":["Bash"],"blockedCommandPatterns":["\\bprod\\b"],"disabledAgents":["codex"]}}'
run "blocked tool Bash"              claude-code "$BASH" DENY
run "allowed tool Read"              claude-code "$READ" ALLOW
run "command pattern \\bprod\\b"      claude-code "$PROD" DENY
run "disabled agent codex"           codex       "$READ" DENY
run "other agent -> allow"           claude-code "$READ" ALLOW

echo "== advisory mode =="
policy '{"version":3,"notAfter":null,"rules":{"mode":"advisory","blockedTools":["Bash"],"blockedCommandPatterns":[],"disabledAgents":[]}}'
run "advisory warns, does not block" claude-code "$BASH" WARN

echo "== expired bundle (fail-open) =="
policy '{"version":4,"notAfter":"2000-01-01T00:00:00.000Z","rules":{"mode":"enforce","blockedTools":["Bash"],"blockedCommandPatterns":[],"disabledAgents":[]}}'
run "expired policy -> allow"        claude-code "$BASH" ALLOW

echo
echo "  $pass passed, $fail failed"
exit $((fail > 0))
