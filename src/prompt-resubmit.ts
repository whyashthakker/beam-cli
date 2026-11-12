// Auto-resubmit for a blocked prompt. Claude Code hooks cannot rewrite a typed prompt (the docs
// say UserPromptSubmit "can't replace the prompt"), so after Beam blocks one and vaults its real
// values, the placeholder version is typed back into the same terminal pane and submitted. That
// needs a terminal Beam can address exactly: tmux (`$TMUX_PANE`). Terminal.app / VS Code / others
// have no safe way to target the right window, so they fall back to the clipboard.
//
// Only ever types the placeholder text, never a real value, and the caller refuses to resubmit
// text that still trips a blocking detector (no loop).
import { spawn as nodeSpawn } from "node:child_process";

type SpawnFn = typeof nodeSpawn;
const MAX_LENGTH = 4000;
// Claude Code needs a moment to return to its input box after a block before keys are accepted.
const DELAY_SECONDS = "0.8";

export function canResubmit(env: NodeJS.ProcessEnv = process.env): boolean {
  return !!env.TMUX && !!env.TMUX_PANE && env.BEAM_PII_RESUBMIT !== "0";
}

/** True when the text was handed to tmux. Multi-line or very long prompts are left to the clipboard. */
export function resubmitViaTmux(text: string, env: NodeJS.ProcessEnv = process.env, spawn: SpawnFn = nodeSpawn): boolean {
  if (!canResubmit(env) || /[\r\n]/.test(text) || text.length === 0 || text.length > MAX_LENGTH) return false;
  try {
    // Detached shell: sleep, type the text literally (-l, so nothing is interpreted as a key name),
    // then Enter. Arguments are passed as argv, never interpolated into the shell string.
    const child = spawn("sh", ["-c", 'sleep "$1"; tmux send-keys -t "$2" -l -- "$3" && tmux send-keys -t "$2" Enter', "beam-resubmit", DELAY_SECONDS, env.TMUX_PANE!, text], { detached: true, stdio: "ignore", env });
    child.unref();
    return true;
  } catch { return false; }
}
