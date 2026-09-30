import { closeSync, createReadStream, createWriteStream, openSync } from "node:fs";
import { createInterface } from "node:readline";

export interface TtyChoice { key: string; label: string }

const PROMPT_TIMEOUT_MS = 120_000;

// Reads a choice directly from the controlling terminal (/dev/tty), bypassing stdin/stdout --
// those carry the hook's JSON protocol with the host agent (Claude Code, Codex, ...) and must
// never be touched here. Returns null -- "could not prompt" -- when there's no TTY attached
// (a headless run, CI, a detached process) or the prompt times out; callers must have a safe
// fallback for that case, never assume a choice was made.
export async function promptTty(message: string, choices: TtyChoice[]): Promise<string | null> {
  if (process.platform === "win32") return null;
  try { closeSync(openSync("/dev/tty", "r+")); } catch { return null; }

  return new Promise(resolvePromise => {
    let settled = false;
    let input: ReturnType<typeof createReadStream>;
    let output: ReturnType<typeof createWriteStream>;
    try {
      input = createReadStream("/dev/tty");
      output = createWriteStream("/dev/tty");
    } catch {
      resolvePromise(null);
      return;
    }
    const rl = createInterface({ input, output, terminal: true });
    const finish = (value: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rl.close();
      input.destroy();
      // Flush the prompt before closing the terminal stream. Destroying it immediately can
      // interrupt an in-flight write and emit ERR_STREAM_DESTROYED after the choice is read.
      output.end();
      resolvePromise(value);
    };
    const timer = setTimeout(() => finish(null), PROMPT_TIMEOUT_MS);
    output.write(`\n${message}\n`);
    for (const c of choices) output.write(`  [${c.key}] ${c.label}\n`);
    rl.question("Choice: ", answer => {
      const normalized = answer.trim().toLowerCase();
      const match = choices.find(c => c.key.toLowerCase() === normalized)
        ?? (normalized.length > 0 ? choices.find(c => c.label.toLowerCase().startsWith(normalized)) : undefined);
      finish(match ? match.key : null);
    });
    rl.on("error", () => finish(null));
    input.on("error", () => finish(null));
  });
}
