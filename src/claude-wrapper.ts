// `beam claude`: run Claude Code inside a pseudo-terminal Beam controls, so sensitive values you type
// or paste are replaced with vault placeholders before Claude Code receives them (see input-guard.ts).
//
// Node has no built-in PTY. Rather than ship a native module (which would break the single-binary
// `pkg` builds), a tiny embedded Python helper (stdlib `pty` only) owns the pseudo-terminal:
//   Node stdin (raw) -> InputGuard -> helper stdin -> pty master -> claude
//   claude -> pty master -> helper stdout -> Node stdout
//   Node -> helper fd 3: "rows cols\n" resize messages.
// If python3 or a TTY is missing, Beam says so and runs Claude Code directly (hooks still protect it).
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { InputGuard, type Inspect } from "./input-guard.js";
import { promptFindings, redactAndVault, vaultScope } from "./pii-vault.js";
import { networkMode } from "./network-detectors.js";
import { summarizeFindings } from "./hook-notice.js";
import { readPolicy } from "./policy.js";
import { addWrapperNotice } from "./wrapper-notice.js";

export const PTY_HELPER = `
import os, pty, sys, select, fcntl, termios, struct
rows, cols = int(sys.argv[1]), int(sys.argv[2]); cmd = sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    try: os.execvp(cmd[0], cmd)
    except OSError as e:
        sys.stderr.write("beam: cannot run %s: %s\\n" % (cmd[0], e)); os._exit(127)
def setsize(r, c):
    try: fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", r, c, 0, 0))
    except OSError: pass
setsize(rows, cols)
def write_all(target, data):
    while data:
        n = os.write(target, data); data = data[n:]
watch = {0, 3, fd}; pending = b""
while fd in watch:
    ready, _, _ = select.select(list(watch), [], [])
    if fd in ready:
        try: data = os.read(fd, 65536)
        except OSError: data = b""
        if not data: break
        write_all(1, data)
    if 0 in ready:
        data = os.read(0, 65536)
        if not data: watch.discard(0)
        else: write_all(fd, data)
    if 3 in ready:
        data = os.read(3, 4096)
        if not data: watch.discard(3)
        else:
            pending += data
            while b"\\n" in pending:
                line, pending = pending.split(b"\\n", 1)
                try: r, c = line.split(); setsize(int(r), int(c))
                except ValueError: pass
try: _, status = os.waitpid(pid, 0)
except ChildProcessError: status = 0
sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))
`;

const NON_INTERACTIVE = /^(?:-p|--print|-v|--version|-h|--help|mcp|doctor|update|install|config|migrate-installer|setup-token)$/;

function runDirect(args: string[]): number {
  const result = spawnSync("claude", args, { stdio: "inherit" });
  if (result.error) { process.stderr.write(`beam: cannot run claude: ${result.error.message}\n`); return 127; }
  return result.status ?? 1;
}

export async function runClaudeWrapper(args: string[]): Promise<number> {
  if (!process.stdin.isTTY || !process.stdout.isTTY || args.some(a => NON_INTERACTIVE.test(a))) return runDirect(args);

  const python = spawnSync("python3", ["-c", "import pty, termios, fcntl"], { stdio: "ignore" });
  if (python.status !== 0) {
    process.stderr.write("beam claude: python3 with the pty module is required for prompt rewriting; running Claude Code without the wrapper (hooks still block sensitive prompts).\n");
    return runDirect(args);
  }

  const policy = await readPolicy().catch(() => null);
  const mode = policy?.rules.piiPrompt ?? (process.env.BEAM_PII_PROMPT === "warn" || process.env.BEAM_PII_PROMPT === "off" ? process.env.BEAM_PII_PROMPT : "block");
  if (mode !== "block") return runDirect(args);

  const netMode = networkMode(policy?.rules.networkTopology, process.env.BEAM_NETWORK_TOPOLOGY);
  const wrapperId = randomBytes(6).toString("hex");
  const scope = vaultScope("", { BEAM_WRAPPER_ID: wrapperId });
  const custom = policy?.rules.customDetectors;
  const inspect: Inspect = async (text) => {
    const found = promptFindings(text, custom, netMode === "redact" || netMode === "block");
    if (!found.blocking.length) return null;
    const redacted = await redactAndVault(text, scope, custom);
    const summary = summarizeFindings(found.blocking);
    await addWrapperNotice(wrapperId, `Beam's terminal wrapper replaced ${summary} in your prompt with vault placeholders before it reached Claude. Real values are only substituted when a shell command runs.`).catch(() => {});
    return { replacement: redacted.text, summary };
  };
  const guard = new InputGuard(inspect);

  const size = () => `${process.stdout.rows ?? 24} ${process.stdout.columns ?? 80}`;
  const [rows, cols] = size().split(" ");
  const child = spawn("python3", ["-c", PTY_HELPER, rows!, cols!, "claude", ...args], {
    stdio: ["pipe", "pipe", "inherit", "pipe"],
    env: { ...process.env, BEAM_WRAPPER_ID: wrapperId },
  });
  child.on("error", (error) => process.stderr.write(`beam claude: ${error.message}\n`));

  process.stdin.setRawMode(true);
  process.stdin.resume();

  // Input must stay ordered while the guard awaits vault writes: chain every chunk.
  let queue: Promise<void> = Promise.resolve();
  const forward = (data: string) => { if (data) child.stdin!.write(data); };
  process.stdin.on("data", (chunk: Buffer) => { queue = queue.then(async () => forward(await guard.feed(chunk))).catch(() => forward(chunk.toString("utf8"))); });
  // A lone Escape keypress (Claude Code uses it to interrupt) must not stay held waiting for more bytes.
  const timer = setInterval(() => {
    queue = queue.then(async () => { if (guard.hasPendingEscape) forward(guard.flushPendingEscape()); forward(await guard.flushStalePaste()); });
  }, 40);

  child.stdout!.on("data", (data: Buffer) => process.stdout.write(data));
  const onResize = () => { try { (child.stdio[3] as NodeJS.WritableStream).write(`${size()}\n`); } catch { /* helper already exiting */ } };
  process.stdout.on("resize", onResize);
  for (const signal of ["SIGTERM", "SIGHUP"] as const) process.on(signal, () => child.kill(signal));

  return new Promise<number>((resolve) => {
    child.on("close", (code) => {
      clearInterval(timer);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.off("resize", onResize);
      resolve(code ?? 1);
    });
  });
}
