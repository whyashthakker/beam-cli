import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

function isPermissionError(err: unknown): boolean {
  const e = err as { code?: string; stderr?: string; message?: string };
  if (e?.code === "EACCES" || e?.code === "EPERM") return true;
  const text = `${e?.stderr ?? ""} ${e?.message ?? ""}`.toLowerCase();
  return text.includes("eacces") || text.includes("permission denied");
}

function sudoSpawn(cmd: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    console.error(`\nThis step needs administrator privileges. Running: sudo ${cmd} ${args.join(" ")}`);
    // stdio: "inherit" so sudo's own password prompt reaches the user's terminal directly.
    const child = spawn("sudo", [cmd, ...args], { stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`sudo ${cmd} exited with code ${code}`));
    });
  });
}

// Runs a command normally; if it fails with a permission error, retries once under sudo with
// inherited stdio so the user can type their password at the terminal. Never elevates anything
// that writes to the invoking user's own home directory (e.g. service install) -- only use this
// for genuinely system-level operations, since running those under sudo would write as root
// instead of the real user.
export async function runWithSudoFallback(cmd: string, args: string[], options: { timeout?: number } = {}): Promise<void> {
  try {
    await run(cmd, args, options);
  } catch (err) {
    if (!isPermissionError(err)) throw err;
    await sudoSpawn(cmd, args);
  }
}
