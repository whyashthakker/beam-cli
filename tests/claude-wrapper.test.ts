import { spawn, spawnSync } from "node:child_process";
import { describe, expect, it } from "@jest/globals";
import { PTY_HELPER } from "../src/claude-wrapper.js";

const hasPython = spawnSync("python3", ["-c", "import pty, termios, fcntl"], { stdio: "ignore" }).status === 0;
const maybe = hasPython ? it : it.skip;

function runHelper(cmd: string[], input: string, rows = 24, cols = 80): Promise<{ out: string; code: number | null }> {
  return new Promise((resolve) => {
    const child = spawn("python3", ["-c", PTY_HELPER, String(rows), String(cols), ...cmd], { stdio: ["pipe", "pipe", "inherit", "pipe"] });
    let out = "";
    child.stdout!.on("data", d => { out += d.toString("utf8"); });
    child.stdin!.write(input);
    child.on("close", code => resolve({ out, code }));
  });
}

describe("PTY helper", () => {
  maybe("gives the child a real terminal, forwards input to it, and returns its output and exit code", async () => {
    const { out, code } = await runHelper(["sh", "-c", "[ -t 0 ] && echo tty:yes; read line; echo got:$line; exit 7"], "hello\n");
    expect(out).toContain("tty:yes");
    expect(out).toContain("got:hello");
    expect(code).toBe(7);
  });

  maybe("starts the child at the requested window size", async () => {
    const { out } = await runHelper(["sh", "-c", "stty size"], "", 30, 100);
    expect(out).toContain("30 100");
  });

  maybe("reports a missing command instead of hanging", async () => {
    const { code } = await runHelper(["definitely-not-a-real-command-xyz"], "");
    expect(code).toBe(127);
  });
});
