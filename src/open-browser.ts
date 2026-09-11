import { spawn } from "node:child_process";

export function openBrowser(url: string): void {
  const platform = process.platform;
  const command = platform === "darwin" ? "open" : platform === "win32" ? "start" : "xdg-open";
  const args = platform === "win32" ? ["", url] : [url];
  const child = spawn(command, args, { detached: true, stdio: "ignore", shell: platform === "win32" });
  // No display, no 'open'/'xdg-open' on PATH, sandboxed exec, etc. -- the URL is already printed
  // and usable manually, so a failed auto-open should never crash the command. Without this
  // listener an unhandled 'error' event here throws and kills the whole process.
  child.on("error", () => {});
  child.unref();
}
