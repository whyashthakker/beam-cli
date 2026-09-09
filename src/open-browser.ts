import { spawn } from "node:child_process";

export function openBrowser(url: string): void {
  const platform = process.platform;
  const command = platform === "darwin" ? "open" : platform === "win32" ? "start" : "xdg-open";
  const args = platform === "win32" ? ["", url] : [url];
  spawn(command, args, { detached: true, stdio: "ignore", shell: platform === "win32" }).unref();
}
