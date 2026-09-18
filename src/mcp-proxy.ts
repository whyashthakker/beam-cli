import { spawn } from "node:child_process";
import { redactSensitive } from "./data-detectors.js";
import { readPolicy } from "./policy.js";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function transform(value: Json, custom: { name: string; pattern: string; replacement: string }[], state: { changed: boolean }): Json {
  if (typeof value === "string") {
    const result = redactSensitive(value, custom);
    if (result.findings.length) state.changed = true;
    return result.text;
  }
  if (Array.isArray(value)) return value.map(item => transform(item, custom, state));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, transform(item, custom, state)]));
  return value;
}

function encode(message: Json): Buffer {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  return Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`), body]);
}

/** Run a local stdio MCP server while filtering responses before the agent sees them. */
export async function runMcpProxy(command: string, args: string[]): Promise<number> {
  const policy = await readPolicy();
  const custom = policy?.rules.customDetectors ?? [];
  const child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });
  let input = Buffer.alloc(0);
  let failed = false;

  const writeResponse = (message: Json) => {
    const state = { changed: false };
    const filtered = transform(message, custom, state) as Record<string, Json>;
    if (state.changed && policy?.rules.mode === "enforce") {
      // The sensitive values have already been removed from the replacement response.
      filtered.result = { isError: true, content: [{ type: "text", text: "Beam blocked sensitive MCP response content by local policy." }] };
      delete filtered.error;
    }
    process.stdout.write(encode(filtered));
  };

  child.stdout.on("data", (chunk: Buffer) => {
    input = Buffer.concat([input, chunk]);
    while (true) {
      const headerEnd = input.indexOf(Buffer.from("\r\n\r\n"));
      if (headerEnd < 0) break;
      const header = input.subarray(0, headerEnd).toString("ascii");
      const match = header.match(/(?:^|\r\n)Content-Length:\s*(\d+)\s*(?:\r\n|$)/i);
      if (!match) { failed = true; process.stderr.write("Beam MCP proxy: invalid MCP response headers.\n"); child.kill(); return; }
      const length = Number(match[1]); const start = headerEnd + 4;
      if (input.length < start + length) break;
      const body = input.subarray(start, start + length); input = input.subarray(start + length);
      try { writeResponse(JSON.parse(body.toString("utf8")) as Json); }
      catch { failed = true; process.stderr.write("Beam MCP proxy: invalid JSON response from MCP server.\n"); child.kill(); return; }
    }
  });
  process.stdin.on("data", chunk => child.stdin.write(chunk));
  process.stdin.on("end", () => child.stdin.end());
  process.stdin.on("error", () => child.stdin.destroy());
  child.on("error", error => { failed = true; process.stderr.write(`Beam MCP proxy: ${error.message}\n`); });
  return await new Promise(resolve => child.on("close", code => resolve(failed ? 1 : (code ?? 0))));
}
