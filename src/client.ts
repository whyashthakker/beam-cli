import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { getCollectorUrl, getDataDirectory } from "./config.js";
import { scanText, type Scan } from "./core.js";
import { adaptHookPayload } from "./hook-adapters.js";

export async function readToken(): Promise<string> {
  if (process.env.BEAM_TOKEN) return process.env.BEAM_TOKEN;
  const tokenPath = join(getDataDirectory(), "token");
  try { return (await readFile(tokenPath, "utf8")).trim(); }
  catch { throw new Error(`No token file at ${tokenPath}. Run 'beam start' first.`); }
}

async function send(route: string, body: string): Promise<unknown> {
  const url = getCollectorUrl();
  const response = await fetch(`${url.origin}${route}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${await readToken()}`, "Content-Type": "application/json" },
    body,
    signal: AbortSignal.timeout(5000)
  });
  if (!response.ok) throw new Error(`Collector rejected request: ${await response.text()}`);
  return response.json();
}

async function boundedFile(filePath: string): Promise<string> {
  const stats = await stat(filePath);
  if (stats.size > 2_000_000) throw new Error("File exceeds 2 MB. Split it into batches.");
  return readFile(filePath, "utf8");
}

export async function importEvents(filePath: string): Promise<unknown> {
  return send("/ingest", await boundedFile(filePath));
}

export interface ScanOptions { mcp?: boolean; save?: boolean }

export async function scanFile(filePath: string, options: ScanOptions = {}): Promise<Scan | unknown> {
  const content = await boundedFile(filePath);
  const kind = options.mcp ? "mcp" : "skill";
  if (options.save) return send("/scan", JSON.stringify({ name: filePath, content, kind }));
  return scanText(filePath, content, kind);
}

async function readStdin(limitBytes: number): Promise<string> {
  let input = "";
  for await (const chunk of process.stdin) {
    input += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    if (input.length > limitBytes) throw new Error(`Hook exceeds ${Math.floor(limitBytes / 1000)} KB.`);
  }
  return input;
}

// Never throws: a Claude Code hook must not block or fail the agent if capture fails.
export async function captureHook(sourceAgent = "claude-code"): Promise<void> {
  try {
    const input = await readStdin(100_000);
    const raw = JSON.parse(input) as Record<string, unknown>;
    const data = adaptHookPayload(sourceAgent, raw);
    data.source_agent = sourceAgent;
    data.source_type = "hook";
    if (data.hook_event_name === "UserPromptSubmit" && typeof data.prompt === "string") {
      data.event_type = data.event_type ?? "prompt.submit";
      data.tool_name = data.tool_name ?? "UserPromptSubmit";
      data.command = data.command ?? data.prompt;
    }
    await send("/ingest", JSON.stringify(data));
    // No hook response means no approval/denial; observation must never become enforcement.
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
  }
}
