import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createCollector } from "./server.js";
import { getDataDirectory } from "./config.js";
import { loadCustomRules } from "./custom-rules.js";
import { readIdentity } from "./enroll.js";
import { syncPolicy } from "./forward.js";
import { installAllDetectedHooks, type InstallAllResult } from "./install.js";
import { startOsMonitor } from "./os-monitor.js";

function toWebRequest(req: IncomingMessage): Promise<Request> {
  return new Promise((resolvePromise, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const hasBody = !["GET", "HEAD"].includes(req.method ?? "GET");
        const headers = new Headers();
        for (const [key, value] of Object.entries(req.headers)) {
          if (Array.isArray(value)) for (const v of value) headers.append(key, v);
          else if (value !== undefined) headers.set(key, value);
        }
        const url = `http://${req.headers.host ?? "127.0.0.1"}${req.url ?? "/"}`;
        resolvePromise(new Request(url, { method: req.method, headers, body: hasBody ? Buffer.concat(chunks) : undefined }));
      } catch (error) { reject(error); }
    });
    req.on("error", reject);
  });
}

async function writeWebResponse(response: Response, res: ServerResponse): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, key) => res.setHeader(key, value));
  const body = response.body ? Buffer.from(await response.arrayBuffer()) : Buffer.alloc(0);
  res.end(body);
}

export interface StartServerOptions {
  directory?: string;
  token?: string;
  port?: number;
  hostname?: string;
  origins?: string[];
  /** Root to load ~/.beam/rules.json from; defaults to the real BEAM_HOME. Tests override this. */
  rulesHome?: string;
  /** Home directory to scan/write agent hook configs into; defaults to the real home. Tests override this. */
  agentHome?: string;
  /** Whether to run OS-level process/network monitoring (see os-monitor.ts). Defaults to on; tests disable it. */
  osMonitor?: boolean;
}

export async function startServer(options: StartServerOptions = {}): Promise<{ url: string; token: string; directory: string; customRules: { path: string; loaded: number; errors: string[] }; policySync: boolean; agentInstalls: InstallAllResult[]; close: () => void }> {
  const directory = options.directory ?? getDataDirectory();
  await mkdir(directory, { recursive: true, mode: 0o700 });
  // Wire beam's hook into every detected-but-not-yet-wired agent on every start, so a newly
  // installed agent (or one that showed up after the last `beam start`) starts getting captured
  // without a separate manual `beam agent install-all` step. Never blocks or fails startup --
  // a single agent's config being unwritable shouldn't stop the collector from serving.
  const agentInstalls = await installAllDetectedHooks(options.agentHome ?? homedir()).catch(() => [] as InstallAllResult[]);
  // Loaded once per process into core.ts's shared rule set; a file edit needs a restart to apply.
  // Errors are returned, not logged here -- the caller (cli.ts) owns all console output, since
  // this same function also runs unattended inside the background service process.
  const customRules = await loadCustomRules(options.rulesHome);
  let token = options.token ?? process.env.BEAM_TOKEN;
  if (!token) {
    const tokenPath = join(directory, "token");
    try { token = (await readFile(tokenPath, "utf8")).trim(); await chmod(tokenPath, 0o600); }
    catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      token = randomBytes(32).toString("hex");
      await writeFile(tokenPath, token, { mode: 0o600, flag: "wx" });
    }
  }
  if (token.length < 32) throw new Error("BEAM_TOKEN must contain at least 32 characters.");

  const app = await createCollector({ directory, token, origins: options.origins ?? process.env.BEAM_ALLOWED_ORIGINS?.split(",").map(s => s.trim()), rulesHome: options.rulesHome });
  const port = options.port ?? Number(process.env.BEAM_PORT || 4319);
  const hostname = options.hostname ?? "127.0.0.1";

  const server = createServer((req, res) => {
    toWebRequest(req)
      .then(webRequest => app.fetch(webRequest))
      .then(webResponse => writeWebResponse(webResponse, res))
      .catch(error => {
        console.error("Beam server error:", error instanceof Error ? error.message : error);
        if (!res.headersSent) res.statusCode = 500;
        res.end();
      });
  });

  const boundPort = await new Promise<number>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(port, hostname, () => {
      const address = server.address();
      resolvePromise(typeof address === "object" && address ? address.port : port);
    });
  });

  // Keep the cached policy fresh so `beam hook` can enforce it without a network call.
  let policyTimer: NodeJS.Timeout | undefined;
  const identity = await readIdentity();
  if (identity) {
    const poll = () => { void syncPolicy().catch(() => {}); };
    poll();
    policyTimer = setInterval(poll, 60_000);
    policyTimer.unref?.();
  }

  // Observes AI agent activity directly (process start/exit, network connections) so agents that
  // don't cooperate with any hook -- or that run through a GUI/IDE surface with no hook path at
  // all -- still get captured. See os-monitor.ts. macOS only; a no-op elsewhere.
  const osMonitor = options.osMonitor === false ? { stop: () => {} } : await startOsMonitor(async events => {
    await app.store.addEvents(events);
    // Same batched forward as hook-captured events (see server.ts's /ingest handler) --
    // otherwise OS-monitor rows would only ever show up in the local studio view.
    app.forwardQueue.push(events);
  });

  return {
    url: `http://${hostname}:${boundPort}`, token, directory, customRules, agentInstalls,
    policySync: Boolean(identity),
    close: () => { if (policyTimer) clearInterval(policyTimer); osMonitor.stop(); app.forwardQueue.flush(); server.close(); },
  };
}
