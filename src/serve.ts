import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createCollector } from "./server.js";
import { getDataDirectory } from "./config.js";

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
}

export async function startServer(options: StartServerOptions = {}): Promise<{ url: string; token: string; directory: string; close: () => void }> {
  const directory = options.directory ?? getDataDirectory();
  await mkdir(directory, { recursive: true, mode: 0o700 });
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

  const app = await createCollector({ directory, token, origins: options.origins ?? process.env.BEAM_ALLOWED_ORIGINS?.split(",").map(s => s.trim()) });
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

  return { url: `http://${hostname}:${boundPort}`, token, directory, close: () => server.close() };
}
