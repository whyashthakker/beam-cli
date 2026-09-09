import { timingSafeEqual } from "node:crypto";
import { normalize, parseInput, ruleCatalog, scanText } from "./core.js";
import { Store } from "./store.js";
import { inventory } from "./inventory.js";

export async function createCollector(options: { directory: string; token: string; origins?: string[] }) {
  const store = new Store(options.directory); await store.init();
  const origins = new Set(options.origins ?? ["http://localhost:3200", "http://127.0.0.1:3200"]);
  const secret = Buffer.from(`Bearer ${options.token}`);
  return { store, async fetch(req: Request): Promise<Response> {
    const origin = req.headers.get("origin");
    const url = new URL(req.url);
    const headers: Record<string, string> = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Vary": "Origin" };
    const json = (data: unknown, status = 200) => Response.json(data, { status, headers });
    if (!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) return json({ error: "Loopback host required." }, 403);
    if (origin && !origins.has(origin)) return json({ error: "Origin not permitted." }, 403);
    if (origin) {
      headers["Access-Control-Allow-Origin"] = origin;
      headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
      headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
      headers["Access-Control-Allow-Private-Network"] = "true";
    }
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });
    const provided = Buffer.from(req.headers.get("authorization") ?? "");
    if (provided.length !== secret.length || !timingSafeEqual(provided, secret)) return json({ error: "Pairing token is missing or incorrect." }, 401);
    if (req.headers.get("content-encoding")) return json({ error: "Compressed requests are not supported; disable gzip in the exporter." }, 415);
    try {
      if (req.method === "GET" && url.pathname === "/agents") return json(await inventory(store.events));
      if (req.method === "GET" && url.pathname === "/health") return json({ name: "Beam", version: "0.1.0", mode: "observe", events: store.events.length, retention: store.maxEvents });
      if (req.method === "GET" && url.pathname === "/state") return json({ events: store.events, scans: store.scans, reviews: store.reviews, rules: ruleCatalog, retention: store.maxEvents });
      if (req.method === "GET" && url.pathname === "/export") return new Response(store.events.map(e => JSON.stringify(e)).join("\n"), { headers: { ...headers, "Content-Type": "application/x-ndjson", "Content-Disposition": 'attachment; filename="beam-events.ndjson"' } });
      if (req.method !== "POST" || !["/ingest", "/v1/logs", "/scan", "/review"].includes(url.pathname)) return json({ error: "Route not found." }, 404);
      // Bound streamed bodies too; Content-Length alone cannot protect chunked requests.
      const reader = req.body?.getReader(); let size = 0; const chunks: Uint8Array[] = [];
      if (reader) while (true) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > 2_000_000) { await reader.cancel(); return json({ error: "Request exceeds 2 MB." }, 413); } chunks.push(value); }
      const body = Buffer.concat(chunks).toString("utf8");
      if (url.pathname === "/ingest" || url.pathname === "/v1/logs") {
        const records = parseInput(body, url.pathname === "/v1/logs");
        if (records.length > 2000) throw new Error("Batch exceeds 2,000 records.");
        // Some exporters also emit indicator, summary and enforcement records; those are not action events.
        const supported = records.filter(r => !r.record_type || ["event", "finding"].includes(String(r.record_type)));
        const result = await store.addEvents(supported.map(normalize));
        return json(url.pathname === "/v1/logs" ? {} : { ...result, skipped: records.length - supported.length });
      }
      const data = JSON.parse(body);
      if (url.pathname === "/scan") {
        if (typeof data.content !== "string" || typeof data.name !== "string" || !["skill", "mcp"].includes(data.kind)) throw new Error("Expected name, content and kind (skill or mcp).");
        return json(await store.addScan(scanText(data.name, data.content, data.kind)));
      }
      if (typeof data.id !== "string" || typeof data.reviewed !== "boolean") throw new Error("Expected event id and reviewed boolean.");
      await store.review(data.id, data.reviewed); return json({ ok: true });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code) { console.error("Beam storage error:", (e as NodeJS.ErrnoException).code); return json({ error: "Local storage failed. Check collector permissions and disk space; retry the request." }, 500); }
      return json({ error: e instanceof Error ? e.message : "Invalid request." }, 400);
    }
  } };
}
