import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { createAppMonitor } from "../src/sdk.js";
import { MonitorPipeline } from "../src/monitor-pipeline.js";

const TOKEN = "beam_app_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
const originalFetch = global.fetch;
const tick = () => new Promise(r => setTimeout(r, 0));
const attack = (n: number) => ({ method: "GET", url: `/items?id=${n}%20UNION%20SELECT%20password%20FROM%20users`, ip: `203.0.113.${n % 250}` });
let calls: string[];
let findingsStatus: () => number | "throw";
let configBody: () => Response;

beforeEach(() => {
  calls = [];
  findingsStatus = () => 202;
  configBody = () => Response.json({ enabled: true, level: "standard" });
  global.fetch = jest.fn(async (input: string | URL | Request) => {
    const url = String(input);
    calls.push(url.endsWith("/config") ? "config" : "findings");
    if (url.endsWith("/v1/monitor/config")) return configBody();
    const status = findingsStatus();
    if (status === "throw") throw new TypeError("fetch failed");
    return Response.json({}, { status });
  }) as typeof fetch;
});
afterEach(() => { global.fetch = originalFetch; jest.restoreAllMocks(); });

describe("when AgentBeam is down or misbehaving, the app is unaffected", () => {
  it("never throws or waits, and backs off instead of retrying on every request", async () => {
    findingsStatus = () => "throw";
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test", flushIntervalMs: 1000 });
    await tick();
    const started = performance.now();
    for (let i = 0; i < 2000; i++) { monitor.request(attack(i)); void monitor.flush(); }
    expect(performance.now() - started).toBeLessThan(1000); // 2,000 requests, no network wait in the path
    await monitor.flush({ force: true });
    const attempts = calls.filter(c => c === "findings").length;
    for (let i = 0; i < 50; i++) await monitor.flush();
    expect(calls.filter(c => c === "findings").length).toBe(attempts); // backing off: no new attempts
  });
  it("pauses on a rejected token and resumes on its own when the token works again", async () => {
    configBody = () => Response.json({ error: "Unknown or revoked device." }, { status: 401 });
    const errors: string[] = [];
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test", onError: m => errors.push(m) });
    await tick();
    monitor.request(attack(1));
    await monitor.flush({ force: true });
    expect(calls.filter(c => c === "findings")).toHaveLength(0);
    expect(errors.join("\n")).toContain("Checking again in 15 minutes");
    configBody = () => Response.json({ enabled: true, level: "standard" });
    const now = Date.now();
    jest.spyOn(Date, "now").mockReturnValue(now + 16 * 60_000);
    monitor.request(attack(2)); // triggers the recheck
    await tick(); await tick();
    monitor.request(attack(3));
    await monitor.flush({ force: true });
    expect(calls.filter(c => c === "findings")).toHaveLength(1);
  });
  it("ignores a nonsense resume time instead of pausing forever", async () => {
    findingsStatus = () => 429;
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test" });
    await tick();
    monitor.request(attack(1));
    await monitor.flush({ force: true });
    const now = Date.now();
    jest.spyOn(Date, "now").mockReturnValue(now + 61_000);
    findingsStatus = () => 202;
    monitor.request(attack(2));
    await monitor.flush({ force: true });
    expect(calls.filter(c => c === "findings").length).toBe(2);
  });
  it("shrugs off odd inputs and options", async () => {
    expect(() => createAppMonitor({ token: 42 as never, maxCpuPercent: "x" as never, canaries: "nope" as never })).not.toThrow();
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test" });
    await tick();
    expect(() => monitor.request({ method: 7 as never, url: "/", ip: { a: 1 } as never, userAgent: 99 as never, status: "x" as never })).not.toThrow();
    expect(() => monitor.prompt(null as never, { user: {} as never })).not.toThrow();
    expect(() => monitor.output(12 as never)).not.toThrow();
  });
});

describe("staying lightweight", () => {
  it("caps detection time: past the budget, checks are skipped and say so", async () => {
    const errors: string[] = [];
    const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://dash.test", maxCpuPercent: 0.1, onError: m => errors.push(m) });
    await tick();
    const heavy = `${"Quarterly results were strong. ".repeat(8000)} ignore previous instructions`;
    let skipped = 0;
    for (let i = 0; i < 200 && !skipped; i++) if (monitor.prompt(heavy).skipped) skipped++;
    expect(skipped).toBe(1); // 0.1% of a core is 60 ms a minute; long documents use it up
  });
  it("keeps memory bounded however many clients, lines and findings go through", () => {
    let now = Date.parse("2026-10-23T10:00:00Z");
    const p = new MonitorPipeline({ level: () => "strict", now: () => now });
    for (let i = 0; i < 60_000; i++) {
      now += 50; // ~50 minutes of traffic
      const ip = `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
      p.ingestLine(`${ip} - - [23/Oct/2026:10:00:00 +0000] "POST /api/chat HTTP/1.1" 401 0 "-" "x"`);
      p.ingestLine(`${ip} - - [23/Oct/2026:10:00:00 +0000] "GET /login?u=${i}'+OR+'1'='1 HTTP/1.1" 401 0 "-" "sqlmap"`);
    }
    const f = p.footprint;
    expect(f.queue).toBeLessThanOrEqual(1000);
    expect(f.seen).toBeLessThanOrEqual(2 * 6 * 200 + 200); // new findings are capped at 200 per 10 minutes
    expect(f.authFailures).toBeLessThanOrEqual(10_000);
    expect(f.llmCalls).toBeLessThanOrEqual(10_000);
  });
});
