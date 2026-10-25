import { describe, expect, it } from "@jest/globals";
import {
  PauseBook, autoPauseFor, isProtectedIp, normalizeTarget, parseIp, pauseTarget, trustedRequestIp,
} from "../src/monitor-pause.js";
import type { MonitorFinding } from "../src/monitor-client.js";

const finding = (ruleId: string, extra: Partial<MonitorFinding> = {}): MonitorFinding => ({
  id: `${ruleId}-1`, ruleId, title: ruleId, severity: "high", source: "http", evidence: "", count: 1, firstSeen: new Date(0).toISOString(), ...extra,
});
const headers = (h: Record<string, string>) => (name: string) => h[name];

describe("addresses", () => {
  it("parses IPv4, IPv6, mapped and bracketed addresses", () => {
    expect(parseIp("203.0.113.9")).toEqual({ v: 4, bytes: [203, 0, 113, 9] });
    expect(parseIp("::ffff:203.0.113.9")).toEqual({ v: 4, bytes: [203, 0, 113, 9] });
    expect(parseIp("[2001:db8::1]")?.v).toBe(6);
    expect(parseIp("fe80::1%eth0")?.v).toBe(6);
    expect(parseIp("64:ff9b::192.0.2.1")?.bytes.slice(-4)).toEqual([192, 0, 2, 1]);
    for (const bad of ["256.1.1.1", "1.2.3", "1::2::3", "gggg::1", "", "not an ip", "1.2.3.4.5"]) expect(parseIp(bad)).toBeNull();
  });
  it("keys IPv6 senders by their /64 and IPv4 by the address", () => {
    expect(pauseTarget("2001:db8:1:2:aaaa:bbbb:cccc:dddd")).toBe("2001:db8:1:2::/64");
    expect(pauseTarget("2001:db8:1:2::9")).toBe("2001:db8:1:2::/64");
    expect(pauseTarget("2001:db8::9")).toBe("2001:db8::/64");
    expect(pauseTarget("::ffff:198.51.100.7")).toBe("198.51.100.7");
  });
  it("never treats private, loopback or link-local addresses as pausable", () => {
    for (const ip of ["10.1.2.3", "172.20.0.1", "192.168.1.1", "127.0.0.1", "::1", "fd00::1", "fe80::1", "100.64.0.1", "garbage"]) expect(isProtectedIp(ip)).toBe(true);
    for (const ip of ["203.0.113.9", "2001:db8::1", "172.32.0.1"]) expect(isProtectedIp(ip)).toBe(false);
  });
  it("normalizes what a person types, and refuses ranges wider than a /16", () => {
    expect(normalizeTarget(" 203.0.113.9 ")).toBe("203.0.113.9");
    expect(normalizeTarget("203.0.113.77/24")).toBe("203.0.113.0/24");
    expect(normalizeTarget("203.0.113.9/32")).toBe("203.0.113.9");
    expect(normalizeTarget("2001:DB8:1:2::5/64")).toBe("2001:db8:1:2::/64");
    expect(normalizeTarget("2001:db8:1::/48")).toBe("2001:db8:1::/48");
    expect(normalizeTarget("user:42")).toBe("user:42");
    expect(normalizeTarget("10.0.0.0/8")).toBeNull();
    expect(normalizeTarget("::/0")).toBeNull();
    expect(normalizeTarget("nope")).toBeNull();
  });
});

describe("trustedRequestIp", () => {
  it("reads the platform's own header on Cloudflare, Vercel and Fly.io", () => {
    expect(trustedRequestIp("1.1.1.1", headers({ "cf-connecting-ip": "203.0.113.9" }), { cloudflare: true })).toBe("203.0.113.9");
    expect(trustedRequestIp(undefined, headers({ "x-real-ip": "203.0.113.9" }), { vercel: true })).toBe("203.0.113.9");
    expect(trustedRequestIp(undefined, headers({ "fly-client-ip": "203.0.113.9" }), { fly: true })).toBe("203.0.113.9");
  });
  it("never trusts the first entry of a forwarded list: the client wrote it", () => {
    const xff = headers({ "x-forwarded-for": "198.51.100.1, 203.0.113.9" });
    expect(trustedRequestIp("198.51.100.1", xff, {})).toBeNull();
    expect(trustedRequestIp("203.0.113.9", xff, {})).toBe("203.0.113.9"); // the proxy appended it
    expect(trustedRequestIp("203.0.113.9", headers({ "x-forwarded-for": "203.0.113.9" }), {})).toBe("203.0.113.9");
    expect(trustedRequestIp("203.0.113.9", headers({}), {})).toBe("203.0.113.9"); // a socket address
    expect(trustedRequestIp("198.51.100.1", xff, { trustGiven: true })).toBe("198.51.100.1");
    expect(trustedRequestIp("not-an-ip", headers({}), {})).toBeNull();
  });
});

describe("autoPauseFor", () => {
  it("pauses patterns and critical exploits that weren't refused, nothing else", () => {
    expect(autoPauseFor(finding("app.auth_bruteforce"))?.scope).toBe("auth");
    expect(autoPauseFor(finding("signal.path_walk"))?.scope).toBe("all");
    expect(autoPauseFor(finding("llm.denial_of_wallet"))?.scope).toBe("llm");
    expect(autoPauseFor(finding("web.sql_injection"))).toBeNull();
    expect(autoPauseFor(finding("web.jndi_injection", { severity: "critical", category: "exploit", request: { outcome: "unknown" } }))?.scope).toBe("all");
    expect(autoPauseFor(finding("web.jndi_injection", { severity: "critical", category: "exploit", request: { outcome: "blocked" } }))).toBeNull();
    expect(autoPauseFor(finding("signal.path_walk", { rollup: {} as MonitorFinding["rollup"] }))).toBeNull();
  });
});

describe("PauseBook", () => {
  const book = (mode: "off" | "dry_run" | "auto", extra: Record<string, unknown> = {}, now = { t: 1_000_000_000_000 }) => {
    const notices: string[] = [];
    const b = new PauseBook({ now: () => now.t, onNotice: m => notices.push(m) });
    b.configure({ mode, ...extra }, [], []);
    return { b, notices, now };
  };

  it("pauses a sender in auto mode, scoped to what it did", () => {
    const { b } = book("auto");
    expect(b.consider(finding("app.auth_bruteforce"), { ip: "203.0.113.9" })).toMatchObject({ target: "203.0.113.9", scope: "auth" });
    expect(b.check({ ip: "203.0.113.9" }, { path: "/api/login" })).toMatchObject({ paused: true, scope: "auth" });
    expect(b.check({ ip: "203.0.113.9" }, { path: "/pricing" }).paused).toBe(false);
    expect(b.check({ ip: "198.51.100.1" }, { path: "/api/login" }).paused).toBe(false);
    const [report] = b.takeReports();
    expect(report).toMatchObject({ target: "203.0.113.9", scope: "auth", dryRun: false, strike: 1, ruleId: "app.auth_bruteforce" });
  });
  it("only records what it would pause in dry run, and nothing when off", () => {
    const dry = book("dry_run").b;
    dry.consider(finding("signal.path_walk"), { ip: "203.0.113.9" });
    expect(dry.check({ ip: "203.0.113.9" }, { path: "/" })).toMatchObject({ paused: false, wouldPause: true });
    expect(dry.takeReports()[0]).toMatchObject({ dryRun: true });
    const off = book("off").b;
    expect(off.consider(finding("signal.path_walk"), { ip: "203.0.113.9" })).toBeNull();
  });
  it("never pauses private, allowlisted or untrusted senders", () => {
    const { b } = book("auto", { allowlist: ["198.51.100.0/24", "user:ops"] });
    expect(b.consider(finding("signal.path_walk"), { ip: "10.0.0.5" })).toBeNull();
    expect(b.consider(finding("signal.path_walk"), { ip: "198.51.100.20" })).toBeNull();
    expect(b.consider(finding("signal.path_walk"), { ip: null })).toBeNull();
    expect(b.consider(finding("llm.token_spend"), { user: "ops" })).toBeNull();
  });
  it("pauses an LLM abuser by user id when it has one", () => {
    const { b } = book("auto");
    expect(b.consider(finding("llm.token_spend"), { user: "u_42", ip: "203.0.113.9" })).toMatchObject({ target: "user:u_42", scope: "llm" });
    expect(b.check({ user: "u_42", ip: "198.51.100.1" }, { llm: true }).paused).toBe(true);
    expect(b.check({ user: "u_42" }, { path: "/settings" }).paused).toBe(false);
  });
  it("pauses repeat offenders for longer, up to a day", () => {
    const { b, now } = book("auto");
    const lengths: number[] = [];
    for (let i = 0; i < 4; i++) {
      const pause = b.consider(finding("app.auth_bruteforce"), { ip: "203.0.113.9" })!;
      lengths.push((pause.until - now.t) / 60_000);
      now.t = pause.until + 1;
    }
    expect(lengths).toEqual([15, 60, 240, 960]);
  });
  it("trips a breaker on a burst of new pauses instead of refusing everyone", () => {
    const { b, notices } = book("auto", { burst: 3 });
    for (let i = 1; i <= 3; i++) expect(b.consider(finding("signal.path_walk"), { ip: `203.0.113.${i}` })).not.toBeNull();
    expect(b.consider(finding("signal.path_walk"), { ip: "203.0.113.4" })).toBeNull();
    expect(notices[0]).toContain("stopped for 30 minutes");
    expect(b.consider(finding("signal.path_walk"), { ip: "203.0.113.5" })).toBeNull();
  });
  it("caps how many are paused at once", () => {
    const { b, notices } = book("auto", { maxActive: 2 });
    b.consider(finding("signal.path_walk"), { ip: "203.0.113.1" });
    b.consider(finding("signal.path_walk"), { ip: "203.0.113.2" });
    expect(b.consider(finding("signal.path_walk"), { ip: "203.0.113.3" })).toBeNull();
    expect(notices[0]).toContain("most this app pauses at once");
  });
  it("enforces the workspace's pauses, ranges included, and honors lifts", () => {
    const now = { t: 1_000_000_000_000 };
    const b = new PauseBook({ now: () => now.t });
    const until = new Date(now.t + 3_600_000).toISOString();
    b.configure({ mode: "auto" }, [{ target: "203.0.113.0/24", scope: "all", until, reason: "Paused in the dashboard", source: "manual" }], []);
    expect(b.check({ ip: "203.0.113.77" }, { path: "/" })).toMatchObject({ paused: true, reason: "Paused in the dashboard" });
    expect(b.active().map(p => p.target)).toEqual(["203.0.113.0/24"]);
    b.consider(finding("signal.path_walk"), { ip: "198.51.100.7" });
    expect(b.check({ ip: "198.51.100.7" }, { path: "/" }).paused).toBe(true);
    // An admin lifts it: the local pause goes, and it isn't remade for a day.
    b.configure({ mode: "auto" }, [], [{ target: "198.51.100.7", scope: "all", at: new Date(now.t).toISOString() }]);
    expect(b.check({ ip: "198.51.100.7" }, { path: "/" }).paused).toBe(false);
    expect(b.consider(finding("signal.path_walk"), { ip: "198.51.100.7" })).toBeNull();
  });
  it("stops enforcing its own pauses when the dashboard turns pausing down", () => {
    const { b } = book("auto");
    b.consider(finding("signal.path_walk"), { ip: "203.0.113.9" });
    b.configure({ mode: "dry_run" }, [], []);
    expect(b.check({ ip: "203.0.113.9" }, { path: "/" })).toMatchObject({ paused: false, wouldPause: true });
    b.configure({ mode: "auto" }, [], []);
    expect(b.check({ ip: "203.0.113.9" }, { path: "/" })).toEqual({ paused: false });
  });
  it("forgets expired pauses", () => {
    const { b, now } = book("auto");
    b.consider(finding("app.auth_bruteforce"), { ip: "203.0.113.9" });
    now.t += 16 * 60_000;
    expect(b.check({ ip: "203.0.113.9" }, { path: "/login" }).paused).toBe(false);
    expect(b.size.local).toBe(0);
  });
});

describe("deny lists", () => {
  it("renders one scope's addresses, sorted, with reasons that can't break the file", async () => {
    const { renderDenyList } = await import("../src/monitor-deny.js");
    const until = Date.now() + 60_000;
    const pauses = [
      { target: "203.0.113.9", scope: "all" as const, until, reason: "x;\n}\ninclude /etc/passwd", source: "manual" as const },
      { target: "198.51.100.7", scope: "all" as const, until, reason: "Walking the app's paths", source: "auto" as const },
      { target: "198.51.100.8", scope: "auth" as const, until, reason: "", source: "auto" as const },
      { target: "198.51.100.9", scope: "all" as const, until, reason: "", source: "auto" as const, dryRun: true },
      { target: "user:42", scope: "all" as const, until, reason: "", source: "manual" as const },
    ];
    const nginx = renderDenyList(pauses, "all", "nginx");
    const lines = nginx.trim().split("\n").filter(l => !l.startsWith("#"));
    expect(lines.map(l => l.split(";")[0])).toEqual(["deny 198.51.100.7", "deny 203.0.113.9"]);
    expect(lines.every(l => l.split(";").length === 2)).toBe(true); // nothing after the comment can be read as syntax
    expect(nginx).not.toContain("\ninclude");
    expect(renderDenyList(pauses, "auth", "plain").trim().split("\n").pop()).toBe("198.51.100.8");
  });
});

describe("beam monitor pause settings", () => {
  it("parses durations from a minute to a week", async () => {
    const { parseDuration } = await import("../src/monitor.js");
    expect(parseDuration("15m")).toBe(900_000);
    expect(parseDuration("2h")).toBe(7_200_000);
    expect(parseDuration("7d")).toBe(604_800_000);
    for (const bad of ["8d", "0m", "soon", "30s"]) expect(parseDuration(bad)).toBeNull();
  });
  it("refuses deny lists and reload commands from a project file", async () => {
    const { validateLayer } = await import("../src/monitor-config.js");
    expect(() => validateLayer({ pause: { denyFile: "/tmp/x", reload: "rm -rf /" } }, "project", "beam.monitor.json")).toThrow("can't come from a project file");
    expect(validateLayer({ pause: { denyFile: "/etc/nginx/beam-deny.conf", reload: "nginx -s reload" } }, "managed", "/etc/beam/monitor.json").settings.pause)
      .toMatchObject({ denyFile: "/etc/nginx/beam-deny.conf", format: "nginx", reload: "nginx -s reload" });
  });
});
