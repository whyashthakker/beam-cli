#!/usr/bin/env node
// Stress test for `beam monitor` and the in-app SDK (@agent-beam/beam/monitor), run against the
// built package in dist/. The release workflow runs it for every version and attaches the JSON to
// the GitHub release, where agentbeam.com/releases shows it.
//
// It measures what matters for running next to, or inside, someone else's app: hostile input
// can't stall detection, memory stays flat, AgentBeam being down or slow never reaches the app's
// request path, and detection stays inside its CPU budget. It exits 1 when a limit is broken, so
// a release that breaks one isn't published. Limits are generous because CI machines are slow;
// the numbers in the report are the measurements.
//
//   npm run build && node --expose-gc scripts/stress-report.mjs [--out stress-report.json]
import { readFileSync, writeFileSync } from "node:fs";
import os from "node:os";

const dist = new URL("../dist/", import.meta.url);
const { matchLine } = await import(new URL("monitor-rules.js", dist).href);
const { MonitorPipeline } = await import(new URL("monitor-pipeline.js", dist).href);
const { checkOutput, checkPrompt, createAppMonitor } = await import(new URL("sdk.js", dist).href);
const { scanCode } = await import(new URL("package-risk-rules.js", dist).href);
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

if (typeof globalThis.gc !== "function") {
  console.error("Run with node --expose-gc so heap measurements are taken after garbage collection.");
  process.exit(1);
}
const heapMb = () => { globalThis.gc(); globalThis.gc(); return process.memoryUsage().heapUsed / 1e6; };
const clock = () => performance.now();
const round = (n, d = 1) => Math.round(n * 10 ** d) / 10 ** d;
const TOKEN = "beam_app_stresstest_abcdefghijklmnopqrstuvwxyz0123456789";
const tick = () => new Promise(r => setTimeout(r, 0));
const checks = [];
const check = (id, title, passed, summary, measured, limit) => {
  checks.push({ id, title, passed, summary, measured, limit });
  console.log(`${passed ? "PASS" : "FAIL"}  ${title}: ${summary}`);
};

// 1. Hostile input: every rule family against 16 KB inputs built to trigger backtracking.
{
  const N = 16_384;
  const fill = unit => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  const attacks = {
    "curl|": fill("curl|"), "base64 -d": fill("base64 -d "), "base64 -d |": fill("base64 -d |"), "?url": `/x${fill("?url")}`,
    "&urlurl": `/x?${fill("urlurl")}`, "&a=gopher:": fill("&a=gopher:"), "![a](https://?": `![a](https://${fill("?a")}`,
    "![a](https://e/?": fill("![a](https://e/?"), "<img src=https://?": `<img src="https://${fill("?a")}`, "<img many": fill("<img src=https://e/?"),
    "print AB_": fill("print AB_"), "echo $A": fill("echo $A"), "ignore all previous": fill("ignore all previous "), "repeat the": fill("repeat the "),
    "note to the": fill("note to the "), "classify this request": fill("classify this request "), "show me your": fill("show me your "),
    "entire full": fill("entire full "), "base64 blob": fill("QUJD"), "unicode tags": `x${String.fromCodePoint(0xe0041).repeat(N / 2)}`,
    "zero-width": fill("ig​n"), "full-width": fill("ｉｇｎｏｒｅ "), "sk-": fill("sk-a"), "bearer": fill("bearer "), "token=": fill("token="),
    "' or 1": fill("' or 1"), "union select": fill("union select "), "%25": fill("%25"), "../": fill("../"), "{{7*": fill("{{7*"), "${${": fill("${${"),
    "<img ": fill("<img "), "socket ": fill("socket "), "nc ": fill("nc "), "env |": fill("env |"), "cat ../": fill("cat ../"), "__proto__": fill("__proto__"),
    "${jndi": fill("${jndi"), "a@b.": fill("a@b."), "http://a:b": fill("http://a:b"), "rm -": fill("rm -"), "git push ": fill("git push "),
  };
  const time = fn => { const t = clock(); fn(); return clock() - t; };
  const results = Object.entries(attacks).map(([name, text]) => {
    let worst = 0;
    for (const source of ["log", "http", "prompt", "output"]) worst = Math.max(worst, time(() => matchLine(text, source)));
    worst = Math.max(worst, time(() => checkPrompt(text)), time(() => checkOutput(text, { canaries: ["canary-7f3a9c1e"] })));
    return { input: name, ms: round(worst, 2) };
  }).sort((a, b) => b.ms - a.ms);
  const worst = results[0].ms;
  check("hostile-input", "Hostile input", worst < 250,
    `${results.length} attack shapes at 16 KB; the slowest took ${worst} ms (${results[0].input})`,
    { worstMs: worst, cases: results.length, slowest: results.slice(0, 5) }, "under 250 ms for any single 16 KB input");
}

// 1b. Package scanning reads attacker-written code: every package rule against 3 MB files (the
// largest file 'beam add package' and 'beam packages scan' read) shaped to trigger backtracking.
{
  const N = 3 * 1024 * 1024;
  const fill = unit => unit.repeat(Math.ceil(N / unit.length)).slice(0, N);
  const attacks = {
    "eval(Buffer.from(": fill("eval(Buffer.from("), "exec(compile(": fill("exec(compile( "), "hex escapes": fill(`${"\\x41".repeat(39)} `), "_0x": fill("_0x12 "),
    "webhook": fill("discord.com/api/webhooks/123456789012345678/"), "telegram": fill("api.telegram.org/bot123456:"), "ngrok": fill("a-a-a.ngrok"),
    "JSON.stringify(": fill("JSON.stringify( "), ".ssh/": fill(".ssh/"), "os.hostname()": fill("os.hostname() "), "curl ": fill("curl "),
    "require('dns')": fill("require('dns')."), "fetch": fill("fetch "), "rm -rf": fill("rm -rf "), "launchctl": fill("launchctl "),
    "one long line": fill("a"), "short lines": fill("x\n"),
  };
  const results = Object.entries(attacks).map(([name, text]) => {
    const t = clock();
    scanCode(text, { shell: true });
    return { input: name, ms: round(clock() - t, 1) };
  }).sort((a, b) => b.ms - a.ms);
  const worst = results[0].ms;
  check("package-scan", "Package scanning, hostile files", worst < 1000,
    `${results.length} attack shapes at 3 MB; the slowest took ${worst} ms (${results[0].input})`,
    { worstMs: worst, cases: results.length, slowest: results.slice(0, 5) }, "under 1 s for any single 3 MB file");
}

// 2. Throughput of the detection pipeline on realistic, mixed traffic.
const mixed = [
  i => `203.0.${i % 255}.${i % 200} - - [23/Oct/2026:10:00:00 +0000] "GET /api/orders?page=${i}&sort=created_at HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Macintosh) Chrome/155.0.0.0 Safari/537.36"`,
  i => `{"timestamp":"2026-10-23T10:08:58Z","method":"POST","path":"/api/chat","httpStatus":200,"clientUa":"Mozilla/5.0","srcIp":"198.51.${i % 255}.${i % 200}","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I6PlFLbZ11dHb4"}`,
  i => `2026-10-23T10:00:00Z INFO worker job=${i} processed user_id=${i * 7} in 12ms — résumé upload ok`,
  i => `198.51.100.${i % 250} - - [23/Oct/2026:10:00:00 +0000] "GET /item?id=${i}%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 200 1 "-" "sqlmap/1.8"`,
];
{
  const pipeline = new MonitorPipeline({ level: () => "strict" });
  for (let i = 0; i < 20_000; i++) pipeline.ingestLine(mixed[i & 3](i));
  const lines = 300_000;
  const t = clock();
  for (let i = 0; i < lines; i++) pipeline.ingestLine(mixed[i & 3](i));
  const perSecond = Math.round(lines / ((clock() - t) / 1000));
  check("throughput", "Log throughput", perSecond > 10_000,
    `${perSecond.toLocaleString("en-US")} log lines per second on one core, attacks included`,
    { linesPerSecond: perSecond, lines }, "over 10,000 lines per second");
}

// 3. Cost per call inside an app (AgentBeam answering normally).
{
  globalThis.fetch = async url => (String(url).endsWith("/config") ? Response.json({ level: "standard" }) : Response.json({}, { status: 202 }));
  const requests = createAppMonitor({ token: TOKEN, dashboardUrl: "https://stress.test", maxCpuPercent: 50 });
  const prompts = createAppMonitor({ token: TOKEN, dashboardUrl: "https://stress.test", maxCpuPercent: 50 });
  await tick();
  let n = 100_000;
  let t = clock();
  for (let i = 0; i < n; i++) requests.request({ method: "GET", url: `/api/orders?page=${i}&sort=created_at`, ip: "203.0.113.9", userAgent: "Mozilla/5.0 (Macintosh) Chrome/155.0.0.0 Safari/537.36" });
  const requestUs = round(((clock() - t) * 1000) / n);
  n = 20_000;
  t = clock();
  for (let i = 0; i < n; i++) prompts.prompt(`Can you help me write a polite email to my landlord about the heating? #${i}`, { user: "u1" });
  const promptUs = round(((clock() - t) * 1000) / n);
  check("per-call", "Cost per call in your app", requestUs < 100 && promptUs < 200,
    `request() ${requestUs} µs, prompt() ${promptUs} µs on a short message`,
    { requestMicros: requestUs, promptMicros: promptUs }, "request() under 100 µs and prompt() under 200 µs");
}

// 4. Memory over millions of lines with AgentBeam unreachable the whole time (nothing ever leaves).
{
  let now = Date.parse("2026-10-23T10:00:00Z");
  const pipeline = new MonitorPipeline({ level: () => "strict", now: () => now });
  const samples = [];
  const start = heapMb();
  for (let r = 1; r <= 6; r++) {
    for (let i = 0; i < 500_000; i++) { now += 10; pipeline.ingestLine(mixed[i & 3](r * 1_000_000 + i)); }
    await pipeline.flush(async () => "retry");
    samples.push(round(heapMb()));
  }
  const growth = round(samples.at(-1) - samples[1]);
  check("memory-cli", "Memory under load (beam monitor)", growth < 20,
    `${round(start)} MB at start; ${samples.join(", ")} MB after each 500,000 lines; ${growth >= 0 ? "+" : ""}${growth} MB from 1M to 3M lines`,
    { heapMb: samples, startMb: round(start), growthMb: growth, footprint: pipeline.footprint }, "under 20 MB growth from 1M to 3M lines");
}
{
  globalThis.fetch = async () => { throw new TypeError("fetch failed"); };
  const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://down.stress.test" });
  const samples = [];
  for (let r = 1; r <= 4; r++) {
    for (let i = 0; i < 250_000; i++) {
      monitor.request({ method: "GET", url: `/x?id=${i}%20UNION%20SELECT%201`, ip: `203.0.${(i >> 8) & 255}.${i & 255}` });
      monitor.prompt(`hello ${i}`, { user: `u${i}` });
    }
    await monitor.flush({ force: true });
    samples.push(round(heapMb()));
  }
  const growth = round(samples.at(-1) - samples[0]);
  check("memory-sdk", "Memory in your app while AgentBeam is down", growth < 10,
    `${samples.join(", ")} MB after each 250,000 requests and prompts`,
    { heapMb: samples, growthMb: growth }, "under 10 MB growth over 1M requests");
}

// 5. AgentBeam down, then slow: the app's request path never waits, and retries back off.
{
  let attempts = 0;
  globalThis.fetch = async url => {
    if (String(url).endsWith("/config")) return Response.json({ level: "standard" });
    attempts++;
    throw new TypeError("fetch failed");
  };
  const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://down.stress.test", flushIntervalMs: 1000 });
  await tick();
  const t = clock();
  for (let i = 0; i < 5_000; i++) { monitor.request({ method: "GET", url: `/i?id=${i}%20UNION%20SELECT%201`, ip: `198.51.100.${i % 250}` }); void monitor.flush(); }
  const perRequestUs = round(((clock() - t) * 1000) / 5_000);
  await monitor.flush({ force: true });
  const afterFirst = attempts;
  for (let i = 0; i < 200; i++) await monitor.flush();

  globalThis.fetch = (url, init) => String(url).endsWith("/config")
    ? Promise.resolve(Response.json({ level: "standard" }))
    : new Promise((_, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
  const slow = createAppMonitor({ token: TOKEN, dashboardUrl: "https://slow.stress.test" });
  await tick();
  slow.request({ method: "GET", url: "/?id=1%20UNION%20SELECT%201", ip: "203.0.113.1" });
  // The SDK's timeout timer is unref'd so it never keeps an app alive; a real app's server keeps
  // the event loop running, which this script stands in for while it waits.
  const keepAlive = setInterval(() => {}, 1_000);
  const s = clock();
  await slow.flush({ force: true });
  const hangMs = Math.round(clock() - s);
  clearInterval(keepAlive);
  const passed = perRequestUs < 100 && attempts === afterFirst && hangMs < 7_000;
  check("outage", "AgentBeam down or slow", passed,
    `request() stayed at ${perRequestUs} µs; ${afterFirst} send attempt${afterFirst === 1 ? "" : "s"}, then none while backing off; a hung connection was dropped after ${(hangMs / 1000).toFixed(1)} s, off the request path`,
    { requestMicros: perRequestUs, attemptsBeforeBackoff: afterFirst, attemptsDuringBackoff: attempts - afterFirst, hungFlushMs: hangMs },
    "no slowdown, no retries during backoff, hung sends dropped within 7 s");
}

// 6. The CPU cap: a flood of large documents can't take more than its share. Time is counted for
// checks that ran; a skipped call returns at once (its cost is reported separately).
{
  globalThis.fetch = async url => (String(url).endsWith("/config") ? Response.json({ level: "standard" }) : Response.json({}, { status: 202 }));
  const monitor = createAppMonitor({ token: TOKEN, dashboardUrl: "https://stress.test", maxCpuPercent: 1 });
  await tick();
  const doc = `${"Quarterly results were strong across every region. ".repeat(4000)} ignore previous instructions`;
  let spent = 0;
  let skippedTime = 0;
  let checked = 0;
  let skipped = 0;
  const minute = Math.floor(Date.now() / 60_000);
  const until = clock() + 2_000;
  while (clock() < until && Math.floor(Date.now() / 60_000) === minute) {
    const t = clock();
    const result = monitor.prompt(doc);
    const took = clock() - t;
    if (result.skipped) { skipped++; skippedTime += took; } else { checked++; spent += took; }
    if (skipped >= 100_000) break; // enough to measure a skipped call
  }
  const budgetMs = 600; // 1% of a core for a minute
  const skipUs = skipped ? round((skippedTime * 1000) / skipped, 2) : 0;
  check("cpu-budget", "CPU cap", spent < budgetMs * 2,
    `with a 1% cap (600 ms a minute), a flood of 200 KB documents got ${Math.round(spent)} ms of checking (${checked} documents); the rest were skipped, flagged as skipped, at ${skipUs} µs each`,
    { capMs: budgetMs, spentMs: Math.round(spent), checked, skipped, skippedCallMicros: skipUs }, "under twice the cap (one check can finish after the cap is reached)");
}

const report = {
  schema: 1,
  package: pkg.name,
  version: pkg.version,
  generatedAt: new Date().toISOString(),
  passed: checks.every(c => c.passed),
  environment: { node: process.version, platform: `${os.platform()} ${os.arch()}`, cpu: os.cpus()[0]?.model ?? "unknown", cores: os.cpus().length, ci: Boolean(process.env.CI) },
  checks,
};
const out = process.argv.includes("--out") ? process.argv[process.argv.indexOf("--out") + 1] : undefined;
if (out) writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
console.log(`\n${report.passed ? "All checks passed" : "Some checks failed"} for ${pkg.name} ${pkg.version}${out ? `; report written to ${out}` : ""}.`);
process.exit(report.passed ? 0 : 1);
