import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "@jest/globals";
import { ANOMALY_THRESHOLD, recordAndCheckAnomaly } from "../src/behavioral-anomaly.js";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});
async function tempHome(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-anomaly-"));
  temporaryDirectories.push(dir);
  return dir;
}

describe("recordAndCheckAnomaly", () => {
  it("triggers once a session reaches the threshold of high/critical events within the window", async () => {
    const home = await tempHome();
    let last;
    for (let i = 0; i < ANOMALY_THRESHOLD; i++) last = await recordAndCheckAnomaly("sess-1", "HIGH", home);
    expect(last!.count).toBe(ANOMALY_THRESHOLD);
    expect(last!.triggered).toBe(true);
  });

  it("does not trigger below the threshold", async () => {
    const home = await tempHome();
    let last;
    for (let i = 0; i < ANOMALY_THRESHOLD - 1; i++) last = await recordAndCheckAnomaly("sess-1", "CRITICAL", home);
    expect(last!.triggered).toBe(false);
  });

  it("LOW and MEDIUM severity events never count toward the threshold", async () => {
    const home = await tempHome();
    let last;
    for (let i = 0; i < ANOMALY_THRESHOLD + 5; i++) last = await recordAndCheckAnomaly("sess-1", "LOW", home);
    expect(last!.count).toBe(0);
    expect(last!.triggered).toBe(false);
    for (let i = 0; i < ANOMALY_THRESHOLD + 5; i++) last = await recordAndCheckAnomaly("sess-1", "MEDIUM", home);
    expect(last!.count).toBe(0);
  });

  it("tracks sessions independently -- one session's burst never affects another's count", async () => {
    const home = await tempHome();
    for (let i = 0; i < ANOMALY_THRESHOLD; i++) await recordAndCheckAnomaly("sess-1", "HIGH", home);
    const other = await recordAndCheckAnomaly("sess-2", "HIGH", home);
    expect(other.count).toBe(1);
    expect(other.triggered).toBe(false);
  });

  it("never triggers and never throws when no session id is available", async () => {
    const home = await tempHome();
    const result = await recordAndCheckAnomaly("", "CRITICAL", home);
    expect(result).toEqual({ triggered: false, count: 0, windowMinutes: 10 });
  });

  it("regression: genuinely concurrent calls (an agent's parallel tool calls in one turn) never lose events to a read-write race", async () => {
    const home = await tempHome();
    // Fired together, not awaited one at a time -- this is what used to collapse to 1 persisted
    // event no matter how many concurrent HIGH-severity actions actually happened, because every
    // process independently read "0 prior events" before any of them had written back.
    const results = await Promise.all(Array.from({ length: ANOMALY_THRESHOLD }, () => recordAndCheckAnomaly("sess-parallel", "HIGH", home)));
    expect(results.some(r => r.triggered)).toBe(true);
    expect(Math.max(...results.map(r => r.count))).toBe(ANOMALY_THRESHOLD);
  });
});
