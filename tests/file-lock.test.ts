import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "@jest/globals";
import { withFileLock } from "../src/file-lock.js";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});
async function tempHome(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-lock-"));
  temporaryDirectories.push(dir);
  return dir;
}

describe("withFileLock", () => {
  it("serializes concurrent callers against the same path -- no two run their critical section at once", async () => {
    const home = await tempHome();
    const target = path.join(home, "state.json");
    let concurrent = 0;
    let maxConcurrent = 0;
    const order: number[] = [];

    await Promise.all(Array.from({ length: 10 }, (_, i) => withFileLock(target, async () => {
      concurrent++;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise(resolve => setTimeout(resolve, 5)); // hold the lock long enough to overlap if unserialized
      order.push(i);
      concurrent--;
    })));

    expect(maxConcurrent).toBe(1); // never more than one holder at a time
    expect(order).toHaveLength(10); // every caller still ran, none were dropped
  });

  it("releases the lock even when the critical section throws", async () => {
    const home = await tempHome();
    const target = path.join(home, "state.json");
    await expect(withFileLock(target, async () => { throw new Error("boom"); })).rejects.toThrow("boom");
    // a second call must not hang waiting on a lock the first call failed to release
    await expect(withFileLock(target, async () => "ok")).resolves.toBe("ok");
  });

  it("removes a stale lock left by a crashed process instead of blocking forever", async () => {
    const home = await tempHome();
    const target = path.join(home, "state.json");
    const lockPath = `${target}.lock`;
    await fs.mkdir(home, { recursive: true });
    await fs.writeFile(lockPath, "");
    // Back-date it past the staleness threshold so this doesn't need a real multi-second wait.
    const old = new Date(Date.now() - 10_000);
    await fs.utimes(lockPath, old, old);

    await expect(withFileLock(target, async () => "recovered")).resolves.toBe("recovered");
  });

  it("different paths never contend with each other", async () => {
    const home = await tempHome();
    const results = await Promise.all([
      withFileLock(path.join(home, "a.json"), async () => "a"),
      withFileLock(path.join(home, "b.json"), async () => "b"),
    ]);
    expect(results).toEqual(["a", "b"]);
  });
});
