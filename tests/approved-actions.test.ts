import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { approvedActionFingerprint, consumeApprovedAction, recordApprovedAction } from "../src/approved-actions.js";

const originalEnv = { ...process.env };
const temporaryDirectories: string[] = [];

beforeEach(() => {
  process.env = { ...originalEnv };
});

afterEach(async () => {
  process.env = { ...originalEnv };
  await Promise.all(temporaryDirectories.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

async function tempDataDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-approved-actions-"));
  temporaryDirectories.push(dir);
  process.env.BEAM_DATA_DIR = dir;
  return dir;
}

const action = { agent: "codex", tool: "Bash", command: "rm -rf /tmp/scratch" };

describe("approvedActionFingerprint", () => {
  it("is stable for the same action and case-insensitive on agent/tool", async () => {
    expect(approvedActionFingerprint(action)).toBe(approvedActionFingerprint(action));
    expect(approvedActionFingerprint(action)).toBe(approvedActionFingerprint({ agent: "CODEX", tool: "bash", command: "rm -rf /tmp/scratch" }));
  });

  it("differs for a different command, path, url, agent, or tool", () => {
    const fp = approvedActionFingerprint(action);
    expect(approvedActionFingerprint({ ...action, command: "rm -rf /tmp/other" })).not.toBe(fp);
    expect(approvedActionFingerprint({ ...action, agent: "claude-code" })).not.toBe(fp);
    expect(approvedActionFingerprint({ ...action, tool: "Write" })).not.toBe(fp);
    expect(approvedActionFingerprint({ agent: "codex", tool: "WebFetch", url: "https://example.com" })).not.toBe(
      approvedActionFingerprint({ agent: "codex", tool: "WebFetch", path: "https://example.com" }),
    );
  });
});

describe("recordApprovedAction / consumeApprovedAction", () => {
  it("consuming an action nobody recorded returns false", async () => {
    await tempDataDir();
    expect(await consumeApprovedAction(action)).toBe(false);
  });

  it("a recorded action is consumed exactly once (single-use, APPROVE_ONCE semantics)", async () => {
    await tempDataDir();
    await recordApprovedAction(action);
    expect(await consumeApprovedAction(action)).toBe(true);
    expect(await consumeApprovedAction(action)).toBe(false);
  });

  it("does not grant a different action from the one that was approved", async () => {
    await tempDataDir();
    await recordApprovedAction(action);
    expect(await consumeApprovedAction({ ...action, command: "rm -rf /tmp/other" })).toBe(false);
    expect(await consumeApprovedAction({ ...action, agent: "claude-code" })).toBe(false);
    expect(await consumeApprovedAction(action)).toBe(true);
  });

  it("an expired record is not consumable", async () => {
    await tempDataDir();
    await recordApprovedAction(action, -1);
    expect(await consumeApprovedAction(action)).toBe(false);
  });

  it("recording prunes already-expired entries so the file does not grow unbounded", async () => {
    const dir = await tempDataDir();
    await recordApprovedAction({ ...action, command: "a" }, -1);
    await recordApprovedAction({ ...action, command: "b" });
    const raw = JSON.parse(await fs.readFile(path.join(dir, "approved-actions.json"), "utf8"));
    expect(raw).toHaveLength(1);
  });

  it("a malformed or missing approved-actions.json is treated as empty, not an error", async () => {
    const dir = await tempDataDir();
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(path.join(dir, "approved-actions.json"), "not json");
    await expect(consumeApprovedAction(action)).resolves.toBe(false);
    await expect(recordApprovedAction(action)).resolves.toBeUndefined();
  });
});
