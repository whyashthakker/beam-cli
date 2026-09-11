import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { clearIdentity, readIdentity, writeIdentity, type Identity } from "../src/enroll.js";

const temporaryDirectories: string[] = [];
const originalEnv = { ...process.env };

beforeEach(() => {
  process.env = { ...originalEnv };
  delete process.env.BEAM_HOME;
  delete process.env.BEAM_DATA_DIR;
});

afterEach(async () => {
  process.env = { ...originalEnv };
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

async function tempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  temporaryDirectories.push(dir);
  return dir;
}

const identity: Identity = {
  deviceId: "dev_1",
  deviceSecret: "bd_secret",
  orgId: "org_1",
  apiBase: "http://127.0.0.1:3200",
  publicKey: "pub",
  privateKey: "priv",
  hostname: "test-host",
  os: "darwin",
  enrolledAt: "2026-01-01T00:00:00.000Z",
};

describe("clearIdentity", () => {
  it("removes the identity file so readIdentity sees this device as unenrolled", async () => {
    process.env.BEAM_DATA_DIR = await tempDir("beam-logout-");
    await writeIdentity(identity);
    await expect(readIdentity()).resolves.not.toBeNull();

    await clearIdentity();
    await expect(readIdentity()).resolves.toBeNull();
  });

  it("is a no-op when nothing is enrolled", async () => {
    process.env.BEAM_DATA_DIR = await tempDir("beam-logout-empty-");
    await expect(clearIdentity()).resolves.toBeUndefined();
  });
});
