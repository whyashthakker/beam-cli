import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { startConnect } from "../src/connect.js";
import { readIdentity } from "../src/enroll.js";

const temporaryDirectories: string[] = [];
const originalEnv = { ...process.env };
const originalFetch = global.fetch;

beforeEach(() => {
  process.env = { ...originalEnv };
  delete process.env.BEAM_DASHBOARD_URL;
  delete process.env.BEAM_HOME;
  delete process.env.BEAM_DATA_DIR;
});

afterEach(async () => {
  global.fetch = originalFetch;
  process.env = { ...originalEnv };
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

async function tempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  temporaryDirectories.push(dir);
  return dir;
}

describe("startConnect", () => {
  it("builds the dashboard connect URL from the started session's token", async () => {
    process.env.BEAM_DASHBOARD_URL = "http://localhost:3001";
    const fetchMock = jest.fn(async (url: string) => {
      expect(url).toBe("http://localhost:3001/api/connect/start");
      return { ok: true, json: async () => ({ ok: true }) } as Response;
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    const session = await startConnect();
    expect(session.url).toMatch(/^http:\/\/localhost:3001\/connect\?token=[0-9a-f]{64}$/);
  });

  it("throws a clear message when the dashboard is unreachable", async () => {
    process.env.BEAM_DASHBOARD_URL = "http://localhost:3001";
    global.fetch = jest.fn(async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch;
    await expect(startConnect()).rejects.toThrow("Could not reach");
  });

  it("surfaces the server's error message when starting fails", async () => {
    process.env.BEAM_DASHBOARD_URL = "http://localhost:3001";
    global.fetch = jest.fn(async () => ({
      ok: false, status: 400, json: async () => ({ error: "Bad request." }),
    })) as unknown as typeof fetch;
    await expect(startConnect()).rejects.toThrow("Bad request.");
  });

  describe("poll", () => {
    it("keeps polling on 202 pending, then writes the identity once authorized", async () => {
      process.env.BEAM_DASHBOARD_URL = "http://localhost:3001";
      process.env.BEAM_HOME = await tempDir("beam-connect-home-");

      let pollCount = 0;
      const fetchMock = jest.fn(async (url: string, init?: RequestInit) => {
        if (url.endsWith("/api/connect/start")) return { ok: true, json: async () => ({ ok: true }) } as Response;
        expect(url).toBe("http://localhost:3001/api/connect/poll");
        pollCount += 1;
        if (pollCount < 3) return { ok: false, status: 202, json: async () => ({ status: "pending" }) } as Response;
        return {
          ok: true, status: 200,
          // A server that tries to hand back a different api_base must be ignored -- see below.
          json: async () => ({ device_id: "dev_1", device_secret: "secret", org_id: "org_1", api_base: "http://127.0.0.1:3200" }),
        } as Response;
      });
      global.fetch = fetchMock as unknown as typeof fetch;

      const session = await startConnect();
      const identity = await session.poll({ intervalMs: 1 });

      expect(identity.deviceId).toBe("dev_1");
      expect(identity.orgId).toBe("org_1");
      // Always the CLI's own configured base (BEAM_DASHBOARD_URL here), never the server's
      // api_base -- a misconfigured or malicious server can't redirect future device traffic.
      expect(identity.apiBase).toBe("http://localhost:3001");
      expect(pollCount).toBe(3);
      await expect(readIdentity()).resolves.toMatchObject({ deviceId: "dev_1" });
    });

    it("throws once the connect request has expired (404)", async () => {
      process.env.BEAM_DASHBOARD_URL = "http://localhost:3001";
      process.env.BEAM_HOME = await tempDir("beam-connect-home-");

      const fetchMock = jest.fn(async (url: string) => {
        if (url.endsWith("/api/connect/start")) return { ok: true, json: async () => ({ ok: true }) } as Response;
        return { ok: false, status: 404, json: async () => ({ status: "expired" }) } as Response;
      });
      global.fetch = fetchMock as unknown as typeof fetch;

      const session = await startConnect();
      await expect(session.poll({ intervalMs: 1 })).rejects.toThrow("expired");
    });

    it("times out if never authorized within the given window", async () => {
      process.env.BEAM_DASHBOARD_URL = "http://localhost:3001";
      process.env.BEAM_HOME = await tempDir("beam-connect-home-");

      const fetchMock = jest.fn(async (url: string) => {
        if (url.endsWith("/api/connect/start")) return { ok: true, json: async () => ({ ok: true }) } as Response;
        return { ok: false, status: 202, json: async () => ({ status: "pending" }) } as Response;
      });
      global.fetch = fetchMock as unknown as typeof fetch;

      const session = await startConnect();
      await expect(session.poll({ intervalMs: 1, timeoutMs: 5 })).rejects.toThrow("Timed out");
    });
  });
});
