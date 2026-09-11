import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { fetchAccount, revokeDevice } from "../src/account.js";
import type { Identity } from "../src/enroll.js";

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
});

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

describe("fetchAccount", () => {
  it("sends the device secret as a bearer token and returns the parsed account", async () => {
    const fetchMock = jest.fn(async (url: string, init: RequestInit) => {
      expect(url).toBe("http://127.0.0.1:3200/v1/account");
      expect((init.headers as Record<string, string>).Authorization).toBe("Bearer bd_secret");
      return {
        ok: true,
        json: async () => ({
          user: { email: "a@example.com", name: "A" },
          org: { id: "org_1", name: "Acme", slug: "acme" },
          device: { id: "dev_1", hostname: "test-host", os: "darwin", status: "ACTIVE", enrolled_at: "2026-01-01T00:00:00.000Z" },
        }),
      } as Response;
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    const account = await fetchAccount(identity);
    expect(account.user.email).toBe("a@example.com");
    expect(account.org.slug).toBe("acme");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("throws a clear message when the device was revoked", async () => {
    global.fetch = jest.fn(async () => ({
      ok: false, status: 401, json: async () => ({ error: "Unknown or revoked device." }),
    })) as unknown as typeof fetch;

    await expect(fetchAccount(identity)).rejects.toThrow("revoked");
  });

  it("throws a clear message when the API is unreachable", async () => {
    global.fetch = jest.fn(async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch;
    await expect(fetchAccount(identity)).rejects.toThrow("Could not reach");
  });
});

describe("revokeDevice", () => {
  it("posts to /v1/logout with the device secret as a bearer token", async () => {
    const fetchMock = jest.fn(async (url: string, init: RequestInit) => {
      expect(url).toBe("http://127.0.0.1:3200/v1/logout");
      expect(init.method).toBe("POST");
      expect((init.headers as Record<string, string>).Authorization).toBe("Bearer bd_secret");
      return { ok: true, status: 200, json: async () => ({ ok: true }) } as Response;
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    await expect(revokeDevice(identity)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("treats an already-revoked device (401) as success, not an error", async () => {
    global.fetch = jest.fn(async () => ({ ok: false, status: 401, json: async () => ({ error: "Unknown or already revoked device." }) })) as unknown as typeof fetch;
    await expect(revokeDevice(identity)).resolves.toBeUndefined();
  });

  it("throws a clear message when the API is unreachable", async () => {
    global.fetch = jest.fn(async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch;
    await expect(revokeDevice(identity)).rejects.toThrow("Could not reach");
  });

  it("surfaces other server errors instead of silently succeeding", async () => {
    global.fetch = jest.fn(async () => ({ ok: false, status: 500, json: async () => ({ error: "Internal error." }) })) as unknown as typeof fetch;
    await expect(revokeDevice(identity)).rejects.toThrow("Internal error.");
  });
});
