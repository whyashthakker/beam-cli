import { generateKeyPairSync, randomBytes } from "node:crypto";
import { hostname } from "node:os";
import { getDashboardUrl } from "./config.js";
import { writeIdentity, type Identity } from "./enroll.js";

export interface ConnectSession {
  /** Open this in a browser; the dashboard authorizes the pending request once the user is signed in. */
  url: string;
  /** Waits for the dashboard to authorize the request, then writes and returns the resulting identity. */
  poll: (options?: { timeoutMs?: number; intervalMs?: number }) => Promise<Identity>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readError(response: Response, fallback: string): Promise<string> {
  try {
    const body = (await response.json()) as { error?: string };
    return body.error ?? fallback;
  } catch {
    return fallback;
  }
}

// Starts a browser-based pairing request: registers this device's public key and a one-time
// connect token with the dashboard, then hands back a URL to open and a poll() to wait on.
// Unlike 'beam enroll', there's no code to type -- the dashboard authorizes the token once the
// signed-in user's browser session confirms it, and poll() picks that up on the CLI side.
export async function startConnect(): Promise<ConnectSession> {
  const base = getDashboardUrl();
  const token = randomBytes(32).toString("hex");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const priv = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
  const os = process.platform;
  const host = hostname();

  let response: Response;
  try {
    response = await fetch(`${base}/api/connect/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, device: { hostname: host, os, public_key: pub } }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error(`Could not reach ${base}. Is the dashboard running?`);
  }
  if (!response.ok) throw new Error(await readError(response, `Could not start a connection request (${response.status}).`));

  const url = `${base}/connect?token=${encodeURIComponent(token)}`;

  async function poll(options: { timeoutMs?: number; intervalMs?: number } = {}): Promise<Identity> {
    const timeoutMs = options.timeoutMs ?? 5 * 60_000;
    const intervalMs = options.intervalMs ?? 2000;
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      let pollResponse: Response;
      try {
        pollResponse = await fetch(`${base}/api/connect/poll`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
          signal: AbortSignal.timeout(10_000),
        });
      } catch {
        await sleep(intervalMs);
        continue;
      }

      if (pollResponse.status === 202) { await sleep(intervalMs); continue; }
      if (pollResponse.status === 404) throw new Error("Connection request expired. Run 'beam connect' again.");
      if (!pollResponse.ok) throw new Error(await readError(pollResponse, `Connection request failed (${pollResponse.status}).`));

      const data = (await pollResponse.json()) as {
        device_id?: string;
        device_secret?: string;
        org_id?: string;
      };
      if (!data.device_id || !data.device_secret || !data.org_id) {
        throw new Error("Connect response is missing device credentials.");
      }

      const identity: Identity = {
        deviceId: data.device_id,
        deviceSecret: data.device_secret,
        orgId: data.org_id,
        // Always the CLI's own configured base (BEAM_DASHBOARD_URL or the app.agentbeam.com
        // default) -- never whatever the server hands back, so a misconfigured deployment can't
        // redirect a device's future traffic to the wrong host.
        apiBase: base,
        publicKey: pub,
        privateKey: priv,
        hostname: host,
        os,
        enrolledAt: new Date().toISOString(),
      };
      await writeIdentity(identity);
      return identity;
    }

    throw new Error("Timed out waiting for confirmation in the browser. Run 'beam connect' again.");
  }

  return { url, poll };
}
