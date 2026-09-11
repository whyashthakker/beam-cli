import { generateKeyPairSync } from "node:crypto";
import { hostname } from "node:os";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { getApiUrl, getIdentityPath } from "./config.js";

export interface Identity {
  deviceId: string;
  deviceSecret: string;
  orgId: string;
  apiBase: string;
  publicKey: string; // base64 SPKI DER — sent to the collector at enrollment
  privateKey: string; // base64 PKCS8 DER — never leaves this machine
  hostname: string;
  os: string;
  enrolledAt: string;
}

const CODE_RE = /^BEAM-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/;

export async function readIdentity(): Promise<Identity | null> {
  try {
    return JSON.parse(await readFile(getIdentityPath(), "utf8")) as Identity;
  } catch {
    return null;
  }
}

// Shared by every enrollment path (code-based 'beam enroll' and browser-based 'beam connect')
// so the on-disk identity file always has the same shape regardless of how it was obtained.
export async function writeIdentity(identity: Identity): Promise<void> {
  const path = getIdentityPath();
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o600 });
}

// Local half of `beam logout` -- removing the identity file is what actually makes this device
// "not enrolled" to every other command (readIdentity() returning null). Safe to call even when
// nothing is enrolled.
export async function clearIdentity(): Promise<void> {
  await rm(getIdentityPath(), { force: true });
}

// Never blocks anything; enrollment just writes credentials this machine uses later.
export async function enrollDevice(options: { code: string; url?: string }): Promise<Identity> {
  const code = options.code.trim().toUpperCase();
  if (!CODE_RE.test(code)) throw new Error("Code must look like BEAM-XXXX-XXXX-XXXX.");

  const base = (options.url ?? getApiUrl()).replace(/\/+$/, "");

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const priv = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
  const os = process.platform;
  const host = hostname();

  let response: Response;
  try {
    response = await fetch(`${base}/v1/enroll`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, device: { hostname: host, os, public_key: pub } }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error(`Could not reach ${base}. Pass --url or set BEAM_API_URL.`);
  }

  if (!response.ok) {
    let message = `Enrollment rejected (${response.status}).`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch { /* keep the status-only message */ }
    throw new Error(message);
  }

  const data = (await response.json()) as {
    device_id?: string;
    device_secret?: string;
    org_id?: string;
    api_base?: string;
  };
  if (!data.device_id || !data.device_secret || !data.org_id) {
    throw new Error("Enrollment response is missing device credentials.");
  }

  const identity: Identity = {
    deviceId: data.device_id,
    deviceSecret: data.device_secret,
    orgId: data.org_id,
    apiBase: (data.api_base ?? base).replace(/\/+$/, ""),
    publicKey: pub,
    privateKey: priv,
    hostname: host,
    os,
    enrolledAt: new Date().toISOString(),
  };

  await writeIdentity(identity);
  return identity;
}
