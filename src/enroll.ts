import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { getIdentityPath } from "./config.js";

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

export async function readIdentity(): Promise<Identity | null> {
  try {
    return JSON.parse(await readFile(getIdentityPath(), "utf8")) as Identity;
  } catch {
    return null;
  }
}

// Written by the browser-based connect flow ('beam setup' / 'beam connect').
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
