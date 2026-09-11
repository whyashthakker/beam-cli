import type { Identity } from "./enroll.js";

export interface Account {
  user: { email: string; name: string | null };
  org: { id: string; name: string; slug: string };
  device: { id: string; hostname: string; os: string; status: string; enrolled_at: string };
}

// identity.json only holds opaque device/org ids -- this resolves them into the human-readable
// email/org name the workspace actually knows, via the same Bearer-device-secret auth every
// other /v1/* call (sync, hook forwarding) already uses.
export async function fetchAccount(identity: Identity): Promise<Account> {
  let response: Response;
  try {
    response = await fetch(`${identity.apiBase}/v1/account`, {
      headers: { Authorization: `Bearer ${identity.deviceSecret}` },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error(`Could not reach ${identity.apiBase}.`);
  }

  if (!response.ok) {
    let message = `Could not fetch account details (${response.status}).`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch { /* keep the status-only message */ }
    if (response.status === 401) message = "This device's credentials were revoked. Run 'beam enroll' or 'beam connect' again.";
    throw new Error(message);
  }

  return (await response.json()) as Account;
}

// Self-service revoke: the device turns off its own credential. Called by `beam logout` before
// the identity file is deleted locally, so the deviceSecret still has a chance to authenticate.
// Best-effort -- if the workspace is unreachable, `beam logout` still clears local state so the
// CLI is never stuck "connected" just because the network call failed.
export async function revokeDevice(identity: Identity): Promise<void> {
  let response: Response;
  try {
    response = await fetch(`${identity.apiBase}/v1/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${identity.deviceSecret}` },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error(`Could not reach ${identity.apiBase}.`);
  }

  // Already revoked (or never valid) -- fine, that's the state we want anyway.
  if (response.status === 401) return;

  if (!response.ok) {
    let message = `Could not revoke this device (${response.status}).`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch { /* keep the status-only message */ }
    throw new Error(message);
  }
}
