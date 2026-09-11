import os from "node:os";
import path from "node:path";

export function getBeamHome(): string {
  return process.env.BEAM_HOME ? path.resolve(process.env.BEAM_HOME) : path.join(os.homedir(), ".beam");
}

export function getDataDirectory(): string {
  return process.env.BEAM_DATA_DIR ? path.resolve(process.env.BEAM_DATA_DIR) : path.join(getBeamHome(), "data");
}

export function getCollectorUrl(): URL {
  const url = new URL(process.env.BEAM_COLLECTOR_URL || "http://127.0.0.1:4319");
  if (url.protocol !== "http:" || !["localhost", "127.0.0.1"].includes(url.hostname)) throw new Error("Collector must be on HTTP loopback.");
  return url;
}

// The Beam workspace API (dashboard / control plane) this device enrolls with and
// reports to. Not loopback-restricted — this is the remote SaaS endpoint.
export function getApiUrl(): string {
  return (process.env.BEAM_API_URL || "https://app.agentbeam.com").replace(/\/+$/, "");
}

export function getIdentityPath(): string {
  return path.join(getDataDirectory(), "identity.json");
}

// The dashboard (agentbeam) web app that `beam connect` pairs this device with.
export function getDashboardUrl(): string {
  return (process.env.BEAM_DASHBOARD_URL || "https://app.agentbeam.com").replace(/\/+$/, "");
}
