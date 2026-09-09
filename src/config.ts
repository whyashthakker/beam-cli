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
