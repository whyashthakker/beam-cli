// Policy 3 (Network Transport: "HTTPS with TLS 1.2 or higher... unencrypted or self-signed-certificate
// connections are not permitted") and 5.6 (API Tier: official commercial endpoint only). Checks both
// the live environment and shell startup files, since a developer sets these once and forgets them.
import { readFileSync } from "node:fs";
import type { AuditContext, Check } from "../types.js";
import { readShellRcFiles } from "../shell-env.js";

const ANTHROPIC_HOST = /(?:^|\.)anthropic\.com$/i;

// A /etc/hosts (or Windows equivalent) entry for Anthropic's domain is a persistent MITM primitive:
// it silently redirects every agent on the machine regardless of what ANTHROPIC_BASE_URL says, and
// survives reboots and new terminals. No legitimate commercial-API setup needs one.
export function hostsFileCheck(ctx: AuditContext, readHosts: () => string = () => readFileSync(ctx.platform === "win32" ? "C:\\Windows\\System32\\drivers\\etc\\hosts" : "/etc/hosts", "utf8")): Check {
  const base = { id: "3-hosts-file-override", policySection: "3, 6.5 (Network Transport)", title: "No hosts-file override for Anthropic's domain" };
  let text: string;
  try { text = readHosts(); } catch { return { ...base, status: "skip", detail: "Hosts file could not be read." }; }
  const hits: string[] = [];
  for (const line of text.split("\n")) {
    const stripped = line.replace(/#.*$/, "").trim();
    if (!stripped) continue;
    const [ip, ...hostnames] = stripped.split(/\s+/);
    if (ip && hostnames.some(h => ANTHROPIC_HOST.test(h))) hits.push(`Hosts-file entry maps an anthropic.com hostname to a configured address (address omitted).`);
  }
  return {
    ...base,
    status: hits.length > 0 ? "fail" : "pass",
    detail: hits.length > 0
      ? `${hits.length} hosts-file entry/entries redirect an anthropic.com hostname to another address. This overrides DNS for every process on the machine, including Claude Code, regardless of any endpoint allowlist in its own configuration.`
      : "No hosts-file entries override an anthropic.com hostname.",
    evidence: hits,
    fix: hits.length > 0 ? "Remove the anthropic.com entry from the hosts file unless it is an explicitly approved, documented proxy/testing setup." : undefined,
  };
}

const TLS_DISABLE = /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0\b/;

export function tlsVerificationCheck(ctx: AuditContext): Check {
  const base = { id: "3-tls-verification", policySection: "3 (Network Transport)", title: "TLS certificate verification not disabled" };
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    return { ...base, status: "fail", detail: "NODE_TLS_REJECT_UNAUTHORIZED=0 is set in the current environment, which disables TLS certificate verification for all Node.js processes, including Claude Code.", fix: "Unset NODE_TLS_REJECT_UNAUTHORIZED." };
  }
  const hits: string[] = [];
  for (const { path, text } of readShellRcFiles(ctx.home)) {
    for (const line of text.split("\n")) {
      if (TLS_DISABLE.test(line) && !line.trim().startsWith("#")) hits.push(`${path}: TLS verification disabling declaration (value omitted)`);
    }
  }
  return {
    ...base,
    status: hits.length > 0 ? "fail" : "pass",
    detail: hits.length > 0
      ? "Shell startup files permanently disable TLS certificate verification via NODE_TLS_REJECT_UNAUTHORIZED=0."
      : "TLS certificate verification is not disabled in the current environment or shell startup files.",
    evidence: hits,
    fix: hits.length > 0 ? "Remove the line from the listed shell startup file(s)." : undefined,
  };
}

export function apiEndpointCheck(): Check {
  const base = { id: "5.6-api-endpoint", policySection: "3, 5.6 (API Tier)", title: "Anthropic API endpoint is official" };
  const base_url = process.env.ANTHROPIC_BASE_URL;
  if (!base_url) {
    return { ...base, status: "pass", detail: "ANTHROPIC_BASE_URL is not set; using Anthropic's default endpoint." };
  }
  let trusted = false;
  try {
    const url = new URL(base_url);
    trusted = url.protocol === "https:" && (url.hostname === "anthropic.com" || url.hostname.endsWith(".anthropic.com"));
  } catch {
    trusted = false;
  }
  return {
    ...base,
    status: trusted ? "pass" : "fail",
    detail: trusted
      ? `ANTHROPIC_BASE_URL is set to a custom but trusted Anthropic host (configured value omitted).`
      : `ANTHROPIC_BASE_URL (configured value omitted) does not point to an https anthropic.com host. Policy 3/5.6 permit only Anthropic's official endpoints.`,
    fix: trusted ? undefined : "Unset ANTHROPIC_BASE_URL unless it has been explicitly approved by the security lead.",
  };
}
