// Policy 3 (Network Transport: "HTTPS with TLS 1.2 or higher... unencrypted or self-signed-certificate
// connections are not permitted") and 5.6 (API Tier: official commercial endpoint only). Checks both
// the live environment and shell startup files, since a developer sets these once and forgets them.
import type { AuditContext, Check } from "../types.js";
import { readShellRcFiles } from "../shell-env.js";

const TLS_DISABLE = /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0\b/;

export function tlsVerificationCheck(ctx: AuditContext): Check {
  const base = { id: "3-tls-verification", policySection: "3 (Network Transport)", title: "TLS certificate verification not disabled" };
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    return { ...base, status: "fail", detail: "NODE_TLS_REJECT_UNAUTHORIZED=0 is set in the current environment, which disables TLS certificate verification for all Node.js processes, including Claude Code.", fix: "Unset NODE_TLS_REJECT_UNAUTHORIZED." };
  }
  const hits: string[] = [];
  for (const { path, text } of readShellRcFiles(ctx.home)) {
    for (const line of text.split("\n")) {
      if (TLS_DISABLE.test(line) && !line.trim().startsWith("#")) hits.push(`${path}: ${line.trim()}`);
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
      ? `ANTHROPIC_BASE_URL is set to a custom but trusted Anthropic host (${base_url}).`
      : `ANTHROPIC_BASE_URL (${base_url}) does not point to an https anthropic.com host. Policy 3/5.6 permit only Anthropic's official endpoints.`,
    fix: trusted ? undefined : "Unset ANTHROPIC_BASE_URL unless it has been explicitly approved by the security lead.",
  };
}
