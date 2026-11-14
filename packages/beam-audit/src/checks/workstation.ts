// Policy 6.3 Workstation Security. Written for Windows 10 + BitLocker; each check is platform-gated
// and falls back to "skip" (not "fail") when the platform-specific command isn't available, rather
// than guessing at an OS it can't inspect.
import { spawnSync } from "node:child_process";
import type { AuditContext, Check } from "../types.js";

function run(cmd: string, args: string[]): { status: number | null; stdout: string } {
  const res = spawnSync(cmd, args, { encoding: "utf8", timeout: 10_000 });
  return { status: res.status, stdout: typeof res.stdout === "string" ? res.stdout : "" };
}

function diskEncryptionCheck(ctx: AuditContext): Check {
  const base = { id: "6.3-disk-encryption", policySection: "6.3 (Workstation Security)", title: "Full-disk encryption enabled" };
  if (ctx.platform === "darwin") {
    const { status, stdout } = run("fdesetup", ["status"]);
    if (status === 0 && /FileVault is On/i.test(stdout)) return { ...base, status: "pass", detail: "FileVault is enabled.", evidence: [stdout.trim()] };
    return { ...base, status: status === 0 ? "fail" : "skip", detail: status === 0 ? "FileVault is not enabled on this Mac." : "FileVault state unavailable.", evidence: [stdout.trim() || "fdesetup status returned no output"], fix: "Enable FileVault via System Settings > Privacy & Security > FileVault, or `sudo fdesetup enable`." };
  }
  if (ctx.platform === "win32") {
    const { status, stdout } = run("manage-bde", ["-status"]);
    if (status === 0 && /Protection Status:\s*Protection On/i.test(stdout)) return { ...base, status: "pass", detail: "BitLocker is enabled.", evidence: [stdout.trim()] };
    return { ...base, status: status === 0 ? "warn" : "skip", detail: "BitLocker state is disabled, ambiguous, or unavailable; verify each volume.", evidence: [stdout.trim() || "manage-bde -status returned no output"], fix: "Enable BitLocker per policy 6.3." };
  }
  return { ...base, status: "skip", detail: `No automated disk-encryption check for platform "${ctx.platform}". Verify full-disk encryption (e.g. LUKS) manually.` };
}

function screenLockCheck(ctx: AuditContext): Check {
  const base = { id: "6.3-screen-lock", policySection: "6.3 (Workstation Security)", title: "Automatic screen lock <= 5 minutes" };
  if (ctx.platform === "darwin") {
    const { stdout } = run("defaults", ["-currentHost", "read", "com.apple.screensaver", "idleTime"]);
    const seconds = Number.parseInt(stdout.trim(), 10);
    if (Number.isFinite(seconds) && seconds > 0 && seconds <= 300) return { ...base, status: "pass", detail: `Screensaver idle time is ${seconds}s (<= 300s).`, evidence: [stdout.trim()] };
    return {
      ...base, status: Number.isFinite(seconds) ? "fail" : "skip",
      detail: Number.isFinite(seconds) ? `Screensaver idle time is ${seconds}s, exceeding the 5-minute maximum.` : "Could not read screensaver idle time (requires a logged-in GUI session).",
      evidence: [stdout.trim() || "no value returned"],
      fix: "Set System Settings > Lock Screen > screensaver timeout to 5 minutes or less, with a password required immediately after.",
    };
  }
  if (ctx.platform === "win32") {
    const result = run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name InactivityTimeoutSecs -ErrorAction Stop"]);
    const seconds = Number(result.stdout.trim());
    return { ...base, status: result.status !== 0 || !result.stdout.trim() ? "skip" : seconds > 0 && seconds <= 300 ? "pass" : "fail", detail: "Checked Windows machine inactivity timeout policy; other screen-lock mechanisms were not evaluated." };
  }
  return { ...base, status: "skip", detail: `No automated screen-lock check for platform "${ctx.platform}".` };
}

function osPatchLevelCheck(ctx: AuditContext): Check {
  const base = { id: "6.3-os-patch-level", policySection: "6.3 (Workstation Security)", title: "OS patched to latest cumulative update" };
  if (ctx.platform === "darwin") {
    if (!ctx.online) return { ...base, status: "skip", detail: "Pending macOS updates require --online." };
    const { status, stdout } = run("softwareupdate", ["-l"]);
    const version = run("sw_vers", ["-productVersion"]).stdout.trim();
    if (status === 0 && /No new software available/i.test(stdout)) return { ...base, status: "pass", detail: `No pending macOS updates (running ${version || "unknown version"}).`, evidence: [stdout.trim()] };
    return { ...base, status: stdout.trim() ? "fail" : "skip", detail: `macOS ${version || ""} has pending updates or the check was inconclusive (requires network access).`, evidence: [stdout.trim() || "softwareupdate -l returned no output"], fix: "Apply pending macOS updates via System Settings > General > Software Update." };
  }
  return { ...base, status: "skip", detail: `No automated OS patch check for platform "${ctx.platform}". The policy specifies Windows 10 fully patched; verify via Windows Update.` };
}

function endpointProtectionCheck(ctx: AuditContext): Check {
  const base = { id: "6.3-endpoint-protection", policySection: "6.3 (Workstation Security)", title: "Endpoint protection / EDR active" };
  if (ctx.platform === "win32") {
    const result = run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress"]);
    try { const state = JSON.parse(result.stdout); return { ...base, status: result.status !== 0 ? "skip" : state.AntivirusEnabled && state.RealTimeProtectionEnabled && state.AntivirusSignatureAge <= 1 ? "pass" : "warn", detail: "Checked Microsoft Defender enablement, real-time protection, and signature age. Third-party EDR needs separate verification." }; } catch { return { ...base, status: "skip", detail: "Microsoft Defender state unavailable." }; }
  }
  const KNOWN = ["CrowdStrike", "Carbon Black", "SentinelOne", "Defender", "MsMpEng", "Sophos", "Malwarebytes", "ClamAV", "clamd", "cbagentd", "falcond"];
  if (ctx.platform === "darwin") {
    const { stdout } = run("ps", ["-axo", "comm"]);
    const found = KNOWN.filter(k => stdout.toLowerCase().includes(k.toLowerCase()));
    if (found.length > 0) return { ...base, status: "pass", detail: `Detected endpoint protection process: ${found.join(", ")}.`, evidence: found };
    return { ...base, status: "skip", detail: "No known third-party EDR/AV process detected; macOS includes built-in XProtect/Gatekeeper, but the policy requires an active AV/EDR solution -- confirm which product fulfils this." };
  }
  return { ...base, status: "skip", detail: `No automated endpoint-protection check for platform "${ctx.platform}".` };
}

export function workstationChecks(ctx: AuditContext): Check[] {
  return [diskEncryptionCheck(ctx), screenLockCheck(ctx), osPatchLevelCheck(ctx), endpointProtectionCheck(ctx)];
}
