import type { Command } from "commander";
import { fetchAccount } from "./account.js";
import { dim, green, red } from "./color.js";
import { readIdentity, type Identity } from "./enroll.js";
import { confirm, renderColumns, withSpinner } from "./prompts.js";
import { ALL_SKILL_AGENTS } from "./skills.js";
import { scanSkillDir, scanSkillFile } from "./skill-scan.js";
import {
  collectShareFiles, deleteShare, detectKind, findCredentials, installShare, KIND_NAMES, listShares, publishShare, SHARE_KINDS, slugify, updateShares,
  type InstallResult, type ShareKind,
} from "./share.js";

async function requireIdentity(): Promise<Identity> {
  const identity = await readIdentity();
  if (!identity) throw new Error("This device isn't connected to a Beam workspace. Run 'beam setup' first.");
  return identity;
}

const kb = (n: number) => `${(n / 1024).toFixed(1)} KB`;
const parseKind = (value?: string): ShareKind | undefined => {
  if (!value) return undefined;
  const kind = value.toUpperCase().replace(/-/g, "_");
  const aliases: Record<string, ShareKind> = { CLAUDE_MD: "INSTRUCTIONS", AGENTS_MD: "INSTRUCTIONS", AGENT: "SUBAGENT", CMD: "COMMAND" };
  const resolved = (SHARE_KINDS as readonly string[]).includes(kind) ? (kind as ShareKind) : aliases[kind];
  if (!resolved) throw new Error(`Unknown kind "${value}". Choose from: ${SHARE_KINDS.map(k => k.toLowerCase()).join(", ")}.`);
  return resolved;
};

function printInstall(result: InstallResult) {
  if (result.blocked) {
    console.log(red(`✖ Not installed: beam's scan on this device blocks "${result.slug}" (risk ${result.scan.score}/100, ${result.scan.level}).`));
    for (const f of result.scan.findings.slice(0, 5)) console.log(`  ${f.severity.padEnd(8)} ${f.title}  ${dim(`${f.file}${f.line ? `:${f.line}` : ""}`)}`);
    console.log(dim("  Review the files in the dashboard's Team library. --force installs anyway."));
    process.exitCode = 1;
    return;
  }
  for (const path of result.installed) console.log(`${green("✔")} ${result.name} v${result.version} → ${path}`);
  for (const path of result.backups) console.log(dim(`  your previous copy was moved to ${path}`));
  for (const path of result.conflicts) {
    console.log(red(`✖ ${path} already exists and wasn't installed by beam from "${result.slug}" (or was edited since).`));
    console.log(dim("  Left untouched. --force replaces it and keeps a backup beside it."));
    process.exitCode = 1;
  }
  if (result.installed.length && result.scan.findings.length) console.log(dim(`  local scan: risk ${result.scan.score}/100 (${result.scan.level}), ${result.scan.findings.length} finding${result.scan.findings.length === 1 ? "" : "s"}`));
}

export function registerShareCommands(program: Command): void {
  const share = program.command("share")
    .description("Share skills, CLAUDE.md, slash commands and subagents with your team, and install what teammates shared");

  share.command("publish <path>", { isDefault: true })
    .description("Share a skill folder, CLAUDE.md / AGENTS.md, slash command, subagent or Cursor rule with your workspace (the default: 'beam share <path>')")
    .option("--kind <kind>", `what it is, when beam can't tell from the path: ${SHARE_KINDS.map(k => k.toLowerCase()).join(", ")}`)
    .option("--name <name>", "display name; also gives the install name (default: the folder or file name)")
    .option("--description <text>", "what it does and when to use it")
    .option("-m, --message <text>", "what changed in this version")
    .option("--yes", "share without the confirmation prompt (required when not in a terminal)")
    .action(async (target: string, options: { kind?: string; name?: string; description?: string; message?: string; yes?: boolean }) => {
      const identity = await requireIdentity();
      const kind = parseKind(options.kind) ?? await detectKind(target);
      if (!kind) throw new Error(`Can't tell what ${target} is. Pass --kind (${SHARE_KINDS.map(k => k.toLowerCase()).join(", ")}).`);
      const collected = await collectShareFiles(target, kind);
      const name = (options.name ?? collected.defaultName).trim();
      const slug = slugify(name);
      if (!slug) throw new Error("Give it a --name with at least one letter or digit.");

      // A credential never leaves this machine, not even to be refused by the workspace.
      const credentials = findCredentials(collected.files);
      if (credentials.length) {
        console.log(red(`✖ Not shared: ${credentials.length === 1 ? "a credential was" : `${credentials.length} credentials were`} found.`));
        for (const c of credentials.slice(0, 10)) console.log(`  ${c.kind} in ${c.file}:${c.line}`);
        console.log(dim("  Remove it (use an environment variable or a placeholder) and run 'beam share' again. Nothing was uploaded."));
        process.exitCode = 1;
        return;
      }

      const scan = kind === "SKILL" ? await scanSkillDir(collected.root, slug) : await scanSkillFile(`${collected.root}/${collected.files[0].path}`);
      const total = collected.files.reduce((sum, f) => sum + Buffer.byteLength(f.content, "utf8"), 0);
      let orgName = "your workspace";
      try { orgName = (await fetchAccount(identity)).org.name; } catch { /* name is cosmetic */ }

      console.log(`\nSharing ${KIND_NAMES[kind]} "${name}" (install name: ${slug}) with ${orgName}: ${collected.files.length} file${collected.files.length === 1 ? "" : "s"}, ${kb(total)}`);
      for (const f of collected.files.slice(0, 25)) console.log(`  ${f.path}`);
      if (collected.files.length > 25) console.log(dim(`  … ${collected.files.length - 25} more`));
      for (const s of collected.skipped.slice(0, 10)) console.log(dim(`  left out: ${s}`));
      console.log(`Local scan: risk ${scan.score}/100 (${scan.level})${scan.findings.length ? `, ${scan.findings.length} finding${scan.findings.length === 1 ? "" : "s"}` : ""}`);
      for (const f of scan.findings.slice(0, 5)) console.log(`  ${f.severity.padEnd(8)} ${f.title}  ${dim(`${f.file}${f.line ? `:${f.line}` : ""}`)}`);
      console.log(dim(`Everyone in ${orgName} will be able to read and install these files.`));

      if (!options.yes) {
        if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("Run with --yes to share from a script.");
        if (!await confirm("\nShare these files?", false)) { console.log("Cancelled. Nothing was uploaded."); return; }
      }
      const result = await withSpinner("Uploading and scanning", () => publishShare(identity, {
        kind, name, slug, description: options.description ?? "", changelog: options.message ?? "", files: collected.files,
      }));
      if (result.unchanged) console.log(`No changes since version ${result.version} of ${result.slug}.`);
      else if (result.status === "APPROVED") console.log(`${green("✔")} Shared ${result.slug} v${result.version}. Teammates install it with:\n  beam share install ${result.slug}`);
      else {
        console.log(`! ${result.slug} v${result.version} is waiting for an administrator's review before teammates can install it.`);
        if (result.findings.length) console.log(dim(`  the workspace's scan flagged: ${[...new Set(result.findings.map(f => f.title))].slice(0, 3).join("; ")}`));
      }
    });

  share.command("list")
    .description("List what your team has shared")
    .option("--kind <kind>", "only one kind")
    .option("--json", "print as JSON")
    .action(async (options: { kind?: string; json?: boolean }) => {
      const identity = await requireIdentity();
      const { sharing, assets } = await listShares(identity, parseKind(options.kind));
      if (options.json) { console.log(JSON.stringify({ sharing, assets }, null, 2)); return; }
      if (!assets.length) {
        console.log(sharing === "OFF" ? "Sharing is turned off for this workspace." : "Nothing has been shared yet. Share a skill with: beam share ./path/to/skill");
        return;
      }
      console.log(renderColumns(["NAME", "KIND", "VERSION", "RISK", "BY"], assets.map(a => [
        a.slug,
        KIND_NAMES[a.kind],
        a.version ? `v${a.version}` : "—",
        a.score === null ? "—" : String(a.score),
        `${a.mine ? "you" : a.author ?? "former member"}${a.pending ? dim(` · v${a.pending.version} ${a.pending.status === "PENDING_REVIEW" ? "awaiting review" : a.pending.status.toLowerCase()}`) : ""}`,
      ])));
      console.log(dim("\nInstall one with: beam share install <name>"));
    });

  share.command("install <name>")
    .description("Install a share from your team library (checked against its content hash and re-scanned first); name@3 pins version 3")
    .option("-a, --agent <agent...>", `for a skill, which agents (${ALL_SKILL_AGENTS.join(", ")})`, ["claude-code"])
    .option("--all-agents", "for a skill, install for every supported agent")
    .option("-g, --global", "install for your user instead of this project")
    .option("--force", "replace files beam didn't install (a backup is kept), and install even if the local scan blocks it")
    .action(async (spec: string, options: { agent?: string[]; allAgents?: boolean; global?: boolean; force?: boolean }) => {
      const identity = await requireIdentity();
      // `name@3` -- the root program owns --version, so a version is given npm-style.
      const [slug, pinned] = spec.split("@");
      const version = pinned === undefined ? undefined : Number(pinned);
      if (version !== undefined && (!Number.isInteger(version) || version < 1)) throw new Error(`"${spec}": give a version number after @, e.g. ${slug}@3.`);
      printInstall(await withSpinner(`Fetching ${spec}`, () => installShare(identity, slug, { ...options, version })));
    });

  share.command("update [name]")
    .description("Update installed shares to their newest approved versions")
    .option("--force", "replace local edits (a backup is kept), and install even if the local scan blocks it")
    .action(async (slug: string | undefined, options: { force?: boolean }) => {
      const identity = await requireIdentity();
      const report = await withSpinner("Checking the team library", () => updateShares(identity, { slug, force: options.force }));
      report.updated.forEach(printInstall);
      for (const s of report.current) console.log(dim(`${s} is up to date.`));
      for (const r of report.removed) console.log(`! ${r.slug} was removed from the team library. Your copy stays at ${r.paths.join(", ")}.`);
      if (!report.updated.length && !report.current.length && !report.removed.length) console.log("Nothing from the team library is installed on this device.");
    });

  share.command("delete <name>")
    .description("Remove something you shared from the team library (copies already installed stay where they are)")
    .option("--yes", "skip the confirmation prompt")
    .action(async (slug: string, options: { yes?: boolean }) => {
      const identity = await requireIdentity();
      if (!options.yes) {
        if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("Run with --yes to delete from a script.");
        if (!await confirm(`Delete "${slug}" and all its versions from the team library? Nobody will be able to install it any more.`, false)) { console.log("Cancelled."); return; }
      }
      await deleteShare(identity, slug);
      console.log(`${green("✔")} Deleted ${slug} from the team library.`);
    });
}
