// Policy 4.2 applied to every repository on the machine: are any of the prohibited data categories
// (credentials, PII, PHI, customer data, trade secrets, DB schemas, network topology) sitting in a
// workspace Claude Code could read, with nothing gitignoring or flagging it?
import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { spawnSync } from "node:child_process";
import type { AuditContext, Check } from "../types.js";
import { confidentHits, phiHits, CONFIDENTIAL_MARKER, SCHEMA_FILE, SENSITIVE_FIELD_NAME, type DetectorKind } from "../detectors.js";

const MAX_FILE_BYTES = 1_000_000;
const SKIP_EXT = /\.(?:png|jpg|jpeg|gif|webp|ico|woff2?|ttf|eot|mp4|mov|zip|gz|pdf|lock)$|(?:^|\/)(?:package-lock\.json|pnpm-lock\.yaml|composer\.lock|Cargo\.lock|poetry\.lock)$/i;
// Directory-based AND filename-based fixture markers -- "seed-test-users.ts" or
// "test-workshop-emails.ts" at the repo root never lands inside a tests?/ directory, but is
// exactly as much a synthetic fixture (permitted by policy 4.1) as one that does.
const FIXTURE_PATH = /(^|\/)(?:tests?|__tests__|__fixtures__|fixtures?|safety-bench|test-data|testdata|mocks?|examples?|samples?)(\/|$)|(?:^|\/)[\w.-]*\b(?:test|spec|seed|fixture|mock)\b[\w.-]*\.(?:ts|tsx|js|jsx|mjs|cjs|py)$/i;

// .env.example / .env.sample / .env.template etc. are placeholder templates explicitly permitted
// by policy 4.1 -- they must NOT be treated as leaked credentials just because the base name is .env,
// neither by path (the file itself isn't a real credential file) nor by content (its placeholder
// values, e.g. EMAIL_FROM=noreply@example.com, aren't leaked PII either).
const TEMPLATE_ENV = /\.env(?:\.[\w-]+)*\.(?:example|sample|template|dist|defaults?)$/i;
const PRIVATE_PATH = /(?:^|[/\\])\.env(?:\.[\w-]+)?$|\.ssh[/\\]|\.aws[/\\]credentials\b|id_(?:rsa|ed25519)|\.npmrc\b|\.netrc\b|kubeconfig|\.pgpass\b|credentials\.json|\.docker[/\\]config\.json|\.gnupg[/\\]/i;
const isCredentialPath = (path: string) => PRIVATE_PATH.test(path) && !TEMPLATE_ENV.test(path);

// Customer-data file detection is filename-only (there's no reliable content signal for "this row
// is a real customer," as opposed to PII, which the content scan below catches separately). A bare
// `.bak`/`.db` extension matches almost anything, so require a customer/production-sounding keyword
// in the name rather than extension alone.
export const CUSTOMER_DATA_NAME = /(?:customers?|clients?|patients?|members?|employees?|subscribers?|prod(?:uction)?[-_]?(?:dump|data|export|backup))[\w.-]*\.(?:csv|tsv|sql|json|jsonl|ndjson|xlsx?|parquet|dump|bak|sqlite3?|db)$/i;

// Low-precision / noisy-on-prose kinds (PASSWORD, EMAIL, PHONE, GOV_ID, ADDRESS, CREDIT_CARD, IBAN)
// are skipped on documentation/prose files -- a README mentioning a support email or a sample
// password in a code block is not a leak. Literal API keys/tokens are still scanned everywhere,
// since a real key pasted into a README is still a real key.
const DOC_EXT = /\.(?:md|mdx|txt|rst|adoc)$/i;
const PROSE_KINDS: ReadonlySet<DetectorKind> = new Set(["PASSWORD", "EMAIL", "PHONE", "GOV_ID", "ADDRESS", "CREDIT_CARD", "IBAN", "SSN"]);

// i18n/locale dictionaries are full of the literal word "password" as a UI label ("password":
// "Passwort") -- that's a translation string, not a credential. PASSWORD is excluded there too.
const I18N_PATH = /(?:^|\/)(?:i18n|locales?|lang(?:uages)?|translations?)\//i;

function trackedFiles(repo: string): string[] {
  const res = spawnSync("git", ["-C", repo, "ls-files"], { encoding: "utf8", timeout: 15_000 });
  if (res.status !== 0 || typeof res.stdout !== "string") return [];
  return res.stdout.split("\n").filter(Boolean);
}

function isIgnored(repo: string, path: string): boolean {
  return spawnSync("git", ["-C", repo, "check-ignore", "-q", path], { timeout: 5_000 }).status === 0;
}

export function repoDataExposureCheck(ctx: AuditContext): Check[] {
  const credentialFiles: string[] = [];
  const dataHits = new Map<string, Set<DetectorKind>>();
  const phiFiles = new Map<string, Set<string>>();
  const customerDataFiles: string[] = [];
  const confidentialFiles: string[] = [];
  const schemaFieldHits = new Map<string, Set<string>>();

  for (const repo of ctx.repos) {
    for (const file of trackedFiles(repo)) {
      if (FIXTURE_PATH.test(file)) continue;
      const label = `${relative(ctx.home, repo)}/${file}`;

      if (isCredentialPath(file)) { credentialFiles.push(label); continue; }
      if (CUSTOMER_DATA_NAME.test(file)) customerDataFiles.push(label);
      if (SKIP_EXT.test(file) || TEMPLATE_ENV.test(file)) continue;

      let text: string;
      try {
        const buf = readFileSync(join(repo, file));
        if (buf.byteLength > MAX_FILE_BYTES) continue;
        text = buf.toString("utf8");
      } catch {
        continue;
      }

      const isProse = DOC_EXT.test(file);
      const isI18n = I18N_PATH.test(file);
      const hits = confidentHits(text).filter(h => (!isProse || !PROSE_KINDS.has(h.kind)) && (!isI18n || h.kind !== "PASSWORD"));
      if (hits.length > 0) {
        const kinds = dataHits.get(label) ?? new Set<DetectorKind>();
        for (const h of hits) kinds.add(h.kind);
        dataHits.set(label, kinds);
      }

      const phi = phiHits(text);
      if (phi.length > 0) {
        const kinds = phiFiles.get(label) ?? new Set<string>();
        for (const h of phi) kinds.add(h.kind);
        phiFiles.set(label, kinds);
      }

      if (CONFIDENTIAL_MARKER.test(text)) confidentialFiles.push(label);

      if (SCHEMA_FILE.test(file)) {
        const fields = new Set<string>();
        for (const m of text.matchAll(new RegExp(SENSITIVE_FIELD_NAME.source, "gi"))) fields.add(m[0].toLowerCase());
        if (fields.size > 0) schemaFieldHits.set(label, fields);
      }
    }

    // Untracked private-path files that aren't gitignored yet are the same exposure, just not committed.
    const untracked = spawnSync("git", ["-C", repo, "status", "--porcelain", "--untracked-files=all"], { encoding: "utf8", timeout: 15_000 });
    if (untracked.status === 0 && typeof untracked.stdout === "string") {
      for (const line of untracked.stdout.split("\n")) {
        const path = line.slice(3).trim();
        if (!path || FIXTURE_PATH.test(path) || !isCredentialPath(path)) continue;
        if (!isIgnored(repo, path)) credentialFiles.push(`${relative(ctx.home, repo)}/${path} (untracked, not gitignored)`);
      }
    }
  }

  const checks: Check[] = [];

  checks.push({
    id: "credential-files-present",
    policySection: "4.2 (Production credentials)",
    title: "Credential files present and reachable by Claude Code",
    status: credentialFiles.length > 0 ? "fail" : "pass",
    detail: credentialFiles.length > 0
      ? `${credentialFiles.length} credential-shaped file(s) (.env, id_rsa, credentials.json, kubeconfig, ...) are tracked or untracked-but-ungitignored across scanned repositories. .env.example/.sample/.template placeholders are excluded. Any of these can be auto-included in a Claude Code workspace context.`
      : "No .env / SSH key / cloud-credential files found tracked or ungitignored across scanned repositories.",
    evidence: credentialFiles.slice(0, 50),
    fix: credentialFiles.length > 0 ? "Add these paths to .gitignore immediately; if already tracked, `git rm --cached` them and rotate anything real." : undefined,
  });

  const realDataHits = [...dataHits.entries()].filter(([, kinds]) => kinds.size > 0);
  checks.push({
    id: "pii-financial-literal-content",
    policySection: "4.2 (PII / financial data)",
    title: "PII or financial-data patterns in tracked files",
    status: realDataHits.length > 0 ? "fail" : "pass",
    detail: realDataHits.length > 0
      ? `${realDataHits.length} tracked, non-fixture file(s) contain content shaped like PII or payment data (documentation/prose files are excluded for the noisy pattern kinds). This does not include personal names -- that category isn't reliably detectable with pattern matching and is flagged separately as not checked.`
      : "No PII/financial-data-shaped content found in tracked, non-fixture, non-documentation files.",
    evidence: realDataHits.slice(0, 50).map(([f, kinds]) => `${f} (${[...kinds].join(", ")})`),
    fix: realDataHits.length > 0 ? "Remove or sanitize this data before opening the repo in a Claude Code workspace; replace with clearly fictitious values per policy 4.1's mandatory sanitisation requirement." : undefined,
  });

  checks.push({
    id: "pii-names-not-checkable",
    policySection: "4.2 (PII - names)",
    title: "Personal names in content",
    status: "skip",
    detail: "Not checked. Detecting real personal names in free text reliably requires a named-entity-recognition model, not pattern matching -- a regex-based attempt would either miss most real names or flag nearly every capitalized word pair. Reported honestly as not covered rather than faked.",
  });

  const phiEntries = [...phiFiles.entries()];
  checks.push({
    id: "phi-literal-content",
    policySection: "4.2 (PHI)",
    title: "Protected Health Information patterns in tracked files",
    status: phiEntries.length > 0 ? "fail" : "pass",
    detail: phiEntries.length > 0
      ? `${phiEntries.length} tracked file(s) contain a labelled medical-record number, health-plan ID, or ICD-10 diagnosis code (e.g. "mrn: ...", "icd-10: ..."). Free-text clinical notes (diagnosis/medication/allergy written as prose) are NOT covered -- tested and dropped because it fired on ordinary blog headlines using "Diagnosis:" rhetorically, which no cheap regex can tell apart from a real clinical note.`
      : "No labelled MRN, health-plan ID, or ICD-10 code found in tracked files. (Free-text clinical notes aren't covered -- see this check's own note on why.)",
    evidence: phiEntries.slice(0, 50).map(([f, kinds]) => `${f} (${[...kinds].join(", ")})`),
    fix: phiEntries.length > 0 ? "Remove or sanitize this data before opening the repo in a Claude Code workspace, per policy 4.1's mandatory sanitisation requirement." : undefined,
  });

  checks.push({
    id: "customer-data-files",
    policySection: "4.2 (Customer data / client records)",
    title: "Customer-data-shaped files in the workspace",
    status: customerDataFiles.length > 0 ? "warn" : "pass",
    detail: customerDataFiles.length > 0
      ? `${customerDataFiles.length} file(s) are named like a customer/production data export (CSV/SQL/JSON dump). This is a filename heuristic only -- it does not confirm the file actually contains real customer records. Confirm manually before using Claude Code in this workspace.`
      : "No files named like a customer/production data export were found.",
    evidence: customerDataFiles.slice(0, 50),
    fix: customerDataFiles.length > 0 ? "Move real customer data out of any directory Claude Code has access to, per policy 4.3 Workspace Isolation." : undefined,
  });

  checks.push({
    id: "confidential-marker",
    policySection: "4.2 (Proprietary / trade secret)",
    title: "Files explicitly marked confidential or trade secret",
    status: confidentialFiles.length > 0 ? "warn" : "pass",
    detail: confidentialFiles.length > 0
      ? `${confidentialFiles.length} file(s) contain an explicit marker ("PROPRIETARY AND CONFIDENTIAL", "TRADE SECRET", "INTERNAL USE ONLY", ...). Policy 4.2 names exactly this category ("source code explicitly marked as confidential"); this only catches an explicit textual marker, not proprietary logic in general, which isn't detectable without understanding the business.`
      : 'No explicit confidentiality/trade-secret markers found in tracked files.',
    evidence: confidentialFiles.slice(0, 50),
    fix: confidentialFiles.length > 0 ? "Confirm these files should be in a workspace Claude Code can read; move them out if not." : undefined,
  });

  const schemaEntries = [...schemaFieldHits.entries()];
  checks.push({
    id: "db-schema-sensitive-fields",
    policySection: "4.2 (DB schemas / data dictionaries)",
    title: "Database schema files with PII/financial/health field names",
    status: schemaEntries.length > 0 ? "warn" : "pass",
    detail: schemaEntries.length > 0
      ? `${schemaEntries.length} schema-shaped file(s) (.sql, .prisma, .graphql, migrations/) define column/field names that map to PII, financial, or health data (ssn, date_of_birth, credit_card_number, diagnosis, mrn, ...). The schema itself isn't the leak -- it tells an agent exactly where production PII lives if it's ever handed a real data export.`
      : "No schema files with PII/financial/health-shaped field names were found.",
    evidence: schemaEntries.slice(0, 50).map(([f, fields]) => `${f} (${[...fields].join(", ")})`),
    fix: schemaEntries.length > 0 ? "No action required on the schema alone, but treat it as a map of what's sensitive when deciding what data files are safe to open alongside it (policy 4.2's 6th category)." : undefined,
  });

  return checks;
}
