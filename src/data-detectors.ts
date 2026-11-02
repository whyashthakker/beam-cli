export type DetectorKind = "EMAIL" | "PHONE" | "SECRET" | "API_KEY" | "PASSWORD" | "PRIVATE_KEY" | "CUSTOM";
export interface DataFinding { kind: DetectorKind; confidence: number; start: number; end: number; replacement: string }

const detectors: Array<{ kind: DetectorKind; pattern: RegExp; replacement: string }> = [
  { kind: "PRIVATE_KEY", pattern: /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, replacement: "[PRIVATE_KEY_REDACTED]" },
  { kind: "API_KEY", pattern: /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,}|beam_app_[\w-]{20,})\b/g, replacement: "[API_KEY_REDACTED]" },
  { kind: "EMAIL", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replacement: "[EMAIL_REDACTED]" },
  { kind: "PHONE", pattern: /(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\d[\s.-]?){8,14}\d(?!\w)/g, replacement: "[PHONE_REDACTED]" },
];

// SECRET/PASSWORD used to require their keyword sit immediately before "="/":", so
// AWS_SECRET_ACCESS_KEY (keyword not adjacent -- "_ACCESS_KEY" sits between "SECRET" and "=")
// went through un-redacted even though it's the standard AWS credential variable name. Fixed by
// extracting any NAME=value assignment, then checking whether NAME *contains* a credential
// keyword as a whole underscore/hyphen/camelCase-delimited segment, in any position -- so
// "secretary_name" (the word "secret" only as a substring, not a segment) still correctly never
// matches, while "AWS_SECRET_ACCESS_KEY", "appSecretToken", "DB-PASSWORD-HASH" all do.
const ASSIGNMENT = /\b([A-Za-z][\w.-]*)\s*[:=]\s*["']?([^\s,"';&}\]]+)/g;
function segments(identifier: string): string[] {
  return identifier.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().split(/[_.-]+/).filter(Boolean);
}
const SECRET_SEGMENTS = new Set(["secret", "token", "authorization"]);
const PASSWORD_SEGMENTS = new Set(["password", "passwd", "pwd"]);
// "key" alone is far too common a segment to flag by itself (primary_key, sort_key,
// partition_key are ordinary DB/infra terms, not secrets) -- only the "api"+"key" pairing counts,
// and only when adjacent, matching the original api[_-]?key compound.
function hasApiKeyPair(segs: string[]): boolean {
  return segs.some((s, i) => s === "api" && segs[i + 1] === "key");
}

// A value pointing at a secret manager instead of holding the secret itself: 1Password
// (op://vault/item/field), Azure Key Vault app-setting references, HashiCorp Vault paths,
// Infisical/Doppler references, GitHub Actions' ${{ secrets.X }}, or a generic broker-issued
// placeholder like __CREDENTIAL_REF_123__. There is nothing to redact -- the real value never
// left the vault -- so flagging it as an exposed secret would itself be the false positive.
// `${{ secrets.X }}` is checked by its opening token alone: the SECRET/PASSWORD detectors' own
// value-capture regex stops at the first whitespace, so it never sees past "${{" either way.
const CREDENTIAL_REFERENCE = /^(?:op:\/\/|@Microsoft\.KeyVault\(|vault:|infisical:\/\/|doppler:\/\/|\$\{\{|__[A-Z][A-Z0-9_]*_REF_[\w-]+__$)/i;
const isReference = (value: string) => CREDENTIAL_REFERENCE.test(value.trim());

export interface CustomDetector { name: string; pattern: string; replacement: string }
export function detectSensitive(text: string, custom: CustomDetector[] = []): DataFinding[] {
  const findings: DataFinding[] = [];
  for (const detector of detectors) {
    detector.pattern.lastIndex = 0;
    for (const match of text.matchAll(detector.pattern)) {
      findings.push({ kind: detector.kind, confidence: 0.9, start: match.index ?? 0, end: (match.index ?? 0) + match[0].length, replacement: detector.replacement });
    }
  }
  // SECRET/PASSWORD: redact only the captured value (group 2), not the "name=" prefix (group 1),
  // so "AWS_SECRET_ACCESS_KEY=xxx" redacts to "AWS_SECRET_ACCESS_KEY=[SECRET_REDACTED]", not the
  // whole assignment. A reference value there (op://, @Microsoft.KeyVault(...), ...) is skipped
  // entirely -- it isn't a real secret.
  ASSIGNMENT.lastIndex = 0;
  for (const match of text.matchAll(ASSIGNMENT)) {
    const [, name, value] = match;
    const segs = segments(name!);
    const kind = segs.some(s => SECRET_SEGMENTS.has(s)) || hasApiKeyPair(segs) ? "SECRET" : segs.some(s => PASSWORD_SEGMENTS.has(s)) ? "PASSWORD" : null;
    if (!kind || isReference(value ?? "")) continue;
    const start = (match.index ?? 0) + name!.length + match[0].slice(name!.length).indexOf(value!);
    findings.push({ kind, confidence: 0.9, start, end: start + value!.length, replacement: kind === "SECRET" ? "[SECRET_REDACTED]" : "[PASSWORD_REDACTED]" });
  }
  for (const customDetector of custom) {
    try {
      const pattern = new RegExp(customDetector.pattern, "g");
      for (const match of text.matchAll(pattern)) findings.push({ kind: "CUSTOM", confidence: 0.8, start: match.index ?? 0, end: (match.index ?? 0) + match[0].length, replacement: customDetector.replacement });
    } catch { /* policy validation reports malformed custom detectors */ }
  }
  // Different detectors can match overlapping or identical spans on the same value (an API-key-
  // shaped value assigned to a field named "token" trips both the API_KEY and SECRET detectors).
  // Applying two replacements to overlapping ranges corrupts the text (the second splice operates
  // on offsets computed against the pre-replacement string). Kept in detector-priority order
  // (array order above: PRIVATE_KEY/API_KEY's precise format match wins over SECRET/PASSWORD's
  // generic keyword match), via a stable sort by start -- ties keep their original push order --
  // then a left-to-right sweep that drops anything starting before the last kept finding's end.
  const nonOverlapping: DataFinding[] = [];
  let lastEnd = -1;
  for (const finding of [...findings].sort((a, b) => a.start - b.start)) {
    if (finding.start < lastEnd) continue;
    nonOverlapping.push(finding);
    lastEnd = finding.end;
  }
  return nonOverlapping.sort((a, b) => b.start - a.start);
}

export function redactSensitive(text: string, custom: CustomDetector[] = []): { text: string; findings: DataFinding[] } {
  const findings = detectSensitive(text, custom); let result = text;
  for (const finding of findings) result = result.slice(0, finding.start) + finding.replacement + result.slice(finding.end);
  return { text: result, findings };
}
