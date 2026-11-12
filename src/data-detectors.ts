import { NATIONAL_ID_DETECTORS } from "./pii-validators.js";
export type DetectorKind = "EMAIL" | "PHONE" | "SSN" | "CREDIT_CARD" | "IBAN" | "NATIONAL_ID" | "PASSPORT" | "DRIVER_LICENSE" | "ADDRESS" | "DOB" | "SECRET" | "API_KEY" | "PASSWORD" | "PRIVATE_KEY" | "CUSTOM";
export interface DataFinding { kind: DetectorKind; confidence: number; start: number; end: number; replacement: string }

// Checksum validators keep the PII detectors from flagging arbitrary digit strings (build ids,
// timestamps, order numbers). A candidate is only redacted when it also passes its own check.
function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}
function validCard(raw: string): boolean {
  const digits = raw.replace(/[\s-]/g, "");
  return digits.length >= 13 && digits.length <= 19 && !/^(\d)\1+$/.test(digits) && luhn(digits);
}
function validIban(raw: string): boolean {
  const iban = raw.replace(/\s/g, "").toUpperCase();
  if (iban.length < 15 || iban.length > 34) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const chunk = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of chunk) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}
// US SSN: area 000/666/9xx, group 00 and serial 0000 are never issued.
function validSsn(raw: string): boolean {
  const [area, group, serial] = raw.split(/[\s-]/);
  return area !== "000" && area !== "666" && !area!.startsWith("9") && group !== "00" && serial !== "0000";
}
// Aadhaar uses the Verhoeff checksum.
const V_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const V_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
function validAadhaar(raw: string): boolean {
  const digits = raw.replace(/\s/g, "");
  let c = 0;
  [...digits].reverse().forEach((ch, i) => { c = V_D[c]![V_P[i % 8]![Number(ch)]!]!; });
  return c === 0;
}

const phoneDigits = (raw: string) => { const n = raw.replace(/\D/g, "").length; return n >= 8 && n <= 15; };
// North American numbers: area code and exchange never start with 0 or 1.
function validNanp(raw: string): boolean {
  const d = raw.replace(/\D/g, "").replace(/^1(?=\d{10}$)/, "");
  return d.length === 10 && /[2-9]/.test(d[0]!) && /[2-9]/.test(d[3]!);
}

const detectors: Array<{ kind: DetectorKind; pattern: RegExp; replacement: string; validate?: (match: string) => boolean }> = [
  { kind: "PRIVATE_KEY", pattern: /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, replacement: "[PRIVATE_KEY_REDACTED]" },
  { kind: "API_KEY", pattern: /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,}|beam_app_[\w-]{20,})\b/g, replacement: "[API_KEY_REDACTED]" },
  { kind: "EMAIL", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replacement: "[EMAIL_REDACTED]" },
  { kind: "SSN", pattern: /(?<![\w-])\d{3}([- ])\d{2}\1\d{4}(?![\w-])/g, replacement: "[SSN_REDACTED]", validate: validSsn },
  { kind: "CREDIT_CARD", pattern: /(?<![\w-])\d{4}(?:[ -]?\d{4}){2}[ -]?\d{1,7}(?![\w-])|(?<![\w-])3[47]\d{2}[ -]?\d{6}[ -]?\d{5}(?![\w-])/g, replacement: "[CREDIT_CARD_REDACTED]", validate: validCard },
  { kind: "IBAN", pattern: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g, replacement: "[IBAN_REDACTED]", validate: validIban },
  { kind: "NATIONAL_ID", pattern: /(?<![\w-])[2-9]\d{3} \d{4} \d{4}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validAadhaar },
  { kind: "NATIONAL_ID", pattern: /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g, replacement: "[NATIONAL_ID_REDACTED]" },
  { kind: "ADDRESS", pattern: /\b\d{1,6} (?:[A-Z][a-z]+\.? ){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b\.?(?:,? (?:Apt|Suite|Unit|#)\.? ?\w+)?/g, replacement: "[ADDRESS_REDACTED]" },
  { kind: "DOB", pattern: /\b(?:dob|date[ _-]?of[ _-]?birth|birth[ _-]?date|born(?: on)?)\s*[:=]?\s*["']?(?:\d{4}-\d{2}-\d{2}|\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4})/gi, replacement: "[DOB_REDACTED]" },
  ...NATIONAL_ID_DETECTORS,
  // Phone numbers need real structure. The previous pattern joined ANY run of 9-15 digits across spaces,
  // dots and dashes, so whisper timestamps ("12.34 15.67 0.12"), dates, ids and lists of numbers were all
  // redacted as phones. Each format below is anchored (no adjacent word/dot/dash characters) and checked.
  { kind: "PHONE", pattern: /(?<![\w.])\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{1,4}(?:[\s.-]?\d{2,4}){1,4}(?![\w.-])/g, replacement: "[PHONE_REDACTED]", validate: phoneDigits },
  { kind: "PHONE", pattern: /(?<![\w.$-])(?:1[\s.-])?(?:\(\d{3}\)[\s.-]?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\w.-])/g, replacement: "[PHONE_REDACTED]", validate: validNanp },
  { kind: "PHONE", pattern: /(?<![\w.-])0\d{1,4}[\s-]\d{3,4}[\s-]\d{3,4}(?![\w.-])|(?<![\w.-])07\d{3}[\s-]?\d{6}(?![\w.-])/g, replacement: "[PHONE_REDACTED]", validate: phoneDigits },
  { kind: "PHONE", pattern: /(?<![\w.+-])[6-9]\d{4}[\s-]?\d{5}(?![\w.-])/g, replacement: "[PHONE_REDACTED]" },
  { kind: "PHONE", pattern: /(?<=\b(?:phone|tel|telephone|mobile|cell|whatsapp|fax|contact)(?:[ _-]?(?:no|num|number))?\.?\s*[:=#]\s*["']?)\+?[\d\s().-]{6,22}\d(?![\w])/gi, replacement: "[PHONE_REDACTED]", validate: phoneDigits },
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
      if (detector.validate && !detector.validate(match[0])) continue;
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
