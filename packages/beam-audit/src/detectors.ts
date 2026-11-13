// Standalone pattern detectors for the exact data categories policy 4.2 ("Data Prohibited from
// Sharing with Claude Code") lists. Deliberately self-contained -- no import from beam-cli's own
// detector set -- so this package has no runtime dependency on the main product and can be
// published and run on its own.

export type DetectorKind =
  | "API_KEY" | "OAUTH_TOKEN" | "PRIVATE_KEY" | "PASSWORD" | "SERVICE_ACCOUNT"
  | "EMAIL" | "PHONE" | "SSN" | "GOV_ID" | "ADDRESS"
  | "CREDIT_CARD" | "IBAN"
  | "INTERNAL_IP" | "NETWORK_RANGE"
  | "MRN" | "HEALTH_PLAN_ID" | "PHI";

export interface Hit { kind: DetectorKind; index: number }

const PATTERNS: Array<{ kind: DetectorKind; re: RegExp }> = [
  // Production credentials
  { kind: "API_KEY", re: /\b(?:sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,})\b/ },
  { kind: "OAUTH_TOKEN", re: /\b(?:ya29\.[A-Za-z0-9_-]{20,}|Bearer\s+[A-Za-z0-9._-]{20,})/ },
  { kind: "PRIVATE_KEY", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { kind: "PASSWORD", re: /\b(?:password|passwd|pwd|secret|api[_-]?secret)["']?\s*[:=]\s*["'][^"'\s]{6,}["']/i },
  // Excludes secret-manager REFERENCES (${{ secrets.X }}, @Microsoft.KeyVault(...), op://, vault:,
  // process.env.X) -- a reference to where a secret lives is the opposite of a leaked secret.
  { kind: "SERVICE_ACCOUNT", re: /"type"\s*:\s*"service_account"|client_secret["']?\s*[:=]\s*["']?(?!\s*\$\{\{|op:\/\/|vault:|@Microsoft\.KeyVault|process\.env|import\.meta\.env)[^\s"']{6,}/i },
  // PII. Excludes placeholder/example domains (you@example.com, name@test.com, ...) -- UI hint text
  // and sample code use these constantly, and they're not anyone's real address by construction
  // (example.com/.org/.net/.test are reserved for exactly this under RFC 2606).
  // (?!git@) excludes SCP-style git remotes (git@github.com:owner/repo.git) -- structurally
  // identical to an email address but is an SSH remote URL, not anyone's PII.
  { kind: "EMAIL", re: /\b(?!git@)[A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net)\b|test\.(?:com|test)\b|yourdomain\.|yourcompany\.|acme\.com\b|placeholder\.|domain\.com\b|localhost\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
  { kind: "PHONE", re: /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/ },
  { kind: "SSN", re: /\b\d{3}-\d{2}-\d{4}\b/ },
  { kind: "GOV_ID", re: /\b[A-Z]{1,2}\d{6,9}\b/ }, // loose passport/license shape; low precision, used only as a signal
  { kind: "ADDRESS", re: /\b\d{1,5}\s+\w+(?:\s\w+){0,3}\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b/i },
  // Financial
  { kind: "CREDIT_CARD", re: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b/ },
  { kind: "IBAN", re: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/ },
  // Infrastructure topology
  { kind: "INTERNAL_IP", re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/ },
  { kind: "NETWORK_RANGE", re: /\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b/ },
];

// Policy 4.2's PII/PHI/financial-data category is noisy on free prose (a README that says "support@
// example.com" or documents a sample password is not a leak). Low-precision kinds are gated by
// requiring at least two independent kinds in the same text; everything is additionally gated by
// file type in repo-scan.ts (prose/doc files are excluded from these, not from credential patterns).
const LOW_PRECISION: ReadonlySet<DetectorKind> = new Set(["GOV_ID", "ADDRESS", "IBAN"]);

// An IP/CIDR match sitting a few characters from regex metacharacters is almost always part of a
// *pattern definition* (this file is a repeat offender) rather than a literal address in config or
// logs -- e.g. `/\b(?:10\.\d{1,3}\.\d{1,3}...)/`. Skip those instead of reporting them as topology.
const REGEX_CONTEXT = /\\d|\\\.|\(\?:|\[0-9|\\b/;
function looksLikePatternDefinition(text: string, index: number): boolean {
  const window = text.slice(Math.max(0, index - 30), index + 30);
  return REGEX_CONTEXT.test(window);
}

// The textbook reserved ranges from RFC 1918 (private-use), RFC 6598 (shared carrier-grade NAT),
// RFC 5735/3927 (loopback, link-local, broadcast) and RFC 4193 (unique-local IPv6) are universally
// public knowledge, not anyone's actual deployment topology -- a security tool's own source code
// (an allowlist, a detector's pattern table) is expected to spell these out verbatim. A real leak is
// a specific host or a narrower subnet, not the full documented /8-/16 block.
const WELL_KNOWN_RANGES = new Set([
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.168.0.0/16", "255.255.255.255/32",
]);
function isWellKnownRange(text: string, index: number): boolean {
  const window = text.slice(index, index + 20);
  return [...WELL_KNOWN_RANGES].some(r => window.startsWith(r));
}

// An email a few characters after `placeholder=`/`placeholder:` is UI hint text in a form field,
// not a real address anyone typed in -- the single biggest source of EMAIL noise in a real web
// app's source (every login/register/forgot-password page has one). Same idea as the regex-context
// filter above: look at local context instead of trying to list every possible example domain.
const PLACEHOLDER_CONTEXT = /\bplaceholder\s*[:=]\s*["'`][^"'`]{0,40}$/i;
function looksLikeFormPlaceholder(text: string, index: number): boolean {
  return PLACEHOLDER_CONTEXT.test(text.slice(Math.max(0, index - 60), index));
}

// Any value explicitly labeled synthetic nearby (this package's own SYNTHETIC_PAYLOAD constants
// used for live testing are the canonical case) is test data, not a leak -- regardless of which
// file it happens to live in, so this doesn't need a path-based exclusion.
const SYNTHETIC_LABEL = /SYNTHETIC/;
function looksLikeSyntheticTestValue(text: string, index: number): boolean {
  // Wide enough to cover the whole SYNTHETIC_PAYLOAD object literal, not just the matched line --
  // the label sits on one field (apiKey) while the others (ssn, email, ...) are nearby sibling lines.
  return SYNTHETIC_LABEL.test(text.slice(Math.max(0, index - 400), index + 400));
}

export function detect(text: string): Hit[] {
  const hits: Hit[] = [];
  for (const { kind, re } of PATTERNS) {
    const global = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    for (const m of text.matchAll(global)) {
      const index = m.index ?? 0;
      if ((kind === "INTERNAL_IP" || kind === "NETWORK_RANGE") && (looksLikePatternDefinition(text, index) || isWellKnownRange(text, index))) continue;
      if (kind === "EMAIL" && looksLikeFormPlaceholder(text, index)) continue;
      if (looksLikeSyntheticTestValue(text, index)) continue;
      hits.push({ kind, index });
    }
  }
  return hits;
}

export function confidentHits(text: string): Hit[] {
  const hits = detect(text);
  const kinds = new Set(hits.map(h => h.kind));
  return hits.filter(h => !LOW_PRECISION.has(h.kind) || kinds.size >= 2);
}

// ---- PHI: ported from beam-cli's own src/phi-detectors.ts, trimmed to what's checkable without a
// classifier. A label must precede the value (mrn:, diagnosis:, patient name:, ...) so ordinary code
// and prose that merely use these words don't match -- the same discipline the main product uses.
const LABEL_TAIL = String.raw`(?:[ _-]?(?:no|num|number|#))?["']?\.?\s*[:=#]\s*["']?`;
// Case-sensitive on purpose: real insurance/member/MRN identifiers are conventionally uppercase+
// digits (POLICY-00231, MRN4471829). Allowing lowercase here (as a bare "gi" flag would) matches
// almost any camelCase variable's value in ordinary application code (memberId, subscriberId, ...
// are common SaaS fields with nothing to do with health insurance), which is exactly the false
// positive this package must not ship.
const ID_VALUE = String.raw`[A-Z0-9][A-Z0-9-]{4,14}[A-Z0-9]\b`;

interface PhiPattern { kind: "MRN" | "HEALTH_PLAN_ID" | "PHI"; re: RegExp }
const PHI_PATTERNS: PhiPattern[] = [
  { kind: "MRN", re: new RegExp(String.raw`(?<=\b(?:mrn|medical[ _-]?record|patient[ _-]?id|chart)${LABEL_TAIL})${ID_VALUE}`, "gi") },
  // Deliberately health-specific keywords only -- "member"/"subscriber" alone are far too common
  // in ordinary SaaS apps (community membership, newsletter subscribers, ...) to be health-plan signal.
  { kind: "HEALTH_PLAN_ID", re: new RegExp(String.raw`(?<=\b(?:insurance|health[ _-]?plan|beneficiary|medicare|medicaid)[ _-]?(?:member|subscriber)?[ _-]?id${LABEL_TAIL})${ID_VALUE}|(?<=\bpolicy[ _-]?(?:no|num|number)${LABEL_TAIL})${ID_VALUE}`, "gi") },
  { kind: "PHI", re: new RegExp(String.raw`(?<=\b(?:icd[ _-]?10(?:[ _-]?cm)?|icd[ _-]?code|diagnosis[ _-]?code|dx[ _-]?code)${LABEL_TAIL})[A-TV-Z]\d{2}(?:\.[0-9A-Z]{1,4})?\b`, "g") },
  // Deliberately NOT included: a free-text "labelled clinical field" pattern (diagnosis:/medication:/
  // allergy: followed by prose). Tested against this codebase and it fires on ordinary blog/marketing
  // writing that uses "Diagnosis:" as a rhetorical headline device ("Diagnosis: Enterprise AI's
  // Information Paradox"), which no cheap regex reliably tells apart from a real clinical record.
  // Shipping that would trade a few real catches for a lot of noise; it's listed in the check's own
  // detail text as a known gap instead.
];

// The keyword lookbehind is case-insensitive (so `MRN:`/`mrn:` both count), but a genuinely
// health-shaped identifier value shouldn't be a plain lowercase/camelCase token -- reject any match
// that contains a lowercase letter.
const ALL_UPPER_ID = /^[A-Z0-9-]+$/;

export function phiHits(text: string): Hit[] {
  const hits: Hit[] = [];
  for (const { kind, re } of PHI_PATTERNS) {
    for (const m of text.matchAll(re)) {
      if ((kind === "MRN" || kind === "HEALTH_PLAN_ID") && !ALL_UPPER_ID.test(m[0])) continue;
      hits.push({ kind, index: m.index ?? 0 });
    }
  }
  return hits;
}

// ---- Trade secrets / proprietary source (policy 4.2: "explicitly marked as confidential"). The
// policy's own wording implies a textual marker to find, so this looks for exactly that, not for
// "proprietary-sounding code" in general, which isn't detectable without understanding the
// business. Anchored to its own line (optionally inside a comment/header) so an article or blog
// post *discussing* trade secrets as a news topic doesn't count as a file marked confidential --
// a real marker is a standalone legal notice, not a word embedded in running prose.
export const CONFIDENTIAL_MARKER = /^[ \t]*(?:\/\/|#|\*|<!--|")?[ \t]*(?:PROPRIETARY AND CONFIDENTIAL|TRADE SECRET(?:S)?|CONFIDENTIAL\s*[-–]\s*DO NOT DISTRIBUTE|INTERNAL USE ONLY|NOT FOR DISTRIBUTION)[ \t]*(?:-->|\*\/|")?[ \t]*$/im;

// ---- DB schemas / data dictionaries with field names that map to PII/financial/health data
// (policy 4.2's 6th bullet). Scanning free text for these words is useless noise; scanning them
// as column/field identifiers inside an actual schema-shaped file is the real signal.
export const SCHEMA_FILE = /\.(?:sql|prisma|graphql|gql)$|(?:^|\/)schema\.(?:rb|json|ts|js)$|(?:^|\/)migrations?\//i;
export const SENSITIVE_FIELD_NAME = /\b(?:ssn|social_security(?:_number)?|date_of_birth|dob|credit_card(?:_number)?|card_number|cvv|cvc|bank_account(?:_number)?|routing_number|passport_number|driver(?:s)?_license|tax_id|national_id|patient_id|diagnosis|health_plan_id|member_id|medical_record_number|mrn)\b/i;

/** Synthetic, obviously-fake values used ONLY for the live round-trip test -- never a real secret. */
export const SYNTHETIC_PAYLOAD = {
  apiKey: "sk-ant-api03-SYNTHETIC00000000000000000000000000000000000000000000000TEST",
  ssn: "987-65-4320",
  email: "jordan.sample.beamaudit@example-prospect.test",
  phone: "555-019-4273", // NANP 555 exchange is reserved for fictional use, never a real line
  internalIp: "10.77.231.14",
  creditCard: "4000-1111-2222-3330",
};

/** One row per policy-4.2 data type for the pass/fail matrix -- field name, the single synthetic
 * value to send, and the value to look for in the response. */
export const MATRIX_FIELDS: Array<{ label: string; field: string; value: string }> = [
  { label: "Email", field: "EMAIL", value: SYNTHETIC_PAYLOAD.email },
  { label: "Phone", field: "PHONE", value: SYNTHETIC_PAYLOAD.phone },
  { label: "SSN", field: "SSN", value: SYNTHETIC_PAYLOAD.ssn },
  { label: "Credit card", field: "CARD", value: SYNTHETIC_PAYLOAD.creditCard },
  { label: "API key", field: "API_KEY", value: SYNTHETIC_PAYLOAD.apiKey },
];
