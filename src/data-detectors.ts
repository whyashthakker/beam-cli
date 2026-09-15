export type DetectorKind = "EMAIL" | "PHONE" | "SECRET" | "API_KEY" | "PASSWORD" | "PRIVATE_KEY" | "CUSTOM";
export interface DataFinding { kind: DetectorKind; confidence: number; start: number; end: number; replacement: string }

const detectors: Array<{ kind: DetectorKind; pattern: RegExp; replacement: string }> = [
  { kind: "PRIVATE_KEY", pattern: /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, replacement: "[PRIVATE_KEY_REDACTED]" },
  { kind: "API_KEY", pattern: /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[\w-]{10,})\b/g, replacement: "[API_KEY_REDACTED]" },
  { kind: "SECRET", pattern: /((?:api[_-]?key|access[_-]?token|token|secret|authorization)\s*[:=]\s*["']?)([^\s,"';&}\]]+)/gi, replacement: "$1[SECRET_REDACTED]" },
  { kind: "PASSWORD", pattern: /((?:password|passwd|pwd)\s*[:=]\s*["']?)([^\s,"';&}\]]+)/gi, replacement: "$1[PASSWORD_REDACTED]" },
  { kind: "EMAIL", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replacement: "[EMAIL_REDACTED]" },
  { kind: "PHONE", pattern: /(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\d[\s.-]?){8,14}\d(?!\w)/g, replacement: "[PHONE_REDACTED]" },
];

export interface CustomDetector { name: string; pattern: string; replacement: string }
export function detectSensitive(text: string, custom: CustomDetector[] = []): DataFinding[] {
  const findings: DataFinding[] = [];
  for (const detector of detectors) {
    detector.pattern.lastIndex = 0;
    for (const match of text.matchAll(detector.pattern)) findings.push({ kind: detector.kind, confidence: 0.9, start: match.index ?? 0, end: (match.index ?? 0) + match[0].length, replacement: detector.replacement });
  }
  for (const customDetector of custom) {
    try {
      const pattern = new RegExp(customDetector.pattern, "g");
      for (const match of text.matchAll(pattern)) findings.push({ kind: "CUSTOM", confidence: 0.8, start: match.index ?? 0, end: (match.index ?? 0) + match[0].length, replacement: customDetector.replacement });
    } catch { /* policy validation reports malformed custom detectors */ }
  }
  return findings.sort((a, b) => b.start - a.start);
}

export function redactSensitive(text: string, custom: CustomDetector[] = []): { text: string; findings: DataFinding[] } {
  const findings = detectSensitive(text, custom); let result = text;
  for (const finding of findings) result = result.slice(0, finding.start) + finding.replacement + result.slice(finding.end);
  return { text: result, findings };
}
