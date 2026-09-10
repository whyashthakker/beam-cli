// Ported from ex-check's internal/agent/detect.go. Detects which AI agent (if any) a process
// belongs to from its own identity, independent of whether that agent cooperates with any hook.
//
// A "strong" indicator (a known binary name, a dotted config directory) is specific enough to
// stand on its own anywhere in the process + its full ancestry's name/executable/command line.
// A "weak" indicator (e.g. the bare word "copilot") is generic enough that it's only trustworthy
// when it names the process's own identity (name/executable) -- not when it merely appears
// somewhere in a long command line or an unrelated ancestor, which previously misclassified
// generic helper processes (e.g. a VS Code "Code Helper (Plugin)") as an AI agent.

export interface Indicator { value: string; strong: boolean }
export interface Definition { name: string; indicators: Indicator[] }

export interface DetectedProcess {
  pid: number;
  ppid: number;
  user: string;
  name: string;
  executable: string;
  commandLine: string;
  parentChain?: DetectedProcess[];
  isAIAgent?: boolean;
  agent?: string;
}

export const DEFINITIONS: Definition[] = [
  { name: "codex", indicators: [{ value: "codex", strong: true }, { value: ".codex", strong: true }, { value: "openai.chatgpt", strong: false }] },
  { name: "claude-code", indicators: [{ value: "claude", strong: true }, { value: ".claude", strong: true }] },
  { name: "cursor", indicators: [{ value: "cursor", strong: true }, { value: ".cursor", strong: true }] },
  { name: "vscode-copilot", indicators: [{ value: "github.copilot", strong: true }, { value: "copilot", strong: false }] },
  { name: "gemini-cli", indicators: [{ value: "gemini", strong: true }, { value: ".gemini", strong: true }] },
  { name: "opencode", indicators: [{ value: "opencode", strong: true }, { value: ".opencode", strong: true }] },
  { name: "qwen-code", indicators: [{ value: "qwen", strong: true }, { value: "qwen-code", strong: true }, { value: ".qwen", strong: true }] },
];

function isWordIndicator(value: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(value);
}

const wordPatterns = new Map<string, RegExp>();
for (const definition of DEFINITIONS) {
  for (const indicator of definition.indicators) {
    if (wordPatterns.has(indicator.value)) continue;
    if (isWordIndicator(indicator.value)) {
      const escaped = indicator.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      wordPatterns.set(indicator.value, new RegExp(`\\b${escaped}\\b`, "i"));
    }
  }
}

function matchIndicator(text: string, indicator: string): boolean {
  const pattern = wordPatterns.get(indicator);
  if (pattern) return pattern.test(text);
  // Dotted paths (".codex", ".opencode", ...) aren't plain words, so a boundary match doesn't
  // apply cleanly; substring is precise enough since these are already fairly unique names.
  return text.toLowerCase().includes(indicator.toLowerCase());
}

function identityText(process: DetectedProcess): string {
  return `${process.name} ${process.executable}`;
}

function processText(process: DetectedProcess): string {
  const parts = [process.name, process.executable, process.commandLine];
  for (const parent of process.parentChain ?? []) parts.push(parent.name, parent.executable, parent.commandLine);
  return parts.join(" ");
}

export type Confidence = "high" | "medium" | "low" | "";

// Scores a process using identity fields (name, executable) for weak indicators, and the full
// process/ancestry text for strong indicators.
export function detectProcessFields(process: DetectedProcess): { name: string; confidence: Confidence } {
  const identity = identityText(process);
  const full = processText(process);
  for (const definition of DEFINITIONS) {
    for (const indicator of definition.indicators) {
      if (indicator.strong && matchIndicator(full, indicator.value)) return { name: definition.name, confidence: "high" };
    }
  }
  for (const definition of DEFINITIONS) {
    for (const indicator of definition.indicators) {
      if (!indicator.strong && matchIndicator(identity, indicator.value)) return { name: definition.name, confidence: "medium" };
    }
  }
  return { name: "", confidence: "" };
}

// Tags a process (and leaves an already-trusted tag untouched).
export function detectProcess(process: DetectedProcess): DetectedProcess {
  if (process.isAIAgent && process.agent) return process;
  const { name, confidence } = detectProcessFields(process);
  return { ...process, isAIAgent: confidence !== "", agent: name };
}
