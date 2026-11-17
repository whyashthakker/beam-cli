// Shared types. Mirrors beam-cli's own `doctor` check shape (pass/warn/fail/skip + fix) so the
// output is familiar to anyone who later installs beam, but this package has zero runtime
// dependency on the main beam-cli product -- it must work standalone for people who don't have it.
export type Status = "pass" | "warn" | "fail" | "skip";

export interface Check {
  category?: import("./categories.js").Category;
  id: string;
  policySection: string;
  title: string;
  status: Status;
  detail: string;
  fix?: string;
  evidence?: string[];
}

export interface AuditContext {
  roots: string[];
  repos: string[];
  home: string;
  platform: NodeJS.Platform;
  log: (msg: string) => void;
  online?: boolean;
  maxFiles?: number;
  agentControls?: import("./policy.js").AgentControlsPolicy;
  environment?: NodeJS.ProcessEnv;
}
