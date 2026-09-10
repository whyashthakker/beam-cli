import { describe, expect, it } from "@jest/globals";
import { detectProcess, detectProcessFields, type DetectedProcess } from "../src/os-detect.js";

function process(overrides: Partial<DetectedProcess>): DetectedProcess {
  return { pid: 1, ppid: 0, user: "test", name: "", executable: "", commandLine: "", ...overrides };
}

describe("detectProcessFields", () => {
  it("strong-matches a known agent binary by name", () => {
    const { name, confidence } = detectProcessFields(process({ name: "codex", executable: "/usr/local/bin/codex" }));
    expect(name).toBe("codex");
    expect(confidence).toBe("high");
  });

  it("strong-matches via a dotted config directory anywhere in the command line", () => {
    const { name, confidence } = detectProcessFields(process({ name: "node", executable: "/usr/bin/node", commandLine: "node dist/cli.js hook codex --config ~/.codex/config.toml" }));
    expect(name).toBe("codex");
    expect(confidence).toBe("high");
  });

  it("weak-matches a generic indicator only when it names the process's own identity", () => {
    const { name, confidence } = detectProcessFields(process({ name: "copilot", executable: "/usr/local/bin/copilot" }));
    expect(name).toBe("vscode-copilot");
    expect(confidence).toBe("medium");
  });

  it("does not weak-match a generic indicator that only appears in the command line", () => {
    // Regression case from ex-check: a VS Code helper process whose command line happens to
    // mention the bare word "copilot" must not be tagged as an AI agent just for that -- "copilot"
    // is a weak indicator, only trustworthy when it names the process's own identity.
    const { confidence } = detectProcessFields(process({ name: "Code Helper (Plugin)", executable: "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)", commandLine: "Code Helper (Plugin) --type=extensionHost --loaded-extension-name=copilot" }));
    expect(confidence).toBe("");
  });

  it("reports no match for an unrelated process", () => {
    const { confidence } = detectProcessFields(process({ name: "bash", executable: "/bin/bash", commandLine: "bash -c ls" }));
    expect(confidence).toBe("");
  });
});

describe("detectProcess", () => {
  it("leaves an already-trusted tag untouched", () => {
    const tagged = process({ name: "bash", isAIAgent: true, agent: "custom-agent" });
    expect(detectProcess(tagged)).toEqual(tagged);
  });

  it("tags an untrusted process from its own fields", () => {
    const result = detectProcess(process({ name: "cursor", executable: "/Applications/Cursor.app/Contents/MacOS/Cursor" }));
    expect(result.isAIAgent).toBe(true);
    expect(result.agent).toBe("cursor");
  });
});
