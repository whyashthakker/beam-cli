import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it } from "@jest/globals";
import { REPORT_WINDOW_MS, createIncident, findIncident, formatReport, listIncidents, markReported, urgency } from "../src/incidents.js";

let dir: string;
beforeEach(async () => { dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-inc-")); });
afterEach(async () => { await fs.rm(dir, { recursive: true, force: true }); });

describe("incidents", () => {
  it("sets a four-hour deadline and walks open -> due-soon -> overdue -> reported", () => {
    const at = new Date("2026-11-12T10:00:00Z");
    const { incident } = createIncident({ type: "workstation-loss", summary: "Laptop stolen", at, dir });
    expect(Date.parse(incident.reportBy) - at.getTime()).toBe(REPORT_WINDOW_MS);
    expect(urgency(incident, new Date("2026-11-12T11:00:00Z"))).toBe("open");
    expect(urgency(incident, new Date("2026-11-12T13:30:00Z"))).toBe("due-soon");
    expect(urgency(incident, new Date("2026-11-12T14:01:00Z"))).toBe("overdue");
    const done = markReported(incident.id, "Matthew", dir)!;
    expect(done.status).toBe("reported"); expect(done.reportedTo).toBe("Matthew");
    expect(urgency(done, new Date("2026-11-13T00:00:00Z"))).toBe("reported");
  });

  it("folds repeated automatic detections with the same key inside the window into one record", () => {
    const at = new Date("2026-11-12T10:00:00Z");
    const a = createIncident({ type: "pii-disclosure", summary: "x", key: "prompt:claude-code:pii", source: "auto", at, dir });
    const b = createIncident({ type: "pii-disclosure", summary: "x", key: "prompt:claude-code:pii", source: "auto", at: new Date(at.getTime() + 60_000), dir });
    expect(a.created).toBe(true); expect(b.created).toBe(false); expect(b.incident.id).toBe(a.incident.id);
    const later = createIncident({ type: "pii-disclosure", summary: "x", key: "prompt:claude-code:pii", source: "auto", at: new Date(at.getTime() + REPORT_WINDOW_MS + 1), dir });
    expect(later.created).toBe(true); expect(listIncidents(dir)).toHaveLength(2);
  });

  it("finds by unique prefix and writes a report with type-specific actions", () => {
    const { incident } = createIncident({ type: "secret-disclosure", summary: "Key pasted", details: ["1× API_KEY"], dir });
    expect(findIncident(incident.id.slice(0, 14), dir)?.id).toBe(incident.id);
    const text = formatReport(incident);
    expect(text).toContain("Rotate the exposed credential"); expect(text).toContain("1× API_KEY"); expect(text).toContain("Report to security lead by");
  });
});
