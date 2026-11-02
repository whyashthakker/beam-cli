import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "@jest/globals";
import { redactWithSessionEntities } from "../src/entity-redaction.js";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});
async function tempHome(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "beam-entity-"));
  temporaryDirectories.push(dir);
  return dir;
}

describe("redactWithSessionEntities", () => {
  it("gives the same real value the same numbered id across separate calls in one session", async () => {
    const home = await tempHome();
    const line = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const first = await redactWithSessionEntities(line, "session-A", [], home);
    const second = await redactWithSessionEntities(line, "session-A", [], home);
    expect(first.text).toBe("AWS_SECRET_ACCESS_KEY=[SECRET_001]");
    expect(second.text).toBe(first.text);
  });

  it("gives a different value its own id, numbered after the first", async () => {
    const home = await tempHome();
    await redactWithSessionEntities("SECRET_A=wJalrXUtnFEMI1", "session-A", [], home);
    const second = await redactWithSessionEntities("SECRET_B=differentValueEntirely99999", "session-A", [], home);
    expect(second.text).toBe("SECRET_B=[SECRET_002]");
  });

  it("numbers the same value independently per session (no cross-session leakage)", async () => {
    const home = await tempHome();
    const line = "SECRET_A=wJalrXUtnFEMI1";
    await redactWithSessionEntities(line, "session-A", [], home);
    await redactWithSessionEntities("SECRET_B=something-else-entirely", "session-A", [], home); // bumps session-A's counter to 2
    const otherSession = await redactWithSessionEntities(line, "session-B", [], home);
    expect(otherSession.text).toBe("SECRET_A=[SECRET_001]"); // starts over at 1 in its own session
  });

  it("never writes the real value to disk, only a hash", async () => {
    const home = await tempHome();
    const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    await redactWithSessionEntities(`AWS_SECRET_ACCESS_KEY=${secret}`, "session-A", [], home);
    const stored = await fs.readFile(path.join(home, "entity-map.json"), "utf8");
    expect(stored).not.toContain(secret);
    expect(JSON.parse(stored)["session-A"].entries).toBeDefined();
  });

  it("leaves text with nothing sensitive completely untouched, with no entry written", async () => {
    const home = await tempHome();
    const result = await redactWithSessionEntities("PORT=3000", "session-A", [], home);
    expect(result.text).toBe("PORT=3000");
    expect(result.findings).toEqual([]);
  });

  it("assigns different kinds their own counters", async () => {
    const home = await tempHome();
    const result = await redactWithSessionEntities(
      "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstu\nDB_PASSWORD=hunter2hunter2",
      "session-A", [], home,
    );
    expect(result.text).toContain("GITHUB_TOKEN=[API_KEY_001]");
    expect(result.text).toContain("DB_PASSWORD=[PASSWORD_001]");
  });

  it("still honors the credential-reference convention -- a reference is never assigned an entity id", async () => {
    const home = await tempHome();
    const result = await redactWithSessionEntities("AWS_SECRET_ACCESS_KEY=op://vault/aws/secret", "session-A", [], home);
    expect(result.text).toBe("AWS_SECRET_ACCESS_KEY=op://vault/aws/secret");
  });
});
