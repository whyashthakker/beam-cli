import { describe, expect, it } from "@jest/globals";
import { detectSensitive, redactSensitive } from "../src/data-detectors.js";

describe("data detectors", () => {
  it("detects and transforms common sensitive values", () => {
    const input = "Email rahul@example.com phone +91 9876543210 API key sk-example123456789";
    const result = redactSensitive(input);
    expect(result.text).toContain("[EMAIL_REDACTED]");
    expect(result.text).toContain("[PHONE_REDACTED]");
    expect(result.text).toContain("[API_KEY_REDACTED]");
    expect(result.findings.length).toBeGreaterThanOrEqual(3);
    expect(result.text).not.toContain("rahul@example.com");
  });

  it("does not mutate safe content", () => {
    expect(redactSensitive("npm test").text).toBe("npm test");
    expect(detectSensitive("plain source code")).toEqual([]);
  });

  it("supports policy-defined custom detectors", () => {
    const result = redactSensitive("customer CUST-123", [{ name: "CUSTOMER_ID", pattern: "CUST-\\d+", replacement: "[CUSTOMER_ID_REDACTED]" }]);
    expect(result.text).toBe("customer [CUSTOMER_ID_REDACTED]");
    expect(result.findings[0].kind).toBe("CUSTOM");
  });

  it("redacts a credential keyword anywhere in a compound variable name, not just immediately before '='", () => {
    // AWS_SECRET_ACCESS_KEY is the real-world standard AWS credential variable name; "SECRET"
    // isn't adjacent to "=" there ("_ACCESS_KEY" sits between them), which used to let it through.
    expect(redactSensitive("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").text)
      .toBe("AWS_SECRET_ACCESS_KEY=[SECRET_REDACTED]");
    expect(redactSensitive("appSecretToken=abc123def456").text).toBe("appSecretToken=[SECRET_REDACTED]");
    expect(redactSensitive("DB-PASSWORD-HASH=xyz789").text).toBe("DB-PASSWORD-HASH=[PASSWORD_REDACTED]");
    expect(redactSensitive("apiKey=sk-test-123").text).toBe("apiKey=[SECRET_REDACTED]");
  });

  it("never flags a credential keyword that only appears as a substring, not a whole name segment", () => {
    for (const line of ["secretary_name=John Smith", "primary_key=42", "sort_key=timestamp", "partition_key=user_id", "passwordless_login=true"]) {
      expect(redactSensitive(line).text).toBe(line);
    }
  });

  it("recognizes credential-reference syntax and leaves it unredacted, even on a compound name", () => {
    const line = "AWS_SECRET_ACCESS_KEY=op://vault/aws/secret";
    expect(redactSensitive(line).text).toBe(line);
    expect(detectSensitive(line)).toEqual([]);
  });

  it("applies non-overlapping replacements when two detectors match the same value (API-key-shaped value on a secret-named field)", () => {
    const result = redactSensitive("GITHUB_TOKEN=ghp_abcdefghijklmnopqrstu");
    expect(result.text).toBe("GITHUB_TOKEN=[API_KEY_REDACTED]"); // more specific format match wins, text isn't corrupted
    expect(result.text).not.toContain("$1");
  });
});
