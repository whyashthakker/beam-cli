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
});
