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

  describe("PII detectors", () => {
    const kinds = (text: string) => detectSensitive(text).map(f => f.kind);

    it("redacts valid SSNs and rejects never-issued ranges", () => {
      expect(redactSensitive("ssn 123-45-6789").text).toBe("ssn [SSN_REDACTED]");
      for (const bad of ["000-12-3456", "666-12-3456", "987-65-4321", "123-00-6789", "123-45-0000"]) expect(kinds(bad)).not.toContain("SSN");
    });

    it("redacts Luhn-valid cards in common formats and rejects invalid ones", () => {
      for (const card of ["4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111111", "378282246310005"]) {
        expect(redactSensitive(`card ${card}`).text).toBe("card [CREDIT_CARD_REDACTED]");
      }
      expect(kinds("1234 5678 9012 3456")).not.toContain("CREDIT_CARD");
    });

    it("redacts mod-97-valid IBANs only", () => {
      expect(redactSensitive("GB82 WEST 1234 5698 7654 32").text).toBe("[IBAN_REDACTED]");
      expect(kinds("GB82 WEST 1234 5698 7654 33")).not.toContain("IBAN");
    });

    it("redacts Verhoeff-valid Aadhaar and UK NINO", () => {
      expect(redactSensitive("id 2345 6789 0124").text).toBe("id [NATIONAL_ID_REDACTED]");
      expect(kinds("id 2234 5678 9015")).not.toContain("NATIONAL_ID");
      expect(redactSensitive("nino AB 12 34 56 C").text).toBe("nino [NATIONAL_ID_REDACTED]");
    });

    it("redacts street addresses and labelled dates of birth", () => {
      expect(redactSensitive("lives at 221 Baker Street, Apt 4B").text).toBe("lives at [ADDRESS_REDACTED]");
      expect(redactSensitive("dob: 1990-05-14").text).toBe("[DOB_REDACTED]");
      expect(redactSensitive("DateOfBirth=14/05/1990").text).toBe("[DOB_REDACTED]");
    });

    it("does not flag ordinary code, dates or ids", () => {
      for (const line of ["created 2026-11-12", "version 1.2.3", "npm run build", "const port = 8080;", "sha 3f786850e387550fdab836ed7e6dc881de23001b"]) {
        expect(redactSensitive(line).text).toBe(line);
      }
    });

    describe("international national IDs", () => {
      const valid: Array<[string, string]> = [
        ["US ITIN", "912-70-1234"], ["Canada SIN", "046 454 286"], ["Australia TFN", "123 456 782"],
        ["UK NHS", "943 476 5919"], ["Spain DNI", "12345678Z"], ["Spain NIE", "X1234567L"],
        ["Italy CF", "RSSMRA85T10A562S"], ["France NIR", "2 69 05 49 588 157 80"],
        ["China ID", "11010519491231002X"], ["Singapore NRIC", "S1234567D"], ["Sweden", "811218-9876"],
        ["Poland PESEL", "44051401359"], ["Brazil CPF", "529.982.247-25"],
        ["Brazil CNPJ", "11.222.333/0001-81"], ["Mexico CURP", "HEGG560427MVZRRL04"], ["India PAN", "ABCPE1234F"],
        ["South Korea RRN", "900101-1234568"],
      ];
      it.each(valid)("redacts a valid %s", (_name, id) => {
        expect(redactSensitive(`id ${id} end`).text).toBe("id [NATIONAL_ID_REDACTED] end");
      });

      const invalid: Array<[string, string]> = [
        ["Canada SIN", "046 454 287"], ["UK NHS", "943 476 5918"], ["Spain DNI", "12345678A"],
        ["Italy CF", "RSSMRA85T10A562X"], ["France NIR", "2 69 05 49 588 157 81"], ["China ID", "110105194912310021"],
        ["Singapore NRIC", "S1234567A"], ["Sweden", "811218-9877"], ["Poland PESEL", "44051401358"],
        ["Brazil CPF", "529.982.247-26"], ["South Korea RRN", "900101-1234567"],
      ];
      it.each(invalid)("rejects a %s that fails its checksum", (_name, id) => {
        expect(kinds(id).filter(k => k !== "PHONE")).toEqual([]);
      });

      it("redacts a South African ID (label may be CREDIT_CARD: a 13-digit Luhn number is ambiguous, both are sensitive)", () => {
        expect(redactSensitive("id 8001015009087 end").text).toMatch(/^id \[(?:NATIONAL_ID|CREDIT_CARD)_REDACTED\] end$/);
      });

      it("redacts labelled passport, driver's licence and tax ids from any country, keeping the label", () => {
        expect(redactSensitive("passport: X1234567").text).toBe("passport: [PASSPORT_REDACTED]");
        expect(redactSensitive("Passport No: 123456789").text).toBe("Passport No: [PASSPORT_REDACTED]");
        expect(redactSensitive("driver's license #: D123-4567-8901").text).toBe("driver's license #: [DRIVER_LICENSE_REDACTED]");
        expect(redactSensitive("tax id = 12-3456789").text).toBe("tax id = [NATIONAL_ID_REDACTED]");
        expect(redactSensitive("national_id: AB1234567").text).toBe("national_id: [NATIONAL_ID_REDACTED]");
      });

      it("does not flag prose, timestamps, versions or code that merely resembles an id", () => {
        for (const line of ["passport: required", "const sin = Math.sin(x)", "port: 8080", "build 20261112 v1.2.3", "sha 3f786850e387550fdab836ed7e6dc881de23001b"]) {
          expect(redactSensitive(line).text).toBe(line);
        }
      });
    });
  });

  describe("phone detection does not swallow ordinary numbers", () => {
    const phones = ["+1 415 555 2671", "(415) 555-2671", "1-415-555-2671", "+44 20 7946 0958", "+91 98765 43210", "07911 123456", "020 7946 0958", "98765 43210", "phone: 5551234567", "tel=+49 30 123456", "Mobile No: 9876543210"];
    it.each(phones)("still redacts the real phone number %s", (phone) => {
      expect(redactSensitive(`call ${phone} now`).text).toContain("REDACTED");
    });

    // The regression: whisper start/end times, durations, dates, ids and lists of numbers used to be
    // joined across spaces and dots and redacted as one phone number.
    const ordinary = [
      "start 12.34 end 15.67 0.12 0.08 1.5 2.25", "segments: 12.345 13.456 14.567 15.678", "2026-11-12 12:44:53",
      "ts 1731412345678", "sha 123456789012", "v1.2.3 port 8080", "123 456 7890", "duration 0.12 0.08 0.4 0.2 1.25 3.5",
      "frames 120 240 360 480", "id 20261112123456", "[0.12, 0.08, 1.5, 2.25, 3.0]", "size 1024 2048 4096 8192",
    ];
    it.each(ordinary)("leaves %s alone", (line) => {
      expect(redactSensitive(line).text).toBe(line);
      expect(detectSensitive(line)).toEqual([]);
    });
  });
});
