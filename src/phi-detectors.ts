// Protected health information (PHI) detectors. PHI is PII plus health context, and health context
// in free prose ("she was prescribed metformin") cannot be detected reliably without a classifier
// model, so this module covers what has structure:
//   * identifiers with a checksum or a strict format: US Medicare MBI, DEA registration numbers,
//     and NPI numbers when labelled (a bare 10-digit number is too ambiguous);
//   * labelled fields: medical record numbers, health-plan/insurance/member ids, ICD-10 codes,
//     patient names, diagnoses, medications, allergies, and clinical dates (admission, discharge, ...).
// UK NHS numbers are already covered by the national-id detectors in pii-validators.ts.
// A label must precede the value (`mrn: ...`, `"diagnosis": "..."`), which keeps code and prose that
// merely mention these words from matching. Pure/stateless, like data-detectors.ts.

export interface PhiDetector { kind: "MRN" | "HEALTH_PLAN_ID" | "MEDICAL_ID" | "PHI"; pattern: RegExp; replacement: string; validate?: (match: string) => boolean }

const hasDigit = (value: string) => /\d/.test(value);

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

// DEA registration: 2 letters + 7 digits; check digit = (d1 + d3 + d5 + 2*(d2 + d4 + d6)) mod 10.
function validDea(raw: string): boolean {
  const d = raw.slice(2).split("").map(Number);
  return (d[0]! + d[2]! + d[4]! + 2 * (d[1]! + d[3]! + d[5]!)) % 10 === d[6];
}
// NPI: Luhn over the 10 digits prefixed with 80840.
function validNpi(raw: string): boolean {
  const d = raw.replace(/\D/g, "");
  return d.length === 10 && luhn(`80840${d}`);
}

// Labelled free text must look like a value, not a type annotation or a boolean in source code.
const NOT_A_VALUE = /^(?:string|number|boolean|any|unknown|null|undefined|true|false|none|text|varchar|integer|int|date|datetime|object|array|list|json|required|optional|enum)\b|=>|[{}()<>]/i;
const looksLikeValue = (value: string) => !NOT_A_VALUE.test(value.trim());

const LABEL_TAIL = String.raw`(?:[ _-]?(?:no|num|number|#))?["']?\.?\s*[:=#]\s*["']?`;
const ID_VALUE = String.raw`[A-Z0-9][A-Z0-9-]{4,14}[A-Z0-9]\b`;
const DATE_VALUE = String.raw`(?:\d{4}-\d{2}-\d{2}|\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4})`;

export const PHI_DETECTORS: PhiDetector[] = [
  // Medical record number, patient / chart id.
  { kind: "MRN", pattern: new RegExp(String.raw`(?<=\b(?:mrn|medical[ _-]?record|patient[ _-]?id|chart)${LABEL_TAIL})${ID_VALUE}`, "gi"), replacement: "[MRN_REDACTED]", validate: hasDigit },
  // Health plan / insurance / member / beneficiary ids.
  { kind: "HEALTH_PLAN_ID", pattern: new RegExp(String.raw`(?<=\b(?:member|subscriber|insurance|policy|health[ _-]?plan|beneficiary|medicare|medicaid)[ _-]?id${LABEL_TAIL})${ID_VALUE}|(?<=\b(?:insurance|policy|medicare|medicaid)[ _-]?(?:no|num|number)${LABEL_TAIL})${ID_VALUE}`, "gi"), replacement: "[HEALTH_PLAN_ID_REDACTED]", validate: hasDigit },
  // US Medicare Beneficiary Identifier: fixed 11-character format (letters exclude S, L, O, I, B, Z).
  { kind: "MEDICAL_ID", pattern: /\b[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y]{2}\d{2}\b/g, replacement: "[MEDICAL_ID_REDACTED]" },
  // DEA registration number (checksum-validated).
  { kind: "MEDICAL_ID", pattern: /\b[ABCDEFGHJKLMPRSTUX][A-Z9]\d{7}\b/g, replacement: "[MEDICAL_ID_REDACTED]", validate: validDea },
  // NPI, only when labelled.
  { kind: "MEDICAL_ID", pattern: new RegExp(String.raw`(?<=\bnpi${LABEL_TAIL})\d{10}\b`, "gi"), replacement: "[MEDICAL_ID_REDACTED]", validate: validNpi },
  // ICD-10 diagnosis codes, only when labelled (a bare "A12" is far too common).
  { kind: "PHI", pattern: new RegExp(String.raw`(?<=\b(?:icd[ _-]?10(?:[ _-]?cm)?|icd[ _-]?code|diagnosis[ _-]?code|dx[ _-]?code)${LABEL_TAIL})[A-TV-Z]\d{2}(?:\.[0-9A-Z]{1,4})?\b`, "gi"), replacement: "[PHI_REDACTED]" },
  // Patient name.
  { kind: "PHI", pattern: new RegExp(String.raw`(?<=\b[Pp]atient(?:[ _-]?[Nn]ame)?["']?\s*[:=]\s*["']?)[A-Z][a-z]+(?:[ ,.-]+[A-Z][a-z]+){1,3}`, "g"), replacement: "[PHI_REDACTED]" },
  // Labelled clinical free text: diagnosis, medication, allergy, complaint.
  { kind: "PHI", pattern: new RegExp(String.raw`(?<=\b(?:diagnos[ie]s|dx|medications?|prescriptions?|allerg(?:y|ies)|chief[ _-]?complaint|treatment[ _-]?plan)["']?\s*[:=]\s*["']?)[A-Za-z][^\n\r;|"']{2,98}`, "gi"), replacement: "[PHI_REDACTED]", validate: looksLikeValue },
  // Clinical dates (HIPAA treats admission, discharge, service and death dates as identifiers).
  { kind: "PHI", pattern: new RegExp(String.raw`(?<=\b(?:admission|admit|discharge|visit|appointment|service|procedure|encounter|death)[ _-]?date["']?\s*[:=]\s*["']?)${DATE_VALUE}`, "gi"), replacement: "[PHI_REDACTED]" },
];
