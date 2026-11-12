// International national-ID / tax-ID detectors. Every entry pairs a format regex with the
// country's own check-digit or structural rule, so arbitrary digit strings (timestamps, build
// ids, order numbers) are not redacted as identity documents. Pure/stateless like
// data-detectors.ts, which imports `NATIONAL_ID_DETECTORS` below.
//
// Coverage (kind is always NATIONAL_ID unless noted):
//   US ITIN, UK NHS number, Canada SIN, Australia TFN, Spain DNI/NIE, Italy Codice Fiscale,
//   France NIR, China Resident ID, Singapore NRIC/FIN, Sweden personnummer, South Africa ID,
//   Poland PESEL, Brazil CPF/CNPJ, Mexico CURP, India PAN, South Korea RRN,
//   plus labelled passport / driver's licence / tax / national-id values (any country).

export interface PiiDetector { kind: "NATIONAL_ID" | "PASSPORT" | "DRIVER_LICENSE"; pattern: RegExp; replacement: string; validate?: (match: string) => boolean }

const digitsOf = (raw: string) => raw.replace(/\D/g, "");
const weightedSum = (digits: string, weights: number[]) => weights.reduce((sum, w, i) => sum + w * Number(digits[i]), 0);

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

// Canada SIN (Luhn) and Australia TFN (weighted mod 11) share the 3-3-3 layout.
function validSinOrTfn(raw: string): boolean {
  const d = digitsOf(raw);
  if (d.length !== 9 || /^(\d)\1+$/.test(d)) return false;
  return luhn(d) || weightedSum(d, [1, 4, 3, 7, 5, 8, 6, 9, 10]) % 11 === 0;
}

// UK NHS number: weights 10..2, check = 11 - (sum mod 11); 11 -> 0, 10 is invalid.
function validNhs(raw: string): boolean {
  const d = digitsOf(raw);
  if (d.length !== 10 || /^(\d)\1+$/.test(d)) return false;
  let check = 11 - (weightedSum(d, [10, 9, 8, 7, 6, 5, 4, 3, 2]) % 11);
  if (check === 11) check = 0;
  return check !== 10 && check === Number(d[9]);
}

function validSpanishId(raw: string): boolean {
  const letters = "TRWAGMYFPDXBNJZSQVHLCKE";
  const body = raw.toUpperCase().replace(/^[XYZ]/, ch => String("XYZ".indexOf(ch)));
  return letters[Number(body.slice(0, -1)) % 23] === body.slice(-1);
}

const CF_ODD = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23];
function validCodiceFiscale(raw: string): boolean {
  const cf = raw.toUpperCase();
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    const ch = cf[i]!;
    const idx = /\d/.test(ch) ? Number(ch) : ch.charCodeAt(0) - 65;
    sum += i % 2 === 0 ? CF_ODD[idx]! : idx;
  }
  return String.fromCharCode(65 + (sum % 26)) === cf[15];
}

// France NIR: 13 digits + 2-digit key = 97 - (first 13 mod 97).
function validNir(raw: string): boolean {
  const d = digitsOf(raw);
  return d.length === 15 && 97 - (Number(d.slice(0, 13)) % 97) === Number(d.slice(13));
}

function validChinaId(raw: string): boolean {
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  return "10X98765432"[weightedSum(raw, weights) % 11] === raw[17]!.toUpperCase();
}

function validSingaporeNric(raw: string): boolean {
  const id = raw.toUpperCase();
  const offset = id[0] === "T" || id[0] === "G" ? 4 : 0;
  const table = id[0] === "S" || id[0] === "T" ? "JZIHGFEDCBA" : "XWUTRQPNMLK";
  return table[(weightedSum(id.slice(1, 8), [2, 7, 6, 5, 4, 3, 2]) + offset) % 11] === id[8];
}

function validSwedish(raw: string): boolean {
  const d = digitsOf(raw);
  const month = Number(d.slice(2, 4)), day = Number(d.slice(4, 6));
  return month >= 1 && month <= 12 && day >= 1 && day <= 91 && luhn(d); // day+60 = coordination number
}

function validSouthAfrican(raw: string): boolean { return luhn(raw); }

function validPesel(raw: string): boolean {
  const month = Number(raw.slice(2, 4)) % 20;
  if (month < 1 || month > 12) return false;
  return (10 - (weightedSum(raw, [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]) % 10)) % 10 === Number(raw[10]);
}

function validCpf(raw: string): boolean {
  const d = digitsOf(raw);
  if (d.length !== 11 || /^(\d)\1+$/.test(d)) return false;
  const check = (len: number) => {
    const sum = [...d.slice(0, len)].reduce((s, ch, i) => s + Number(ch) * (len + 1 - i), 0);
    const r = (sum * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return check(9) === Number(d[9]) && check(10) === Number(d[10]);
}

function validCnpj(raw: string): boolean {
  const d = digitsOf(raw);
  if (d.length !== 14 || /^(\d)\1+$/.test(d)) return false;
  const w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  const digit = (weights: number[]) => { const r = weightedSum(d, weights) % 11; return r < 2 ? 0 : 11 - r; };
  return digit(w1) === Number(d[12]) && digit([6, ...w1]) === Number(d[13]);
}

function validKoreanRrn(raw: string): boolean {
  const d = digitsOf(raw);
  const month = Number(d.slice(2, 4)), day = Number(d.slice(4, 6));
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  return (11 - (weightedSum(d, [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]) % 11)) % 10 === Number(d[12]);
}

// Labelled values: the label is matched in a lookbehind so only the value is redacted. A value
// must contain a digit, which keeps prose like "passport: required" from matching.
const hasDigit = (value: string) => /\d/.test(value);
const VALUE = String.raw`[A-Z0-9][A-Z0-9 -]{3,18}[A-Z0-9]\b`;
const PASSPORT_LABEL = String.raw`(?<=\bpassport(?:[ _-]?(?:no|num|number|#))?\.?\s*[:=#]\s*["']?)`;
const LICENSE_LABEL = String.raw`(?<=\b(?:driver'?s?[ _-]?licen[sc]e|driving[ _-]?licen[sc]e|dl)(?:[ _-]?(?:no|num|number|#))?\.?\s*[:=#]\s*["']?)`;
const NATIONAL_LABEL = String.raw`(?<=\b(?:national[ _-]?id|nat[ _-]?id|tax[ _-]?(?:id|number|no)|tin|ssn|sin|nino|bsn|cpf|nric|pesel|aadhaar|aadhar|pan|id[ _-]?(?:card|number)|citizen[ _-]?id)(?:[ _-]?(?:no|num|number|#))?\.?\s*[:=#]\s*["']?)`;

export const NATIONAL_ID_DETECTORS: PiiDetector[] = [
  // US ITIN: 9XX-GG-XXXX with the IRS-assigned group ranges.
  { kind: "NATIONAL_ID", pattern: /(?<![\w-])9\d{2}([- ])(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])\1\d{4}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]" },
  { kind: "NATIONAL_ID", pattern: /(?<![\w-])\d{3}([- ])\d{3}\1\d{4}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validNhs },
  { kind: "NATIONAL_ID", pattern: /(?<![\w-])\d{3}([- ])\d{3}\1\d{3}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validSinOrTfn },
  { kind: "NATIONAL_ID", pattern: /\b\d{8}[A-Z]\b|\b[XYZ]\d{7}[A-Z]\b/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validSpanishId },
  { kind: "NATIONAL_ID", pattern: /\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validCodiceFiscale },
  { kind: "NATIONAL_ID", pattern: /\b[12] ?\d{2} ?(?:0[1-9]|1[0-2]) ?\d{2} ?\d{3} ?\d{3} ?\d{2}\b/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validNir },
  { kind: "NATIONAL_ID", pattern: /\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validChinaId },
  { kind: "NATIONAL_ID", pattern: /\b[STFG]\d{7}[A-Z]\b/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validSingaporeNric },
  { kind: "NATIONAL_ID", pattern: /(?<![\w-])\d{6}[-+]\d{4}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validSwedish },
  { kind: "NATIONAL_ID", pattern: /(?<![\w-])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}[01]\d{2}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validSouthAfrican },
  { kind: "NATIONAL_ID", pattern: /(?<![\w-])\d{11}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validPesel },
  { kind: "NATIONAL_ID", pattern: /(?<![\w.-])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validCpf },
  { kind: "NATIONAL_ID", pattern: /(?<![\w.-])\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validCnpj },
  { kind: "NATIONAL_ID", pattern: /\b[A-Z]{4}\d{6}[HM][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[A-Z0-9]\d\b/g, replacement: "[NATIONAL_ID_REDACTED]" },
  { kind: "NATIONAL_ID", pattern: /\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b/g, replacement: "[NATIONAL_ID_REDACTED]" },
  { kind: "NATIONAL_ID", pattern: /(?<![\w-])\d{6}-[1-4]\d{6}(?![\w-])/g, replacement: "[NATIONAL_ID_REDACTED]", validate: validKoreanRrn },
  // Labelled catch-alls for countries without a dedicated checksum rule above.
  { kind: "PASSPORT", pattern: new RegExp(PASSPORT_LABEL + VALUE, "gi"), replacement: "[PASSPORT_REDACTED]", validate: hasDigit },
  { kind: "DRIVER_LICENSE", pattern: new RegExp(LICENSE_LABEL + VALUE, "gi"), replacement: "[DRIVER_LICENSE_REDACTED]", validate: hasDigit },
  { kind: "NATIONAL_ID", pattern: new RegExp(NATIONAL_LABEL + VALUE, "gi"), replacement: "[NATIONAL_ID_REDACTED]", validate: hasDigit },
];
