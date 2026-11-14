import type { Check } from './types.js';
export const CATEGORIES = [
 'AI agent discovery and configuration', 'Agent permissions and bypasses',
 'Git and repository safeguards', 'Workstation security', 'Sensitive data exposure',
 'Organization policy compliance', 'Scan coverage and evidence',
 'Third-party integrations and supply chain', 'Network and data destinations',
 'Updates and vulnerability management', 'Logging and incident traceability',
] as const;
export type Category = typeof CATEGORIES[number];
export function categoryFor(c: Check): Category {
 if(c.category) return c.category;
 const s=c.policySection;
 if(/Organization policy/i.test(s)) return CATEGORIES[5];
 if(/Coverage/i.test(s)) return CATEGORIES[6];
 if(/Logging|traceability/i.test(s)) return CATEGORIES[10];
 if(/Updates|vulnerability/i.test(s)) return CATEGORIES[9];
 if(/Third-party|Supply chain/i.test(s)) return CATEGORIES[7];
 if(/Network|TLS|Transport|API Tier/i.test(s)) return CATEGORIES[8];
 if(/Workstation|6\.3/i.test(s)) return CATEGORIES[3];
 if(/Repository|Git safeguards|6\.2/i.test(s)) return CATEGORIES[2];
 if(/Permissions|bypasses|4\.3/i.test(s)) return CATEGORIES[1];
 if(/4\.2|Sensitive|PII|PHI|credential|Customer|Proprietary|schema|6\.1/i.test(s)) return CATEGORIES[4];
 if(/Agent inventory|^3(?:\D|$)/i.test(s)) return CATEGORIES[0];
 return CATEGORIES[5];
}
export function categorySummary(checks: Check[]) {
 return CATEGORIES.map(category=>{
  const items=checks.filter(c=>categoryFor(c)===category);
  const counts={pass:0,fail:0,warn:0,skip:0}; for(const c of items) counts[c.status]++;
  return {category, ...counts, total:items.length, outcome:counts.fail?'fail':counts.warn?'review':counts.skip||!items.length?'not-verified':'pass'};
 });
}
