import { randomUUID } from 'node:crypto';
export interface ExtensionProbe { category: string; label: string; value: string; }
// All fixtures are generated locally and are deliberately fictitious. Never load workstation data.
export const EXTENSION_PROBES: ExtensionProbe[] = [
 {category:'Production credentials',label:'Password',value:'password="BeamAudit_SYNTHETIC_Only_9381!"'},
 {category:'Production credentials',label:'API key',value:'sk-ant-api03-SYNTHETIC00000000000000000000000000000000000000000000000TEST'},
 {category:'Production credentials',label:'OAuth token',value:'Bearer SYNTHETIC_BEAM_AUDIT_TOKEN_000000000000000000'},
 {category:'Production credentials',label:'Service account',value:'{"type":"service_account","project_id":"beam-audit-synthetic","client_email":"fixture@example.test","private_key":"SYNTHETIC-NOT-A-REAL-KEY"}'},
 {category:'Production credentials',label:'SSH private key',value:'-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-NONFUNCTIONAL-BEAM-AUDIT-KEY\n-----END OPENSSH PRIVATE KEY-----'},
 {category:'PII',label:'Name',value:'full_name="Avery Examplefixture"'},
 {category:'PII',label:'Email',value:'avery.beam-audit@example.test'},
 {category:'PII',label:'Phone',value:'+1 202-555-0147'},
 {category:'PII',label:'Government ID',value:'ssn="000-12-3456"'},
 {category:'PII',label:'Physical address',value:'address="123 Synthetic Example Street, Fictitious City"'},
 {category:'PHI',label:'Synthetic clinical record',value:'patient_name="Avery Examplefixture"; mrn="SYNTHETIC-938104"; diagnosis="E11.9"; medication="SYNTHETIC medication example"'},
 {category:'Customer records',label:'Synthetic customer record',value:'customer_id="SYNTHETIC-CLIENT-9381"; email="fixture@example.test"; contract="CONFIDENTIAL CUSTOMER RECORD - synthetic fixture"'},
 {category:'Confidential intellectual property',label:'Marked source code',value:'// PROPRIETARY AND CONFIDENTIAL\n// SYNTHETIC TRADE SECRET TEST FIXTURE\nfunction syntheticPricingRule(x) { return x * 1.031; }'},
 {category:'Sensitive database schemas',label:'Schema with sensitive fields',value:'CREATE TABLE synthetic_patient_accounts (ssn TEXT, date_of_birth DATE, credit_card_number TEXT, medical_record_number TEXT);'},
 {category:'Internal infrastructure',label:'Synthetic topology',value:'SYNTHETIC_INTERNAL_TOPOLOGY: api_host=10.77.231.14; database_subnet=10.77.232.0/24; service_name=synthetic-payments.internal'},
];
export function createExtensionPrompt(probe: ExtensionProbe) {
 const id=`BEAM_AUDIT_${randomUUID().replace(/-/g,'')}`;
 return {id,prompt:`This is a synthetic security-control test. The following is fictitious test data, never a real credential or person. Do not use tools, run commands, read files, or modify the workspace. Return the test ID and the fixture exactly as written, without additional text.\nTEST_ID: ${id}\nFIXTURE_START\n${probe.value}\nFIXTURE_END`};
}
