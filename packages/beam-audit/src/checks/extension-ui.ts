import { testExtensionReview, unavailableExtensionReview } from './extension-review.js';
import { createHash } from 'node:crypto';
import { chromium, type Frame, type Browser } from 'playwright-core';
import { readFileSync } from 'node:fs';
import { EXTENSION_PROBES, createExtensionPrompt, type ExtensionProbe } from '../extension-probes.js';
import type { MatrixCell, Surface } from './matrix-test.js';
import type { AuditContext } from '../types.js';
export interface ExtensionAdapter {
 agent:'Claude'|'Codex'; extensionId:string; composerSelector:string; submitSelector:string;
 assistantSelector:string; userSelector:string; emptyChatSelector:string; pendingSelector?:string; approvalSelector?:string;
 // Optional organization control UI must echo this test's unique ID to establish correlation.
 blockedSelector?:string;
}
export const DEFAULT_EXTENSION_ADAPTERS: ExtensionAdapter[] = [
 {agent:'Claude',emptyChatSelector:'[class*="emptyState_"]',extensionId:'anthropic.claude-code',composerSelector:'[role="textbox"][aria-label="Message input"]',submitSelector:'button[aria-label="Send message"]',assistantSelector:'[class*="message_"]:has([data-message-actions])',userSelector:'[class*="userMessageContainer_"]',pendingSelector:'button[aria-label="Stop"]'},
 {agent:'Codex',emptyChatSelector:'[data-vscode-context*="supportsNewChatMenu"]:not(:has([data-thread-find-target="conversation"]))',extensionId:'openai.chatgpt',composerSelector:'[data-codex-composer][contenteditable="true"], [data-codex-composer] [contenteditable="true"]',submitSelector:'button[aria-label="Send message"], button[aria-label="Send prompt"], button[aria-label="Send"], button[data-testid="send-button"]',assistantSelector:'[data-local-conversation-final-assistant="true"] [data-markdown-text-style="assistant-message"]',userSelector:'[data-markdown-text-tone="user-message"]',pendingSelector:'button[aria-label="Stop generating"], button[aria-label="Stop"]'},
];
export function loadExtensionAdapters(path?:string):ExtensionAdapter[]{
 if(!path)return DEFAULT_EXTENSION_ADAPTERS;
 const parsed=JSON.parse(readFileSync(path,'utf8'));
 if(!Array.isArray(parsed)||!parsed.length||parsed.length>2)throw new Error('Extension adapter file must contain one or two adapters');
 for(const a of parsed){if(!['Claude','Codex'].includes(a.agent)||!['anthropic.claude-code','openai.chatgpt'].includes(a.extensionId))throw new Error('Unsupported extension identity');
 for(const field of ['composerSelector','submitSelector','assistantSelector','userSelector','emptyChatSelector'])if(typeof a[field]!=='string'||!a[field].trim())throw new Error(`Missing adapter ${field}`);
 for(const field of ['pendingSelector','blockedSelector','approvalSelector'])if(a[field]!==undefined&&typeof a[field]!=='string')throw new Error(`Invalid adapter ${field}`);
 if(a.extensionId!==(a.agent==='Claude'?'anthropic.claude-code':'openai.chatgpt'))throw new Error('Agent/extension identity mismatch');}
 return parsed;
}
export function validateCdpEndpoint(endpoint:string):string {
 const url=new URL(endpoint);
 if(!['http:','https:'].includes(url.protocol)||!['127.0.0.1','localhost','[::1]'].includes(url.hostname)||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw new Error('VS Code CDP endpoint must be a credential-free loopback HTTP(S) origin');
 return url.origin;
}
export function classifyExtensionEvidence(probe:ExtensionProbe,id:string,response:string,blockEvent:string):{blocked:boolean|null;detail:string}{
 if(response.includes(id)&&response.includes(probe.value))return {blocked:false,detail:'The extension assistant response echoed this test ID and synthetic fixture. This synthetic sample was not blocked before reaching the response path. Synthetic fixtures may be permitted by policy; this does not establish that real sensitive data would pass.'};
 if(blockEvent.includes(id))return {blocked:true,detail:'The configured guardrail UI reports a block event correlated with this unique test ID. This is UI evidence, not independent network interception proof.'};
 return {blocked:null,detail:'No conclusive result. A refusal, omitted echo, timeout, or missing response does not prove a pre-transmission block.'};
}
function surface(adapter:ExtensionAdapter):Surface{return adapter.agent==='Claude'?'VS Code · Claude extension':'VS Code · Codex extension';}
function unavailable(adapter:ExtensionAdapter,detail:string,probes=EXTENSION_PROBES):MatrixCell[]{return probes.map(p=>({surface:surface(adapter),label:`${p.category} / ${p.label}`,blocked:null,detail}));}
async function findFrame(browser:Browser,adapter:ExtensionAdapter):Promise<Frame|null>{
 const matches:Frame[]=[];
 for(const context of browser.contexts())for(const page of context.pages())for(const frame of page.frames()){
  try{
   // Identity uses loaded extension resource URLs, never chat text or authentication storage.
   const resources=await frame.evaluate(()=>document.baseURI+'\n'+[...document.querySelectorAll('script[src], link[href]')].map(n=>n.getAttribute('src')??n.getAttribute('href')??'').join('\n'));
   if(resources.includes(adapter.extensionId)&&await frame.locator(adapter.composerSelector).count()===1&&await frame.locator(adapter.composerSelector).isVisible())matches.push(frame);
  }catch{/* Detached/unavailable webview. */}
 }
 return matches.length===1?matches[0]!:null;
}
export async function testExtensionFrame(frame:Frame,adapter:ExtensionAdapter,probes=EXTENSION_PROBES,timeoutMs=30000,log:(message:string)=>void=()=>{},ownedConversation?:{userMessages:string[];assistantMessages:string[]}):Promise<MatrixCell[]>{
 const cells:MatrixCell[]=[];
 const composer=frame.locator(adapter.composerSelector);
 const current=await composer.inputValue({timeout:1000}).catch(()=>composer.innerText({timeout:1000}));
 const users=await frame.locator(adapter.userSelector).allTextContents();
 const assistants=await frame.locator(adapter.assistantSelector).allTextContents();
 const exact=(actual:string[],expected:string[])=>actual.length===expected.length&&actual.every((value,i)=>value.trim()===expected[i]?.trim());
 // Internal callers may resume a conversation they created only with exact known transcript evidence.
 const owned=ownedConversation&&ownedConversation.userMessages.length>0&&exact(users,ownedConversation.userMessages)&&exact(assistants,ownedConversation.assistantMessages);
 if(current.trim()||(!owned&&(!await frame.locator(adapter.emptyChatSelector).isVisible().catch(()=>false)||assistants.length||users.length)))return unavailable(adapter,'An empty conversation could not be verified (or the version-specific adapter did not match). Open an empty extension conversation first. The scanner will not append to an existing chat or overwrite a draft.',probes);
 for(const probe of probes){
  log(`${adapter.agent} extension: testing ${probe.category} / ${probe.label}`);
  const {id,prompt}=createExtensionPrompt(probe);
  try{

   // Refuse ambiguous selectors rather than submitting through the wrong control.
   if(await composer.count()!==1||await frame.locator(adapter.submitSelector).count()!==1)throw new Error('Ambiguous UI controls');
   await composer.fill(prompt,{timeout:3000});
   await frame.locator(adapter.submitSelector).click({timeout:3000});
   const deadline=Date.now()+timeoutMs;let lastResponse='',observedResponse='',stableSince=Date.now();let result={blocked:null as boolean|null,detail:'No conclusive extension response.'};
   while(Date.now()<deadline){
    const responses=frame.locator(adapter.assistantSelector);
    let response='';if(await responses.count()>0)response=await responses.last().innerText({timeout:1000});
    if(response.includes(id))observedResponse=response;
    const blockEvent=adapter.blockedSelector?await frame.locator(adapter.blockedSelector).allTextContents().then(x=>x.join('\n')):'';
    result=classifyExtensionEvidence(probe,id,response,blockEvent);
    if(result.blocked!==null)break;
    if(response!==lastResponse){lastResponse=response;stableSince=Date.now();}
    const pending=adapter.pendingSelector ? await frame.locator(adapter.pendingSelector).isVisible().catch(()=>false) : false;
    if(response.includes(id) && !pending && Date.now()-stableSince>=1500)break;
    await new Promise(resolve=>setTimeout(resolve,250));
   }
   log(`${adapter.agent} extension: ${probe.label}: ${result.blocked === false ? "sample echoed (not blocked)" : result.blocked === true ? "guardrail reports block" : "inconclusive"}`);
   cells.push({surface:surface(adapter),label:`${probe.category} / ${probe.label}`,testId:id,dataCategory:probe.category,observedAt:new Date().toISOString(),responseSha256:observedResponse ? createHash("sha256").update(observedResponse).digest("hex") : undefined,...result});
   // Never submit the next test while a turn is still running or a draft remains.
   while(adapter.pendingSelector&&Date.now()<deadline&&await frame.locator(adapter.pendingSelector).isVisible().catch(()=>false)) await new Promise(resolve=>setTimeout(resolve,250));
   if(adapter.pendingSelector&&await frame.locator(adapter.pendingSelector).isVisible().catch(()=>false)){
    cells.push(...unavailable(adapter,'Previous turn is still running; remaining tests were not submitted.',probes.slice(cells.length)));break;
   }
   const draft=await composer.inputValue({timeout:1000}).catch(()=>composer.innerText({timeout:1000}));
   if(draft.trim()) {cells.push(...unavailable(adapter,'Previous submission left content in the composer; remaining tests were not submitted.',probes.slice(cells.length)));break;}
  }catch{
   cells.push(...unavailable(adapter,'UI controls unavailable, ambiguous, changed, or timed out. No blocking result inferred. Inspect the extension chat before rerunning.',probes.slice(cells.length)));break;
  }
 }
 return cells;
}
export async function runExtensionUiTests(ctx:AuditContext,endpoint:string,adapters=DEFAULT_EXTENSION_ADAPTERS,options:{waitForUiMs?:number;reviewWorkspace?:string}={}):Promise<MatrixCell[]>{
 const origin=validateCdpEndpoint(endpoint);let browser:Browser;
 try{browser=await chromium.connectOverCDP(origin,{timeout:5000});}catch{return adapters.flatMap(a=>[...unavailable(a,'VS Code debugging endpoint unavailable. Start VS Code with a loopback remote debugging port and open an empty extension chat.'),unavailableExtensionReview(a,'Extension UI endpoint unavailable; edit review test not submitted.')]);}
 try{const cells:MatrixCell[]=[];
 for(const adapter of adapters){ctx.log(`testing actual VS Code ${adapter.agent} extension UI with synthetic fixtures`);let frame=await findFrame(browser,adapter);
 const readyDeadline=Date.now()+(options.waitForUiMs??0);let lastNotice=0;
 while(!frame&&Date.now()<readyDeadline){
  if(Date.now()-lastNotice>10000){ctx.log(`Waiting for a visible empty ${adapter.agent} extension chat in the isolated window (authentication/trust may require attention).`);lastNotice=Date.now();}
  await new Promise(resolve=>setTimeout(resolve,1000));frame=await findFrame(browser,adapter);
 }
 if(!frame){cells.push(...unavailable(adapter,'A unique visible extension chat could not be identified. Open its empty chat; adapter selectors may need updating for this extension version.'));cells.push(unavailableExtensionReview(adapter,'No unique visible extension frame; edit review test not submitted.'));continue;}
 try{
 const dataCells=await testExtensionFrame(frame,adapter,EXTENSION_PROBES,30000,ctx.log);cells.push(...dataCells);
 const submitted=dataCells.some(cell=>Boolean(cell.testId));
 if(options.reviewWorkspace&&submitted){ctx.log(`testing automatic file-edit review in the isolated ${adapter.agent} extension workspace`);cells.push(await testExtensionReview(frame,adapter,options.reviewWorkspace));}
 else cells.push(unavailableExtensionReview(adapter,'No verified audit conversation or isolated synthetic workspace was available. No edit request submitted.'));
 }catch{cells.push(...unavailable(adapter,'Extension UI inspection failed; no blocking result inferred.'));cells.push(unavailableExtensionReview(adapter,'UI stage unavailable; edit review test not submitted.'));}}
 return cells;
 }finally{await browser.close();} // Disconnect CDP; do not close the user's VS Code window.
}
