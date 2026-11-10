import {expect,it} from '@jest/globals';
import {normalize,redact} from '../src/core.js';
import {classifyActionContext} from '../src/action-context.js';
import {explainFinding} from '../src/plain-explain.js';

const explain=(command:string,ruleId='source.private_files',severity='high')=>explainFinding({ruleId,severity,command,context:classifyActionContext('Bash',{},'/repo',command,redact,false),safe:redact})!;
const flow=(command:string)=>normalize({hook_event_name:'PreToolUse',tool_name:'Bash',tool_input:{command},session_id:'s1',cwd:'/repo'}).flow!;

// The real command from the dashboard, with the values the live detector sees (the stored copy is redacted).
const YOUTUBE=`cd /Users/yash/code/blog-bot && set -a && . ./.env.local && set +a && node --input-type=module -e '
const r=await fetch("https://oauth2.googleapis.com/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({client_id:process.env.YT_CLIENT_ID,client_secret:process.env.YT_CLIENT_SECRET,refresh_token:process.env.YT_REFRESH_TOKEN,grant_type:"refresh_token"})}).then(r=>r.json());
const a=await fetch("https://youtubeanalytics.googleapis.com/v2/reports?ids=channel==MINE",{headers:{Authorization:"Bearer "+r.access_token}}).then(r=>r.json());
console.log(a.rows.length)'`;

it('narrates "load .env.local, then an inline script that sends a request to Google using it"',()=>{
  const p=explain(YOUTUBE);
  expect(p.steps).toEqual(['loaded settings from “./.env.local”','ran an inline Node script that contacts oauth2.googleapis.com and youtubeanalytics.googleapis.com']);
  expect(p.opened).toBe('contents');
  expect(p.contacted).toEqual(['oauth2.googleapis.com','youtubeanalytics.googleapis.com']);
  expect(p.sent).toEqual({kind:'post',target:'oauth2.googleapis.com',withSecret:true});
  expect(p.verdict).toBe('risky');
});
it('the flow record marks the same command as an outward post with a secret',()=>{
  const f=flow(YOUTUBE);
  expect(f.outward).toEqual({kind:'post',target:'oauth2.googleapis.com'});
  expect(f.carriesSensitive).toBe('yes');
  expect(f.sensitive).toBe(true);
  expect(f.effects?.hosts).toEqual(['oauth2.googleapis.com','youtubeanalytics.googleapis.com']);
});
it('an API key from a loaded env file used in a curl upload is outward with a secret',()=>{
  const cmd='set -a && . ./.env && set +a && curl -s -X POST https://api.elevenlabs.io/v1/speech-to-text -H "xi-api-key: $ELEVEN_API_KEY" -F file=@voice/voice.mp3 -o out.json';
  const p=explain(cmd);
  expect(p.sent).toEqual({kind:'upload',target:'api.elevenlabs.io',withSecret:true});
  expect(p.contacted).toEqual(['api.elevenlabs.io']);
});
it('a harmless inline script is named as inline, with no hosts and nothing sent',()=>{
  const p=explain('node -e "console.log(1+1)"','credentials.environment','high');
  expect(p.steps).toEqual(['ran an inline Node script']);
  expect(p.contacted).toBeUndefined(); expect(p.sent).toBeUndefined();
});
it('a GET from inline code is contact, not something sent',()=>{
  const p=explain(`python3 -c "import requests; print(requests.get('https://api.github.com/zen').text)"`,'credentials.environment','high');
  expect(p.steps).toEqual(['ran an inline Python script that contacts api.github.com']);
  expect(p.contacted).toEqual(['api.github.com']); expect(p.sent).toBeUndefined();
});
it('a script typed as a heredoc names what it contacts and what it sends',()=>{
  const p=explain(`python3 - <<'EOF'\nimport requests\nrequests.post("https://hooks.slack.com/services/T0/B0/x", json={"text":"done"})\nEOF`,'credentials.environment','high');
  expect(p.steps[0]).toBe('ran a short Python script typed into the command that contacts hooks.slack.com');
  expect(p.sent).toEqual({kind:'post',target:'hooks.slack.com',withSecret:false});
});
it('text written to a file is not "contacted", and a plain download is not "sent"',()=>{
  const written=explain(`cat > notes.md <<'EOF'\nsee https://evil.example.com/x for details\nEOF`,'credentials.access','medium');
  expect(written.steps).toEqual(['wrote to “notes.md”']);
  expect(written.contacted).toBeUndefined();
  const get=explain('curl -s https://example.org/data.json | jq .','credentials.environment','high');
  expect(get.sent).toBeUndefined(); expect(get.contacted).toEqual(['example.org']);
});
it('an outward request that carries a secret is never rated routine',()=>{
  const p=explain('curl -s -d x=1 -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/x','credentials.environment','high');
  expect(p.sent?.withSecret).toBe(true); expect(p.verdict).not.toBe('routine');
});
it('stays small',()=>{ expect(JSON.stringify(explain(YOUTUBE)).length).toBeLessThan(1500); });
it('narrates writes to files, but not redirects to /dev/null',()=>{
  expect(explain('echo hi > out.txt','credentials.access','medium').steps).toEqual(['wrote to “out.txt”']);
  expect(explain('curl -s https://x.example.org/a.json > data.json','credentials.environment','high').steps).toEqual(['contacted x.example.org, saving the output to “data.json”']);
  expect(explain('ls .env* 2>/dev/null').steps.join(' ')).not.toMatch(/wrote|saving/);
});
