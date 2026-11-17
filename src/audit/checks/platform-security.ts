import { spawnSync } from 'node:child_process';
import type { AuditContext,Check } from '../types.js';
export interface CommandResult {status:number|null;stdout:string;}
export type CommandRunner=(command:string,args:string[])=>CommandResult;
const systemRun:CommandRunner=(command,args)=>{const r=spawnSync(command,args,{encoding:'utf8',timeout:30000,maxBuffer:1024*1024});return {status:r.status,stdout:typeof r.stdout==='string'?r.stdout:''};};
export function platformSecurityChecks(ctx:AuditContext,run:CommandRunner=systemRun):Check[]{
 const out:Check[]=[];
 function add(id:string,title:string,result:CommandResult,valid:(s:string)=>boolean,category:Check['category']='Workstation security',detail=''){
 out.push({id,category,policySection:category==='Network and data destinations'?'6.5':'6.3',title,status:result.status!==0||!result.stdout.trim()?'skip':valid(result.stdout)?'pass':'warn',detail:result.status!==0||!result.stdout.trim()?'Command failed, timed out, or returned no accessible evidence.':detail||'Checked the reported platform setting. Organization policy may require stronger controls.'});}
 const ps=(script:string)=>run('powershell.exe',['-NoProfile','-NonInteractive','-Command',`$ErrorActionPreference='Stop'; ${script}`]);
 if(ctx.platform==='win32'){
  add('windows-firewall','Windows firewall profiles enabled',ps('@(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) | ConvertTo-Json -Compress'),s=>{try{const a=JSON.parse(s);return Array.isArray(a)&&a.length===3&&a.every(x=>x===true||x===1);}catch{return false;}},'Network and data destinations');
  add('windows-update-service','Windows Update service configuration',ps('(Get-CimInstance Win32_Service -Filter "Name=\'wuauserv\'").StartMode'),s=>/Auto|Manual/.test(s),'Updates and vulnerability management','Windows Update service is not disabled. This does not prove an approved patch cadence.');
  if(ctx.online)add('windows-pending-updates','Pending Windows software updates',ps('$s=New-Object -ComObject Microsoft.Update.Session; $r=$s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type=\'Software\'"); if($r.ResultCode -ne 2){throw "Incomplete search"}; $r.Updates.Count'),s=>/^0\s*$/.test(s),'Updates and vulnerability management','Checked pending software updates through Windows Update Agent. The scan did not install updates.');
  else out.push({id:'windows-pending-updates',category:'Updates and vulnerability management',policySection:'6.3',title:'Pending Windows software updates',status:'skip',detail:'Windows Update search requires --online.'});
  add('windows-remote-desktop','Remote Desktop exposure',ps('Get-ItemPropertyValue -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections'),s=>/^1\s*$/.test(s),'Workstation security','Remote Desktop enabled/disabled setting inspected. When enabled, verify MFA through the organization access gateway.');
 }
 if(ctx.platform==='linux'){
  add('linux-root-encryption','Linux root block encryption evidence',run('lsblk',['-s','-J','-o','NAME,TYPE,MOUNTPOINT']),s=>{try{const data=JSON.parse(s);const encrypted=(x:any):boolean=>x.type==='crypt'||(x.children??[]).some(encrypted); const roots=(data.blockdevices??[]).filter((x:any)=>x.mountpoint==='/');return roots.length>0&&roots.every(encrypted);}catch{return false;}},'Workstation security','Block-device topology inspected; encryption of all volumes, swap, and home directories needs separate verification.');
  add('linux-screen-idle','GNOME inactivity timeout <= 5 minutes',run('gsettings',['get','org.gnome.desktop.session','idle-delay']),s=>{const n=Number(s.replace(/^uint32\s+/,''));return n>0&&n<=300;});
  add('linux-screen-lock','GNOME screen locking enabled',run('gsettings',['get','org.gnome.desktop.screensaver','lock-enabled']),s=>s.trim()==='true');
  add('linux-firewall','UFW firewall active',run('ufw',['status']),s=>/^Status: active/m.test(s),'Network and data destinations','UFW state inspected. Other firewall systems require separate evidence.');
  const updates=run('apt',['list','--upgradable']);
  add('linux-pending-updates','APT cached pending updates',updates,s=>!s.split('\n').some(line=>line.includes('[upgradable from:')),'Updates and vulnerability management','Compared packages with the local APT cache. Cache freshness is not verified; no packages were installed.');
  add('linux-edr','Linux endpoint protection process signals',run('ps',['-eo','comm']),s=>/falcon|sentinel|clamd|sophos|mdatp/i.test(s),'Workstation security','Known process-name signals inspected; operational health and definition freshness require vendor evidence.');
 }
 if(ctx.platform==='darwin')add('macos-firewall','macOS application firewall enabled',run('/usr/libexec/ApplicationFirewall/socketfilterfw',['--getglobalstate']),s=>/enabled|State = 1/i.test(s),'Network and data destinations');
 return out;
}
