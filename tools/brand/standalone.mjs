// Standalone design reference, intentionally synthetic and not a working product UI.
import {Resvg} from '@resvg/resvg-js';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../../',import.meta.url));
const out=path.join(root,'design/standalone');
await mkdir(path.join(out,'icons'),{recursive:true});await mkdir(path.join(out,'illustrations'),{recursive:true});
const tokens={
 version:1,
 typography:{family:'-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif',mono:'ui-monospace, SFMono-Regular, Consolas, monospace',page:28,section:18,body:14,small:12,metric:32,lineHeight:1.5},
 space:{unit:4,page:32,panel:24,gap:20,row:48,sidebar:216,inspector:360},
 radius:{control:8,panel:14,pill:999},
 motion:{feedbackMs:120,paneMs:160,reducedMotionMs:0,continuousDecorativeAnimation:false},
 light:{canvas:'#F4F6F3',surface:'#FFFFFF',subtle:'#EDF2EE',sidebar:'#F9FBF8',ink:'#173B43',muted:'#586F72',border:'#DCE5DF',accent:'#2D6B68',accentSoft:'#E4F1EA',warning:'#85581C',warningSoft:'#FFF2DA',danger:'#A13F3D',dangerSoft:'#FCECE8',info:'#385E7E',infoSoft:'#EAF1F8'},
 dark:{canvas:'#10262E',surface:'#17323B',subtle:'#203E46',sidebar:'#132C34',ink:'#ECF3EF',muted:'#AEC3C3',border:'#345159',accent:'#A9DDC9',accentSoft:'#244D49',warning:'#F1D39B',warningSoft:'#4D4028',danger:'#F1B7AD',dangerSoft:'#503A3B',info:'#BCD5EF',infoSoft:'#2A425B'},
 semantics:{statusColorIsNeverSoleIndicator:true,unknownIsNotZero:true,discoveryIsNotInspection:true,reviewIsNotCredentialValidation:true},
};
const glyphs={
 overview:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
 findings:'<circle cx="10" cy="10" r="6.5"/><path d="m15 15 6 6 M10 7v4 m0 3v.1"/>',
 sources:'<rect x="3" y="3" width="18" height="12" rx="2"/><path d="M8 21h8 M12 15v6 M6 12h12"/>',
 activity:'<path d="M2 12h4l3-7 5 14 3-7h5"/>',
 vault:'<rect x="4" y="4" width="16" height="17" rx="3"/><circle cx="12" cy="12" r="3"/><path d="M12 9v6 M9 12h6 M7 4V2 M17 4V2"/>',
 settings:'<path d="M4 6h16 M4 12h16 M4 18h16"/><rect x="7" y="4" width="3" height="4" rx="1"/><rect x="15" y="10" width="3" height="4" rx="1"/><rect x="9" y="16" width="3" height="4" rx="1"/>',
 plugins:'<path d="M4 4h6V2h4v2h6v6h2v4h-2v6h-6v2h-4v-2H4v-6H2v-4h2z"/>',
 lock:'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3 M12 14v3"/>',
 check:'<circle cx="12" cy="12" r="9"/><path d="m7 12 3 3 7-7"/>',
 gap:'<path d="m12 3 10 18H2z M12 9v5 M12 17v.2"/>',
 queued:'<circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/>',
 disconnected:'<path d="M6 8h4v8H6l-3-4z M18 8h-4v8h4l3-4z M2 3l20 18"/>',
 arrow:'<path d="M4 12h16 m-6-6 6 6-6 6"/>',
 folder:'<path d="M3 6h6l2 3h10v11H3z M3 6V4h6l2 2h8v3"/>',
 pause:'<path d="M8 5v14 M16 5v14"/>',
 search:'<circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/>',
};
let c=tokens.light;
const esc=s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
const rect=(x,y,w,h,fill=c.surface,r=14,stroke='none')=>`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${r}" fill="${fill}" stroke="${stroke}"/>`;
const text=(x,y,s,size=14,color=c.ink,weight=400)=>`<text x="${x}" y="${y}" font-family="Arial, sans-serif" font-size="${size}" fill="${color}" font-weight="${weight}">${esc(s)}</text>`;
const line=(x,y,w,color=c.border)=>`<path d="M${x} ${y}h${w}" stroke="${color}"/>`;
const icon=(name,x,y,size=20,color=c.muted)=>`<g transform="translate(${x} ${y}) scale(${size/24})" fill="none" stroke="${color}" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${glyphs[name]}</g>`;
const chip=(x,y,label,kind='info',w=label.length*6.6+24)=>rect(x,y,w,26,c[kind+'Soft'],13)+text(x+12,y+17,label,11,c[kind],600);
const button=(x,y,label,primary=false,w=label.length*7+32)=>rect(x,y,w,36,primary?c.accent:c.surface,8,primary?'none':c.border)+text(x+16,y+23,label,12,primary?(c===tokens.dark?'#173B43':'#FFF'):c.ink,600);
const panel=(x,y,w,h,title,subtitle='')=>rect(x,y,w,h,c.surface,14,c.border)+text(x+22,y+32,title,17,c.ink,600)+(subtitle?text(x+22,y+55,subtitle,12,c.muted):'');
const keyMark=await readFile(path.join(root,'design/brand/app-icon.svg'),'utf8');
const mark=(x,y,size)=>keyMark.replace('<svg ',`<svg x="${x}" y="${y}" width="${size}" height="${size}" `);
function shell(page,subtitle,{dark=false,banner=true}={}){
 c=dark?tokens.dark:tokens.light;
 let s=rect(0,0,1440,930,c.canvas,0)+rect(0,0,216,930,c.sidebar,0)+`<path d="M216 0v930" stroke="${c.border}"/>`;
 s+=mark(23,22,40)+text(72,40,'Password',14,c.ink,700)+text(72,59,'Buddy',14,c.ink,700);
 const nav=[['overview','Overview'],['findings','Findings'],['sources','Sources'],['activity','Activity'],['vault','Vault'],['settings','Settings'],['plugins','Plugins']];
 nav.forEach(([name,label],i)=>{let y=108+i*48,active=label===page;s+=active?rect(16,y,184,40,c.accentSoft,9):'';s+=icon(name,30,y+10,20,active?c.accent:c.muted)+text(62,y+26,label,13,active?c.accent:c.muted,active?600:400);if(label==='Findings')s+=chip(162,y+8,'9','warning',27);});
 s+=line(24,754,168)+icon('check',26,778,16,c.accent)+text(50,791,'Scan storage unlocked',11,c.muted)+icon('lock',26,808,16)+text(50,821,'Credential vault locked',11,c.muted)+text(26,874,'LOCAL WORKSPACE',10,c.muted,700)+text(26,895,'This Mac',12,c.ink,600);
 s+=text(248,39,'WORKSPACE / '+page.toUpperCase(),10,c.muted,600)+chip(1125,18,'Polling active','accent',114)+button(1256,16,'Pause',false,96);
 s+=text(248,101,page,29,c.ink,600)+text(248,130,subtitle,14,c.muted);
 if(banner)s+=rect(248,155,1152,42,c.infoSoft,8)+icon('activity',262,167,18,c.info)+text(290,181,'Initial backfill is still running. Completed inspections and coverage gaps are shown separately.',12,c.info);
 s+=text(248,911,'DESIGN FIXTURE · synthetic locations and counts · unavailable measurements must display “Not measured”',10,c.muted);
 return s;
}
function metric(x,title,value,copy,kind='accent'){
 return rect(x,219,370,129,c.surface,14,c.border)+text(x+22,247,title,12,c.muted,600)+text(x+22,292,value,34,c[kind],600)+text(x+22,324,copy,12,c.muted);
}
function overview(dark=false){
 let s=shell('Overview','A clear view of what needs attention and what has actually been inspected.',{dark});
 s+=metric(248,'NEEDS REVIEW','9','Potential sensitive items awaiting your review.','warning')+metric(639,'CONTENT PENDING','163','Discovery is ahead of content inspection.')+metric(1030,'COVERAGE GAPS','4','Unreadable, unsupported or deliberately omitted.','info');
 s+=panel(248,370,746,263,'Locations','Scanning your local footprint and explicitly added locations.')+button(831,387,'Manage',false,140);
 s+=text(272,455,'LOCATION',10,c.muted,600)+text(571,455,'STATE',10,c.muted,600)+text(752,455,'LAST INSPECTION',10,c.muted,600);
 const rows=[['This Mac','Automatic footprint','Scanning','accent','2 minutes ago'],['lab-vm','/demo/team','Queued','info','18 minutes ago'],['archive-vm','/demo/archive','Offline','warning','Yesterday']];
 rows.forEach(([name,sub,state,kind,last],i)=>{const y=476+i*49;s+=line(270,y-9,700)+icon('sources',272,y+2,21)+text(306,y+13,name,13,c.ink,600)+text(306,y+31,sub,10,c.muted)+chip(571,y,state,kind)+text(752,y+16,last,12,c.muted);});
 s+=panel(1014,370,386,263,'Inspection health','Execution evidence, not a “device clean” score.');
 s+=text(1038,464,'Last successful content inspection',12,c.muted)+text(1038,490,'2 minutes ago',20,c.ink,600)+line(1038,509,338);
 s+=text(1038,538,'Oldest observed pending item',12,c.muted)+text(1038,564,'Not measured',18,c.ink,600)+text(1038,594,'Available after queue-age collection starts.',11,c.muted);
 s+=panel(248,653,746,217,'Recent changes','New evidence appears here without exposing secret values.');
 [['findings','Potential access token','/demo/project/.env · 2 minutes ago','Review'],['check','Edited file inspected','/demo/config/app.json · 4 minutes ago','Details'],['disconnected','Location unavailable','archive-vm · 8 minutes ago','Sources']].forEach(([glyph,label,sub,action],i)=>{const y=730+i*49;s+=icon(glyph,274,y-12,20)+text(308,y,label,12,c.ink,600)+text(308,y+17,sub,10,c.muted)+text(882,y+6,action,12,c.accent,600);});
 s+=panel(1014,653,386,217,'Next scheduled check','Global schedule: every hour');
 s+=icon('queued',1040,734,34,c.accent)+text(1090,751,'In 24 minutes',22,c.ink,600)+text(1038,798,'Source overrides remain in effect.',12,c.muted)+button(1038,819,'Review schedule',false,184);
 return s;
}
function findings(){
 let s=shell('Findings','Review why an item matched, its copies, and the current source version.');
 s+=rect(248,219,1152,62,c.surface,12,c.border)+icon('search',266,240,18)+text(295,254,'Filter by source, rule or category…',13,c.muted)+chip(740,237,'Needs review','warning',119)+button(882,232,'All sources',false,136)+button(1034,232,'All categories',false,148)+button(1198,232,'Apply filters',true,180);
 s+=panel(248,303,744,559,'Potential sensitive material','9 rows on this page · coverage incomplete');
 s+=text(272,393,'ITEM / LOCATION',10,c.muted,600)+text(724,393,'TYPE',10,c.muted,600)+text(858,393,'STATE',10,c.muted,600);
 const rows=[['Access token','/demo/project/.env','Token','Review'],['Connection password','/demo/config/app.json','Password','Review'],['Private key material','/demo/keys/test.key','Key','Review'],['Bearer credential','/demo/logs/request.txt','Token','Review'],['Encrypted JOSE object','/demo/docs/sample.txt','JOSE','Review'],['Password assignment','/demo/scratch/settings.ini','Password','Reviewed']];
 rows.forEach(([label,sub,type,state],i)=>{let y=415+i*62;s+=i===0?rect(260,y-3,720,57,c.accentSoft,8):line(272,y-5,696);s+=icon(i===2?'vault':'findings',274,y+10,20,i===0?c.accent:c.muted)+text(307,y+20,label,13,c.ink,600)+text(307,y+39,sub,11,c.muted)+text(724,y+23,type,11,c.muted)+chip(850,y+9,state,state==='Reviewed'?'accent':'warning',104);});
 s+=text(272,834,'Page 1 · exact cursor paging',11,c.muted)+button(774,809,'Next page',false,188);
 s+=panel(1012,303,388,559,'Access token','Potential credential · not authenticated');
 s+=chip(1036,379,'Review','warning')+text(1036,434,'WHY IT MATCHED',10,c.muted,600)+text(1036,461,'Credential field + literal value',16,c.ink,600)+text(1036,489,'Rule: credential-access-token',12,c.muted)+text(1036,514,'Field: GITHUB_TOKEN · line 7',12,c.muted);
 s+=rect(1036,536,340,58,c.subtle,8)+text(1052,560,'GITHUB_TOKEN = ••••••••••••',12,c.ink,600)+text(1052,580,'Redacted evidence; value not displayed.',10,c.muted);
 s+=text(1036,631,'SOURCE VERSION',10,c.muted,600)+text(1036,656,'Inspected 2 minutes ago',13,c.ink)+text(1036,681,'Recheck before acting on an edited source.',11,c.muted);
 s+=button(1036,714,'Review & save to vault',true,340)+button(1036,762,'Mark reviewed',false,162)+button(1210,762,'Dismiss alert',false,166)+text(1036,832,'Saving does not remove the original copy.',11,c.muted);
 return s;
}
function sources(){
 let s=shell('Sources','Automatic coverage for this Mac, with deliberate remote locations.');
 s+=button(1220,89,'Add location',true,180);
 s+=panel(248,219,1152,224,'This Mac','Automatic local footprint · hidden configuration and history included');
 s+=chip(1220,240,'Scanning','accent',154)+text(272,319,'Discovery',12,c.muted,600)+text(272,346,'Still enumerating accessible locations',16,c.ink,600)+text(780,319,'Content inspection',12,c.muted,600)+text(780,346,'163 pending · 487 complete · 4 gaps',16,c.ink,600);
 s+=line(272,368,1104)+text(272,400,'Next reconciliation in 24 minutes · global schedule',12,c.muted)+button(1140,382,'View coverage',false,234);
 s+=panel(248,463,1152,248,'Additional locations','Existing SSH aliases and explicitly configured directories.');
 [['lab-vm','SSH · /demo/team','Queued','info','Every 30 minutes · override'],['archive-vm','SSH · /demo/archive','Offline','warning','Hourly · global']].forEach(([label,sub,state,kind,schedule],i)=>{const y=552+i*74;s+=line(272,y-11,1104)+icon('sources',275,y+5,24)+text(315,y+15,label,14,c.ink,600)+text(315,y+38,sub,11,c.muted)+chip(650,y+3,state,kind)+text(836,y+22,schedule,12,c.muted)+button(1214,y,'Details',false,160);});
 s+=panel(248,731,1152,139,'Coverage gaps','A gap is visible work, never a silent success.');
 s+=chip(272,809,'2 inaccessible','warning',162)+chip(452,809,'1 unsupported','info',162)+chip(632,809,'1 policy omission','info',184)+text(1044,827,'Review reasons →',13,c.accent,600);
 return s;
}
function settings(){
 let s=shell('Settings','One place to configure scope, recognition, schedules and exceptions.',{banner:false});
 s+=rect(248,160,1152,48,c.surface,10,c.border);
 ['Protection','Storage','Appearance','Advanced'].forEach((v,i)=>{s+=i===0?rect(256+i*154,168,144,32,c.accentSoft,7):'';s+=text(276+i*154,189,v,12,i===0?c.accent:c.muted,i===0?600:400);});
 s+=panel(248,230,744,184,'What to inspect','Start from a preset; retain explicit team packs and source overrides.')+chip(272,307,'Standard credentials','accent',182)+button(470,301,'Change preset',false,158)+text(272,369,'Installed packs: team-credentials · 2 custom aliases',12,c.muted)+text(791,369,'Advanced JSON →',12,c.accent,600);
 s+=panel(248,434,744,178,'When to inspect','Polling is separate from the initial backfill.');
 s+=text(272,522,'Run schedule',11,c.muted)+rect(272,535,244,44,c.subtle,8,c.border)+text(288,562,'Every hour',13,c.ink)+text(543,522,'Time zone',11,c.muted)+rect(543,535,258,44,c.subtle,8,c.border)+text(559,562,'America/New_York',13,c.ink)+text(824,561,'1 override',12,c.accent,600);
 s+=panel(248,632,744,238,'Limits & exceptions','Different controls for scope exclusion, inspection omission and alerts.');
 [['Scope exclusions','2 explicit paths','Review'],['Inspection limits','20 MiB / file · 2 workers','Edit'],['Alert preferences','Notify for new findings','Edit']].forEach(([a,b,d],i)=>{let y=720+i*48;s+=line(272,y-13,696)+text(272,y+8,a,12,c.ink,600)+text(479,y+8,b,12,c.muted)+text(905,y+8,d,12,c.accent,600);});
 s+=panel(1012,230,388,640,'Review changes','Preview before changing active behavior.');
 s+=chip(1036,310,'2 proposed changes','info',189)+text(1036,371,'Reconciliation',12,c.muted)+text(1036,400,'Hourly → every 15 minutes',16,c.ink,600)+text(1036,426,'Origin: custom preset',11,c.muted)+line(1036,449,340)+text(1036,484,'Custom aliases',12,c.muted)+text(1036,513,'1 → 2 explicit aliases',16,c.ink,600)+text(1036,539,'Origin: team-credentials@1',11,c.muted);
 s+=rect(1036,572,340,87,c.infoSoft,9)+text(1052,599,'Unchanged',12,c.info,600)+text(1052,623,'Automatic Mac scope, vault location',12,c.info)+text(1052,644,'and source schedule overrides.',12,c.info);
 s+=text(1036,705,'Native events and archive recursion',12,c.muted)+text(1036,727,'are not available in this version.',12,c.muted)+button(1036,771,'Apply reviewed changes',true,340)+text(1036,835,'Preview expires if settings change elsewhere.',11,c.muted);
 return s;
}
function vault(){
 let s=shell('Vault','Your credential vault has its own independent unlock gate.',{banner:false});
 s+=panel(248,165,1152,91,'Scan storage is available','Review and scanning can continue while the credential vault stays locked.')+chip(1202,193,'Vault locked','info',173);
 s+=rect(248,280,706,583,c.surface,14,c.border)+illustration('lock',472,322,220)+text(487,578,'Vault is locked',25,c.ink,600)+text(370,612,'Unlock only when you need to save, reveal or copy a credential.',13,c.muted)+button(457,645,'Unlock credential vault',true,286)+text(387,710,'OS session lock and app close lock the vault again.',12,c.muted)+text(396,739,'Scan storage uses a separate key and lock state.',12,c.muted);
 s+=panel(974,280,426,583,'Review → save → verify','A deliberate handoff, with no automatic source deletion.');
 [['1','Review the source','Check the current version and why it matched.'],['2','Unlock and save','Choose a label and confirm the destination.'],['3','Verify the entry','Confirm the vault accepted the credential.'],['4','Recheck the original','Its original copy may still need attention.']].forEach(([n,label,sub],i)=>{let y=388+i*103;s+=rect(1000,y-20,29,29,c.accentSoft,15)+text(1010,y,n,12,c.accent,600)+text(1045,y,label,15,c.ink,600)+text(1000,y+35,sub,12,c.muted);});
 s+=text(1000,833,'Cancel safely at any step. Never imply “removed”.',11,c.muted);return s;
}
function activity(){
 let s=shell('Activity','Inspect what ran, what completed, and what needs another attempt.');
 s+=panel(248,219,744,644,'Recent inspection runs','A completed slice is not a completed full-machine backfill.');
 [['This Mac','Running','accent','Bounded slice · 24 completed · 3 deferred'],['lab-vm','Completed','accent','Reconciliation · next check in 18 minutes'],['archive-vm','Needs attention','warning','Acquisition · ssh-timeout · retry pending'],['This Mac','Completed','accent','Bounded slice · 31 complete · 1 unsupported']].forEach(([name,state,kind,sub],i)=>{let y=313+i*114;s+=i===0?rect(264,y-8,712,99,c.accentSoft,9):line(272,y-10,696);s+=icon('activity',280,y+11,24)+text(322,y+22,name,15,c.ink,600)+chip(796,y+4,state,kind,174)+text(322,y+49,sub,12,c.muted)+text(322,y+72,'Run receipt · source generation · effective policy',10,c.muted);});
 s+=button(272,796,'Load older runs',false,214);
 s+=panel(1012,219,388,644,'Current run','Only measured stage evidence is displayed.');
 [['Enumerate','Locations observed'],['Acquire','Current source version verified'],['Parse','Bounded document extraction'],['Recognize','Installed configured detectors'],['Publish','Findings + completion receipt']].forEach(([title,sub],i)=>{let y=325+i*79;s+=icon(i<3?'check':'queued',1036,y-17,20,i<3?c.accent:c.muted)+text(1070,y,title,14,c.ink,600)+text(1070,y+23,sub,11,c.muted);if(i<4)s+=`<path d="M1046 ${y+11}v38" stroke="${c.border}"/>`;});
 s+=line(1036,738,340)+text(1036,771,'Oldest pending completion',12,c.muted)+text(1036,799,'Not measured',18,c.ink,600)+text(1036,833,'Stage failures show codes, never secret values.',11,c.muted);return s;
}
function illustration(kind,x,y,size=140){
 const accent=c.accent,soft=c.accentSoft;
 return `<g transform="translate(${x} ${y}) scale(${size/160})">${rect(4,14,152,132,c.subtle,28)}<circle cx="80" cy="80" r="48" fill="${soft}"/>${icon(kind,52,52,56,accent)}<circle cx="133" cy="27" r="6" fill="${c.warningSoft}"/><path d="M23 124h22 M34 113v22" stroke="${c.border}" stroke-width="2" stroke-linecap="round"/></g>`;
}
function states(){
 let s=shell('Overview','State patterns: explicit, calm, and honest about unavailable evidence.',{banner:false});
 const cards=[['lock','Scan storage locked','Unlock to resume scanning and see findings.','Unlock scan storage'],['disconnected','Location offline','Its last findings remain; freshness is unknown.','Review connection'],['search','No matching findings','No rows matched these filters. Coverage may be incomplete.','Clear filters'],['folder','No additional locations','This Mac can still be covered automatically.','Add a location']];
 cards.forEach(([glyph,title,copy,action],i)=>{let x=248+(i%2)*586,y=170+Math.floor(i/2)*352;s+=rect(x,y,566,330,c.surface,14,c.border)+illustration(glyph,x+29,y+35,122)+text(x+175,y+86,title,20,c.ink,600);const words=copy.split(' ');let split=words.length>8?7:words.length;s+=text(x+175,y+119,words.slice(0,split).join(' '),12,c.muted)+text(x+175,y+139,words.slice(split).join(' '),12,c.muted)+button(x+175,y+174,action,true,330)+text(x+25,y+293,'Never substitute a successful / clean state for missing evidence.',11,c.muted);});return s;
}
function addLocation(){
 let s=sources();s+=rect(216,0,1224,930,'#10262E',0).replace('fill="#10262E"','fill="#10262E" fill-opacity=".18"');
 s+=rect(880,0,560,930,c.surface,0)+text(912,47,'Add a location',25,c.ink,600)+text(912,79,'Explicit scope. Existing credentials and host trust.',13,c.muted)+text(1394,46,'×',24,c.muted);
 s+=chip(912,113,'SSH directory','accent',150)+text(912,178,'DISPLAY NAME',11,c.muted,600)+rect(912,191,496,46,c.subtle,8,c.border)+text(928,220,'Team working files',14);
 s+=text(912,276,'EXISTING SSH ALIAS',11,c.muted,600)+rect(912,289,496,46,c.subtle,8,c.border)+text(928,318,'lab-vm',14)+text(912,360,'No key material is entered or copied here.',12,c.muted);
 s+=text(912,403,'DIRECTORY',11,c.muted,600)+rect(912,416,496,46,c.subtle,8,c.border)+text(928,445,'/demo/team',14)+button(912,482,'Check location',false,496);
 s+=rect(912,543,496,107,c.infoSoft,10)+text(932,574,'Check before adding',14,c.info,600)+text(932,600,'Verify the configured host and directory identity.',12,c.info)+text(932,625,'Adding this source does not grant broader access.',12,c.info);
 s+=text(912,696,'SCHEDULE',11,c.muted,600)+chip(912,718,'Use global schedule','accent',185)+button(1113,713,'Set override',false,295);
 s+=line(912,822,496)+button(912,849,'Cancel',false,150)+rect(1078,849,330,36,c.subtle,8)+text(1094,872,'Add checked location',12,c.muted,600);return s;
}
function plugins(){
 let s=shell('Plugins','Review installed capabilities and explicitly configure recognition packs.',{banner:false});
 s+=panel(248,167,1152,112,'Standard credentials + team-credentials','Resolved profile · installed components · explicit aliases · no automatic plugin downloads.')+button(1174,201,'Edit profile',true,202);
 const cards=[['Native rules','Gitleaks','Provider formats and explicit credential rules','Enabled'],['Credential aliases','Credential detector','Bundled roles + explicit team aliases','Enabled'],['JOSE & entities','Presidio factory','Configured pattern recognizers; no NER model','Enabled'],['Document text','Extractors','Bounded PDF / OOXML / MSG text surfaces','Available']];
 cards.forEach(([title,sub,copy,state],i)=>{let x=248+(i%2)*586,y=301+Math.floor(i/2)*226;s+=panel(x,y,566,206,title,sub)+icon('plugins',x+496,y+25,30,c.accent)+text(x+24,y+105,copy,12,c.muted)+chip(x+24,y+142,state,'accent',110)+text(x+365,y+159,'View provenance →',12,c.accent,600);});
 s+=rect(248,775,1152,89,c.infoSoft,12)+icon('gap',272,800,24,c.info)+text(314,808,'Capability unavailable is a real state',14,c.info,600)+text(314,835,'Native event monitoring, recursive archives and read auditing are not installed. No decorative “on” toggles.',12,c.info);return s;
}
const pages=[['01-overview','Overview',()=>overview()],['02-findings','Findings',findings],['03-sources','Sources',sources],['04-settings','Settings',settings],['05-vault','Vault',vault],['06-activity','Activity',activity],['07-add-location','Add location',addLocation],['08-state-patterns','States',states],['09-plugins','Plugins',plugins],['10-overview-dark','Dark overview',()=>overview(true)]];
const records=[];
async function output(file,data){await writeFile(path.join(out,file),data);records.push({path:file,sha256:createHash('sha256').update(data).digest('hex')});}
const svg=(body,view='0 0 1440 930')=>`<svg xmlns="http://www.w3.org/2000/svg" viewBox="${view}">${body}</svg>`;
for(const [id,,render] of pages){const source=svg(render());await output(id+'.svg',source);await output(id+'.png',new Resvg(source,{fitTo:{mode:'width',value:1440}}).render().asPng());}
c=tokens.light;
for(const name of Object.keys(glyphs))await output(`icons/${name}.svg`,svg(icon(name,0,0,24,'currentColor'),'0 0 24 24'));
for(const name of ['lock','disconnected','search','folder'])await output(`illustrations/${name}.svg`,svg(illustration(name,0,0,160),'0 0 160 160'));
await output('tokens.json',JSON.stringify(tokens,null,2)+'\n');
await output('tokens.css',`:root {\n${Object.entries(tokens.light).map(([k,v])=>`  --buddy-${k.replace(/[A-Z]/g,x=>'-'+x.toLowerCase())}: ${v};`).join('\n')}\n  --buddy-radius-panel: 14px;\n  --buddy-radius-control: 8px;\n  --buddy-focus-ring: 0 0 0 3px #82b8b2;\n  --buddy-duration: 120ms;\n}\n[data-theme="dark"] {\n${Object.entries(tokens.dark).map(([k,v])=>`  --buddy-${k.replace(/[A-Z]/g,x=>'-'+x.toLowerCase())}: ${v};`).join('\n')}\n}\n@media (prefers-reduced-motion: reduce) { :root { --buddy-duration: 0ms; } }\n`);
const html=`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Password Buddy — standalone design reference</title><style>body{margin:0;background:#e8eeea;color:#173b43;font:14px system-ui}header{padding:18px 24px;background:#fff;border-bottom:1px solid #dce5df;position:sticky;top:0;z-index:2}h1{font-size:18px;margin:0 0 8px}p{margin:0;color:#586f72}nav{display:flex;gap:6px;flex-wrap:wrap;margin-top:14px}button,a{font:inherit}button{border:1px solid #dce5df;background:#fff;border-radius:8px;padding:8px 12px;color:#173b43;cursor:pointer}button[aria-pressed=true]{background:#2d6b68;color:#fff}button:focus-visible,a:focus-visible{outline:3px solid #82b8b2;outline-offset:2px}main{padding:24px;max-width:1440px;margin:auto}img{width:100%;height:auto;box-shadow:0 12px 42px #173b4312;border-radius:12px}footer{padding:14px 0;color:#586f72}a{color:#2d6b68}</style><header><h1>Password Buddy · standalone design reference</h1><p>Editable SVG screens and synthetic states. This is a design browser, not the running scanner.</p><nav aria-label="Reference screens">${pages.map(([id,title],i)=>`<button data-id="${id}" aria-pressed="${i===0}">${title}</button>`).join('')}</nav></header><main><img id="screen" src="01-overview.svg" alt="Overview design reference"><footer><a id="download" href="01-overview.svg" download>Download editable SVG</a> · <a href="README.md">Implementation and behavior notes</a> · Actual data must come from the authenticated backend.</footer></main><script>document.querySelectorAll('button[data-id]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('button[data-id]').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));const img=document.getElementById('screen');img.src=b.dataset.id+'.svg';img.alt=b.textContent+' design reference';document.getElementById('download').href=img.src;}));</script></html>`;
await output('preview.html',html);
await writeFile(path.join(out,'manifest.json'),JSON.stringify({version:1,syntheticOnly:true,generator:'tools/brand/standalone.mjs',screens:pages.map(([id,title])=>({id,title})),files:records},null,2)+'\n');
console.log(`Wrote ${pages.length} editable screens and ${records.length} assets.`);
