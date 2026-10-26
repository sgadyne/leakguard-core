import { app, BrowserWindow, clipboard, dialog, ipcMain, Menu, nativeImage, powerMonitor, session, Tray, type IpcMainInvokeEvent } from 'electron';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { ClipboardOwner } from './clipboard.ts';
import { Control } from './control.ts';
import { CHANNELS, type BackendStatus, type ClearReason, type DesktopEvent, type Page, type Preferences } from './contracts.ts';
import { backupBytes, failure, pageAllowed, record } from './policy.ts';
import { canonicalDataDirectorySync, cleanEnvironment, prepareRuntime, waitForPreparation } from './runtime.ts';

let window:BrowserWindow|undefined;
let tray:Tray|undefined;
let control:Control|undefined;
let origin='';
let dataDir='';
let status:BackendStatus|undefined;
let stage='Starting Password Buddy…';
let preferences:Preferences={theme:'system',startAtLogin:false};
let firstCloseExplained=false;
let quitAllowed=false;
let quitting=false;
let requestedOpen=false;
let pendingPage:Page|undefined;
let startup:Promise<void>|undefined;
let recovering=false;
let lockInFlight:Promise<void>|undefined;
const clipboardOwner=new ClipboardOwner({readText:()=>clipboard.readText(),writeText:text=>clipboard.writeText(text),clear:()=>clipboard.clear()});
let statusTimer:NodeJS.Timeout|undefined;
let idleTimer:NodeJS.Timeout|undefined;
let idleLocked=false;
const supportedLogin=()=>app.isPackaged && (process.platform==='darwin'||process.platform==='win32');
const supportedLock=()=>process.platform==='darwin'||process.platform==='win32';
const asset=(name:string)=>path.join(__dirname,'..','assets',name);

function emit(event:DesktopEvent){
  if(window && !window.isDestroyed())window.webContents.send(CHANNELS.event,event);
}
function errorCode(error:unknown):string{
  const value=error instanceof Error?error.message:'desktop-operation-failed';
  return /^[a-z][a-z0-9-]{0,79}$/.test(value)?value:'desktop-operation-failed';
}
const clearClipboard=()=>clipboardOwner.clear();
function clearSensitive(reason:ClearReason){emit({type:'clear-sensitive',reason});void clearClipboard();}
function updateMenus(){
  const scan=status?status.observations.unlocked?'Scan storage unlocked':'Scan storage locked':stage;
  const vault=status?status.vault.unlocked?'Credential vault unlocked':'Credential vault locked':'Credential vault unavailable';
  const jobs=status?status.pending_jobs+' pending scan jobs':'Backend unavailable';
  const menu=[
    {label:'Open Password Buddy',click:()=>show()},
    {label:scan,enabled:false},{label:vault,enabled:false},{label:jobs,enabled:false},
    {type:'separator' as const},
    {label:'Open Sources',click:()=>show('sources')},
    {label:'Lock credential vault',enabled:!!status?.vault.unlocked && !quitting,click:()=>{void lockCredentials('hide');}},
    {label:'Settings',click:()=>show('settings')},
    {type:'separator' as const},
    {label:'Quit Password Buddy',click:()=>{void requestQuit();}},
  ];
  app.dock?.setBadge(status?'':'…');
  tray?.setContextMenu(Menu.buildFromTemplate(menu));
  tray?.setToolTip('Password Buddy — '+(control?.hasExited?'Unavailable':scan));
  const applicationMenu:Electron.MenuItemConstructorOptions[]=[
    ...(process.platform==='darwin'?[{label:'Password Buddy',submenu:[
      {role:'about' as const},{type:'separator' as const},{label:'Settings…',accelerator:'CmdOrCtrl+,',click:()=>show('settings')},
      {type:'separator' as const},{role:'hide' as const},{role:'hideOthers' as const},{role:'unhide' as const},
      {type:'separator' as const},{label:'Quit Password Buddy',accelerator:'CmdOrCtrl+Q',click:()=>{void requestQuit();}},
    ]}]:[{label:'File',submenu:[{label:'Open Password Buddy',click:()=>show()},{label:'Quit',accelerator:'Ctrl+Q',click:()=>{void requestQuit();}}]}]),
    {label:'Edit',submenu:[{role:'undo'},{role:'redo'},{type:'separator'},{role:'cut'},{role:'copy'},{role:'paste'},{role:'selectAll'}]},
    {label:'View',submenu:[{role:'reload'},{role:'resetZoom'},{role:'zoomIn'},{role:'zoomOut'}]},
    {label:'Window',submenu:[{role:'minimize'},{label:'Open Password Buddy',click:()=>show()}]},
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(applicationMenu));
}
function show(page?:Page){
  requestedOpen=true;if(page)pendingPage=page;
  if(!window || window.isDestroyed())return;
  if(window.isMinimized())window.restore();
  window.show();window.focus();
  if(page && !window.webContents.isLoadingMainFrame()){emit({type:'navigate',page});pendingPage=undefined;}
}
async function refreshStatus(){
  const current=control;
  if(!current || current.hasExited)return;
  try{
    const result=await current.request('status',10_000) as BackendStatus;
    if(!result || typeof result.observations?.unlocked!=='boolean' || typeof result.vault?.unlocked!=='boolean' ||
       !Number.isSafeInteger(result.pending_jobs)||result.pending_jobs<0)throw failure('backend-protocol-invalid');
    const wasUnlocked=status?.vault.unlocked;
    status=result;stage='Ready';updateMenus();
    if(wasUnlocked && !result.vault.unlocked){clearSensitive('disconnect');emit({type:'vault-locked'});}
  }catch(error){
    clearSensitive('disconnect');status=undefined;stage='Backend unavailable';updateMenus();
    emit({type:'backend-state',state:'unavailable',code:errorCode(error)});
  }
}
async function lockCredentials(reason:ClearReason){
  clearSensitive(reason);
  if(lockInFlight)return lockInFlight;
  lockInFlight=(async()=>{
    try{
      if(!control || control.hasExited)throw failure('backend-unavailable');
      const result=await control.request('lock-credentials');
      if(result?.locked!==true)throw failure('credential-lock-unconfirmed');
      if(status)status.vault.unlocked=false;
      emit({type:'vault-locked'});updateMenus();
    }catch(error){
      status=undefined;stage='Credential lock unconfirmed';updateMenus();
      emit({type:'backend-state',state:'unavailable',code:errorCode(error)});
    }finally{lockInFlight=undefined;}
  })();
  return lockInFlight;
}
async function readPreferences(){
  try{
    const raw=await fs.readFile(path.join(dataDir,'desktop-preferences.json'));
    if(raw.length>4096)throw failure('preferences-invalid');
    const value=JSON.parse(raw.toString('utf8'));
    if(['system','light','dark'].includes(value.theme))preferences.theme=value.theme;
    firstCloseExplained=value.firstCloseExplained===true;
  }catch{}
  if(supportedLogin())preferences.startAtLogin=app.getLoginItemSettings({args:['--background']}).openAtLogin;
}
async function savePreferences(){
  const target=path.join(dataDir,'desktop-preferences.json');
  const temporary=target+'.'+randomUUID()+'.tmp';
  try{await fs.writeFile(temporary,JSON.stringify({...preferences,firstCloseExplained}),{mode:0o600,flag:'wx'});await fs.rename(temporary,target);}
  finally{await fs.rm(temporary,{force:true}).catch(()=>{});}
}
function authorize(event:IpcMainInvokeEvent){
  if(!window || event.sender!==window.webContents || event.senderFrame!==window.webContents.mainFrame ||
     !pageAllowed(event.senderFrame?.url||'',origin))throw failure('sender-rejected');
}
function registerIPC(){
  const handle=(name:string,handler:(...args:any[])=>any)=>ipcMain.handle(name,async(event,...args)=>{
    authorize(event);
    try{return await handler(...args);}
    catch(error){throw failure(errorCode(error));}
  });
  const noArguments=(args:unknown[])=>{if(args.length)throw failure('argument-invalid');};
  handle(CHANNELS.info,(...args:unknown[])=>{
    noArguments(args);
    return {protocolVersion:1,appVersion:app.getVersion(),platform:process.platform,packaged:app.isPackaged,profileKind:'desktop',
      capabilities:{directoryPicker:true,encryptedBackupSave:true,nativeClipboard:true,startAtLogin:supportedLogin(),sessionLockEvents:supportedLock()}};
  });
  handle(CHANNELS.bootstrap,async(...args:unknown[])=>{
    noArguments(args);
    if(!control)throw failure('backend-unavailable');
    const result=await control.request('bootstrap');
    if(!result || typeof result.token!=='string'||!/^[A-Za-z0-9_-]{20,128}$/.test(result.token))throw failure('backend-protocol-invalid');
    return {token:result.token};
  });
  handle(CHANNELS.directory,async(...args:unknown[])=>{
    noArguments(args);
    const result=await dialog.showOpenDialog(window!,{title:'Choose a source folder',properties:['openDirectory']});
    return result.canceled?{canceled:true}:{canceled:false,path:result.filePaths[0]};
  });
  handle(CHANNELS.backup,async(...args:unknown[])=>{
    if(args.length!==1)throw failure('argument-invalid');
    const bytes=backupBytes(args[0]);
    const result=await dialog.showSaveDialog(window!,{title:'Save encrypted credential backup',defaultPath:'leakguard-vault.lgbak',
      filters:[{name:'Encrypted credential backup',extensions:['lgbak']}],properties:['showOverwriteConfirmation','createDirectory']});
    if(result.canceled||!result.filePath)return {canceled:true,saved:false};
    const temporary=path.join(path.dirname(result.filePath),'.buddy-backup-'+randomUUID()+'.tmp');
    try{
      await fs.writeFile(temporary,bytes,{mode:0o600,flag:'wx'});await fs.rename(temporary,result.filePath);
      return {canceled:false,saved:true};
    }finally{await fs.rm(temporary,{force:true}).catch(()=>{});}
  });
  handle(CHANNELS.copy,async(...args:unknown[])=>{
    if(args.length!==1)throw failure('argument-invalid');
    const value=record(args[0],['text']);
    if(typeof value.text!=='string'||value.text.length>65_536)throw failure('argument-invalid');
    if(!window?.isVisible() || !window.isFocused())return {copied:false};
    return clipboardOwner.copy(value.text);
  });
  handle(CHANNELS.preferences,(...args:unknown[])=>{noArguments(args);if(supportedLogin())preferences.startAtLogin=app.getLoginItemSettings({args:['--background']}).openAtLogin;return {...preferences};});
  handle(CHANNELS.setPreferences,async(...args:unknown[])=>{
    if(args.length!==1)throw failure('argument-invalid');
    const patch=record(args[0],['theme','startAtLogin']);
    if('theme' in patch && !['system','light','dark'].includes(patch.theme as string))throw failure('argument-invalid');
    if('startAtLogin' in patch && typeof patch.startAtLogin!=='boolean')throw failure('argument-invalid');
    if('startAtLogin' in patch){
      if(!supportedLogin() && patch.startAtLogin)throw failure('login-unavailable');
      if(supportedLogin()){
        app.setLoginItemSettings({openAtLogin:patch.startAtLogin as boolean,args:['--background']});
        const actual=app.getLoginItemSettings({args:['--background']}).openAtLogin;
        preferences.startAtLogin=actual;
        if(actual!==patch.startAtLogin)throw failure('login-setting-failed');
      }
    }
    if(patch.theme)preferences.theme=patch.theme as Preferences['theme'];
    await savePreferences();return {...preferences};
  });
}
function createWindow(){
  const partition='buddy-'+randomUUID();
  const webSession=session.fromPartition(partition,{cache:false});
  webSession.setPermissionRequestHandler((_contents,_permission,callback)=>callback(false));
  webSession.setPermissionCheckHandler(()=>false);
  webSession.on('will-download',event=>event.preventDefault());
  webSession.webRequest.onBeforeRequest((details,callback)=>{
    let allowed=false;
    try{allowed=new URL(details.url).origin===origin || /^data:image\//.test(details.url);}catch{}
    callback({cancel:!allowed});
  });
  window=new BrowserWindow({
    title:'Password Buddy',width:1280,height:820,minWidth:1000,minHeight:680,show:false,
    backgroundColor:'#f5f5f2',icon:asset('icon.png'),
    webPreferences:{preload:path.join(__dirname,'preload.cjs'),partition,contextIsolation:true,
      sandbox:true,nodeIntegration:false,webSecurity:true,webviewTag:false,devTools:!app.isPackaged,
      spellcheck:false,navigateOnDragDrop:false},
  });
  window.webContents.setWindowOpenHandler(()=>({action:'deny'}));
  window.webContents.on('will-navigate',(event,url)=>{if(!pageAllowed(url,origin))event.preventDefault();});
  window.webContents.on('will-frame-navigate',event=>{if(!event.isMainFrame || !pageAllowed(event.url,origin))event.preventDefault();});
  window.webContents.on('will-attach-webview',event=>event.preventDefault());
  window.webContents.on('render-process-gone',()=>{void lockCredentials('disconnect');});
  window.webContents.on('did-finish-load',()=>{
    emit({type:'backend-state',state:control?.hasExited?'unavailable':'ready'});
    if(pendingPage){emit({type:'navigate',page:pendingPage});pendingPage=undefined;}
  });
  window.on('blur',()=>clearSensitive('blur'));
  window.on('hide',()=>{void lockCredentials('hide');});
  window.on('close',event=>{
    if(quitAllowed)return;
    event.preventDefault();
    void lockCredentials('hide');
    if(!firstCloseExplained){
      firstCloseExplained=true;void savePreferences().catch(()=>{});
      void dialog.showMessageBox(window!,{type:'info',title:'Password Buddy keeps running',
        message:'Closing the window keeps scans running in the menu bar or tray. Your credential vault locks.',
        detail:'Use Quit Password Buddy to stop the owned background process safely.',
        buttons:['Keep running','Open settings'],defaultId:0,cancelId:0}).then(result=>{
          window?.hide();if(result.response===1)show('settings');
        });
    }else window?.hide();
  });
  const hidden=!requestedOpen && process.argv.includes('--background') && status?.background==='available' && status.observations.unlocked;
  window.once('ready-to-show',()=>{if(!hidden)show();});
  void window.loadURL(origin+'/'+(pendingPage?'#'+pendingPage:'')).catch(()=>{
    void lockCredentials('disconnect');void recover('backend-page-unavailable');
  });
}
async function startBackend(){
  const resources=app.isPackaged?path.join(process.resourcesPath,'buddy'):process.env.BUDDY_DESKTOP_RESOURCES;
  if(!resources)throw failure('desktop-resources-required');
  stage='Preparing local runtime…';updateMenus();
  const runtime=await prepareRuntime(resources,dataDir,progress=>{
    stage=progress==='copying-runtime'?'Preparing private Python runtime…':
      progress==='installing-backend'?'Installing offline scanner…':
      progress==='checking-runtime'?'Checking private runtime…':'Runtime preparation is taking longer than expected';
    updateMenus();
  });
  control=new Control(runtime.python,['-I','-B','-X','utf8','-m','leakguard_buddy.desktop','--state-dir',runtime.stateDir,'--config',runtime.config],
    {cwd:path.join(dataDir,'profile'),env:cleanEnvironment(runtime.stateDir,runtime.config)});
  const current=control;
  current.onUnavailable=code=>{
    clearSensitive('disconnect');status=undefined;stage='Backend unavailable';updateMenus();
    emit({type:'backend-state',state:'unavailable',code});
    if(current.hasExited && !quitting && window)void recover(code);
  };
  const ready=await current.ready;origin=ready.origin;
  await refreshStatus();
  if(!window || window.isDestroyed())createWindow();else await window.loadURL(origin+'/');
  if(statusTimer)clearInterval(statusTimer);
  statusTimer=setInterval(()=>{void refreshStatus();},5000);
}
function messageBox(options:Electron.MessageBoxOptions){
  return window && !window.isDestroyed()?dialog.showMessageBox(window,options):dialog.showMessageBox(options);
}
async function stopOwnedBackend(){
  const current=control;
  if(!current || current.hasExited)return;
  if(current.isReady){
    const result=await current.request('shutdown',120_000);
    if(result?.stopped!==true)throw failure('backend-stop-unconfirmed');
  }else current.closeControl(); // EOF requests the same safe owned shutdown.
  await new Promise<void>((resolve,reject)=>{
    const timer=setTimeout(()=>reject(failure('backend-exit-timeout')),120_000);
    void current.exited.then(()=>{clearTimeout(timer);resolve();});
  });
}
async function recover(initialCode:string){
  if(recovering||quitting)return;
  recovering=true;status=undefined;stage='Backend unavailable';updateMenus();
  let code=initialCode;
  try{
    while(!quitting){
      const blocked=['worker-still-running','requests-still-running','backend-control-timeout'].includes(code);
      const result=await messageBox({type:blocked?'warning':'error',title:'Password Buddy backend unavailable',
        message:blocked?'Waiting for the current scan to stop.':'The local backend is unavailable.',
        detail:'Your workspace and owned process are retained. Details: '+code,
        buttons:blocked?['Retry','Keep open']:['Retry','Quit'],defaultId:0,cancelId:1});
      if(result.response===1){
        if(!blocked)await requestQuit();
        return;
      }
      try{
        emit({type:'backend-state',state:'stopping'});
        await stopOwnedBackend();
        startup=startBackend();
        await startup;
        return;
      }catch(error){code=errorCode(error);}
    }
  }finally{recovering=false;}
}
async function requestQuit(){
  if(quitting||quitAllowed)return;
  quitting=true;clearSensitive('quit');emit({type:'backend-state',state:'stopping'});stage='Stopping safely…';updateMenus();
  try{
    if(startup)await startup.catch(()=>{});
    await waitForPreparation();
    await stopOwnedBackend();
    if(statusTimer)clearInterval(statusTimer);if(idleTimer)clearInterval(idleTimer);
    await clearClipboard();quitAllowed=true;tray?.destroy();app.quit();
  }catch(error){
    quitting=false;stage='Waiting for the current scan to stop';updateMenus();show();
    emit({type:'backend-state',state:'unavailable',code:errorCode(error)});
    const result=await messageBox({type:'warning',title:'Waiting for safe shutdown',
      message:'Waiting for the current scan to stop.',detail:'The owned process and encrypted storage remain open. Details: '+errorCode(error),
      buttons:['Retry','Keep open'],defaultId:0,cancelId:1});
    if(result.response===0)await requestQuit();
  }
}
async function main(){
  app.setName('Password Buddy');
  app.setAppUserModelId('org.leakguard.passwordbuddy');
  const index=process.argv.indexOf('--buddy-data-dir');
  const input=index>=0?process.argv[index+1]:path.join(app.getPath('appData'),'Password Buddy');
  if(!input || (index>=0 && input.startsWith('--')))throw failure('profile-path-invalid');
  dataDir=canonicalDataDirectorySync(input);app.setPath('userData',dataDir);app.setPath('sessionData',dataDir);
  if(!app.requestSingleInstanceLock()){app.quit();return;}
  app.on('second-instance',()=>show());
  app.on('activate',()=>show());
  app.on('before-quit',event=>{if(!quitAllowed){event.preventDefault();void requestQuit();}});
  app.on('window-all-closed',()=>{});
  await app.whenReady();
  app.setAboutPanelOptions({applicationName:'Password Buddy',applicationVersion:app.getVersion(),version:'LeakGuard engine',
    copyright:'Local desktop workspace'});
  const image=nativeImage.createFromPath(asset('tray.png')).resize({width:20,height:20});
  if(process.platform==='darwin')image.setTemplateImage(true);
  tray=new Tray(image);tray.on('click',()=>show());updateMenus();
  await readPreferences();registerIPC();
  powerMonitor.on('suspend',()=>{void lockCredentials('suspend');});
  if(supportedLock())powerMonitor.on('lock-screen',()=>{void lockCredentials('os-lock');});
  idleTimer=setInterval(()=>{
    const idle=powerMonitor.getSystemIdleTime()>=300;
    if(idle && !idleLocked)void lockCredentials('idle');
    idleLocked=idle;
  },15_000);
  startup=startBackend();
  try{await startup;}catch(error){await recover(errorCode(error));}
}
void main().catch(async error=>{
  await app.whenReady();
  dialog.showErrorBox('Password Buddy could not start','Workspace retained. Details: '+errorCode(error));
  if(control && !control.hasExited)await requestQuit();
  else {quitAllowed=true;app.quit();}
});
