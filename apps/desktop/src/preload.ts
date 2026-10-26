import { contextBridge, ipcRenderer } from 'electron';
import { CHANNELS, type DesktopEvent, type Preferences } from './contracts.ts';

contextBridge.exposeInMainWorld('buddyDesktop', Object.freeze({
  getInfo:()=>ipcRenderer.invoke(CHANNELS.info),
  bootstrapSession:()=>ipcRenderer.invoke(CHANNELS.bootstrap),
  chooseDirectory:()=>ipcRenderer.invoke(CHANNELS.directory),
  saveEncryptedBackup:(input:{filename:string;base64:string})=>ipcRenderer.invoke(CHANNELS.backup,input),
  copySecret:(input:{text:string})=>ipcRenderer.invoke(CHANNELS.copy,input),
  getPreferences:()=>ipcRenderer.invoke(CHANNELS.preferences),
  setPreferences:(patch:Partial<Preferences>)=>ipcRenderer.invoke(CHANNELS.setPreferences,patch),
  onEvent:(callback:(event:DesktopEvent)=>void)=>{
    if(typeof callback!=='function') throw new Error('callback-invalid');
    const listener=(_event:Electron.IpcRendererEvent,event:DesktopEvent)=>callback(event);
    ipcRenderer.on(CHANNELS.event,listener);
    return ()=>ipcRenderer.removeListener(CHANNELS.event,listener);
  },
}));
