export type Preferences = { theme: 'system'|'light'|'dark'; startAtLogin: boolean };
export type Page = 'overview'|'sources'|'findings'|'vault'|'plugins'|'settings';
export type ClearReason = 'hide'|'blur'|'idle'|'os-lock'|'suspend'|'disconnect'|'quit';
export type DesktopEvent =
  | {type:'navigate'; page:Page}
  | {type:'clear-sensitive'; reason:ClearReason}
  | {type:'vault-locked'}
  | {type:'backend-state'; state:'ready'|'unavailable'|'stopping'; code?:string};
export type BackendStatus = {
  observations:{created:boolean; unlocked:boolean}; vault:{created:boolean; unlocked:boolean};
  scheduler:string; pending_jobs:number; background:string; error_codes:string[];
};
export const CHANNELS = {
  info:'buddy:info', bootstrap:'buddy:bootstrap', directory:'buddy:directory',
  backup:'buddy:backup', copy:'buddy:copy', preferences:'buddy:preferences',
  setPreferences:'buddy:set-preferences', event:'buddy:event',
} as const;
