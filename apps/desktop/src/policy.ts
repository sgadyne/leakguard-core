import path from 'node:path';

export function failure(code:string): Error { return new Error(code); }
export function exactOrigin(input:unknown): string {
  if (typeof input !== 'string' || input.length > 100) throw failure('backend-origin-invalid');
  const url = new URL(input);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port ||
      !/^\d+$/.test(url.port) || Number(url.port)<1 || Number(url.port)>65535 ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash ||
      input !== url.origin) throw failure('backend-origin-invalid');
  return url.origin;
}
export function pageAllowed(input:string, origin:string): boolean {
  try { const url=new URL(input); return url.origin===origin && url.pathname==='/' && !url.search; }
  catch { return false; }
}
export function inside(root:string, input:string): boolean {
  const relative=path.relative(root,input);
  return relative==='' || (!relative.startsWith('..'+path.sep) && relative!=='..' && !path.isAbsolute(relative));
}
export function record(input:unknown, allowed:string[]): Record<string,unknown> {
  if (!input || typeof input!=='object' || Array.isArray(input) ||
      Object.keys(input).some(key=>!allowed.includes(key))) throw failure('argument-invalid');
  return input as Record<string,unknown>;
}
export function backupBytes(input:unknown): Buffer {
  const value=record(input,['filename','base64']);
  if (value.filename!=='leakguard-vault.lgbak' || typeof value.base64!=='string' ||
      !value.base64 || value.base64.length>Math.ceil(16*1024*1024/3)*4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.base64)) {
    throw failure('backup-invalid');
  }
  const bytes=Buffer.from(value.base64,'base64');
  if(bytes.length>16*1024*1024 || bytes.toString('base64')!==value.base64) throw failure('backup-invalid');
  return bytes;
}
