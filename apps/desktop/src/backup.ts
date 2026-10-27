import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { failure } from './policy.ts';

/** Publish a new backup without replacing an existing recovery copy. */
export async function publishBackup(destination:string, bytes:Buffer, io:typeof fs=fs):Promise<void> {
  const directory=path.dirname(destination);
  const temporary=path.join(directory,'.buddy-backup-'+randomUUID()+'.tmp');
  let file:Awaited<ReturnType<typeof fs.open>>|undefined;
  try {
    file=await io.open(temporary,'wx',0o600);
    await file.writeFile(bytes);
    await file.sync();
    await file.close();file=undefined;
    // Hard-link publication is atomic and refuses an existing destination.
    // It cannot silently replace the user's last known-good recovery copy.
    try { await io.link(temporary,destination); }
    catch(error) {
      if((error as NodeJS.ErrnoException).code==='EEXIST')throw failure('backup-already-exists');
      throw error;
    }
    const parent=await io.open(directory,'r');
    try { await parent.sync(); } finally { await parent.close(); }
  } finally {
    if(file)await file.close().catch(()=>{});
    await io.rm(temporary,{force:true}).catch(()=>{});
  }
}
