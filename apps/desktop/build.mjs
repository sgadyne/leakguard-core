import { build } from 'esbuild';
import { mkdir } from 'node:fs/promises';
await mkdir(new URL('./dist/', import.meta.url), {recursive:true});
await build({
  entryPoints:['src/main.ts','src/preload.ts'], outdir:'dist', outExtension:{'.js':'.cjs'},
  bundle:true, platform:'node', format:'cjs', target:'node22', external:['electron'],
  sourcemap:false, logLevel:'info',
});
