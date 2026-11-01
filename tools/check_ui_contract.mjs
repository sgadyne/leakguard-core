import {build} from "../apps/desktop/node_modules/esbuild/lib/main.js";
import {mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";
import {spawnSync} from "node:child_process";
const directory=await mkdtemp(path.join(tmpdir(),"leakguard-ui-contract-"));
try {
 const bundle=path.join(directory,"inspection-render.cjs");
 await build({entryPoints:[new URL("../apps/buddy-ui/tests/inspection-evidence.test.tsx",import.meta.url).pathname],bundle:true,platform:"node",format:"cjs",jsx:"automatic",outfile:bundle,logLevel:"error"});
 const result=spawnSync(process.execPath,["--test",bundle],{stdio:"inherit"});
 process.exitCode=result.status??1;
} finally {await rm(directory,{recursive:true,force:true});}
