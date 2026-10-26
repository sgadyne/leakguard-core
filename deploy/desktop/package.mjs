import packager from '@electron/packager';
import { parseArgs } from 'node:util';
import { mkdtemp, mkdir, readFile, cp, rm, writeFile, access } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const { values } = parseArgs({ options: {
  target: { type: 'string' }, source: { type: 'string' }, resources: { type: 'string' }, output: { type: 'string' },
} });
const targets = { 'macos-arm64': ['darwin', 'arm64'], 'windows-x86_64': ['win32', 'x64'], 'linux-x86_64': ['linux', 'x64'] };
if (!targets[values.target] || !values.source || !values.resources || !values.output) throw Error('Invalid packaging arguments');
if (process.version !== 'v22.23.2') throw Error('Release tooling requires Node 22.23.2');
const source = path.resolve(values.source);
const original = JSON.parse(await readFile(path.join(source, 'package.json'), 'utf8'));
if (original.main !== 'dist/main.cjs') throw Error('Shell main must be dist/main.cjs');
await access(path.join(source, 'dist/main.cjs'));
await access(path.join(source, 'dist/preload.cjs'));
const staging = await mkdtemp(path.join(os.tmpdir(), 'buddy-shell-package-'));
try {
  await mkdir(path.join(staging, 'dist'));
  await cp(path.join(source, 'dist'), path.join(staging, 'dist'), { recursive: true });
  try { await cp(path.join(source, 'assets'), path.join(staging, 'assets'), { recursive: true }); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  // Main/preload are self-contained bundles: no dev dependencies or source tree ship.
  await writeFile(path.join(staging, 'package.json'), JSON.stringify({
    name: 'password-buddy', productName: 'Password Buddy', version: '0.1.0-alpha.1',
    main: 'dist/main.cjs', author: 'LeakGuard', description: 'Password Buddy desktop workbench',
  }, null, 2) + '\n');
  const [platform, arch] = targets[values.target];
  const paths = await packager({
    dir: staging, name: 'Password Buddy', executableName: 'Password Buddy', platform, arch,
    electronVersion: '45.0.0', appVersion: '0.1.0-alpha.1', appBundleId: 'org.leakguard.passwordbuddy',
    out: path.resolve(values.output), asar: true, prune: true, overwrite: false,
    extraResource: [path.resolve(values.resources)], osxSign: false, osxNotarize: false,
    win32metadata: { CompanyName: 'LeakGuard', FileDescription: 'Password Buddy', ProductName: 'Password Buddy' },
  });
  process.stdout.write(JSON.stringify({ appDirectories: paths, nativeAcceptance: 'not-run' }) + '\n');
} finally {
  await rm(staging, { recursive: true, force: true });
}
