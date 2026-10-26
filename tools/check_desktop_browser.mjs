// Test-only native bridge simulation. Never included in a production package.
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
let input = '';
for await (const chunk of process.stdin) {
  input += chunk;
  if (input.length > 16384) throw Error('input-too-large');
}
const configuration = JSON.parse(input);
const environment = JSON.parse(await readFile(configuration.browserInputs, 'utf8'));
const require = createRequire(path.join(environment.prior_playwright_modules, 'package.json'));
const { chromium } = require('playwright');
let browser;
const receipt = { passed: false, scope: 'Chromium production UI with test-only bridge; not Electron native acceptance' };
let stage = 'launch';
try {
  browser = await chromium.launch({ headless: true, executablePath: environment.headless_executable,
    env: { ...process.env, LD_LIBRARY_PATH: environment.libraries } });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  let scriptErrors = 0;
  let cspErrors = 0;
  page.on('pageerror', () => { scriptErrors++; });
  page.on('console', message => { if (message.type() === 'error' && /content.security.policy|refused to (apply|execute|load)/i.test(message.text())) cspErrors++; });
  await page.addInitScript(({ token }) => {
    window.buddyDesktop = Object.freeze({
      getInfo: async () => ({ protocolVersion: 1, appVersion: '0.1.0-alpha.1', platform: 'linux', packaged: false,
        profileKind: 'desktop', capabilities: { directoryPicker: false, encryptedBackupSave: false,
          nativeClipboard: false, startAtLogin: false, sessionLockEvents: false } }),
      bootstrapSession: async () => ({ token }),
      getPreferences: async () => ({ theme: 'system', startAtLogin: false }),
      setPreferences: async patch => ({ theme: patch.theme || 'system', startAtLogin: false }),
      chooseDirectory: async () => ({ canceled: true }),
      saveEncryptedBackup: async () => ({ canceled: true, saved: false }),
      copySecret: async () => ({ copied: false }),
      onEvent: () => () => {},
    });
  }, { token: configuration.token });
  stage = 'load-and-authenticate';
  await page.goto(configuration.origin, { waitUntil: 'domcontentloaded' });
  await page.getByText('Connected', { exact: true }).waitFor();
  stage = 'unlock-scan-storage';
  await page.getByRole('button', { name: 'Unlock scan storage', exact: true }).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Passphrase', { exact: true }).fill(configuration.observationPhrase);
  await dialog.getByRole('button', { name: 'Continue', exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
  const navigation = page.getByRole('navigation', { name: 'Main navigation' });
  for (const label of ['Overview', 'Sources', 'Findings', 'Credential vault', 'Plugins', 'Settings']) {
    stage = 'route-' + label.toLowerCase().replaceAll(' ', '-');
    await navigation.getByRole('button', { name: label, exact: true }).click();
    await page.getByRole('heading', { level: 1, name: label, exact: true }).waitFor();
  }
  await navigation.getByRole('button', { name: 'Findings', exact: true }).click();
  stage = 'real-findings-grid';
  await page.getByRole('grid').waitFor();
  const styleBoundary = await page.evaluate(() => {
    const nonce = document.querySelector('meta[name="buddy-style-nonce"]')?.content;
    const styles = [...document.querySelectorAll('style')];
    return { noncePresent: Boolean(nonce && !nonce.includes('__BUDDY_')), styleCount: styles.length,
      stylesNonced: styles.length > 0 && styles.every(node => node.nonce === nonce),
      noNodeGlobals: typeof window.require === 'undefined' && typeof window.process === 'undefined' };
  });
  receipt.checks = { sixRoutesReachable: true, installedScanEvidenceGrid: true,
    noScriptErrors: scriptErrors === 0, noCspErrors: cspErrors === 0, ...styleBoundary };
  receipt.passed = scriptErrors === 0 && cspErrors === 0 && styleBoundary.noncePresent
    && styleBoundary.stylesNonced && styleBoundary.noNodeGlobals;
  if (configuration.screenshot) await page.screenshot({ path: configuration.screenshot, fullPage: true });
} catch (error) {
  receipt.failure = 'browser-' + error.name;
  receipt.stage = stage;
} finally {
  if (browser) await browser.close();
}
process.stdout.write(JSON.stringify(receipt) + '\n');
process.exitCode = receipt.passed ? 0 : 1;
