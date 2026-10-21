// Browser automation only: native review and dialogs are exercised by XCTest.
import assert from 'node:assert/strict';
import { firefox } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { until } from '../native.mjs';
const [origin, profile, configuration, evidence] = process.argv.slice(2);
const get = async route => (await fetch(origin + route)).json();
const config = await get('/config');
await mkdir(profile, { recursive: true, mode: 0o700 });
execFileSync('certutil', ['-N', '-d', `sql:${profile}`, '--empty-password']);
execFileSync('certutil', ['-A', '-d', `sql:${profile}`, '-n', 'Firmica synthetic WSS', '-t', 'C,,', '-i', path.join(configuration, 'browser-tls/ca.pem')]);
const prefs = {
  'network.protocol-handler.external.afirma': true,
  'network.protocol-handler.warn-external.afirma': false,
  'network.protocol-handler.expose.afirma': false,
  'security.enterprise_roots.enabled': false,
};
let context;
try {
  await until(async () => (await get('/state')).local_done, 600000);
  context = await firefox.launchPersistentContext(profile, { headless: false, firefoxUserPrefs: prefs });
  let rejected = false;
  for (let index = 0; index < config.browser.length; index++) {
    const scenario = config.browser[index];
    let listener;
    const page = await context.newPage();
    page.on('websocket', socket => { if (socket.url().startsWith('wss://127.0.0.1:')) listener = socket.url(); });
    await page.goto(origin);
    await page.locator('#sign').click();
    await get('/started');
    if (!rejected) {
      await until(() => listener);
      const untrusted = await firefox.launchPersistentContext(profile + '-untrusted', { headless: false, firefoxUserPrefs: prefs });
      try {
        const fresh = await untrusted.newPage();
        await assert.rejects(fresh.goto(listener.replace('wss:', 'https:')), /SEC_ERROR_UNKNOWN_ISSUER/);
        rejected = true;
      } finally { await untrusted.close(); }
    }
    let result;
    if (scenario.action === 'disconnect') {
      await until(async () => (await get('/state')).prepared, 45000);
      await page.close();
      result = { disconnected: true };
    } else {
      await page.waitForFunction(() => window.result, undefined, { timeout: 60000 });
      result = await page.evaluate(() => window.result);
      await page.screenshot({ path: path.join(evidence, `firefox-${index}.png`) });
      await page.close();
    }
    await writeFile(path.join(evidence, `browser-${index}.json`), JSON.stringify(result), { mode: 0o600 });
    await get('/result-received');
    await until(async () => (await get('/state')).native_done, 30000);
    await get('/next');
  }
  await writeFile(path.join(evidence, 'browser-checks.json'), JSON.stringify({ untrusted_profile_rejected: rejected, firefox: context.browser().version() }));
} finally {
  await context?.close();
}
