// Raw browser WSS conformance: the pinned AutoScript negotiates protocol 4.
// Rust owns fixtures, application decisions and validation of the observed frames.
import { readFile, writeFile } from 'node:fs/promises';
import { chromium, firefox } from 'playwright';
const [configuration, report] = process.argv.slice(2);
const config = JSON.parse(await readFile(configuration, 'utf8'));
const context = config.browser === 'firefox'
  ? await firefox.launchPersistentContext(config.profile, { headless: true,
      firefoxUserPrefs: { 'security.enterprise_roots.enabled': false } })
  : await chromium.launchPersistentContext('', { headless: true,
      args: [`--ignore-certificate-errors-spki-list=${config.pins.join(',')}`] });
try {
  const page = await context.newPage();
  await page.goto(config.origin);
  const cases = [];
  for (const [index, scenario] of config.cases.entries()) {
    cases.push(await page.evaluate(async ({ index, scenario }) => {
      const session = '0123456789abcdef';
      const open = () => new Promise((resolve, reject) => {
        const socket = new WebSocket(scenario.endpoint);
        socket.onopen = () => resolve(socket);
        socket.onerror = () => reject(new Error('WSS connection failed'));
      });
      const exchange = (socket, message) => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('WSS response timed out')), 5000);
        socket.onmessage = event => { clearTimeout(timer); resolve(event.data); };
        socket.send(message);
      });
      const hello = `echo=-idsession=${session}@EOF`;
      const query = `getresult?idsession=${session}`;
      const sign = `afirma://sign?ver=4&idsession=${session}&dat=AA==`;
      let socket = await open();
      const initial = [];
      for (const message of [hello, 'getresult?idsession=invalidsession123',
        `afirma://unknown?idsession=${session}`, `afirma://websocket?idsession=${session}`, sign, query]) {
        initial.push(await exchange(socket, message));
      }
      socket.close();
      socket = await open();
      const reconnected = [await exchange(socket, hello), await exchange(socket, query)];
      await fetch(`/release/${index}`);
      let result;
      const deadline = performance.now() + 5000;
      do {
        result = await exchange(socket, query);
        if (result === '#wait') await new Promise(resolve => setTimeout(resolve, 25));
      } while (result === '#wait' && performance.now() < deadline);
      const consumed = [await exchange(socket, query), await exchange(socket, sign)];
      socket.close();
      return { name: scenario.name, initial, reconnected, result, consumed };
    }, { index, scenario }));
  }
  await writeFile(report, JSON.stringify({ protocol: '4.1', browser: config.browser,
    version: context.browser().version(), cases }, null, 2));
} finally {
  await context.close();
}
