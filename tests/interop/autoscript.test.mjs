// Test harness only. Upstream AutoScript is loaded byte-for-byte from a pinned revision.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { connect as tlsConnect } from 'node:tls';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';

import { autoscript, revision } from './autoscript.mjs';
const root = path.resolve(import.meta.dirname, '../..');

function waitReady(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('probe readiness timed out')), 10000);
    child.once('exit', (code) => { clearTimeout(timer); reject(new Error(`probe exited: ${code}`)); });
    child.stdout.on('data', data => { if (data.toString().includes('READY')) { clearTimeout(timer); resolve(); } });
  });
}

test('unmodified AutoScript: URI → TLS WebSocket → headless peer → async polling → cancellation', { timeout: 60000 }, async () => {
  const script = await autoscript();
  const dir = await mkdtemp(path.join(tmpdir(), 'firmica-interop-'));
  const cert = path.join(dir, 'cert.pem');
  const key = path.join(dir, 'key.pem');
  // Ephemeral test key, never a document signing key. Trust is scoped to this browser process.
  execFileSync('openssl', ['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  const pin = createHash('sha256').update(execFileSync('openssl',
    ['pkey','-pubin','-outform','DER'], {input:execFileSync('openssl',['x509','-in',cert,'-pubkey','-noout'])})).digest('base64');
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><title>AutoScript interoperability test</title>
    <button id="sign">Request signature</button>
    <output id="result"></output><script src="/autoscript.js"></script><script>
    AutoScript.enableProgressDialog(false);
    AutoScript.setPortRange(49152, 49154);
    AutoScript.cargarAppAfirma();
    AutoScript.setKeyStore(AutoScript.KEYSTORE_PKCS12);
    document.querySelector('#sign').onclick = () => AutoScript.sign('c3ludGhldGljIHRlc3QgZG9jdW1lbnQ=', 'SHA256withRSA', 'CAdES', ${JSON.stringify('# Detached signature\nmode : explicit')},
      () => { window.operationResult = { unexpectedSuccess: true }; },
      (type, message, code) => { window.operationResult = { type, message, code }; document.querySelector('#result').textContent = type; });
    </script></html>`;
  const server = createServer((req,res) => {
    res.setHeader('Content-Type', req.url === '/autoscript.js' ? 'text/javascript' : 'text/html');
    res.end(req.url === '/autoscript.js' ? script : html);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  let browser, probe, bootstrapUri;
  try {
    browser = await chromium.launch({ args: [`--ignore-certificate-errors-spki-list=${pin}`] });
    const page = await browser.newPage();
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('Page.enable');
    const frames = [];
    page.on('websocket', ws => {
      ws.on('framesent', frame => frames.push({ direction: 'sent', data: frame.payload, url: ws.url() }));
      ws.on('framereceived', frame => frames.push({ direction: 'received', data: frame.payload, url: ws.url() }));
    });
    const invoked = new Promise((resolve, reject) => {
      const launchProbe = async event => {
        if (!event.url.startsWith('afirma://')) return;
        cdp.off('Page.frameRequestedNavigation', launchProbe);
        try {
          bootstrapUri = event.url;
          const invocation = new URL(event.url);
          assert.equal(invocation.hostname, 'websocket');
          assert.equal(invocation.searchParams.get('v'), '4');
          assert.equal(invocation.searchParams.get('jvc'), '4');
          // Pass the captured URI directly to the headless transport probe.
          const binary = process.env.FIRMICA_PROBE || path.join(root, 'target/debug/examples/probe');
          probe = spawn(binary, [cert, key, origin, event.url], { stdio: ['ignore', 'pipe', 'inherit'] });
          probe.once('error', reject);
          await waitReady(probe);
          resolve();
        } catch (error) { reject(error); }
      };
      cdp.on('Page.frameRequestedNavigation', launchProbe);
    });
    await page.goto(origin);
    assert.equal(await page.evaluate(() => AutoScript.VERSION), '1.10.1');
    await Promise.all([page.locator('#sign').click(), invoked]);
    await page.waitForFunction(() => window.operationResult, undefined, { timeout: 20000 });
    const result = await page.evaluate(() => window.operationResult);
    assert.equal(result.type, 'es.gob.afirma.core.AOCancelledOperationException');
    assert.equal(result.code, 'AF500001');
    assert.ok(frames.some(f => f.direction === 'sent' && f.data.startsWith('echo=-idsession=')));
    assert.ok(frames.some(f => f.direction === 'received' && f.data === 'OK'));
    assert.ok(frames.some(f => f.direction === 'sent' && f.data.startsWith('afirma://sign?')));
    assert.ok(frames.some(f => f.direction === 'received' && f.data === '#wait'));
    assert.ok(frames.some(f => f.direction === 'sent' && f.data.startsWith('getresult?')));
    assert.ok(frames.some(f => f.direction === 'received' && f.data === 'err-11:=AF500001 - Operation cancelled by user'));
    const endpoint = frames.find(f => f.direction === 'received' && f.data === 'OK').url;
    const session = new URL(bootstrapUri).searchParams.get('idsession');
    const exchange = message => page.evaluate(({endpoint,message}) => new Promise((resolve,reject) => {
      const ws = new WebSocket(endpoint);
      const timer = setTimeout(() => { ws.close(); reject(new Error('WebSocket response timed out')); },5000);
      ws.onopen = () => ws.send(message);
      ws.onmessage = event => { clearTimeout(timer); ws.close(); resolve(event.data); };
      ws.onerror = () => { clearTimeout(timer); reject(new Error('WebSocket failed')); };
    }),{endpoint,message});
    assert.equal(await exchange(`echo=-idsession=${session}@EOF`),'OK','reconnect retains session');
    assert.match(await exchange('getresult?idsession=invalidsession123'),/^err-00:=AF620010 - /);
    assert.match(await exchange(`afirma://sign?idsession=${session}`),/^err-00:=AF600002 - /,'completed session cannot sign twice');
    assert.match(await exchange(`getresult?idsession=${session}&idsession=${session}`),/^err-00:=AF620010 - /,'duplicate session fields are rejected');
    const port = Number(new URL(endpoint).port);
    const ca = await readFile(cert);
    const handshake = (requestedOrigin,host) => new Promise((resolve,reject) => {
      const client = tlsConnect({host:'127.0.0.1',port,ca,rejectUnauthorized:true},() => {
        client.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: ${requestedOrigin}\r\n\r\n`);
      });
      let response = '';
      client.setTimeout(5000,() => client.destroy(new Error('handshake timed out')));
      client.on('error',reject);
      client.on('data',chunk => { response += chunk; if(response.includes('\r\n')) { client.destroy(); resolve(response.split('\r\n')[0]); } });
    });
    assert.match(await handshake('https://untrusted.invalid',`127.0.0.1:${port}`),/403/,'foreign origin is rejected by the transport listener');
    assert.match(await handshake(origin,`localhost:${port}`),/403/,'unexpected Host is rejected');
    const closeCode = await page.evaluate(endpoint => new Promise((resolve,reject) => {
      const ws = new WebSocket(endpoint);
      const timer = setTimeout(() => {ws.close(); reject(new Error('oversize response timed out'));},5000);
      ws.onopen = () => ws.send('x'.repeat(65537));
      ws.onclose = event => {clearTimeout(timer); resolve(event.code);};
      ws.onmessage = () => reject(new Error('oversized message was processed'));
    }),endpoint);
    assert.ok([1006,1009].includes(closeCode),'oversized message closes the connection');
    console.log(JSON.stringify({
      autoscript: '1.10.1', revision, advertisedProtocol: '4', protocol: '4.1', jvc: 4,
      callback: result.type, browser: browser.version(), frameCount: frames.length,
    }));
  } finally {
    probe?.kill('SIGTERM');
    await browser?.close();
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive:true, force:true });
  }
});
