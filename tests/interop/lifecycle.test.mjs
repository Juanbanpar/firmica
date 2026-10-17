// Exercise the production timeouts without shortening them in application code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';
import { freePort, until, inspector } from './native.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const binary = process.env.FIRMICA_DESKTOP || path.join(root,'target/dx/firmica/release/linux/app/firmica');

async function lifetime(asynchronous) {
  const output = path.join(root,'.test-artifacts','lifecycle');
  const resultFile = path.join(output,asynchronous ? 'async.json' : 'sync.json');
  await mkdir(output,{recursive:true});
  await rm(resultFile,{force:true});
  const dir = await mkdtemp(path.join(tmpdir(),'firmica-lifetime-'));
  const runtime = path.join(dir,'run');
  await mkdir(runtime,{mode:0o700});
  const cert = path.join(dir,'cert.pem');
  const key = path.join(dir,'key.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,
    '-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});
  const pubkey = execFileSync('openssl',['x509','-in',cert,'-pubkey','-noout']);
  const spki = execFileSync('openssl',['pkey','-pubin','-outform','DER'],{input:pubkey});
  const pin = createHash('sha256').update(spki).digest('base64');
  const server = createServer((_req,res) => {
    res.setHeader('Content-Type','text/html');
    res.end('<!doctype html><html lang="en"><title>Review lifetime test</title>');
  });
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const port = await freePort();
  const inspectorPort = await freePort();
  const session = '0123456789abcdef';
  const bootstrap = `afirma://websocket?v=4&jvc=${asynchronous ? 4 : 3}&ports=${port}&idsession=${session}`;
  const env = {...process.env,GDK_BACKEND:'x11',XDG_RUNTIME_DIR:runtime,
    WEBKIT_INSPECTOR_HTTP_SERVER:`127.0.0.1:${inspectorPort}`};
  let app, browser, native;
  let started;
  try {
    started = performance.now();
    app = spawn('xvfb-run',['-a','-s','-screen 0 1280x900x24',binary,
      '--tls-cert',cert,'--tls-key',key,'--origin',origin,bootstrap],
      {env,stdio:['ignore','ignore','inherit'],detached:true});
    native = await inspector(inspectorPort);
    browser = await chromium.launch({args:[`--ignore-certificate-errors-spki-list=${pin}`]});
    const page = await browser.newPage();
    await page.goto(origin);
    async function connect() {
      await page.evaluate(({port,session}) => new Promise((resolve,reject) => {
        window.replies = [];
        const ws = window.reviewSocket = new WebSocket(`wss://127.0.0.1:${port}`);
        const timer = setTimeout(() => reject(new Error('WSS connection timed out')),5000);
        ws.onopen = () => ws.send(`echo=-idsession=${session}@EOF`);
        ws.onmessage = event => {
          window.replies.push(event.data);
          if(event.data === 'OK') {clearTimeout(timer); resolve();}
        };
        ws.onerror = () => {clearTimeout(timer); reject(new Error('WSS connection failed'));};
      }),{port,session});
    }
    await connect();
    const submitted = performance.now();
    await page.evaluate(({session,asynchronous}) => window.reviewSocket.send(`afirma://sign?idsession=${session}&dat=c3ludGhldGlj${asynchronous ? '&format=CAdES&algorithm=SHA256withRSA' : ''}`),{session,asynchronous});
    await until(async () => await native.evaluate('document.querySelector("#request-operation")?.textContent === "sign"'));
    if(asynchronous) {
      assert.equal(await native.evaluate('!!document.querySelector("#sign-language")'),true,'asynchronous review must use the signing form');
      await page.waitForFunction(() => window.replies.includes('#wait'));
      await page.evaluate(() => window.reviewSocket.close());
      await page.waitForFunction(() => window.reviewSocket.readyState === WebSocket.CLOSED);
      await connect();
      await page.evaluate(session => window.reviewSocket.send(`getresult?idsession=${session}`),session);
      await page.waitForFunction(() => window.replies.includes('#wait'));
      assert.equal(await native.evaluate('document.querySelector("#request-operation")?.textContent'),'sign');
      await page.evaluate(() => window.reviewSocket.close());
    } else {
      await page.waitForFunction(() => window.replies.includes('CANCEL'),null,{timeout:75000});
    }
    const expiredStatus = asynchronous ? '#browser-status' : '#review-status';
    await until(async () => (await native.evaluate(`document.querySelector("${expiredStatus}")?.textContent`))?.includes('caducado'),130000);
    const elapsed = (performance.now() - (asynchronous ? started : submitted)) / 1000;
    const deadline = asynchronous ? 120 : 60;
    assert.ok(elapsed >= deadline - 5 && elapsed <= deadline + 15,
      `review expired after ${elapsed}s; expected approximately ${deadline}s`);
    assert.equal(await native.evaluate('document.querySelector("#request-operation")'),null);
    assert.equal(await native.evaluate('document.querySelectorAll("#reject-request, #acknowledge-request").length'),0);
    if (!asynchronous) {
      await native.evaluate('document.querySelector("header button").click(); true');
    }
    await until(async () => (await native.evaluate(`document.querySelector("${expiredStatus}")?.textContent`))?.includes('request has expired'));

    execFileSync(binary,['afirma://cosign?ver=4'],{env});
    await until(async () => await native.evaluate('document.querySelector("#request-operation")?.textContent === "cosign"'));
    await native.evaluate('document.querySelector("#acknowledge-request").click(); true');
    await until(async () => (await native.evaluate('document.querySelector("#review-status")?.textContent'))?.includes(asynchronous ? 'no está implementada' : 'not implemented'));
    const report = {mode:asynchronous ? 'async listener expiry' : 'synchronous review timeout',
      protocol:4,jvc:asynchronous ? 4 : 3,request:'sign',certificateBackend:null,
      platform:process.platform,browser:browser.version(),elapsedSeconds:elapsed,
      applicationSha256:createHash('sha256').update(await readFile(binary)).digest('hex'),
      expected:'expired review clears controls and accepts a new local invocation',actual:'passed',
      reconnectPreservesReview:asynchronous ? true : null};
    await writeFile(resultFile,JSON.stringify(report,null,2)+'\n');
    console.log(JSON.stringify(report));
  } finally {
    native?.close();
    await browser?.close();
    if(app?.pid) {try {process.kill(-app.pid,'SIGTERM');} catch {}}
    await new Promise(resolve => server.close(resolve));
    await rm(dir,{recursive:true,force:true});
  }
}

test('native WSS review lifetime', {skip:process.platform !== 'linux',concurrency:2,timeout:160000}, async t => {
  await Promise.all([
    t.test('synchronous timeout revokes review', () => lifetime(false)),
    t.test('asynchronous review survives reconnect and expires with listener', () => lifetime(true)),
  ]);
});
