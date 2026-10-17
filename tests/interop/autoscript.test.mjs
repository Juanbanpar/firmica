// Test harness only. Upstream AutoScript is loaded byte-for-byte from a pinned revision.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { readFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { connect as tlsConnect } from 'node:tls';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { chromium, firefox } from 'playwright';
import { freePort, until, inspector } from './native.mjs';

import { autoscript } from './autoscript.mjs';
const root = path.resolve(import.meta.dirname, '../..');
const artifact = path.join(root, '.test-artifacts');

function waitReady(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('probe readiness timed out')), 10000);
    child.once('exit', (code) => { clearTimeout(timer); reject(new Error(`probe exited: ${code}`)); });
    child.stdout.on('data', data => { if (data.toString().includes('READY')) { clearTimeout(timer); resolve(); } });
  });
}

const osHandlerMode = process.env.FIRMICA_OS_HANDLER === '1';
const nativeMode = osHandlerMode || process.env.FIRMICA_NATIVE_INTEROP === '1';
const osArtifacts = path.join(artifact,'linux-os-handler');
test(`unmodified AutoScript: URI → ${osHandlerMode ? 'Firefox OS handler → ' : ''}TLS WebSocket → ${nativeMode ? 'Dioxus review' : 'headless peer'} → async polling → cancellation`, { timeout: 60000 }, async () => {
  const script = await autoscript();
  const dir = await mkdtemp(path.join(tmpdir(), 'firmica-interop-'));
  const cert = path.join(dir, 'cert.pem');
  const key = path.join(dir, 'key.pem');
  const trust = osHandlerMode ? path.join(dir,'ca.pem') : cert;
  // Ephemeral test key, never a document signing key. Trust is scoped to this browser process.
  if (osHandlerMode) {
    const caKey = path.join(dir,'ca.key');
    const csr = path.join(dir,'server.csr');
    const extensions = path.join(dir,'server.ext');
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',caKey,'-out',trust,
      '-days','1','-subj','/CN=Firmica ephemeral test CA','-addext','basicConstraints=critical,CA:TRUE',
      '-addext','keyUsage=critical,keyCertSign,cRLSign'],{stdio:'ignore'});
    execFileSync('openssl',['req','-newkey','rsa:2048','-nodes','-keyout',key,'-out',csr,'-subj','/CN=127.0.0.1'],{stdio:'ignore'});
    await writeFile(extensions,'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n');
    execFileSync('openssl',['x509','-req','-in',csr,'-CA',trust,'-CAkey',caKey,'-CAcreateserial',
      '-days','1','-out',cert,'-extfile',extensions],{stdio:'ignore'});
  } else {
    execFileSync('openssl', ['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  }
  const pubkey = execFileSync('openssl', ['x509','-in',cert,'-pubkey','-noout']);
  const spki = execFileSync('openssl', ['pkey','-pubin','-outform','DER'], { input: pubkey });
  const pin = createHash('sha256').update(spki).digest('base64');
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><title>AutoScript interoperability test</title>
    <button id="sign">Request signature</button><a id="warm" href="afirma://cosign?ver=4&format=CAdES">Warm invocation</a>
    <output id="result"></output><script src="/autoscript.js"></script><script>
    AutoScript.enableProgressDialog(false);
    AutoScript.setPortRange(49152, 49154);
    AutoScript.cargarAppAfirma();
    document.querySelector('#sign').onclick = () => AutoScript.sign('c3ludGhldGljIHRlc3QgZG9jdW1lbnQ=', 'SHA256withRSA', 'CAdES', 'mode=explicit',
      () => { window.operationResult = { unexpectedSuccess: true }; },
      (type, message, code) => { window.operationResult = { type, message, code }; document.querySelector('#result').textContent = type; });
    </script></html>`;
  const server = createServer((req,res) => {
    res.setHeader('Content-Type', req.url === '/autoscript.js' ? 'text/javascript' : 'text/html');
    res.end(req.url === '/autoscript.js' ? script : html);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  let browser, probe, bootstrapUri, native, osAppPid, handlerEnv;
  const inspectorPort = nativeMode ? await freePort() : undefined;
  const runtime = path.join(dir,'run');
  if(nativeMode) await mkdir(runtime,{mode:0o700});
  try {
    let page;
    if (osHandlerMode) {
      assert.equal(process.platform, 'linux');
      assert.ok(process.env.DISPLAY, 'run the OS-handler test under Xvfb');
      await mkdir(osArtifacts,{recursive:true});
      await rm(path.join(osArtifacts,'result.json'),{force:true});
      const profile = path.join(dir, 'firefox');
      const data = path.join(dir, 'data');
      const config = path.join(dir, 'config');
      await Promise.all([mkdir(profile), mkdir(path.join(data,'applications'),{recursive:true}), mkdir(config)]);
      // Trust only this test certificate, only in the disposable Firefox profile.
      execFileSync('certutil',['-N','-d',`sql:${profile}`,'--empty-password']);
      execFileSync('certutil',['-A','-d',`sql:${profile}`,'-n','Firmica ephemeral WSS','-t','C,,','-i',trust]);
      const binary = process.env.FIRMICA_DESKTOP || path.join(root,'target/dx/firmica/release/linux/app/firmica');
      const quote = value => `"${value.replaceAll('\\','\\\\').replaceAll('"','\\"').replaceAll('%','%%')}"`;
      await writeFile(path.join(data,'applications','firmica-interop.desktop'),
        `[Desktop Entry]\nType=Application\nName=Firmica interoperability test\nExec=${[binary,'--tls-cert',cert,'--tls-key',key,'--origin',origin].map(quote).join(' ')} %u\nMimeType=x-scheme-handler/afirma;\nTerminal=false\n`);
      await writeFile(path.join(config,'mimeapps.list'),'[Default Applications]\nx-scheme-handler/afirma=firmica-interop.desktop\n');
      const env = {...process.env, GDK_BACKEND:'x11', XDG_RUNTIME_DIR:runtime, XDG_DATA_HOME:data,
        XDG_CONFIG_HOME:config, WEBKIT_INSPECTOR_HTTP_SERVER:`127.0.0.1:${inspectorPort}`};
      handlerEnv = env;
      execFileSync('update-desktop-database',[path.join(data,'applications')],{env});
      assert.match(execFileSync('gio',['mime','x-scheme-handler/afirma'],{env,encoding:'utf8'}),/firmica-interop\.desktop/);
      browser = await firefox.launchPersistentContext(profile, {headless:false, env,
        firefoxUserPrefs: {
          // Preapprove this protocol only in the disposable test profile. AutoScript
          // starts it from an async iframe; default permission-dialog UX is separate.
          'network.protocol-handler.external.afirma': true,
          'network.protocol-handler.warn-external.afirma': false,
          'network.protocol-handler.prompt-without-user-activation': false,
          'widget.use-xdg-desktop-portal.mime-handler': 0,
          'widget.use-xdg-desktop-portal.open-uri': 0,
        },
      });
      page = await browser.newPage();
    } else {
      browser = await chromium.launch({ args: [`--ignore-certificate-errors-spki-list=${pin}`] });
      page = await browser.newPage();
    }
    const cdp = osHandlerMode ? undefined : await page.context().newCDPSession(page);
    await cdp?.send('Page.enable');
    const frames = [];
    page.on('websocket', ws => {
      ws.on('framesent', frame => frames.push({ direction: 'sent', data: frame.payload, url: ws.url() }));
      ws.on('framereceived', frame => frames.push({ direction: 'received', data: frame.payload, url: ws.url() }));
    });
    const invoked = osHandlerMode ? undefined : new Promise((resolve,reject) => {
      cdp.on('Page.frameRequestedNavigation', async event => {
        if (!event.url.startsWith('afirma://')) return;
        try {
          bootstrapUri = event.url;
          const invocation = new URL(event.url);
          assert.equal(invocation.hostname, 'websocket');
          assert.equal(invocation.searchParams.get('v'), '4');
          assert.equal(invocation.searchParams.get('jvc'), '4');
          // The harness bridges the captured URI to a native process. OS registration is tested separately.
          if (nativeMode) {
            const binary = process.env.FIRMICA_DESKTOP || path.join(root,'target/dx/firmica/release/linux/app/firmica');
            probe = spawn('xvfb-run',['-a','-s','-screen 0 1280x900x24',binary,'--tls-cert',cert,'--tls-key',key,'--origin',origin,event.url],{
              env:{...process.env,GDK_BACKEND:'x11',XDG_RUNTIME_DIR:runtime,WEBKIT_INSPECTOR_HTTP_SERVER:`127.0.0.1:${inspectorPort}`},
              stdio:['ignore','pipe','inherit'],detached:true,
            });
            probe.once('error',reject);
            native = await inspector(inspectorPort);
          } else {
            const binary = process.env.FIRMICA_PROBE || path.join(root, 'target/debug/examples/probe');
            probe = spawn(binary, [cert, key, origin, event.url], { stdio: ['ignore','pipe','inherit'] });
            probe.once('error', reject);
            await waitReady(probe);
          }
          resolve();
        } catch (error) { reject(error); }
      });
    });
    await page.goto(origin);
    assert.equal(await page.evaluate(() => AutoScript.VERSION), '1.10.1');
    await page.locator('#sign').click();
    if (osHandlerMode) {
      // Firefox, not a captured-navigation callback, must launch the registered executable.
      native = await inspector(inspectorPort);
      const window = execFileSync('xdotool',['search','--onlyvisible','--name','^Firmica'],{encoding:'utf8'}).trim().split('\n')[0];
      osAppPid = Number(execFileSync('xdotool',['getwindowpid',window],{encoding:'utf8'}).trim());
      const command = (await readFile(`/proc/${osAppPid}/cmdline`,'utf8')).split('\0');
      bootstrapUri = command.find(argument => argument.startsWith('afirma://websocket?'));
      assert.ok(bootstrapUri, 'OS handler must receive the AutoScript bootstrap URI');
      const bootstrap = new URL(bootstrapUri);
      assert.equal(bootstrap.searchParams.get('v'),'4');
      assert.equal(bootstrap.searchParams.get('jvc'),'4');
    } else {
      await invoked;
    }
    if (nativeMode) {
      await until(async () => await native.evaluate('document.querySelector("#request-operation")?.textContent === "sign"'));
      assert.equal(await native.evaluate('document.querySelector("#request-version")?.textContent'),'4');
      await until(() => frames.some(f => f.direction === 'sent' && f.data.startsWith('getresult?')));
      await native.evaluate('document.querySelector("#reject-request").click(); true');
    }
    await page.waitForFunction(() => window.operationResult, { timeout: 20000 });
    const result = await page.evaluate(() => window.operationResult);
    assert.equal(result.type, 'es.gob.afirma.core.AOCancelledOperationException');
    assert.ok(frames.some(f => f.direction === 'sent' && f.data.startsWith('echo=-idsession=')));
    assert.ok(frames.some(f => f.direction === 'received' && f.data === 'OK'));
    assert.ok(frames.some(f => f.direction === 'sent' && f.data.startsWith('afirma://sign?')));
    assert.ok(frames.some(f => f.direction === 'received' && f.data === '#wait'));
    assert.ok(frames.some(f => f.direction === 'sent' && f.data.startsWith('getresult?')));
    assert.ok(frames.some(f => f.direction === 'received' && f.data === 'CANCEL'));
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
    assert.match(await exchange('getresult?idsession=invalidsession123'),/^SAF_46:/);
    assert.match(await exchange(`afirma://sign?idsession=${session}`),/^SAF_04:/,'completed session cannot sign twice');
    assert.match(await exchange(`getresult?idsession=${session}&idsession=${session}`),/^SAF_46:/,'duplicate session fields are rejected');
    const port = Number(new URL(endpoint).port);
    const ca = await readFile(trust);
    const handshake = (requestedOrigin,host) => new Promise((resolve,reject) => {
      const client = tlsConnect({host:'127.0.0.1',port,ca,rejectUnauthorized:true},() => {
        client.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: ${requestedOrigin}\r\n\r\n`);
      });
      let response = '';
      client.setTimeout(5000,() => client.destroy(new Error('handshake timed out')));
      client.on('error',reject);
      client.on('data',chunk => { response += chunk; if(response.includes('\r\n')) { client.destroy(); resolve(response.split('\r\n')[0]); } });
    });
    assert.match(await handshake('https://untrusted.invalid',`127.0.0.1:${port}`),/403/,'foreign origin is rejected by the native listener');
    assert.match(await handshake(origin,`localhost:${port}`),/403/,'unexpected Host is rejected');
    const closeCode = await page.evaluate(endpoint => new Promise((resolve,reject) => {
      const ws = new WebSocket(endpoint);
      const timer = setTimeout(() => {ws.close(); reject(new Error('oversize response timed out'));},5000);
      ws.onopen = () => ws.send('x'.repeat(65537));
      ws.onclose = event => {clearTimeout(timer); resolve(event.code);};
      ws.onmessage = () => reject(new Error('oversized message was processed'));
    }),endpoint);
    assert.ok([1006,1009].includes(closeCode),'oversized message closes the connection');
    if (osHandlerMode) {
      const opens = (page, address) => page.evaluate(address => new Promise((resolve,reject) => {
        const ws = new WebSocket(address);
        const timer = setTimeout(() => {ws.close(); reject(new Error('TLS control timed out'));},5000);
        ws.onopen = () => {clearTimeout(timer); ws.close(); resolve(true);};
        ws.onerror = () => {clearTimeout(timer); resolve(false);};
      }),address);
      assert.equal(await opens(page,endpoint),true,'profile-local CA permits the test listener');
      const untrusted = await firefox.launch({headless:true,env:handlerEnv});
      try {
        const control = await untrusted.newPage();
        await control.goto(origin);
        assert.equal(await opens(control,endpoint),false,'a fresh profile must reject the untrusted CA');
      } finally {
        await untrusted.close();
      }
      assert.equal(await opens(page,endpoint),true,'listener remains available after the trust control');
      await page.locator('#warm').click();
      await until(async () => await native.evaluate('document.querySelector("#request-operation")?.textContent === "cosign"'));
      // The original inspector session still works: the app process was not replaced.
      assert.equal(await native.evaluate('document.querySelector("#request-version")?.textContent'),'4');
    }
    const report = { autoscript: '1.10.1', revision, protocol: 4, jvc: 4, callback: result.type,
      browser: osHandlerMode ? browser.browser().version() : browser.version(), frameCount: frames.length,
      invocation: osHandlerMode ? 'Firefox → isolated XDG handler, cold/warm' : 'captured URI → test bridge' };
    if (osHandlerMode) {
      const executable = (await readFile(`/proc/${osAppPid}/cmdline`,'utf8')).split('\0')[0];
      Object.assign(report, {platform:process.platform, applicationSha256:createHash('sha256').update(await readFile(executable)).digest('hex'),
        tls:'ephemeral CA trusted in one disposable Firefox profile; fresh profile rejects it',
        scope:'protocol 4 cancellation and direct warm URI; scheme preapproved; default permission UX, signing and production TLS provisioning unverified'});
      await page.screenshot({path:path.join(osArtifacts,'browser-cancelled.png')});
      if(process.env.FIRMICA_SCREENSHOT) {
        const window = execFileSync('xdotool',['search','--onlyvisible','--name','^Firmica'],{encoding:'utf8'}).trim().split('\n')[0];
        execFileSync('import',['-window',window,process.env.FIRMICA_SCREENSHOT]);
      }
      await writeFile(path.join(osArtifacts,'result.json'),JSON.stringify(report,null,2)+'\n');
    }
    console.log(JSON.stringify(report));
  } finally {
    native?.close();
    if(osAppPid) {try {process.kill(osAppPid,'SIGTERM');} catch {}}
    if(nativeMode && probe?.pid) {try {process.kill(-probe.pid,'SIGTERM');} catch {}}
    else probe?.kill('SIGTERM');
    await browser?.close();
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive:true, force:true });
  }
});
