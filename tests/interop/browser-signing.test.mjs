// AutoScript (4) or a raw 4.1 client → Firefox OS handler → native consent → controlled key
// worker → WSS result. Every key, profile, association and trust entry is disposable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { firefox } from 'playwright';
import { freePort, until, inspector } from './native.mjs';
import { autoscript } from './autoscript.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const password = 'synthetic-browser-password';
const smallContent = Buffer.from('Browser signing\x00\xff\r\n', 'latin1');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

for (const scenario of ['rsa', 'ec', 'pades-rsa', 'pades-ec', 'xades-enveloped', 'xades-enveloping', 'xades-detached', 'worker-failure', 'unmount', 'large-detached', 'large-attached', 'oversize-document', 'managed-tls', ...['rsa', 'ec', 'pades-rsa', 'pades-ec', 'xades-enveloped', 'xades-enveloping', 'xades-detached', 'worker-failure', 'unmount'].map(name => `protocol41-${name}`)]) {
  test(`Firefox ${scenario.startsWith('protocol41-') ? 'protocol 4.1' : 'AutoScript'} signing: ${scenario}`, {skip:process.platform !== 'linux', timeout:90000}, async () => {
    const protocol41 = scenario.startsWith('protocol41-');
    const operation = protocol41 ? scenario.slice('protocol41-'.length) : scenario;
    const protocolPort = protocol41 ? await freePort() : undefined;
    const dir = await mkdtemp(path.join(tmpdir(), 'firmica-browser-signing-'));
    const openssl = args => execFileSync('openssl', args, {cwd:dir, stdio:['ignore','pipe','pipe']});
    const ec = operation === 'ec' || operation === 'pades-ec' || operation === 'xades-detached';
    const pdf = operation.startsWith('pades-');
    const xml = operation.startsWith('xades-');
    const placement = operation === 'xades-enveloped' ? 'XAdES Enveloped'
      : operation === 'xades-detached' ? 'XAdES Detached' : 'XAdES Enveloping';
    const format = pdf ? 'PAdES' : xml ? 'XAdES' : 'CAdES';
    const properties = pdf ? (ec ? 'signaturePage=1\nsignaturePositionOnPageLowerLeftX=40\nsignaturePositionOnPageLowerLeftY=30\nsignaturePositionOnPageUpperRightX=400\nsignaturePositionOnPageUpperRightY=70\nlayer2Text=Browser appearance' : '')
      : xml ? `format=${placement}` : `mode=${ec || operation === 'large-attached' ? 'implicit' : 'explicit'}`;
    const managed = operation === 'managed-tls';
    const attached = ec || operation === 'large-attached';
    const content = pdf ? await readFile(path.join(root,'crates/pades/tests/fixtures/document.pdf'))
      : operation === 'xades-enveloped' ? Buffer.from('<document xmlns="urn:firmica:test">Browser XML &amp; content</document>')
      : operation === 'oversize-document' ? Buffer.alloc(16 * 1024 * 1024 + 1, 0xff)
      : operation === 'large-attached' ? Buffer.alloc(16 * 1024 * 1024, 0xff)
      : operation === 'large-detached' ? Buffer.alloc(1024 * 1024, 0xa5) : smallContent;
    const script = await autoscript();
    const protocol41Script = await readFile(path.join(root,'tests/interop/protocol41-client.js'));
    const rawClient = `document.querySelector('#sign').onclick = () => signProtocol41(${JSON.stringify({
      port:protocolPort, content:content.toString('base64'), algorithm:ec ? 'ec' : 'rsa', format, properties,
    })}).then(result=>window.result=result).catch(()=>window.result={error:'Protocol 4.1 exchange failed'});`;
    const html = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Synthetic browser signing</title>
      <button id="sign">Sign</button><script src="/autoscript.js"></script><script src="/protocol41.js"></script><script>
      ${protocol41 ? rawClient : `AutoScript.enableProgressDialog(false); AutoScript.setPortRange(49152, 49154); AutoScript.cargarAppAfirma(); AutoScript.setKeyStore(AutoScript.KEYSTORE_PKCS12);
      document.querySelector('#sign').onclick = () => AutoScript.sign('${content.toString('base64')}',
        '${ec ? 'SHA256withECDSA' : 'SHA256withRSA'}', '${format}', ${JSON.stringify(properties)},
        (signature, certificate) => {window.result = {signature, certificate};},
        (type, message, code) => {window.result = {type, message, code};});`}
      </script></html>`;
    const server = createServer((req,res) => {
      res.setHeader('Content-Type', req.url.endsWith('.js') ? 'text/javascript' : 'text/html');
      res.end(req.url === '/autoscript.js' ? script : req.url === '/protocol41.js' ? protocol41Script : html);
    });
    let child, browser, native, xenv;
    let stderr = '';
    try {
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const origin = `http://127.0.0.1:${server.address().port}`;
      const runtime = path.join(dir, 'run');
      const data = path.join(dir, 'data');
      const config = path.join(dir, 'config');
      const profile = path.join(dir, 'firefox');
      await Promise.all([mkdir(runtime,{mode:0o700}), mkdir(path.join(data,'applications'),{recursive:true}), mkdir(config), mkdir(profile)]);
      if (!managed) {
        openssl(['req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Synthetic local TLS CA',
          '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign']);
        openssl(['req','-newkey','rsa:2048','-nodes','-keyout','tls.key','-out','tls.csr','-subj','/CN=127.0.0.1']);
        await writeFile(path.join(dir,'tls.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n');
        openssl(['x509','-req','-in','tls.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-out','tls.pem','-extfile','tls.ext']);
      }
      openssl(['req','-x509','-newkey',ec ? 'ec' : 'rsa:2048', ...(ec ? ['-pkeyopt','ec_paramgen_curve:prime256v1'] : []),
        '-nodes','-keyout','signer.key','-out','signer.pem','-days','1','-subj','/CN=Firmica synthetic browser signer',
        '-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature']);
      openssl(['pkcs12','-export','-inkey','signer.key','-in','signer.pem','-out','signer.p12','-passout',`pass:${password}`]);
      await writeFile(path.join(dir,'reference.bin'), content);
      let binary = path.resolve(process.env.FIRMICA_DESKTOP || path.join(root,'target/dx/firmica/release/linux/app/firmica'));
      if (process.env.FIRMICA_DEB) {
        const payload = path.join(dir,'payload'); await mkdir(payload);
        execFileSync('tar',['-xz','-C',payload],{input:execFileSync('ar',['p',path.resolve(process.env.FIRMICA_DEB),'data.tar.gz'],{maxBuffer:128*1024*1024})});
        binary = path.join(payload,'usr/bin/firmica');
      }
      if (managed) {
        const options = {env:{...process.env,XDG_CONFIG_HOME:config},encoding:'utf8',stdio:['ignore','pipe','pipe']};
        const output = execFileSync(binary,['tls','init','--origin',origin],options);
        assert.equal(execFileSync(binary,['tls','status'],options),output);
        const fingerprint = openssl(['x509','-in',path.join(config,'firmica/browser-tls/ca.pem'),'-noout','-sha256','-fingerprint']).toString().trim().split('=').at(-1);
        assert.ok(output.includes(`CA SHA-256: ${fingerprint}`));
        assert.ok(output.includes(`Origin: ${origin}`));
      }
      execFileSync('certutil',['-N','-d',`sql:${profile}`,'--empty-password']);
      execFileSync('certutil',['-A','-d',`sql:${profile}`,'-n','Synthetic local WSS','-t','C,,','-i',
        managed ? path.join(config,'firmica/browser-tls/ca.pem') : path.join(dir,'ca.pem')]);
      const flags = managed ? [] : ['--tls-cert',path.join(dir,'tls.pem'),'--tls-key',path.join(dir,'tls.key'),'--origin',origin];
      const quote = value => `"${value.replaceAll('\\','\\\\').replaceAll('"','\\"').replaceAll('%','%%')}"`;
      const entry = managed && process.env.FIRMICA_DEB
        ? await readFile(path.join(dir,'payload/usr/share/applications/firmica.desktop'),'utf8')
        : `[Desktop Entry]\nType=Application\nName=Firmica test\nExec=${[binary,...flags].map(quote).join(' ')} %u\nMimeType=x-scheme-handler/afirma;\nTerminal=false\n`;
      if (managed && process.env.FIRMICA_DEB) assert.match(entry,/^Exec=firmica %u$/m);
      await writeFile(path.join(data,'applications','firmica-test.desktop'),entry);
      await writeFile(path.join(config,'mimeapps.list'), '[Default Applications]\nx-scheme-handler/afirma=firmica-test.desktop\n');
      const bus = path.join(dir,'bus.conf');
      await writeFile(bus, `<busconfig><type>session</type><listen>unix:tmpdir=${runtime}</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow send_destination="*" eavesdrop="true"/><allow receive_sender="*" eavesdrop="true"/><allow own="*"/></policy></busconfig>`);
      const port = await freePort();
      const env = {...process.env, GDK_BACKEND:'x11', XDG_RUNTIME_DIR:runtime, XDG_SESSION_TYPE:'x11', LC_ALL:'C.UTF-8',
        XDG_DATA_HOME:data, XDG_CONFIG_HOME:config, XDG_CACHE_HOME:path.join(dir,'cache'), PATH:`${path.dirname(binary)}:${process.env.PATH}`, WEBKIT_INSPECTOR_HTTP_SERVER:`127.0.0.1:${port}`};
      execFileSync('update-desktop-database',[path.join(data,'applications')],{env});
      child = spawn('xvfb-run',['-a','-s','-screen 0 1280x1100x24','sh','-c','openbox >/dev/null 2>&1 & exec "$@"','test-wm',
        'dbus-run-session','--config-file',bus,'--','sh','-c',
        'printf "%s\n%s\n%s\n%s" "$DISPLAY" "$XAUTHORITY" "$DBUS_SESSION_BUS_ADDRESS" "$$" > "$1"; shift; exec "$@"',
        'browser-test',path.join(dir,'display'),binary,...flags],
      {env,cwd:dir,stdio:['ignore','ignore','pipe'],detached:true});
      child.stderr.on('data', bytes => {stderr += bytes;});
      native = await inspector(port);
      const [display,authority,busAddress,appPid] = (await readFile(path.join(dir,'display'),'utf8')).split('\n');
      xenv = {...env,DISPLAY:display,XAUTHORITY:authority,DBUS_SESSION_BUS_ADDRESS:busAddress};
      const xdo = args => execFileSync('xdotool',args,{env:xenv,encoding:'utf8',timeout:5000,stdio:['ignore','pipe','pipe']}).trim();
      const click = selector => native.evaluate(`setTimeout(() => document.querySelector(${JSON.stringify(selector)}).click(), 0); true`);
      const workers = async () => {
        const tasks = await readdir(`/proc/${appPid}/task`);
        const children = await Promise.all(tasks.map(task => readFile(`/proc/${appPid}/task/${task}/children`,'utf8').catch(() => '')));
        const pids = [...new Set(children.join(' ').trim().split(/\s+/).filter(Boolean))];
        const names = await Promise.all(pids.map(pid => readFile(`/proc/${pid}/comm`,'utf8').catch(() => '')));
        return pids.filter((_,index) => names[index].trim() === 'firmica-key-wor');
      };
      browser = await firefox.launchPersistentContext(profile, {headless:false,env:xenv,firefoxUserPrefs:{
        'network.protocol-handler.external.afirma':true, 'network.protocol-handler.warn-external.afirma':false,
        'network.protocol-handler.prompt-without-user-activation':false,
        'widget.use-xdg-desktop-portal.mime-handler':0, 'widget.use-xdg-desktop-portal.open-uri':0,
      }});
      const page = await browser.newPage();
      const frames = [];
      page.on('websocket', ws => {
        ws.on('framesent', frame => frames.push({direction:'sent',data:frame.payload,url:ws.url()}));
        ws.on('framereceived', frame => frames.push({direction:'received',data:frame.payload,url:ws.url()}));
      });
      await page.goto(origin);
      await page.locator('#sign').click();
      if (operation === 'oversize-document') {
        await page.waitForFunction(() => window.result, undefined, {timeout:20000});
        const result = await page.evaluate('window.result');
        assert.equal(result.type,'java.lang.Exception');
        assert.match(result.code,/^SAF_03:/);
        assert.equal(result.signature,undefined);
        assert.equal((await workers()).length,0,'oversized input must not open a key');
        assert.equal(await native.evaluate('!!document.querySelector("#sign-certificate")'),false);
        return;
      }
      await until(async () => await native.evaluate('document.querySelector("#request-operation")?.textContent === "sign"'));
      assert.equal(await native.evaluate('document.querySelector("#request-version").textContent'),protocol41 ? '4.1' : '4');
      assert.equal(await native.evaluate('!!document.querySelector("#sign-language")'),true,'supported request must open the signing form');
      await click('#sign-language');
      assert.equal(await native.evaluate('!!document.querySelector("#sign-document")'),false,'browser cannot choose a local document');
      assert.equal(await native.evaluate('!!document.querySelector("#sign-algorithm")'),false,'request fixes algorithm');
      assert.equal((await workers()).length,0,'invocation alone must not open a key');
      await until(() => frames.some(frame => frame.direction === 'sent' && frame.data.startsWith('getresult?')));
      assert.equal(await page.evaluate('window.result'),undefined,'receiving a request must not sign');
      const nativeWindow = xdo(['search','--onlyvisible','--name','^Firmica$']).split('\n')[0];
      xdo(['windowactivate','--sync',nativeWindow]);
      await new Promise(resolve => setTimeout(resolve,200));
      await click('#sign-certificate');
      const window = await until(() => xdo(['search','--onlyvisible','--class','[Zz]enity']).split('\n').filter(Boolean).at(-1));
      xdo(['windowactivate','--sync',window]);
      await new Promise(resolve => setTimeout(resolve,300));
      xdo(['key','ctrl+l']); xdo(['key','ctrl+a']);
      execFileSync('xclip',['-selection','clipboard'],{env:xenv,input:path.join(dir,'signer.p12'),stdio:['pipe','ignore','ignore']});
      xdo(['key','ctrl+v']); await new Promise(resolve => setTimeout(resolve,200)); xdo(['key','alt+o']);
      await until(() => {
        try { return !xdo(['search','--onlyvisible','--class','[Zz]enity']).split('\n').includes(window); }
        catch { return true; }
      });
      await until(async () => await native.evaluate(`document.querySelector('#sign-certificate').files[0]?.name === ${JSON.stringify(path.join(dir,'signer.p12'))}`));
      await native.evaluate(`(() => {const input = document.querySelector('#sign-password'); input.value = ${JSON.stringify(password)}; input.dispatchEvent(new Event('input',{bubbles:true})); return true;})()`);
      // File metadata reaches Rust asynchronously after the DOM file list changes.
      await until(async () => await native.evaluate('document.querySelector("#sign-prepare")?.disabled === false'));
      await click('#sign-prepare');
      const opening = await until(async () => {
        const state = await native.evaluate('({ready:!!document.querySelector("#sign-subject"), failed:document.querySelector("#sign-status")?.getAttribute("role") === "alert", message:document.querySelector("#sign-status")?.textContent})');
        return state.ready || state.failed ? state : undefined;
      });
      assert.equal(opening.ready,true,opening.message);
      const signer = openssl(['x509','-in','signer.pem','-outform','DER']);
      assert.equal(await native.evaluate('document.querySelector("#sign-document-hash").textContent'),sha256(content));
      assert.equal(await native.evaluate('document.querySelector("#sign-fingerprint").textContent'),sha256(signer));
      assert.match(await native.evaluate('document.querySelector("#sign-review-format").textContent'),new RegExp(`^${format}`));
      if (operation === 'pades-ec') assert.match(await native.evaluate('document.querySelector("#sign-review-appearance").textContent'),/Browser appearance/);
      assert.equal(await native.evaluate('document.querySelector("#sign-save").disabled'),true,'explicit acknowledgement is required');
      assert.equal((await workers()).length,1);
      if (process.env.FIRMICA_SCREENSHOT && operation === 'rsa') {
        xdo(['windowmove',nativeWindow,'40','10','windowsize',nativeWindow,'1000','1040']);
        await new Promise(resolve => setTimeout(resolve,200));
        execFileSync('import',['-window',nativeWindow,process.env.FIRMICA_SCREENSHOT],{env:xenv});
      }
      if (operation === 'unmount') {
        await click('a[href="/diagnostics"]');
      } else {
        // A second invocation cannot replace the frozen request or authorize it.
        execFileSync(binary,['afirma://sign?ver=4&format=CAdES&algorithm=SHA256withRSA&dat=b3RoZXI%3D'],{env:xenv,cwd:dir});
        assert.equal(await native.evaluate('document.querySelector("#sign-document-hash").textContent'),sha256(content));
        assert.equal(await native.evaluate('document.querySelector("#sign-save").disabled'),true);
        if (operation === 'worker-failure') {
          process.kill(Number((await workers())[0]),'SIGKILL');
        }
        await click('#sign-acknowledge');
        await until(async () => !(await native.evaluate('document.querySelector("#sign-save").disabled')));
        await click('#sign-save');
      }
      await page.waitForFunction(() => window.result, undefined, {timeout:20000});
      const result = await page.evaluate('window.result');
      await until(async () => (await workers()).length === 0);
      if (operation === 'worker-failure') {
        assert.equal(result.type, protocol41 ? undefined : 'java.lang.Exception');
        assert.match(result.code, protocol41 ? /^err-00:=AF200115 - / : /^SAF_09:/);
        assert.equal(result.signature,undefined);
      } else if (operation === 'unmount') {
        if (protocol41) assert.match(result.code, /^err-11:=AF500001 - /);
        else assert.equal(result.type,'es.gob.afirma.core.AOCancelledOperationException');
        assert.equal(result.signature,undefined);
      } else {
        assert.equal(result.type,undefined);
        assert.deepEqual(Buffer.from(result.certificate,'base64'),signer,'response certificate must be the reviewed leaf');
        const signed=Buffer.from(result.signature,'base64');
        if (pdf) {
          assert.ok(signed.subarray(0,content.length).equals(content),'original PDF revision must remain intact');
          await writeFile(path.join(dir,'result.pdf'),signed);
          const verification=execFileSync('pdfsig',['-nocert','result.pdf'],{cwd:dir,encoding:'utf8'});
          assert.match(verification,/Signature is Valid/);
        } else if (xml) {
          await writeFile(path.join(dir,'result.xml'),signed);
          execFileSync('xmlsec1',['--verify','--pubkey-cert-pem','signer.pem','--enabled-reference-uris','empty,same-doc',
            '--id-attr:Id','http://uri.etsi.org/01903/v1.3.2#:SignedProperties','--id-attr:Id','http://www.w3.org/2000/09/xmldsig#:Object','result.xml'],{cwd:dir,stdio:['ignore','pipe','pipe']});
          if (operation !== 'xades-enveloped') {
            const data=await page.evaluate(text=>new DOMParser().parseFromString(text,'application/xml').querySelector('[Id="Firmica-Content"]').textContent,signed.toString());
            assert.deepEqual(Buffer.from(data,'base64'),content);
          } else assert.ok(signed.toString().includes('Browser XML &amp; content'));
        } else {
          await writeFile(path.join(dir,'result.csig'),signed);
          openssl(['cms','-verify','-cades','-binary','-inform','DER','-in','result.csig','-CAfile','signer.pem',
          '-no-CApath','-no-CAstore','-partial_chain','-purpose','any',...(!attached ? ['-content','reference.bin'] : []),'-out','verified.bin']);
          assert.deepEqual(await readFile(path.join(dir,'verified.bin')),content);
        }
        await until(async () => (await native.evaluate('document.querySelector("#browser-status")?.textContent'))?.includes('Signature prepared'));
      }
      if (operation.startsWith('large-')) {
        const sent = frames.find(frame => frame.direction === 'sent' && frame.data.startsWith('afirma://sign?'));
        assert.ok(sent.data.length > 64 * 1024,'document must cross the old request boundary');
        if (attached) assert.ok(Buffer.from(result.signature,'base64').length > content.length,'attached response must contain the entire document');
      }
      assert.ok(frames.some(frame => frame.direction === 'received' && frame.data === '#wait'));
      const endpoint = frames.find(frame => frame.direction === 'received' && frame.data === 'OK').url;
      const session = frames.find(frame => frame.direction === 'sent' && frame.data.startsWith('getresult?')).data;
      const replay = await page.evaluate(({endpoint,session}) => new Promise((resolve,reject) => {
        const ws = new WebSocket(endpoint); const timer = setTimeout(() => {ws.close();reject(new Error('replay timeout'));},5000);
        ws.onopen = () => ws.send(session); ws.onmessage = event => {clearTimeout(timer);ws.close();resolve(event.data);};
      }),{endpoint,session});
      assert.match(replay, protocol41 ? /^err-00:=AF600002 - / : /^SAF_04:/,'a result cannot be retrieved twice');
      if (protocol41) {
        const evidence = path.join(root,'.test-artifacts/protocol41');
        await mkdir(evidence,{recursive:true});
        await writeFile(path.join(evidence,`native-${operation}.json`), JSON.stringify({protocol:'4.1',scenario:operation,browser:browser.browser().version(),passed:true}));
      }
      assert(!stderr.includes(password)); assert(!stderr.includes('BEGIN PRIVATE KEY')); assert(!stderr.includes('panicked at'));
    } catch (error) {
      console.error(error.message);
      console.error(stderr.slice(-4000));
      throw error;
    } finally {
      native?.close();
      await browser?.close();
      if (child?.pid) {try {process.kill(-child.pid,'SIGTERM');} catch {}}
      await new Promise(resolve => server.close(resolve));
      await rm(dir,{recursive:true,force:true});
    }
  });
}
