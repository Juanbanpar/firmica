// Real Linux WebView, native file dialogs, controlled worker and OpenSSL verifier.
// Inspector access and every credential are confined to this synthetic test process.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { freePort, until, inspector } from './native.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const password = 'synthetic-desktop-password';
const content = Buffer.from('Local desktop signing\x00\xff\r\n', 'latin1');
const sha256 = data => createHash('sha256').update(data).digest('hex');

test('Linux standalone signing: native selection, consent, frozen content, save/cancel and worker cleanup',
  { skip: process.platform !== 'linux', timeout: 150000 }, async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'firmica-signing-'));
    const runtime = path.join(dir, 'run'); await mkdir(runtime, {mode:0o700});
    for (const directory of ['data', 'config', 'cache']) await mkdir(path.join(dir, directory));
    const bus = path.join(dir, 'bus.conf');
    await writeFile(bus, `<busconfig><type>session</type><listen>unix:tmpdir=${runtime}</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow send_destination="*" eavesdrop="true"/><allow receive_sender="*" eavesdrop="true"/><allow own="*"/></policy></busconfig>`);
    const output = path.join(dir, 'output'); await mkdir(output);
    let binary = process.env.FIRMICA_DESKTOP || path.join(root, 'target/dx/firmica/release/linux/app/firmica');
    const deb = process.env.FIRMICA_DEB;
    if (deb) {
      const payload = path.join(dir, 'payload'); await mkdir(payload);
      execFileSync('tar', ['-xz', '-C', payload], {input:execFileSync('ar', ['p', path.resolve(deb), 'data.tar.gz'], {maxBuffer:128*1024*1024})});
      binary = path.join(payload, 'usr/bin/firmica');
    }
    const openssl = args => execFileSync('openssl', args, {cwd:dir, stdio:['ignore', 'pipe', 'pipe']});
    openssl(['req', '-new', '-x509', '-newkey', 'rsa:2048', '-noenc', '-keyout', 'rsa.key', '-out', 'rsa.pem', '-days', '1',
      '-subj', '/CN=Firmica synthetic RSA', '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature']);
    openssl(['req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc', '-keyout', 'ec.key', '-out', 'ec.pem', '-days', '1',
      '-subj', '/CN=Firmica synthetic EC', '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature']);
    for (const algorithm of ['rsa', 'ec']) {
      openssl(['pkcs12', '-export', '-inkey', `${algorithm}.key`, '-in', `${algorithm}.pem`, '-out', `${algorithm}.p12`, '-passout', `pass:${password}`]);
    }
    await writeFile(path.join(dir, 'document.bin'), content);
    await writeFile(path.join(dir, 'reference.bin'), content);
    const port = await freePort();
    // A private session bus without service activation keeps dialogs off the user's
    // portal while letting GTK use a working bus inside this Xvfb display.
    const env = {...process.env, GDK_BACKEND:'x11', XDG_RUNTIME_DIR:runtime, XDG_SESSION_TYPE:'x11',
      LC_ALL:'C.UTF-8',
      XDG_DATA_HOME:path.join(dir, 'data'), XDG_CONFIG_HOME:path.join(dir, 'config'), XDG_CACHE_HOME:path.join(dir, 'cache'),
      WEBKIT_INSPECTOR_HTTP_SERVER:`127.0.0.1:${port}`};
    let child, session, xenv;
    let stderr = '';
    try {
      child = spawn('xvfb-run', ['-a', '-s', '-screen 0 1280x1100x24', 'sh', '-c', 'openbox >/dev/null 2>&1 & exec "$@"', 'test-wm', 'dbus-run-session', '--config-file', bus, '--', 'sh', '-c',
        'printf "%s\n%s\n%s" "$DISPLAY" "$XAUTHORITY" "$$" > "$1"; exec "$2"', 'signing-test', path.join(dir, 'display'), binary],
      {env, cwd:dir, stdio:['ignore', 'ignore', 'pipe'], detached:true});
      child.stderr.on('data', data => { stderr += data; });
      session = await inspector(port);
      const [display, authority, appPid] = (await readFile(path.join(dir, 'display'), 'utf8')).split('\n');
      xenv = {...env, DISPLAY:display, XAUTHORITY:authority};
      const xdo = args => execFileSync('xdotool', args, {env:xenv, timeout:5000, encoding:'utf8', stdio:['ignore','pipe','pipe']}).trim();
      const evaluate = expression => session.evaluate(expression);
      const click = id => evaluate(`setTimeout(() => document.querySelector(${JSON.stringify(id)}).click(), 0); true`);
      const input = (id, value, event='input') => evaluate(`(() => { const input = document.querySelector(${JSON.stringify(id)}); input.value = ${JSON.stringify(value)}; input.dispatchEvent(new Event(${JSON.stringify(event)}, {bubbles:true})); return true; })()`);
      const status = () => evaluate('document.querySelector("#sign-status")?.textContent');
      const workers = async () => {
        const tasks = await readdir(`/proc/${appPid}/task`);
        const children = await Promise.all(tasks.map(task => readFile(`/proc/${appPid}/task/${task}/children`, 'utf8').catch(() => '')));
        const pids = [...new Set(children.join(' ').trim().split(/\s+/).filter(Boolean))];
        const names = await Promise.all(pids.map(pid => readFile(`/proc/${pid}/comm`, 'utf8').catch(() => '')));
        // Linux comm truncates names to 15 bytes. WebKit also owns child processes.
        return pids.filter((pid, index) => names[index].trim() === 'firmica-key-wor');
      };
      async function dialog(selector, filename) {
        await until(async () => !(await evaluate(`document.querySelector(${JSON.stringify(selector)}).disabled`)));
        await click(selector);
        const window = await until(() => xdo(['search', '--onlyvisible', '--class', '[Zz]enity']).split('\n').filter(Boolean).at(-1));
        xdo(['windowactivate', '--sync', window]);
        await new Promise(resolve => setTimeout(resolve, 300));
        if (filename === null) {
          xdo(['key', 'Escape']);
        } else {
          xdo(['key', 'ctrl+l']);
          xdo(['key', 'ctrl+a']);
          // Paste once so GTK's inline completion cannot alter a sequence of
          // synthetic keystrokes. This clipboard belongs only to the private Xvfb.
          execFileSync('xclip', ['-selection', 'clipboard'], {env:xenv, input:filename, stdio:['pipe', 'ignore', 'ignore']});
          xdo(['key', 'ctrl+v']);
          await new Promise(resolve => setTimeout(resolve, 200));
          xdo(['key', 'alt+o']);
        }
        await until(() => {
          try { return !xdo(['search', '--onlyvisible', '--class', '[Zz]enity']).split('\n').includes(window); }
          catch { return true; }
        });
        if (filename && selector !== '#sign-save') {
          await until(async () => await evaluate(`document.querySelector(${JSON.stringify(selector)}).files[0]?.name === ${JSON.stringify(filename)}`));
        }
      }
      async function select(algorithm, attached=false, secret=password) {
        await writeFile(path.join(dir, 'document.bin'), content);
        await dialog('#sign-document', path.join(dir, 'document.bin'));
        await dialog('#sign-certificate', path.join(dir, `${algorithm}.p12`));
        await input('#sign-password', secret);
        await input('#sign-algorithm', algorithm, 'change');
        if (attached) await click('#sign-attached');
        await until(async () => !(await evaluate('document.querySelector("#sign-prepare").disabled')));
        await click('#sign-prepare');
      }
      await until(async () => await evaluate('!!document.querySelector("a[href=\'/sign\']")'));
      await click('a[href="/sign"]');
      await until(async () => await evaluate('!!document.querySelector("#sign-language")'));
      await click('#sign-language');
      await select('rsa', false, 'wrong synthetic password');
      await until(async () => (await status())?.includes('Cannot open'));
      assert.equal(await evaluate('document.querySelector("#sign-password").value'), '', 'password DOM must be cleared after submission');
      assert.equal((await workers()).length, 0);
      await select('rsa');
      await until(async () => await evaluate('!!document.querySelector("#sign-subject")'));
      assert.equal((await workers()).length, 1, 'review must own exactly one live key worker');
      assert.equal(await evaluate('document.querySelector("#sign-document-hash").textContent'), sha256(content));
      const rsaDer = openssl(['x509', '-in', 'rsa.pem', '-outform', 'DER']);
      assert.equal(await evaluate('document.querySelector("#sign-fingerprint").textContent'), sha256(rsaDer));
      assert.match(await evaluate('document.querySelector("#sign-unchecked").textContent'), /have not been checked/);
      assert.equal(await evaluate('document.querySelector("#sign-save").disabled'), true);
      execFileSync(binary, ['afirma://sign?ver=4&dat=dW5yZWxhdGVk'], {env:xenv, cwd:dir});
      assert.equal(await evaluate('document.querySelector("#sign-save").disabled'), true, 'incoming URI cannot approve local signing');
      assert.deepEqual(await readdir(output), []);
      await click('#sign-cancel');
      await until(async () => (await status()) === 'Operation cancelled.');
      await until(async () => (await workers()).length === 0);
      assert.deepEqual(await readdir(output), []);
      for (const [algorithm, attached] of [['rsa', false], ['ec', true]]) {
        await select(algorithm, attached);
        await until(async () => await evaluate('!!document.querySelector("#sign-subject")'));
        await writeFile(path.join(dir, 'document.bin'), 'changed after review');
        await click('#sign-acknowledge');
        await dialog('#sign-save', null);
        assert.equal(await evaluate('!!document.querySelector("#sign-subject")'), true, 'save cancellation preserves pending review');
        assert.deepEqual(await readdir(output), algorithm === 'rsa' ? [] : ['rsa.csig']);
        await dialog('#sign-save', path.join(output, `${algorithm}.csig`));
        await until(async () => (await status()) === 'Signature saved.');
        assert.equal((await workers()).length, 0, 'worker must exit before saved status');
        openssl(['cms', '-verify', '-cades', '-binary', '-inform', 'DER', '-in', path.join(output, `${algorithm}.csig`),
          '-CAfile', `${algorithm}.pem`, '-no-CApath', '-no-CAstore', '-partial_chain', '-purpose', 'any',
          ...(!attached ? ['-content', 'reference.bin'] : []), '-out', 'verified.bin']);
        assert.deepEqual(await readFile(path.join(dir, 'verified.bin')), content);
      }
      await select('ec');
      await until(async () => await evaluate('!!document.querySelector("#sign-subject")'));
      if (process.env.FIRMICA_SCREENSHOT) {
        const window = xdo(['search', '--onlyvisible', '--name', '^Firmica']).split('\n')[0];
        xdo(['windowmove', window, '40', '10', 'windowsize', window, '1000', '1040']);
        await new Promise(resolve => setTimeout(resolve, 200));
        execFileSync('import', ['-window', window, process.env.FIRMICA_SCREENSHOT], {env:xenv});
      }
      await click('a[href="/"]');
      await until(async () => (await workers()).length === 0);
      assert(!stderr.includes(password));
      assert(!stderr.includes('BEGIN PRIVATE KEY'));
      console.log(`Verified ${deb ? 'packaged' : 'built'} desktop signing: native selection, wrong-password cleanup, explicit consent, browser isolation, cancellation, frozen bytes, RSA/P-256 CAdES, worker exit, unmount cleanup.`);
    } catch (error) {
      if (xenv && process.env.FIRMICA_SCREENSHOT) {
        execFileSync('import', ['-window', 'root', process.env.FIRMICA_SCREENSHOT], {env:xenv});
      }
      console.error(stderr.slice(-5000));
      throw error;
    } finally {
      session?.close();
      if (child?.pid) { try { process.kill(-child.pid, 'SIGTERM'); } catch {} }
      await rm(dir, {recursive:true, force:true});
    }
  });
