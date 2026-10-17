// Linux WebView smoke test. The inspector is enabled only in this test process.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { freePort, until, inspector } from './native.mjs';
import { mkdtemp, rm, mkdir, writeFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

const root = path.resolve(import.meta.dirname, '../..');
const deb = process.env.FIRMICA_DEB && path.resolve(process.env.FIRMICA_DEB);
const output = path.join(root,'.test-artifacts','linux-bundle');

test(`Linux ${deb ? 'Debian payload' : 'OS invocation'}: cold launch, running-instance delivery, consent, focus and crash recovery`, { timeout:60000, skip:process.platform !== 'linux' }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(),'firmica-desktop-'));
  const runtime = path.join(dir,'run'); await mkdir(runtime,{ mode:0o700 });
  let binary = process.env.FIRMICA_DESKTOP || path.join(root,'target/dx/firmica/release/linux/app/firmica');
  let data = path.join(dir,'data');
  let handler = 'firmica-phase0.desktop';
  let metadata;
  if (deb) {
    await mkdir(output,{recursive:true});
    await rm(path.join(output,'result.json'),{force:true});
    const payload = path.join(dir,'extracted package');
    const control = path.join(dir,'control');
    await Promise.all([mkdir(payload),mkdir(control)]);
    assert.equal(execFileSync('ar',['p',deb,'debian-binary'],{encoding:'utf8'}),'2.0\n');
    for (const [member,destination] of [['data.tar.gz',payload],['control.tar.gz',control]]) {
      const archive = execFileSync('ar',['p',deb,member],{maxBuffer:64*1024*1024});
      execFileSync('tar',['-xz','-C',destination],{input:archive});
    }
    metadata = await readFile(path.join(control,'control'),'utf8');
    assert.match(metadata,/^Package: firmica$/m);
    assert.match(metadata,/^Description: Firmica electronic-signature client$/m);
    execFileSync('md5sum',['--check',path.join(control,'md5sums')],{cwd:payload,stdio:'pipe'});
    binary = path.join(payload,'usr/bin/firmica');
    data = path.join(payload,'usr/share');
    handler = 'firmica.desktop';
    const desktop = path.join(data,'applications',handler);
    execFileSync('desktop-file-validate',[desktop]);
    const entry = await readFile(desktop,'utf8');
    assert.match(entry,/^Name=Firmica$/m);
    assert.match(entry,/^Exec=firmica %u$/m);
    assert.match(entry,/^MimeType=x-scheme-handler\/afirma;$/m);
  } else {
    await mkdir(path.join(data,'applications'),{recursive:true});
    await writeFile(path.join(data,'applications',handler), `[Desktop Entry]\nType=Application\nName=Firmica Phase 0 test\nExec="${binary}" %u\nMimeType=x-scheme-handler/afirma;\nTerminal=false\n`);
  }
  const config = path.join(dir,'config'); await mkdir(config);
  await writeFile(path.join(config,'mimeapps.list'),`[Default Applications]\nx-scheme-handler/afirma=${handler}\n`);
  const port = await freePort();
  const env = { ...process.env, GDK_BACKEND:'x11', XDG_RUNTIME_DIR:runtime, XDG_DATA_HOME:data, XDG_CONFIG_HOME:config,
    PATH:`${path.dirname(binary)}:${process.env.PATH}`, WEBKIT_INSPECTOR_HTTP_SERVER:`127.0.0.1:${port}` };
  let child, session, recovery, appPid;
  try {
    // Isolated desktop registration leaves the user's actual default handler unchanged.
    execFileSync('update-desktop-database',[path.join(data,'applications')],{env});
    child = spawn('xvfb-run',['-a','-s','-screen 0 1280x900x24','sh','-c',`printf '%s\n%s' "$DISPLAY" "$XAUTHORITY" > "$2"; gio open "$1"; sleep 50`,'firmica-test','afirma://sign?ver=4&format=CAdES&dat=c3ludGhldGlj',path.join(dir,'display')],{env,cwd:dir,stdio:['ignore','pipe','pipe'],detached:true});
    child.stderr.on('data',chunk => process.stderr.write(chunk));
    session = await inspector(port);
    await until(async () => await session.evaluate('document.querySelector("#request-operation")?.textContent === "sign"'));
    assert.equal(await session.evaluate('document.querySelector("#request-version")?.textContent'),'4');
    assert.equal(await session.evaluate('getComputedStyle(document.querySelector("h1")).fontSize'),'30px','Tailwind assets must be loaded');
    const [display,authority] = (await readFile(path.join(dir,'display'),'utf8')).split('\n');
    const xenv = {...env, DISPLAY:display, XAUTHORITY:authority};
    const windowId = execFileSync('xdotool',['search','--onlyvisible','--name','^Firmica'],{env:xenv,encoding:'utf8'}).trim().split('\n')[0];
    appPid = Number(execFileSync('xdotool',['getwindowpid',windowId],{env:xenv,encoding:'utf8'}).trim());
    assert.equal((await readFile(`/proc/${appPid}/cmdline`,'utf8')).split('\0')[0],binary);
    // Warm delivery through the registered entry may not replace a pending review.
    execFileSync('gio',['open','afirma://save?ver=4&dat=ZGlmZmVyZW50'],{env:xenv,cwd:dir});
    await new Promise(resolve => setTimeout(resolve,250));
    assert.equal(await session.evaluate('document.querySelector("#request-operation")?.textContent'),'sign');
    await session.evaluate('document.querySelector("#reject-request").click(); true');
    await until(async () => (await session.evaluate('document.querySelector("#review-status")?.textContent'))?.includes('rechazada'));
    execFileSync('gio',['open','afirma://cosign?ver=3&format=CAdES'],{env:xenv,cwd:dir});
    await until(async () => await session.evaluate('document.querySelector("#request-operation")?.textContent === "cosign"'));
    assert.equal(Number(execFileSync('xdotool',['getwindowpid',windowId],{env:xenv,encoding:'utf8'}).trim()),appPid);
    if(process.env.FIRMICA_SCREENSHOT) execFileSync('import',['-window',windowId,process.env.FIRMICA_SCREENSHOT],{env:xenv});
    execFileSync('xdotool',['windowunmap',windowId],{env:xenv});
    execFileSync('xdotool',['windowmap',windowId,'windowfocus','--sync',windowId],{env:xenv});
    assert.equal(await session.evaluate('document.querySelector("#request-operation")?.textContent'),'cosign');
    await session.evaluate('document.querySelector("#acknowledge-request").click(); true');
    await until(async () => (await session.evaluate('document.querySelector("#review-status")?.textContent'))?.includes('no está implementada'));
    // SIGKILL bypasses cleanup. The per-user file lock permits safe stale-socket recovery.
    session.close(); session = undefined;
    process.kill(appPid,'SIGKILL'); appPid = undefined;
    await new Promise(resolve => setTimeout(resolve,300));
    recovery = spawn(binary,['afirma://selectcert?ver=4'],{env:xenv,cwd:dir,stdio:['ignore','ignore','pipe']});
    recovery.stderr.on('data',chunk => process.stderr.write(chunk));
    session = await inspector(port);
    await until(async () => await session.evaluate('document.querySelector("#request-operation")?.textContent === "selectcert"'));
    if(deb) {
      const report = {platform:process.platform,package:path.basename(deb),
        packageSha256:createHash('sha256').update(await readFile(deb)).digest('hex'),
        applicationSha256:createHash('sha256').update(await readFile(binary)).digest('hex'),
        control:metadata,desktopEntry:'unmodified packaged firmica.desktop',
        checks:['payload checksums','desktop entry validation','cold gio invocation','warm gio invocation in same process',
          'pending-review protection','reject and unsupported outcomes','focus recovery','crash recovery','packaged Tailwind assets'],
        actual:'passed',scope:'extracted payload on this host; package-manager installation, dependency resolution and other distributions unverified'};
      await writeFile(path.join(output,'result.json'),JSON.stringify(report,null,2)+'\n');
      console.log(JSON.stringify(report));
    }
    console.log('Verified: isolated gio afirma handler, cold and warm Dioxus review, pending-request protection, rejection, unsupported result, focus recovery, crash recovery, Tailwind asset loading.');
  } finally {
    session?.close();
    recovery?.kill('SIGTERM');
    if (appPid) { try { process.kill(appPid,'SIGTERM'); } catch {} }
    if (child?.pid) { try { process.kill(-child.pid,'SIGTERM'); } catch {} }
    await rm(dir,{recursive:true,force:true});
  }
});
