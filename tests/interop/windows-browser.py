#!/usr/bin/env python3
"""Firefox AutoScript / protocol 4.1 -> registered Windows handler -> native signing consent."""
import argparse
import base64
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

from windows_gui import free_port, wait_for, windows_for
import windows_gui

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".test-artifacts/windows-browser"))
    options = parser.parse_args()
    if platform.system() != "Windows":
        parser.error("requires a disposable Windows desktop account")
    from playwright.sync_api import sync_playwright
    from pywinauto import Application
    from PIL import ImageGrab
    import winreg

    # This account's association must be unused: the test never resets UserChoice.
    for root, name in [(winreg.HKEY_CLASSES_ROOT, "afirma"),
                       (winreg.HKEY_CURRENT_USER, r"Software\Classes\Firmica.afirma"),
                       (winreg.HKEY_CURRENT_USER, r"Software\Firmica\Capabilities"),
                       (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\afirma\UserChoice")]:
        try:
            with winreg.OpenKey(root, name):
                raise RuntimeError("refusing to replace an existing handler/default; use a disposable Windows account")
        except FileNotFoundError:
            pass
    if windows_gui.processes(name="firmica.exe"):
        raise RuntimeError("another Firmica process is already running")
    fixtures = options.fixtures.resolve(strict=True)
    cases = json.loads((fixtures / "cases.json").read_text())
    app = options.app.resolve(strict=True)
    options.output.mkdir(parents=True, exist_ok=True)
    evidence = {"platform": platform.platform(), "passed": False, "checks": []}
    observed = None
    browser = None
    with tempfile.TemporaryDirectory(prefix="firmica-browser-") as temporary, contextlib.ExitStack() as cleanup:
        directory = Path(temporary)
        # Spaces and shell metacharacters exercise the installed command quoting.
        installed = directory / "Bundle space & 'apostrophe'"
        shutil.copytree(app.parent, installed)
        app = installed / "firmica.exe"
        handler = installed / "handler.ps1"
        assert handler.is_file(), "the portable ZIP must include its registration script"

        def openssl(*arguments):
            return subprocess.check_output(["openssl", *arguments], cwd=directory, stderr=subprocess.PIPE, timeout=30)

        def registration(action, *arguments):
            completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                        "-File", str(handler), "-Action", action, *map(str, arguments)],
                                       capture_output=True, text=True, timeout=20)
            if completed.returncode:
                raise RuntimeError(completed.stdout + completed.stderr)
            return completed.stdout

        # Reuse the existing pinned downloader/checksum instead of maintaining a second pin.
        script = subprocess.check_output(["node", "--input-type=module", "--eval",
                                          "import {autoscript} from './tests/interop/autoscript.mjs'; process.stdout.write(await autoscript());"],
                                         cwd=ROOT, timeout=120)
        protocol41 = (ROOT / "tests/interop/protocol41-client.js").read_bytes()
        protocol_port = free_port()
        buttons = "".join(f'<button id="{case["name"]}">{case["name"]}</button>' for case in cases["browser"])
        html = ("""<!doctype html><html lang="en"><meta charset="utf-8"><title>Synthetic Windows browser signing</title>
BUTTONS
<a id="warm" href="afirma://cosign?ver=4&amp;format=CAdES">Warm invocation</a>
<script src="/autoscript.js"></script><script src="/protocol41.js"></script><script>
AutoScript.enableProgressDialog(false); AutoScript.setPortRange(49152,49154); AutoScript.cargarAppAfirma();
AutoScript.setKeyStore(AutoScript.KEYSTORE_PKCS12);
for (const scenario of CASES) document.getElementById(scenario.name).onclick = () => {
 delete window.result;
 if (scenario.protocol==='4.1') {
   signProtocol41({...scenario,port:PROTOCOL_PORT})
   .then(result=>window.result=result).catch(()=>window.result={error:'Protocol 4.1 exchange failed'});
 } else AutoScript.sign(scenario.content,scenario.algorithm==='ec'?'SHA256withECDSA':'SHA256withRSA',scenario.format,scenario.properties,
 (signature,certificate)=>{window.result={signature,certificate};},
 (type,message,code)=>{window.result={type,message,code};});
};</script></html>""").replace("BUTTONS", buttons).replace("CASES", json.dumps([{key: case[key] for key in ("name", "protocol", "content", "algorithm", "format", "properties")} for case in cases["browser"]])).replace("PROTOCOL_PORT", str(protocol_port)).encode()

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                body = script if self.path == "/autoscript.js" else protocol41 if self.path == "/protocol41.js" else html
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript" if self.path.endswith(".js") else "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
        cleanup.callback(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        cleanup.callback(server.shutdown)
        origin = f"http://127.0.0.1:{server.server_port}"
        port = free_port()
        environment = cleanup.enter_context(windows_gui.debugging(app, port, directory))
        def remove_installation():
            deadline = time.monotonic() + 10
            while True:
                try:
                    shutil.rmtree(installed)
                    break
                except PermissionError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.1)

        # Registered before acquiring resources so deletion runs after all closes.
        cleanup.callback(remove_installation)
        try:
            profile = Path(os.environ["LOCALAPPDATA"]) / "firmica-config" / "browser-tls"
            assert not profile.parent.exists(), "refusing to modify an existing Firmica configuration"
            def remove_profile():
                if profile.parent.exists():
                    shutil.rmtree(profile.parent)
            # This is an explicitly disposable Windows account; only the newly
            # generated profile is removed, after processes and registration close.
            cleanup.callback(remove_profile)
            def tls(*arguments, success=True):
                result = subprocess.run([str(app), "tls", *arguments], env=environment,
                                        capture_output=True, text=True, timeout=30)
                assert (result.returncode == 0) == success, result.stdout + result.stderr
                return result.stdout
            tls("status", success=False)
            initialized = tls("init", "--origin", origin)
            assert sorted(path.name for path in profile.iterdir()) == ["ca.pem", "certificate.pem", "origin", "private-key.pem"]
            fingerprint = openssl("x509", "-in", str(profile / "ca.pem"), "-fingerprint", "-sha256", "-noout").decode().strip().split("=", 1)[1]
            assert fingerprint in initialized and fingerprint in tls("status")
            tls("init", "--origin", origin, success=False)
            registration("Install")
            evidence["checks"].append("packaged TLS CLI provisions and validates a unique private profile without retaining a CA key")
            def unregister():
                registration("Uninstall")
                assert "not registered" in registration("Status")
            cleanup.callback(unregister)
            assert "Registered executable:" in registration("Status")
            playwright = cleanup.enter_context(sync_playwright())
            firefox_copy = directory / "firefox-application"
            shutil.copytree(Path(playwright.firefox.executable_path).parent, firefox_copy)
            distribution = firefox_copy / "distribution"
            distribution.mkdir(exist_ok=True)
            # Both the CA trust and external-handler approval apply only to
            # this private browser copy/profile, never the Windows trust store.
            policy = distribution / "policies.json"
            policy.write_text(json.dumps({"policies": {
                "Certificates": {"ImportEnterpriseRoots": False, "Install": [str(profile / "ca.pem")]},
                "Handlers": {"schemes": {"afirma": {"action": "useSystemDefault", "ask": False}}},
            }}))
            # Playwright's Firefox uses its explicit policy path instead of
            # discovering the normal distribution/policies.json file.
            browser_environment = {**environment, "PLAYWRIGHT_FIREFOX_POLICIES_JSON": str(policy)}
            browser = playwright.firefox.launch_persistent_context(str(directory / "firefox-profile"),
                executable_path=str(firefox_copy / "firefox.exe"), headless=False, env=browser_environment,
                firefox_user_prefs={"network.protocol-handler.external.afirma": True,
                                    "network.protocol-handler.warn-external.afirma": False,
                                    "network.protocol-handler.prompt-without-user-activation": False})
            print("Private Firefox launched with the synthetic CA policy", flush=True)
            cleanup.callback(browser.close)
            browser_page = browser.new_page()
            frames = []

            def socket_started(socket):
                socket.on("socketerror", lambda message: evidence.setdefault("socket_errors", []).append(str(message)))
                socket.on("framesent", lambda payload: frames.append(("sent", socket.url, payload)))
                socket.on("framereceived", lambda payload: frames.append(("received", socket.url, payload)))
            browser_page.on("websocket", socket_started)
            browser_page.goto(origin)
            def connect_application():
                # Only the actual browser-to-OS handler path may start Firmica.
                deadline = time.monotonic() + 45
                pid = None
                while time.monotonic() < deadline:
                    candidates = windows_gui.processes(name="firmica.exe")
                    if len(candidates) == 1:
                        pid = candidates[0]
                        break
                    browser_page.wait_for_timeout(100)
                assert pid is not None, "the browser did not cold-launch the registered handler"
                observed = windows_gui.ObservedProcess(pid)
                cleanup.callback(observed.close)
                def terminate_application(process=observed):
                    if process.poll() is None:
                        subprocess.run(["taskkill.exe", "/F", "/T", "/PID", str(process.pid)],
                                       capture_output=True, timeout=15, check=True)
                cleanup.callback(terminate_application)
                assert len(wait_for(lambda: windows_for(pid), observed)) == 1
                automation = Application(backend="win32").connect(process=pid)
                native_browser, native_page = windows_gui.connect(playwright, port, observed, evidence)
                query = f"Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object -ExpandProperty CommandLine"
                launch_command = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query], text=True, timeout=15).strip()
                assert "--tls-cert" not in launch_command and "--tls-key" not in launch_command
                return observed, pid, automation, native_browser, native_page
            for index, case in enumerate(cases["browser"]):
                scenario = case["name"]
                raw = case["protocol"] == "4.1"
                operation = case["action"]
                algorithm = case["algorithm"]
                if index == 1:
                    # Preserve warm reuse after an actual 120-second listener expiry.
                    previous = next(url for direction, url, payload in reversed(frames)
                                    if direction == "received" and payload == "OK")
                    previous_port = urlsplit(previous).port
                    query = ("Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq 'Listen' -and "
                             f"$_.OwningProcess -eq {pid} -and $_.LocalPort -eq {previous_port}"
                             " } | Select-Object -ExpandProperty LocalPort")
                    deadline = time.monotonic() + 130
                    while True:
                        assert observed.poll() is None, "the native application exited between browser sessions"
                        listening = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive",
                                                             "-Command", query], text=True, timeout=15).strip()
                        if not listening:
                            break
                        assert time.monotonic() < deadline, "the previous WSS listener did not expire"
                        browser_page.wait_for_timeout(1000)
                    evidence["checks"].append("a fresh browser bootstrap reuses the native process after actual listener expiry")
                elif index > 1:
                    assert not windows_gui.processes(name="firmica-key-worker.exe", parent=pid)
                    subprocess.run(["taskkill.exe", "/F", "/T", "/PID", str(pid)], check=True, capture_output=True, timeout=15)
                    observed.wait(timeout=10)
                    native_browser.close()
                browser_page.goto(origin)
                browser_page.locator(f'[id="{scenario}"]').click()
                if index != 1:
                    observed, pid, automation, native_browser, native_page = connect_application()
                    evidence["checks"].append(f"{scenario}: Firefox cold-launches the registered handler")
                native_page.locator("#request-operation").wait_for()
                assert native_page.locator("#request-version").inner_text() == ("4.1" if raw else "4")
                print(f"Native review received: {scenario}", flush=True)
                native_page.locator("#sign-language").click()
                assert native_page.locator("#sign-document").count() == 0
                assert native_page.locator("#sign-algorithm").count() == 0
                assert not windows_gui.processes(name="firmica-key-worker.exe", parent=pid)
                assert not browser_page.evaluate("window.result")
                assert windows_gui.processes(name="firmica.exe") == [pid]
                if operation == "cancel":
                    native_page.locator("#reject-request").click()
                    browser_page.wait_for_function("window.result", timeout=30000)
                    response = browser_page.evaluate("window.result")
                    if raw:
                        assert response["code"] == "err-11:=AF500001 - Operation cancelled by user"
                    else:
                        assert response["type"] == "es.gob.afirma.core.AOCancelledOperationException"
                    assert "signature" not in response
                    evidence["checks"].append(f"{scenario}: native rejection reaches the browser without opening a certificate worker")
                    continue
                windows_gui.dialog(automation, native_page, "#sign-certificate", fixtures / f"{algorithm}.p12")
                native_page.locator("#sign-password").fill(cases["password"])
                native_page.locator("#sign-prepare").click()
                native_page.locator("#sign-document-hash").wait_for()
                assert native_page.locator("#sign-fingerprint").inner_text() == case["fingerprint"]
                assert native_page.locator("#sign-review-format").inner_text().startswith(case["format"])
                if case["visible"]:
                    assert "Signed with Firmica" in native_page.locator("#sign-review-appearance").inner_text()
                native_page.screenshot(path=str(options.output / f"review-{scenario}.png"), full_page=True)
                assert native_page.locator("#sign-document-hash").inner_text() == case["hash"]
                assert native_page.locator("#sign-save").is_disabled()
                if operation == "sign":
                    browser_page.locator("#warm").click()
                    browser_page.wait_for_timeout(500)
                    assert windows_gui.processes(name="firmica.exe") == [pid]
                    assert len(windows_for(pid)) == 1
                    assert native_page.locator("#sign-document-hash").inner_text() == case["hash"]
                    assert native_page.locator("#sign-save").is_disabled()
                    evidence["checks"].append("warm browser URI delivery retains one window and cannot authorize or replace the reviewed document")
                if operation == "worker-failure":
                    workers = windows_gui.processes(name="firmica-key-worker.exe", parent=pid)
                    assert len(workers) == 1
                    subprocess.run(["taskkill.exe", "/F", "/PID", str(workers[0])], check=True, capture_output=True, timeout=15)
                native_page.locator("#sign-acknowledge").check()
                native_page.locator("#sign-save").click()
                browser_page.wait_for_function("window.result", timeout=30000)
                response = browser_page.evaluate("window.result")
                if operation == "worker-failure":
                    if raw:
                        assert response["code"] == "err-00:=AF200115 - Signing failed"
                    else:
                        assert response["type"] == "java.lang.Exception"
                        assert response["code"].startswith("SAF_09:")
                    assert "signature" not in response
                    assert not windows_gui.processes(name="firmica-key-worker.exe", parent=pid)
                    evidence["checks"].append(f"{scenario}: worker failure returns no signature")
                    continue
                assert "type" not in response and "error" not in response, "browser signing failed"
                assert base64.urlsafe_b64decode(response["certificate"]) == (fixtures / f"{algorithm}.der").read_bytes()
                assert not windows_gui.processes(name="firmica-key-worker.exe", parent=pid)
                destination = Path(case["output"])
                assert not destination.exists()
                destination.write_bytes(base64.urlsafe_b64decode(response["signature"]))
                assert windows_gui.processes(name="firmica.exe") == [pid]
                evidence["checks"].append(f"{scenario}: browser signature and reviewed certificate returned after worker exit")
                print(f"Browser signing completed: {scenario}", flush=True)
                if index == 0:
                    untrusted = playwright.firefox.launch(headless=True, env=environment)
                    try:
                        fresh = untrusted.new_page()
                        fresh.goto(origin)
                        url = next(url for direction, url, payload in frames if direction == "received" and payload == "OK")
                        outcome = fresh.evaluate("""url => Promise.race([
                            new Promise(resolve => { const ws = new WebSocket(url);
                                ws.onopen = () => { ws.close(); resolve('open'); };
                                ws.onerror = () => resolve('error'); }),
                            new Promise(resolve => setTimeout(() => resolve('timeout'), 5000))])""", url)
                        assert outcome == "error", outcome
                    finally:
                        untrusted.close()
                    evidence["checks"].append("a fresh Firefox profile rejects the generated CA while the trusted profile continues")
                native_page.locator("#browser-status").wait_for()
            assert any(direction == "received" and payload == "#wait" for direction, _, payload in frames)
            assert any(direction == "received" and payload == "OK" and url.startswith("wss://127.0.0.1:") for direction, url, payload in frames)
            native_page.screenshot(path=str(options.output / "native.png"), full_page=True)
            browser_page.screenshot(path=str(options.output / "browser.png"), full_page=True)
            evidence["checks"].append("unmodified AutoScript uses trusted loopback WSS without disabling TLS verification")
            evidence["protocols"] = ["4", "4.1"]
            browser.close()
            browser = None
            evidence["passed"] = True
        except Exception as error:
            evidence["error"] = repr(error)
            ImageGrab.grab(all_screens=True).save(options.output / "failure-desktop.png")
            if browser is not None:
                try:
                    response = browser_page.evaluate("window.result") or {}
                    evidence["browser_result"] = {"received": bool(response), "has_signature": "signature" in response, "has_certificate": "certificate" in response}
                    evidence["frames"] = [{"direction": direction, "port": urlsplit(url).port, "bytes": len(payload)} for direction, url, payload in frames]
                    browser_page.screenshot(path=str(options.output / "failure-browser.png"), full_page=True)
                except Exception:
                    pass
            raise
        finally:
            (options.output / "result.json").write_text(json.dumps(evidence, indent=2) + "\n")
            print(json.dumps(evidence, indent=2), flush=True)
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
