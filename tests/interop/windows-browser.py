#!/usr/bin/env python3
"""Firefox AutoScript -> registered Windows handler -> native CAdES consent."""
import argparse
import base64
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import threading
import time

from windows import free_port, wait_for, windows_for
import windows_gui

ROOT = Path(__file__).resolve().parents[2]
CONTENT = b"Windows browser signing\x00\xff\r\n"
PASSWORD = "synthetic-browser-password"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
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

        openssl("req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1", "-subj", "/CN=Firmica synthetic local CA",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", "ca.key", "-out", "ca.pem")
        openssl("req", "-newkey", "rsa:2048", "-noenc", "-subj", "/CN=127.0.0.1", "-keyout", "tls.key", "-out", "tls.csr")
        (directory / "tls.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
        openssl("x509", "-req", "-in", "tls.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                "-days", "1", "-out", "tls.pem", "-extfile", "tls.ext")
        (directory / "ca.key").unlink()
        for algorithm in ("rsa", "ec"):
            specification = ["rsa:2048"] if algorithm == "rsa" else ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]
            openssl("req", "-x509", "-newkey", *specification, "-noenc", "-days", "1",
                    "-subj", "/CN=Firmica synthetic browser signer", "-addext", "basicConstraints=critical,CA:FALSE",
                    "-addext", "keyUsage=critical,digitalSignature", "-keyout", f"{algorithm}.key", "-out", f"{algorithm}.pem")
            openssl("pkcs12", "-export", "-inkey", f"{algorithm}.key", "-in", f"{algorithm}.pem",
                    "-out", f"{algorithm}.p12", "-passout", f"pass:{PASSWORD}")
        (directory / "original.bin").write_bytes(CONTENT)
        # Reuse the existing pinned downloader/checksum instead of maintaining a second pin.
        script = subprocess.check_output(["node", "--input-type=module", "--eval",
                                          "import {autoscript} from './tests/interop/autoscript.mjs'; process.stdout.write(await autoscript());"],
                                         cwd=ROOT, timeout=120)
        html = ("""<!doctype html><html lang="en"><meta charset="utf-8"><title>Synthetic Windows browser signing</title>
<button id="rsa">RSA</button><button id="ec">P-256</button><button id="cancel">Cancel request</button>
<a id="warm" href="afirma://cosign?ver=4&amp;format=CAdES">Warm invocation</a>
<script src="/autoscript.js"></script><script>
AutoScript.enableProgressDialog(false); AutoScript.setPortRange(49152,49154); AutoScript.cargarAppAfirma();
AutoScript.setKeyStore(AutoScript.KEYSTORE_PKCS12);
for (const id of ['rsa','ec','cancel']) document.getElementById(id).onclick = () => {
 delete window.result;
 AutoScript.sign('CONTENT', id === 'ec' ? 'SHA256withECDSA' : 'SHA256withRSA', 'CAdES',
 id === 'ec' ? 'mode=implicit' : 'mode=explicit',
 (signature,certificate) => {window.result={signature,certificate};},
 (type,message,code) => {window.result={type,message,code};});
};</script></html>""").replace("CONTENT", base64.b64encode(CONTENT).decode()).encode()

        class Site(BaseHTTPRequestHandler):
            def do_GET(self):
                body = script if self.path == "/autoscript.js" else html
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript" if self.path == "/autoscript.js" else "text/html; charset=utf-8")
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
            registration("Install", "-TlsCertificate", directory / "tls.pem", "-TlsKey", directory / "tls.key", "-Origin", origin)
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
                "Certificates": {"ImportEnterpriseRoots": False, "Install": [str(directory / "ca.pem")]},
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
            browser_page.locator("#rsa").click()
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
            def terminate_application():
                if observed.poll() is None:
                    subprocess.run(["taskkill.exe", "/F", "/T", "/PID", str(observed.pid)],
                                   capture_output=True, timeout=15, check=True)
            cleanup.callback(terminate_application)
            assert len(wait_for(lambda: windows_for(pid), observed)) == 1
            automation = Application(backend="win32").connect(process=pid)
            native_browser, native_page = windows_gui.connect(playwright, port, observed, evidence)
            query = f"Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object -ExpandProperty CommandLine"
            evidence["launch_command"] = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query], text=True, timeout=15).strip()
            evidence["checks"].append("Firefox cold-launches the installed URI command with TLS configuration")
            print("Registered handler cold-launched the native application", flush=True)
            for scenario in ("rsa", "cancel", "ec"):
                if scenario != "rsa":
                    browser_page.goto(origin)
                    browser_page.locator(f"#{scenario}").click()
                native_page.locator("#request-operation").wait_for()
                print(f"Native review received: {scenario}", flush=True)
                native_page.locator("#sign-language").click()
                assert native_page.locator("#sign-document").count() == 0
                assert native_page.locator("#sign-algorithm").count() == 0
                assert not windows_gui.processes(name="firmica-key-worker.exe", parent=pid)
                assert not browser_page.evaluate("window.result")
                if scenario == "cancel":
                    native_page.locator("#reject-request").click()
                    browser_page.wait_for_function("window.result", timeout=30000)
                    response = browser_page.evaluate("window.result")
                    assert response["type"] == "es.gob.afirma.core.AOCancelledOperationException", response
                    assert "signature" not in response
                    evidence["checks"].append("native rejection reaches the browser without opening a certificate worker")
                    continue
                windows_gui.dialog(automation, native_page, "#sign-certificate", directory / f"{scenario}.p12")
                native_page.locator("#sign-password").fill(PASSWORD)
                native_page.locator("#sign-prepare").click()
                native_page.locator("#sign-document-hash").wait_for()
                assert native_page.locator("#sign-document-hash").inner_text() == hashlib.sha256(CONTENT).hexdigest()
                assert native_page.locator("#sign-save").is_disabled()
                if scenario == "rsa":
                    browser_page.locator("#warm").click()
                    browser_page.wait_for_timeout(500)
                    assert windows_gui.processes(name="firmica.exe") == [pid]
                    assert len(windows_for(pid)) == 1
                    assert native_page.locator("#sign-document-hash").inner_text() == hashlib.sha256(CONTENT).hexdigest()
                    assert native_page.locator("#sign-save").is_disabled()
                    evidence["checks"].append("warm browser URI delivery retains one window and cannot authorize or replace the reviewed document")
                native_page.locator("#sign-acknowledge").check()
                native_page.locator("#sign-save").click()
                browser_page.wait_for_function("window.result", timeout=30000)
                response = browser_page.evaluate("window.result")
                assert "type" not in response, response
                assert base64.b64decode(response["certificate"]) == openssl("x509", "-in", f"{scenario}.pem", "-outform", "DER")
                (directory / "result.csig").write_bytes(base64.b64decode(response["signature"]))
                arguments = ["cms", "-verify", "-cades", "-binary", "-inform", "DER", "-in", "result.csig",
                             "-CAfile", f"{scenario}.pem", "-no-CApath", "-no-CAstore", "-partial_chain", "-purpose", "any", "-out", "verified.bin"]
                if scenario == "rsa":
                    arguments += ["-content", "original.bin"]
                openssl(*arguments)
                assert (directory / "verified.bin").read_bytes() == CONTENT
                assert not windows_gui.processes(name="firmica-key-worker.exe", parent=pid)
                assert windows_gui.processes(name="firmica.exe") == [pid]
                evidence["checks"].append(f"{scenario} browser signature and selected certificate verify after worker exit")
                print(f"OpenSSL verified the {scenario} browser signature", flush=True)
                native_page.locator("#browser-status").wait_for()
            assert any(direction == "received" and payload == "#wait" for direction, _, payload in frames)
            assert any(direction == "received" and payload == "OK" and url.startswith("wss://127.0.0.1:") for direction, url, payload in frames)
            native_page.screenshot(path=str(options.output / "native.png"), full_page=True)
            browser_page.screenshot(path=str(options.output / "browser.png"), full_page=True)
            evidence["checks"].append("unmodified AutoScript uses trusted loopback WSS without disabling TLS verification")
            browser.close()
            browser = None
            evidence["passed"] = True
        except Exception as error:
            evidence["error"] = repr(error)
            ImageGrab.grab(all_screens=True).save(options.output / "failure-desktop.png")
            if browser is not None:
                try:
                    evidence["browser_result"] = browser_page.evaluate("window.result")
                    evidence["frames"] = [(direction, url, payload if isinstance(payload, str) else repr(payload)) for direction, url, payload in frames]
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
