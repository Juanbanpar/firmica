#!/usr/bin/env python3
"""Exercise native Windows file dialogs, consent and controlled-worker signing."""
import argparse
import contextlib
import ctypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
import uuid

from windows import free_port, wait_for, windows_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".test-artifacts/windows-signing"))
    args = parser.parse_args()
    if platform.system() != "Windows":
        parser.error("this test requires a native Windows desktop session")
    # Imported only on the supported host; production never enables inspection.
    from playwright.sync_api import sync_playwright
    from pywinauto import Application
    from PIL import ImageGrab

    app = args.app.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    result = {"platform": platform.platform(), "passed": False, "checks": []}
    password = "synthetic-desktop-password"
    content = b"Windows frozen signing\x00\xff\r\n"
    process = None
    with tempfile.TemporaryDirectory(prefix="firmica-signing-") as temporary, (args.output / "application.log").open("w") as log, contextlib.ExitStack() as cleanup:
        directory = Path(temporary)
        copied = directory / "application"
        shutil.copytree(app.parent, copied)
        app = (copied / app.name).rename(copied / f"firmica-qa-{uuid.uuid4().hex}.exe")
        document = directory / "document.bin"
        document.write_bytes(content)
        for algorithm in ("rsa", "ec"):
            key = ["rsa:2048"] if algorithm == "rsa" else ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", *key, "-noenc", "-days", "1",
                "-subj", "/CN=Firmica synthetic Windows signer",
                "-addext", "keyUsage=critical,digitalSignature", "-addext", "basicConstraints=critical,CA:FALSE",
                "-keyout", str(directory / f"{algorithm}.key"), "-out", str(directory / f"{algorithm}.pem"),
            ], check=True, capture_output=True, timeout=30)
            subprocess.run([
                "openssl", "pkcs12", "-export", "-inkey", str(directory / f"{algorithm}.key"),
                "-in", str(directory / f"{algorithm}.pem"), "-out", str(directory / f"{algorithm}.p12"),
                "-passout", f"pass:{password}",
            ], check=True, capture_output=True, timeout=30)
        port = free_port()
        environment = {**os.environ, "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={port}",
                       "WEBVIEW2_USER_DATA_FOLDER": str(directory / "webview")}
        if ctypes.windll.shell32.IsUserAnAdmin():
            # WebView2 ignores environment debugging flags in elevated hosts.
            # The machine policy is scoped to this uniquely named synthetic copy.
            import winreg
            policy = r"SOFTWARE\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments"
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, policy, 0,
                                     winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
            cleanup.callback(key.Close)
            winreg.SetValueEx(key, app.name, 0, winreg.REG_SZ, f"--remote-debugging-port={port}")
            cleanup.callback(winreg.DeleteValue, key, app.name)
        openssl_root = os.environ.get("OPENSSL_DIR")
        if openssl_root:
            environment["PATH"] = os.pathsep.join(entry for entry in environment["PATH"].split(os.pathsep)
                                                 if not Path(entry).is_relative_to(Path(openssl_root)))
        try:
            process = subprocess.Popen([str(app)], env=environment, stdout=log, stderr=log)
            wait_for(lambda: windows_for(process.pid), process)
            automation = Application(backend="win32").connect(process=process.pid)
            with sync_playwright() as playwright:
                def endpoint_ready():
                    try:
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                        try:
                            connection.request("GET", "/json/version")
                            response = connection.getresponse()
                            if response.status != 200:
                                raise OSError(f"WebView2 endpoint returned {response.status}")
                            return json.loads(response.read())
                        finally:
                            connection.close()
                    except OSError as error:
                        result["endpoint_error"] = str(error)
                        return None
                endpoint = wait_for(endpoint_ready, process)
                result.pop("endpoint_error", None)
                result["webview2"] = endpoint
                # CDP attachment initializes targets as well as the socket. Give
                # it its own deadline instead of repeatedly aborting at one second.
                browser = playwright.chromium.connect_over_cdp(endpoint["webSocketDebuggerUrl"], timeout=30000)
                page = wait_for(lambda: next((page for context in browser.contexts for page in context.pages
                                             if page.url.startswith(("http://dioxus", "https://dioxus", "dioxus://"))), None), process)
                page.locator('a[href="/sign"]').click()
                page.locator("#sign-language").click()

                def status():
                    return page.locator("#sign-status").inner_text()

                def workers():
                    query = f"Get-CimInstance Win32_Process -Filter \"ParentProcessId = {process.pid} AND Name = 'firmica-key-worker.exe'\" | Select-Object -ExpandProperty ProcessId"
                    output = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query], text=True, timeout=15)
                    return output.split()

                def dialog(selector, filename):
                    page.locator(selector).click()
                    native = automation.window(class_name="#32770")
                    native.wait("visible", timeout=15)
                    if filename is None:
                        native.child_window(control_id=2, class_name="Button").click()
                    else:
                        native.child_window(class_name="Edit").set_edit_text(str(filename))
                        native.child_window(control_id=1, class_name="Button").click()
                    native.wait_not("visible", timeout=15)

                def prepare(algorithm="rsa", secret=password, attached=False):
                    dialog("#sign-document", document)
                    dialog("#sign-certificate", directory / f"{algorithm}.p12")
                    page.locator("#sign-password").fill(secret)
                    page.locator("#sign-algorithm").select_option(algorithm)
                    page.locator("#sign-attached").set_checked(attached)
                    page.locator("#sign-prepare").click()

                prepare(secret="wrong synthetic password")
                wait_for(lambda: "Cannot open" in status(), process)
                assert page.locator("#sign-password").input_value() == ""
                assert not workers()
                result["checks"].append("native rfd open dialogs and invalid password leave no worker")
                prepare()
                page.locator("#sign-document-hash").wait_for()
                assert page.locator("#sign-save").is_disabled()
                assert len(workers()) == 1
                page.locator("#sign-cancel").click()
                wait_for(lambda: status() == "Operation cancelled.", process)
                assert not workers()
                result["checks"].append("consent is required and cancellation closes the worker")
                for algorithm, attached in (("rsa", False), ("ec", True)):
                    document.write_bytes(content)
                    prepare(algorithm, attached=attached)
                    page.locator("#sign-document-hash").wait_for()
                    assert page.locator("#sign-document-hash").inner_text() == hashlib.sha256(content).hexdigest()
                    assert page.locator("#sign-password").count() == 0
                    document.write_bytes(b"changed after review")
                    page.locator("#sign-acknowledge").check()
                    dialog("#sign-save", None)
                    assert page.locator("#sign-document-hash").count() == 1
                    assert len(workers()) == 1
                    destination = directory / f"{algorithm}.csig"
                    dialog("#sign-save", destination)
                    wait_for(lambda: status() == "Signature saved.", process)
                    assert not workers(), "worker must exit before publication"
                    original = directory / "original.bin"
                    original.write_bytes(content)
                    command = ["openssl", "cms", "-verify", "-cades", "-binary", "-inform", "DER",
                               "-in", str(destination), "-CAfile", str(directory / f"{algorithm}.pem"),
                               "-no-CApath", "-no-CAstore", "-partial_chain", "-purpose", "any",
                               "-out", str(directory / "verified.bin")]
                    if not attached:
                        command += ["-content", str(original)]
                    subprocess.run(command, check=True, capture_output=True, timeout=30)
                    assert (directory / "verified.bin").read_bytes() == content
                    result["checks"].append(f"{algorithm} {'attached' if attached else 'detached'} CAdES verifies with OpenSSL after native save and worker exit")
                page.screenshot(path=str(args.output / "signed.png"), full_page=True)
                result["passed"] = True
        except Exception as error:
            result["error"] = repr(error)
            ImageGrab.grab(all_screens=True).save(args.output / "failure-desktop.png")
            query = "Get-CimInstance Win32_Process | Where-Object Name -eq 'msedgewebview2.exe' | Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json"
            snapshot = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query],
                                      capture_output=True, text=True, timeout=15)
            (args.output / "webview-processes.json").write_text(snapshot.stdout)
            raise
        finally:
            if process is not None and process.poll() is None:
                # WebView2 owns child processes that keep the disposable profile
                # open; terminate this synthetic process tree before removing it.
                subprocess.run(["taskkill.exe", "/F", "/T", "/PID", str(process.pid)],
                               capture_output=True, timeout=15, check=True)
                process.wait(timeout=10)
                # WebView2 can outlive its owner briefly while releasing profile
                # handles. Retry removal within a deadline; do not hide failure.
                deadline = time.monotonic() + 10
                while True:
                    try:
                        shutil.rmtree(directory / "webview")
                        break
                    except FileNotFoundError:
                        break
                    except PermissionError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
            (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
