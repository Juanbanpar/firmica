#!/usr/bin/env python3
"""Exercise native Windows file dialogs, consent and controlled-worker signing."""
import argparse
import contextlib
import http.client
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
import uuid

from windows_gui import free_port, wait_for, windows_for
import windows_gui


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".test-artifacts/windows-signing"))
    parser.add_argument("--require-standard-account", action="store_true")
    parser.add_argument("--attach-pid", type=int)
    parser.add_argument("--debug-port", type=int)
    args = parser.parse_args()
    if bool(args.attach_pid) != bool(args.debug_port):
        parser.error("--attach-pid and --debug-port must be supplied together")
    if platform.system() != "Windows":
        parser.error("this test requires a native Windows desktop session")
    # Imported only on the supported host; production never enables inspection.
    from playwright.sync_api import sync_playwright
    from pywinauto import Application
    from PIL import ImageGrab

    app = args.app.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    import ctypes
    administrator = bool(ctypes.windll.shell32.IsUserAnAdmin())
    if args.require_standard_account:
        assert not administrator, "native signing must run as the standard account"
    result = {"platform": platform.platform(), "administrator": administrator, "passed": False, "checks": []}
    fixtures = args.fixtures.resolve(strict=True)
    cases = json.loads((fixtures / "cases.json").read_text())
    password = cases["password"]
    process = None
    with tempfile.TemporaryDirectory(prefix="firmica-signing-") as temporary, (args.output / "application.log").open("w") as log, contextlib.ExitStack() as cleanup:
        directory = Path(temporary)
        if args.attach_pid is None:
            copied = directory / "application"
            shutil.copytree(app.parent, copied)
            app = (copied / app.name).rename(copied / f"firmica-qa-{uuid.uuid4().hex}.exe")
        port = args.debug_port or free_port()
        environment = cleanup.enter_context(windows_gui.debugging(app, port, directory))
        try:
            process = windows_gui.ObservedProcess(args.attach_pid) if args.attach_pid else subprocess.Popen([str(app)], env=environment, stdout=log, stderr=log)
            wait_for(lambda: windows_for(process.pid), process)
            automation = Application(backend="win32").connect(process=process.pid)
            with sync_playwright() as playwright:
                browser, page = windows_gui.connect(playwright, port, process, result)
                page.locator('a[href="/sign"]').click()
                page.locator("#sign-language").click()

                def status():
                    return page.locator("#sign-status").inner_text()

                def workers():
                    return windows_gui.processes(name="firmica-key-worker.exe", parent=process.pid)

                def dialog(selector, filename):
                    windows_gui.dialog(automation, page, selector, filename)

                def prepare(case=cases["local"][0], secret=password):
                    dialog("#sign-document", Path(case["document"]))
                    dialog("#sign-certificate", Path(case["certificate"]))
                    page.locator("#sign-password").fill(secret)
                    page.locator("#sign-algorithm").select_option(case["algorithm"])
                    page.locator("#sign-format").select_option(case["mode"])
                    if case["mode"] == "cades":
                        page.locator("#sign-attached").set_checked(case["attached"])
                    if case["mode"] == "pades":
                        page.locator("#sign-visible").set_checked(case["visible"])
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
                for case in cases["local"]:
                    prepare(case)
                    page.locator("#sign-document-hash").wait_for()
                    assert page.locator("#sign-document-hash").inner_text() == case["hash"]
                    assert page.locator("#sign-fingerprint").inner_text() == case["fingerprint"]
                    assert page.locator("#sign-review-format").inner_text().startswith(case["format"])
                    if case["visible"]:
                        assert "Signed with Firmica" in page.locator("#sign-review-appearance").inner_text()
                    assert page.locator("#sign-save").is_disabled()
                    assert page.locator("#sign-password").count() == 0
                    Path(case["document"]).write_bytes(b"changed after review")
                    page.screenshot(path=str(args.output / f"review-{case['name']}.png"), full_page=True)
                    page.locator("#sign-acknowledge").check()
                    dialog("#sign-save", None)
                    assert page.locator("#sign-document-hash").count() == 1
                    assert len(workers()) == 1
                    destination = Path(case["output"])
                    assert not destination.exists()
                    dialog("#sign-save", destination)
                    wait_for(lambda: status() == "Signature saved.", process)
                    assert not workers(), "worker must exit before publication"
                    assert destination.is_file()
                    result["checks"].append(f"{case['name']}: frozen review, consent, save cancellation and worker exit before publication")
                    print(f"Native signing completed: {case['name']}", flush=True)
                page.screenshot(path=str(args.output / "signed.png"), full_page=True)
                result["passed"] = True
        except Exception as error:
            result["error"] = repr(error)
            ImageGrab.grab(all_screens=True).save(args.output / "failure-desktop.png")
            endpoint = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            try:
                endpoint.request("GET", "/json/version")
                response = endpoint.getresponse()
                details = json.loads(response.read())
                result["startup_webview"] = {"status": response.status, "browser": details.get("Browser")}
            except (OSError, ValueError, http.client.HTTPException) as endpoint_error:
                result["startup_webview"] = {"error": type(endpoint_error).__name__}
            finally:
                endpoint.close()
            pid = process.pid if process is not None else 0
            query = f"Get-CimInstance Win32_Process | Where-Object {{ $_.Name -eq 'msedgewebview2.exe' -or $_.ParentProcessId -eq {pid} -or $_.ProcessId -eq {pid} }} | Select-Object ProcessId,ParentProcessId,Name,SessionId | ConvertTo-Json"
            snapshot = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query],
                                      capture_output=True, text=True, timeout=15)
            result["process_query_exit"] = snapshot.returncode
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
            if args.attach_pid and process is not None:
                process.close()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
