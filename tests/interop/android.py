#!/usr/bin/env python3
"""Exercise the review-only Android app through real OS intents and accessibility nodes."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

PACKAGE = "org.firmica.client"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"))
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".test-artifacts/android"))
    parser.add_argument("--browser", help="installed browser package with onboarding already completed")
    args = parser.parse_args()
    if not args.apk.is_file():
        parser.error("--apk must name a built debug APK")

    def adb(*parts, binary=False):
        command = [args.adb]
        if args.serial:
            command += ["-s", args.serial]
        return subprocess.run(command + list(parts), check=True, capture_output=True,
                              text=not binary, timeout=40).stdout

    devices = [line.split()[0] for line in adb("devices").splitlines()[1:]
               if len(line.split()) >= 2 and line.split()[1] == "device"]
    if args.serial is None:
        if len(devices) != 1:
            parser.error("select exactly one connected emulator with --serial")
        args.serial = devices[0]
    if args.serial not in devices:
        parser.error("selected Android device is unavailable or unauthorized")

    def shell(*parts):
        # adb shell joins its arguments into a shell command; quote URI ampersands explicitly.
        return adb("shell", shlex.join(parts)).strip()

    if shell("getprop", "ro.kernel.qemu") != "1":
        parser.error("this automated smoke test requires an emulator, not a personal device")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "result.json").unlink(missing_ok=True)
    adb("install", "-r", "-t", str(args.apk.resolve()))
    shell("am", "force-stop", PACKAGE)

    def launch(operation, version="4"):
        uri = f"afirma://{operation}?ver={version}&format=CAdES&dat=c3ludGhldGlj"
        result = shell("am", "start", "-W", "-a", "android.intent.action.VIEW", "-c",
                       "android.intent.category.BROWSABLE", "-d", uri, "-p", PACKAGE)
        if "Error:" in result or "Exception" in result:
            raise AssertionError("Android failed to launch the invocation activity")

    def tree():
        text = adb("exec-out", "uiautomator", "dump", "/dev/tty")
        start, end = text.find("<?xml"), text.rfind("</hierarchy>")
        if start < 0 or end < 0:
            raise RuntimeError("uiautomator returned no accessibility hierarchy")
        return ET.fromstring(text[start:end + len("</hierarchy>")])

    def texts(root):
        return [node.get("text") for node in root.iter("node") if node.get("text")]

    def wait_text(value, *, browser_prompt=False):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            root = tree()
            if value in texts(root):
                return root
            if browser_prompt and "Open in App" in texts(root):
                # Firefox asks for explicit external-app confirmation on each link.
                tap_text("Open in App")
        raise AssertionError(f"expected accessibility text did not appear: {value}")

    def bounds(node):
        values = [int(value) for value in re.findall(r"\d+", node.get("bounds", ""))]
        if len(values) != 4:
            raise AssertionError("node has no usable bounds")
        return values

    def tap_text(value, *, towards_top=False):
        for attempt in range(3):
            root = tree()
            matches = [node for node in root.iter("node") if node.get("text") == value]
            if matches:
                left, top, right, bottom = bounds(matches[0])
                shell("input", "tap", str((left + right) // 2), str((top + bottom) // 2))
                return
            scrollable = [node for node in root.iter("node") if node.get("scrollable") == "true"]
            if not scrollable or attempt == 2:
                break
            left, top, right, bottom = bounds(scrollable[0])
            x = str((left + right) // 2)
            high = str(top + (bottom - top) // 4)
            low = str(top + 3 * (bottom - top) // 4)
            start, end = (high, low) if towards_top else (low, high)
            shell("input", "swipe", x, start, x, end, "400")
        raise AssertionError(f"accessible control not found after scrolling: {value}")

    checks = []

    def passed(description):
        checks.append(description)
        print(f"PASS: {description}", flush=True)

    try:
        launch("sign")
        wait_text("sign")
        pid = shell("pidof", "-s", PACKAGE)
        assert pid, "cold launch did not start the app process"
        (args.output / "cold-review.png").write_bytes(adb("exec-out", "screencap", "-p", binary=True))
        passed("cold ACTION_VIEW reaches Rust and visible Dioxus review")

        launch("save")
        assert shell("pidof", "-s", PACKAGE) == pid, "warm delivery restarted the app"
        assert "sign" in texts(tree()), "pending request was replaced"
        passed("warm intent reuses process and cannot replace pending review")

        tap_text("Rechazar")
        wait_text("Solicitud rechazada.")
        launch("cosign", "3")
        wait_text("cosign")
        passed("new warm invocation appears after explicit rejection")

        shell("input", "keyevent", "KEYCODE_HOME")
        launch("save")
        assert shell("pidof", "-s", PACKAGE) == pid, "background return restarted the app"
        assert "cosign" in texts(tree()), "background return lost pending review"
        passed("background return preserves pending review")

        malformed = "afirma://sign?dat=%00"
        shell("am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", malformed, "-p", PACKAGE)
        assert shell("pidof", "-s", PACKAGE) == pid
        assert "cosign" in texts(tree()), "malformed invocation changed review state"
        passed("malformed URI is rejected without process or state loss")

        tap_text("English", towards_top=True)
        tap_text("Acknowledge review")
        wait_text("Review acknowledged. This operation is not implemented yet.")
        passed("English controls acknowledge review without signing")

        shell("am", "force-stop", PACKAGE)
        launch("selectcert")
        wait_text("selectcert")
        passed("fresh process accepts a new invocation without replaying old consent")

        browser = None
        if args.browser:
            class Page(BaseHTTPRequestHandler):
                def do_GET(self):
                    operation = "cosign" if self.path == "/warm" else "sign"
                    page = (f'<!doctype html><html lang="en"><meta charset="utf-8">'
                            f'<meta name="viewport" content="width=device-width">'
                            f'<title>Firmica invocation test</title>'
                            f'<a href="afirma://{operation}?ver=4&amp;format=CAdES">'
                            f'Open Firmica {operation}</a></html>').encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(page)))
                    self.end_headers()
                    self.wfile.write(page)

                def log_message(self, *_args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), Page)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            reverse = f"tcp:{server.server_port}"
            try:
                adb("reverse", reverse, reverse)
                shell("am", "force-stop", PACKAGE)
                for route, operation in (("/cold", "sign"), ("/warm", "cosign")):
                    shell("am", "start", "-W", "-a", "android.intent.action.VIEW", "-d",
                          f"http://127.0.0.1:{server.server_port}{route}", "-p", args.browser)
                    wait_text(f"Open Firmica {operation}")
                    tap_text(f"Open Firmica {operation}")
                    wait_text(operation, browser_prompt=True)
                    if operation == "sign":
                        browser_pid = shell("pidof", "-s", PACKAGE)
                        activity = shell("dumpsys", "activity", "activities")
                        assert f"launchedFromPackage={args.browser}" in activity
                        tap_text("Rechazar")
                        wait_text("Solicitud rechazada.")
                    else:
                        assert shell("pidof", "-s", PACKAGE) == browser_pid
                passed("browser link resolves untargeted cold/warm intents into visible review")
                (args.output / "browser-review.png").write_bytes(
                    adb("exec-out", "screencap", "-p", binary=True))
                info = shell("dumpsys", "package", args.browser)
                browser_version = re.search(r"versionName=(\S+)", info)
                browser = {"package": args.browser,
                           "version": browser_version.group(1) if browser_version else None}
            finally:
                server.shutdown()
                server.server_close()
                adb("reverse", "--remove", reverse)

        package_info = shell("dumpsys", "package", PACKAGE)
        version = re.search(r"versionName=(\S+)", package_info)
        report = {
            "package": PACKAGE,
            "appVersion": version.group(1) if version else None,
            "androidRelease": shell("getprop", "ro.build.version.release"),
            "androidSdk": shell("getprop", "ro.build.version.sdk"),
            "abi": shell("getprop", "ro.product.cpu.abi"),
            "browser": browser,
            "webview": shell("dumpsys", "webviewupdate").splitlines()[1].strip(),
            "apkSha256": hashlib.sha256(args.apk.read_bytes()).hexdigest(),
            "checks": checks,
            "scope": "URI invocation only; AutoScript mobile services, browser return, signing and physical devices not tested",
        }
        (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        shell("am", "force-stop", PACKAGE)


if __name__ == "__main__":
    main()
