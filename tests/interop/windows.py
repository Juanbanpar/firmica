#!/usr/bin/env python3
"""Exercise cold/warm command-line invocation of the native Windows Dioxus app."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import tempfile
import time


def wait_for(check, process, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"application exited with status {process.returncode}")
        result = check()
        if result:
            return result
        time.sleep(0.1)
    raise TimeoutError("native invocation check timed out")


def windows_for(pid):
    """Find visible top-level Firmica windows belonging to this exact process."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    found = []

    @callback_type
    def visit(window, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(window):
            title = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(window, title, len(title))
            if title.value == "Firmica":
                found.append(window)
        return True

    if not user32.EnumWindows(visit, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    return found


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(".test-artifacts/windows"))
    args = parser.parse_args()
    if platform.system() != "Windows":
        parser.error("this test requires a native Windows desktop session")
    app = args.app.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    result = {"platform": platform.platform(), "executable_sha256": hashlib.sha256(app.read_bytes()).hexdigest(), "passed": False, "checks": []}
    process = None
    with tempfile.TemporaryDirectory(prefix="firmica-windows-") as temporary, (args.output / "application.log").open("w") as log:
        directory = Path(temporary)
        certificate, key = directory / "cert.pem", directory / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
            "-subj", "/CN=Firmica invocation test", "-addext", "subjectAltName=IP:127.0.0.1",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
            "-keyout", str(key), "-out", str(certificate),
        ], check=True, capture_output=True, timeout=30)
        configuration = [str(app), "--tls-cert", str(certificate), "--tls-key", str(key), "--origin", "http://127.0.0.1:8123"]
        context = ssl.create_default_context(cafile=str(certificate))

        def invoke(*arguments, success=True):
            completed = subprocess.run([str(app), *arguments], stdout=log, stderr=log, timeout=10)
            if (completed.returncode == 0) != success:
                raise RuntimeError(f"secondary invocation exited with status {completed.returncode}")

        try:
            process = subprocess.Popen([*configuration, "afirma://save?ver=4"], stdout=log, stderr=log)
            assert len(wait_for(lambda: windows_for(process.pid), process)) == 1
            result["checks"].append("cold CLI invocation creates one native Dioxus window")
            invoke()
            result["checks"].append("warm launch without a URI exits successfully")
            port = free_port()
            invoke(f"afirma://websocket?v=4&jvc=4&ports={port}&idsession=0123456789abcdef")

            def tls_ready():
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
                        with context.wrap_socket(connection, server_hostname="127.0.0.1"):
                            return True
                except (ConnectionError, TimeoutError):
                    return False

            wait_for(tls_ready, process, seconds=10)
            assert len(windows_for(process.pid)) == 1
            result["checks"].append("warm bootstrap reaches the running app and opens its configured TLS listener")
            invoke("https://example.invalid/", success=False)
            assert process.poll() is None and len(windows_for(process.pid)) == 1
            result["checks"].append("invalid invocation fails without replacing the running window")
            process.kill()
            process.wait(timeout=10)
            process = subprocess.Popen(configuration, stdout=log, stderr=log)
            assert len(wait_for(lambda: windows_for(process.pid), process)) == 1
            invoke()
            result["checks"].append("application recovers its private pipe after a forced termination")
            result["passed"] = True
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
