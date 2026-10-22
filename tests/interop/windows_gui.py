"""Shared controls for native Windows Dioxus tests with synthetic credentials."""
import contextlib
import ctypes
from ctypes import wintypes
import http.client
import json
import os
import subprocess
import socket
import time

def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(check, process, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"application exited with status {process.returncode}")
        result = check()
        if result:
            return result
        time.sleep(0.1)
    raise TimeoutError("native UI check timed out")


def windows_for(pid):
    from pywinauto.findwindows import find_windows
    return find_windows(process=pid, title="Firmica", visible_only=True, top_level_only=True)


@contextlib.contextmanager
def debugging(application, port, directory):
    environment = {**os.environ, "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={port}",
                   "WEBVIEW2_USER_DATA_FOLDER": str(directory / "webview")}
    with contextlib.ExitStack() as cleanup:
        if ctypes.windll.shell32.IsUserAnAdmin():
            import winreg
            policy = r"SOFTWARE\Policies\Microsoft\Edge\WebView2\AdditionalBrowserArguments"
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, policy, 0,
                                     winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
            cleanup.callback(key.Close)
            try:
                winreg.QueryValueEx(key, application.name)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("refusing to replace an existing WebView2 debugging policy")
            winreg.SetValueEx(key, application.name, 0, winreg.REG_SZ, f"--remote-debugging-port={port}")
            cleanup.callback(winreg.DeleteValue, key, application.name)
        root = os.environ.get("OPENSSL_DIR")
        if root:
            from pathlib import Path
            environment["PATH"] = os.pathsep.join(entry for entry in environment["PATH"].split(os.pathsep)
                                                 if not Path(entry).is_relative_to(Path(root)))
        yield environment


def connect(playwright, port, process, evidence):
    def ready():
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            connection.request("GET", "/json/version")
            response = connection.getresponse()
            if response.status != 200:
                raise OSError(f"WebView2 endpoint returned {response.status}")
            return json.loads(response.read())
        except OSError as error:
            evidence["endpoint_error"] = str(error)
            return None
        finally:
            connection.close()
    endpoint = wait_for(ready, process)
    evidence.pop("endpoint_error", None)
    evidence["webview2"] = endpoint
    browser = playwright.chromium.connect_over_cdp(endpoint["webSocketDebuggerUrl"], timeout=30000)
    page = wait_for(lambda: next((page for context in browser.contexts for page in context.pages
                                 if page.url.startswith(("http://dioxus", "https://dioxus", "dioxus://"))), None), process)
    return browser, page


def dialog(automation, page, selector, filename):
    # A WebView click does not bring the native application to the foreground.
    automation.top_window().set_focus()
    page.locator(selector).click()
    native = automation.window(class_name="#32770")
    native.wait("ready", timeout=15)
    native.set_focus()
    if filename is None:
        native.child_window(control_id=2, class_name="Button").click_input()
    else:
        edit = native.child_window(class_name="Edit")
        edit.wait("ready", timeout=15)
        edit.set_edit_text(str(filename))
        assert edit.window_text() == str(filename)
        confirm = native.child_window(control_id=1, class_name="Button")
        confirm.wait("ready", timeout=15)
        confirm.click_input()
    native.wait_not("visible", timeout=15)


def processes(name=None, parent=None):
    # Callers supply only fixed fixture names or the test's numeric PID.
    filters = []
    if name is not None:
        assert name.replace("-", "").replace(".", "").isalnum()
        filters.append(f"Name = '{name}'")
    if parent is not None:
        filters.append(f"ParentProcessId = {int(parent)}")
    query = 'Get-CimInstance Win32_Process -Filter "' + " AND ".join(filters) + '" | Select-Object -ExpandProperty ProcessId'
    output = subprocess.check_output(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query], text=True, timeout=15)
    return [int(pid) for pid in output.split()]


class ObservedProcess:
    """Hold the original process handle when the OS, rather than Popen, launches it."""
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.kernel.GetExitCodeProcess.restype = wintypes.BOOL
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def poll(self):
        result = self.kernel.WaitForSingleObject(self.handle, 0)
        if result == 258:
            return None
        if result != 0:
            raise ctypes.WinError(ctypes.get_last_error())
        code = wintypes.DWORD()
        if not self.kernel.GetExitCodeProcess(self.handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.returncode = code.value
        return self.returncode

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None
