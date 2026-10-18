#!/usr/bin/env python3
"""Test registration ownership and argv on a disposable Windows user account."""
import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Windows":
        parser.error("requires Windows and an unused Firmica/afirma registration")
    import winreg
    keys = [r"Software\Classes\afirma", r"Software\Classes\Firmica.afirma", r"Software\Firmica\Capabilities"]

    def exists(path):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path):
                return True
        except FileNotFoundError:
            return False

    def read(path, name=""):
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            return winreg.QueryValueEx(key, name)[0]

    def remove(path):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as key:
                while winreg.QueryInfoKey(key)[0]:
                    remove(path + "\\" + winreg.EnumKey(key, 0))
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except FileNotFoundError:
            pass

    def write(path, value):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, value)

    if any(exists(path) for path in keys):
        raise RuntimeError("refusing to alter an existing user registration; use a disposable account")
    try:
        read(r"Software\RegisteredApplications", "Firmica")
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError("Firmica already appears in RegisteredApplications")
    # Machine registrations remain intact. They also prevent claiming the scheme.
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "afirma"):
            raise RuntimeError("afirma already has a machine handler; use a clean test host")
    except FileNotFoundError:
        pass

    with tempfile.TemporaryDirectory(prefix="firmica-handler-") as temporary:
        directory = Path(temporary) / "App space & 'apostrophe'"
        directory.mkdir()
        script = directory / "handler.ps1"
        shutil.copy2(args.script, script)
        application = directory / "firmica.exe"
        application.write_bytes(b"registration fixture; not executed")
        certificate, private_key = directory / "TLS certificate.pem", directory / "TLS key.pem"
        certificate.write_text("synthetic certificate path fixture")
        private_key.write_text("synthetic key path fixture")
        flags = ["-TlsCertificate", str(certificate), "-TlsKey", str(private_key), "-Origin", "https://example.invalid"]

        def invoke(action, *extra, success=True, target=script):
            command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                       "-File", str(target), "-Action", action, *extra]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            return result.stdout

        try:
            assert "not registered" in invoke("Status")
            invoke("Install", *flags)
            launch = read(keys[1] + r"\shell\open\command")
            assert read(keys[0] + r"\shell\open\command") == launch
            assert read(r"Software\RegisteredApplications", "Firmica") == keys[2]
            assert read(keys[2] + r"\URLAssociations", "afirma") == "Firmica.afirma"
            shell = ctypes.WinDLL("shell32", use_last_error=True)
            shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
            shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.LocalFree.argtypes = [wintypes.HLOCAL]
            kernel.LocalFree.restype = wintypes.HLOCAL
            uri = "afirma://save?ver=4&name=a%22%20b&dat=YWJj"
            count = ctypes.c_int()
            parsed = shell.CommandLineToArgvW(launch.replace("%1", uri), ctypes.byref(count))
            assert parsed
            try:
                arguments = list(parsed[:count.value])
                assert len(arguments) == 9, arguments
                assert [arguments[1], arguments[3], *arguments[5:]] == [
                    "--tls-cert", "--tls-key", "--origin", "https://example.invalid", "--", uri
                ], arguments
                for actual, expected in ((arguments[0], application), (arguments[2], certificate), (arguments[4], private_key)):
                    assert Path(actual).samefile(expected), (actual, str(expected))
            finally:
                kernel.LocalFree(parsed)
            invoke("Install", *flags)
            assert read(keys[1] + r"\shell\open\command") == launch
            for origin in ["https://example.invalid/", "file:///tmp/", "https://user@example.invalid", "https://example.invalid/path"]:
                invoke("Install", *flags[:-1], origin, success=False)
                assert read(keys[1] + r"\shell\open\command") == launch
            assert "Registered executable:" in invoke("Status")
            invoke("Uninstall")
            assert not any(exists(path) for path in keys)
            invoke("Uninstall")

            write(keys[0], "foreign handler")
            write(keys[0] + r"\shell\open\command", '"foreign.exe" "%1"')
            invoke("Install", *flags)
            assert read(keys[0]) == "foreign handler"
            assert read(keys[0] + r"\shell\open\command") == '"foreign.exe" "%1"'
            invoke("Uninstall")
            assert exists(keys[0]) and not exists(keys[1])
            remove(keys[0])

            invoke("Install", *flags)
            write(keys[0] + r"\shell\open\command", "replacement command")
            invoke("Uninstall")
            assert read(keys[0] + r"\shell\open\command") == "replacement command"
            remove(keys[0])

            write(keys[1], "foreign provider")
            invoke("Install", *flags, success=False)
            invoke("Uninstall", success=False)
            assert read(keys[1]) == "foreign provider"
            remove(keys[1])
            percent = directory.parent / "literal %1 path"
            percent.mkdir()
            shutil.copy2(application, percent / "firmica.exe")
            shutil.copy2(script, percent / "handler.ps1")
            invoke("Install", *flags, target=percent / "handler.ps1", success=False)
            assert not any(exists(path) for path in keys)
            print("Passed: quoted argv, idempotence, invalid origins, placeholder rejection, foreign-owner preservation and uninstall.")
        finally:
            for path in keys:
                remove(path)
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\RegisteredApplications", 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, "Firmica")
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()
