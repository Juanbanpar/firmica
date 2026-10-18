#!/usr/bin/env python3
"""Build the Linux or Windows desktop client and its companion worker from the same checkout."""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["build", "bundle"])
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument("--release", action="store_true")
    profiles.add_argument("--debug", action="store_true", help="allow a debug portable bundle")
    args = parser.parse_args()
    system = platform.system()
    if system not in {"Linux", "Windows"}:
        parser.error("this builder requires a native Linux or Windows host")
    suffix = ".exe" if system == "Windows" else ""
    release = args.release or (args.command == "bundle" and not args.debug)
    profile = "release" if release else "debug"
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=ROOT))
    target = Path(metadata["target_directory"])
    subprocess.run(["cargo", "build", "--locked", "-p", "firmica-key-worker"]
                   + (["--release"] if release else []), cwd=ROOT, check=True)
    worker = target / profile / f"firmica-key-worker{suffix}"
    triple = next(line.removeprefix("host: ") for line in
                  subprocess.check_output(["rustc", "-vV"], text=True).splitlines()
                  if line.startswith("host: "))
    if system == "Windows" and triple != "x86_64-pc-windows-msvc":
        raise RuntimeError("Windows runtime staging currently requires an x64 MSVC host")
    sidecars = ROOT / "target" / "sidecars"
    sidecars.mkdir(parents=True, exist_ok=True)
    shutil.copy2(worker, sidecars / f"firmica-key-worker-{triple}{suffix}")
    command = ["dx", "bundle" if args.command == "bundle" and system == "Linux" else "build", "--locked", "--platform", "desktop"]
    if release:
        command.append("--release")
    if args.command == "bundle" and system == "Linux":
        command += ["--package-types", "deb"]
    subprocess.run(command, cwd=ROOT / "packages" / "desktop", check=True)
    # dx build does not copy external_bin; dx bundle uses it for /usr/bin.
    application = target / "dx" / "firmica" / profile / system.lower() / "app"
    if not (application / f"firmica{suffix}").is_file():
        raise RuntimeError("Dioxus did not produce the expected desktop executable")
    shutil.copy2(worker, application / f"firmica-key-worker{suffix}")

    if system == "Windows":
        shutil.copy2(ROOT / "LICENSE", application / "LICENSE")
        shutil.copy2(ROOT / "tools/windows/handler.ps1", application / "handler.ps1")
        root = Path(os.environ["OPENSSL_DIR"])
        for name in ("libcrypto-3-x64.dll", "libssl-3-x64.dll"):
            candidates = [directory / name for directory in (root / "bin", root)]
            library = next((path for path in candidates if path.is_file()), None)
            if library is None:
                raise RuntimeError(f"missing x64 OpenSSL runtime: {name} under {root}")
            shutil.copy2(library, application / name)
        license_file = next((root / name for name in ("license.txt", "LICENSE.txt", "LICENSE")
                             if (root / name).is_file()), None)
        if license_file is None:
            raise RuntimeError(f"OpenSSL distribution license missing under {root}")
        shutil.copy2(license_file, application / "OpenSSL-LICENSE.txt")
        if args.command == "bundle":
            destination = target / "dx" / "firmica" / "bundle" / "windows"
            destination.mkdir(parents=True, exist_ok=True)
            archive = shutil.make_archive(str(destination / f"firmica-{triple}"), "zip", application)
            print(archive)


if __name__ == "__main__":
    main()
