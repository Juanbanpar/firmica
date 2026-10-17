#!/usr/bin/env python3
"""Build the Linux desktop client and its companion worker from the same checkout."""

import argparse
import json
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["build", "bundle"])
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("this builder targets the native Linux host")
    release = args.release or args.command == "bundle"
    profile = "release" if release else "debug"
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=ROOT))
    target = Path(metadata["target_directory"])
    subprocess.run(["cargo", "build", "--locked", "-p", "firmica-key-worker"]
                   + (["--release"] if release else []), cwd=ROOT, check=True)
    worker = target / profile / "firmica-key-worker"
    triple = next(line.removeprefix("host: ") for line in
                  subprocess.check_output(["rustc", "-vV"], text=True).splitlines()
                  if line.startswith("host: "))
    sidecars = ROOT / "target" / "sidecars"
    sidecars.mkdir(parents=True, exist_ok=True)
    shutil.copy2(worker, sidecars / f"firmica-key-worker-{triple}")
    command = ["dx", args.command, "--locked", "--platform", "desktop"]
    if release:
        command.append("--release")
    if args.command == "bundle":
        command += ["--package-types", "deb"]
    subprocess.run(command, cwd=ROOT / "packages" / "desktop", check=True)
    # dx build does not copy external_bin; dx bundle uses it for /usr/bin.
    application = target / "dx" / "firmica" / profile / "linux" / "app"
    if not (application / "firmica").is_file():
        raise RuntimeError("Dioxus did not produce the expected desktop executable")
    shutil.copy2(worker, application / "firmica-key-worker")


if __name__ == "__main__":
    main()
