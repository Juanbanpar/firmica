#!/usr/bin/env python3
"""Verify dependency backports and audit every registry identity, including vendored crates.

Cargo-audit skips path dependencies. An audit-only lockfile restores their original
registry identities so new advisories remain visible. A finding is considered fixed
only for an exact source fingerprint and the recorded package/version/advisory tuple.
The unchanged raw audit report is printed. No advisory ignore list is used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def source_fingerprint(directory):
    """Hash every regular file; reject symlinks and special files."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(f"invalid vendored source directory: {directory}")
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*"), key=lambda path: path.relative_to(directory).as_posix()):
        if path.is_symlink():
            raise ValueError(f"symlink in vendored source: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"non-regular vendored source: {path}")
        data = path.read_bytes()
        digest.update(path.relative_to(directory).as_posix().encode() + b"\0")
        digest.update(len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def verified_lockfile(root):
    """Verify the resolved local packages and return an audit-only registry lockfile."""
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    backports = tomllib.loads((root / "tools/backports.toml").read_text())["backport"]
    lock_text = (root / "Cargo.lock").read_text()
    packages = tomllib.loads(lock_text)["package"]
    if any(package.get("source", REGISTRY) != REGISTRY for package in packages):
        raise ValueError("dependency sources outside crates.io require explicit source verification")
    workspace = {tuple(tomllib.loads((root / member / "Cargo.toml").read_text())["package"][key]
                       for key in ("name", "version")) for member in manifest["workspace"]["members"]}
    allowed = workspace | {(backport["name"], backport["version"]) for backport in backports}
    if any("source" not in package and (package["name"], package["version"]) not in allowed for package in packages):
        raise ValueError("unverified local dependency in Cargo.lock")
    verified = set()
    for backport in backports:
        name, version = backport["name"], backport["version"]
        directory = root / backport["path"]
        if manifest["patch"]["crates-io"][name] != {"path": backport["path"]}:
            raise ValueError(f"unexpected Cargo patch for {name}")
        package = tomllib.loads((directory / "Cargo.toml").read_text())["package"]
        if (package["name"], package["version"]) != (name, version):
            raise ValueError(f"backport package identity changed: {name}")
        if source_fingerprint(directory) != backport["source_sha256"]:
            raise ValueError(f"vendored source fingerprint changed: {name}")
        resolved = [p for p in packages if p["name"] == name and p["version"] == version]
        if len(resolved) != 1 or "source" in resolved[0] or "checksum" in resolved[0]:
            raise ValueError(f"backport is not the resolved local dependency: {name}")
        header = f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        if lock_text.count(header) != 1:
            raise ValueError(f"ambiguous lockfile entry: {name}")
        lock_text = lock_text.replace(header, header + f'source = "{REGISTRY}"\nchecksum = "{backport["archive_sha256"]}"\n')
        verified.update((name, version, advisory) for advisory in backport["fixes"])
        print(f"Verified source: {name} {version} ({backport['source_sha256']})", flush=True)
    return lock_text, verified


def check_report(report, verified, returncode):
    """Reject failures except findings proven fixed in the verified source."""
    settings = report["settings"]
    if any(settings[key] for key in ("ignore", "target_arch", "target_os", "severity")):
        raise ValueError("audit settings must not ignore or filter advisories")
    if not {"unsound", "unmaintained", "notice"}.issubset(settings["informational_warnings"]):
        raise ValueError("audit informational findings must not be filtered")
    vulnerabilities = report["vulnerabilities"]
    if vulnerabilities["found"] or vulnerabilities["count"] or vulnerabilities["list"]:
        raise ValueError("unresolved vulnerability")
    fixed = set()
    for kind, warnings in report["warnings"].items():
        if kind == "unmaintained":
            continue  # Matches the existing --deny unsound policy.
        for warning in warnings:
            package = warning["package"]
            identity = (package["name"], package["version"], warning["advisory"]["id"])
            if kind != "unsound" or identity not in verified or package["source"] != REGISTRY:
                raise ValueError(f"unresolved advisory: {warning['advisory']['id']}")
            fixed.add(identity)
    if returncode not in (0, 1) or (returncode == 1 and not fixed):
        raise ValueError(f"cargo audit failed with status {returncode}")
    for name, version, advisory in sorted(fixed):
        print(f"Fixed in verified local source: {advisory}, {name} {version}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true", help="verify source fingerprints without running cargo-audit")
    args = parser.parse_args()
    lock_text, verified = verified_lockfile(ROOT)
    if args.verify_only:
        return
    with tempfile.TemporaryDirectory(prefix="firmica-audit-") as temporary:
        lockfile = Path(temporary) / "Cargo.lock"
        lockfile.write_text(lock_text)
        result = subprocess.run(["cargo", "audit", "--file", str(lockfile), "--deny", "unsound", "--json"],
                                cwd=ROOT, capture_output=True, text=True, timeout=180)
    print(result.stdout, end="", flush=True)
    print(result.stderr, end="", file=sys.stderr)
    check_report(json.loads(result.stdout), verified, result.returncode)
    print("Dependency audit passed with verified source backports.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(f"Dependency audit failed: {error}")
