"""The source-based audit gate must fail closed on unverified findings and sources."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("audit", Path(__file__).resolve().parents[1] / "audit-dependencies.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditPolicy(unittest.TestCase):
    def setUp(self):
        self.fixed = {("glib", "0.18.5", "RUSTSEC-2024-0429")}
        self.report = {
            "settings": {"ignore": [], "target_arch": [], "target_os": [], "severity": None,
                         "informational_warnings": ["unsound", "unmaintained", "notice"]},
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": {"unsound": [{"package": {"name": "glib", "version": "0.18.5", "source": audit.REGISTRY},
                                      "advisory": {"id": "RUSTSEC-2024-0429"}}]},
        }

    def test_accepts_only_the_verified_fix_and_keeps_other_findings_fatal(self):
        audit.check_report(self.report, self.fixed, 1)
        with self.assertRaises(ValueError):
            audit.check_report(self.report, set(), 1)
        for field, value in [("version", "0.18.4"), ("source", None), ("name", "other")]:
            report = copy.deepcopy(self.report)
            report["warnings"]["unsound"][0]["package"][field] = value
            with self.assertRaises(ValueError):
                audit.check_report(report, self.fixed, 1)
        report = copy.deepcopy(self.report)
        report["warnings"]["unsound"][0]["advisory"]["id"] = "RUSTSEC-2099-0001"
        with self.assertRaises(ValueError):
            audit.check_report(report, self.fixed, 1)
        report["vulnerabilities"] = {"found": True, "count": 1, "list": [{}]}
        with self.assertRaises(ValueError):
            audit.check_report(report, self.fixed, 1)

    def test_filtered_reports_and_auditor_errors_cannot_pass(self):
        for field, value in [("ignore", ["RUSTSEC-2024-0429"]), ("target_os", ["linux"]),
                             ("target_arch", ["x86_64"]), ("severity", "high"),
                             ("informational_warnings", ["unmaintained"])]:
            report = copy.deepcopy(self.report)
            report["settings"][field] = value
            with self.assertRaises(ValueError):
                audit.check_report(report, self.fixed, 1)
        with self.assertRaises(ValueError):
            audit.check_report(self.report, self.fixed, 2)
        report = copy.deepcopy(self.report)
        report["warnings"] = {}
        with self.assertRaises(ValueError):
            audit.check_report(report, self.fixed, 1)

    def test_source_fingerprint_covers_paths_contents_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Z").write_bytes(b"first")
            (root / "a").write_bytes(b"second")
            expected = hashlib.sha256(b"Z\0" + (5).to_bytes(8, "big") + b"first" +
                                      b"a\0" + (6).to_bytes(8, "big") + b"second").hexdigest()
            self.assertEqual(audit.source_fingerprint(root), expected)
            (root / "a").write_bytes(b"changed")
            self.assertNotEqual(audit.source_fingerprint(root), expected)
            (root / "a").unlink()
            (root / "a").symlink_to(root / "Z")
            with self.assertRaises(ValueError):
                audit.source_fingerprint(root)

    def test_real_lockfile_restores_both_registry_identities(self):
        text, verified = audit.verified_lockfile(audit.ROOT)
        packages = audit.tomllib.loads(text)["package"]
        for name in ("glib", "phf_generator"):
            entry = next(package for package in packages if package["name"] == name and
                         package["version"] == {"glib": "0.18.5", "phf_generator": "0.8.0"}[name])
            self.assertEqual(entry["source"], audit.REGISTRY)
            self.assertIn("checksum", entry)
        self.assertEqual(verified, self.fixed)

    def test_changed_sources_registry_replacements_and_unregistered_paths_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app").mkdir()
            (root / "tools").mkdir()
            vendor = root / "crates/vendor/glib"
            vendor.mkdir(parents=True)
            (root / "Cargo.toml").write_text('[workspace]\nmembers=["app"]\n[patch.crates-io]\nglib={path="crates/vendor/glib"}\n')
            (root / "app/Cargo.toml").write_text('[package]\nname="app"\nversion="0.1.0"\n')
            (vendor / "Cargo.toml").write_text('[package]\nname="glib"\nversion="0.18.5"\n')
            source_hash = audit.source_fingerprint(vendor)
            (root / "tools/backports.toml").write_text(
                '[[backport]]\nname="glib"\nversion="0.18.5"\npath="crates/vendor/glib"\n'
                f'archive_sha256="{"0" * 64}"\nsource_sha256="{source_hash}"\nfixes=["RUSTSEC-2024-0429"]\n')
            original = 'version=4\n[[package]]\nname = "glib"\nversion = "0.18.5"\n'
            lockfile = root / "Cargo.lock"
            lockfile.write_text(original)
            audit.verified_lockfile(root)
            (vendor / "added.rs").write_text("changed source")
            with self.assertRaises(ValueError):
                audit.verified_lockfile(root)
            (vendor / "added.rs").unlink()
            for extra in [f'source="{audit.REGISTRY}"\n', 'source="git+https://example.invalid/dependency"\n',
                          '[[package]]\nname="unregistered"\nversion="1.0.0"\n']:
                lockfile.write_text(original + extra)
                with self.assertRaises(ValueError):
                    audit.verified_lockfile(root)


if __name__ == "__main__":
    unittest.main()
