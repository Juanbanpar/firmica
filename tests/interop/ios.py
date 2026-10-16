#!/usr/bin/env python3
"""Build an XCTest runner and exercise a Dioxus app through Safari in a fresh iOS simulator."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import plistlib
import shlex
import shutil
import subprocess
import threading
import uuid
import xml.etree.ElementTree as ET

PACKAGE = "org.firmica.client"
SOURCE = Path(__file__).with_name("ios") / "InvocationTests.swift"


def run(*args, timeout=60):
    print("+ " + shlex.join(args), flush=True)
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        for output in (error.stdout, error.stderr):
            if output:
                print(output.decode(errors="replace") if isinstance(output, bytes) else output, flush=True)
        raise


def test_project(directory, origin):
    """Create only the UI-test target; the app remains the bundle built by Dioxus."""
    directory.mkdir(parents=True)
    shutil.copy2(SOURCE, directory / SOURCE.name)
    project = directory / "Invocation.xcodeproj"
    project.mkdir()
    objects = {}

    def node(key, isa, **values):
        identifier = hashlib.sha256(key.encode()).hexdigest()[:24].upper()
        objects[identifier] = {"isa": isa, **values}
        return identifier

    source = node("source", "PBXFileReference", lastKnownFileType="sourcecode.swift",
                  path=SOURCE.name, sourceTree="<group>")
    product = node("product", "PBXFileReference", explicitFileType="wrapper.cfbundle",
                   path="Invocation.xctest", sourceTree="BUILT_PRODUCTS_DIR")
    products = node("products", "PBXGroup", children=[product], name="Products", sourceTree="<group>")
    group = node("group", "PBXGroup", children=[source, products], sourceTree="<group>")
    build_file = node("build-file", "PBXBuildFile", fileRef=source)
    sources = node("sources", "PBXSourcesBuildPhase", buildActionMask=2147483647,
                   files=[build_file], runOnlyForDeploymentPostprocessing=0)
    settings = {
        "SDKROOT": "iphonesimulator", "SUPPORTED_PLATFORMS": "iphonesimulator",
        "IPHONEOS_DEPLOYMENT_TARGET": "16.4", "TARGETED_DEVICE_FAMILY": "1,2",
        "SWIFT_VERSION": "5.0", "PRODUCT_NAME": "$(TARGET_NAME)",
        "PRODUCT_BUNDLE_IDENTIFIER": "org.firmica.invocation-tests",
        "GENERATE_INFOPLIST_FILE": "YES", "CODE_SIGNING_ALLOWED": "NO",
    }
    config = node("config", "XCBuildConfiguration", name="Debug", buildSettings=settings)
    configs = node("configs", "XCConfigurationList", buildConfigurations=[config],
                   defaultConfigurationIsVisible=0, defaultConfigurationName="Debug")
    target = node("target", "PBXNativeTarget", name="Invocation", productName="Invocation",
                  productType="com.apple.product-type.bundle.ui-testing", productReference=product,
                  buildConfigurationList=configs, buildPhases=[sources], buildRules=[], dependencies=[])
    root = node("project", "PBXProject", buildConfigurationList=configs,
                compatibilityVersion="Xcode 14.0", developmentRegion="en", knownRegions=["en"],
                mainGroup=group, productRefGroup=products, projectDirPath="", projectRoot="",
                targets=[target], attributes={"LastUpgradeCheck": "1640"})
    with (project / "project.pbxproj").open("wb") as output:
        plistlib.dump({"archiveVersion": "1", "objectVersion": "56", "classes": {},
                      "objects": objects, "rootObject": root}, output)
    scheme = ET.Element("Scheme", LastUpgradeVersion="1640", version="1.3")
    build = ET.SubElement(scheme, "BuildAction", parallelizeBuildables="NO", buildImplicitDependencies="YES")
    entry = ET.SubElement(ET.SubElement(build, "BuildActionEntries"), "BuildActionEntry",
                          buildForTesting="YES", buildForRunning="NO", buildForProfiling="NO",
                          buildForArchiving="NO", buildForAnalyzing="YES")

    def reference(parent):
        ET.SubElement(parent, "BuildableReference", BuildableIdentifier="primary", BlueprintIdentifier=target,
                      BuildableName="Invocation.xctest", BlueprintName="Invocation",
                      ReferencedContainer="container:Invocation.xcodeproj")

    reference(entry)
    action = ET.SubElement(scheme, "TestAction", buildConfiguration="Debug",
                           selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB",
                           selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB",
                           shouldUseLaunchSchemeArgsEnv="NO")
    reference(ET.SubElement(ET.SubElement(action, "Testables"), "TestableReference", skipped="NO"))
    ET.SubElement(ET.SubElement(action, "EnvironmentVariables"), "EnvironmentVariable",
                  key="FIRMICA_TEST_ORIGIN", value=origin, isEnabled="YES")
    schemes = project / "xcshareddata/xcschemes"
    schemes.mkdir(parents=True)
    ET.ElementTree(scheme).write(schemes / "Invocation.xcscheme", encoding="UTF-8", xml_declaration=True)
    return project


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'''<!doctype html><html lang="en"><meta name="viewport" content="width=device-width">
        <title>Firmica invocation test</title><style>a{display:block;padding:20px}</style>
        <a href="afirma://sign?ver=4&format=CAdES&dat=c3ludGhldGlj">Sign request</a>
        <a href="afirma://save?ver=4">Save request</a>
        <a href="afirma://cosign?ver=3&format=CAdES">Co-sign request</a>
        <a href="afirma://sign?ver=4&dat=%00">Malformed request</a>
        <a href="afirma://selectcert?ver=4">Certificate request</a></html>'''
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--runtime", default="18.5")
    parser.add_argument("--output", type=Path, default=Path(".test-artifacts/ios"))
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("iOS Simulator testing requires macOS and Xcode")
    info = plistlib.loads((args.app / "Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == PACKAGE
    assert any("afirma" in entry.get("CFBundleURLSchemes", []) for entry in info.get("CFBundleURLTypes", []))
    args.output.mkdir(parents=True, exist_ok=True)
    result = args.output / "result.json"
    result.unlink(missing_ok=True)
    shutil.copy2(args.app / "Info.plist", args.output / "Info.plist")
    runtimes = json.loads(run("xcrun", "simctl", "list", "runtimes", "--json"))["runtimes"]
    runtime = next(r for r in runtimes if r["isAvailable"] and r["version"] == args.runtime
                   and r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS-"))
    device = run("xcrun", "simctl", "create", "Firmica-" + uuid.uuid4().hex[:8],
                 "com.apple.CoreSimulator.SimDeviceType.iPhone-16", runtime["identifier"])
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        run("xcrun", "simctl", "boot", device)
        run("xcrun", "simctl", "bootstatus", device, "-b", timeout=180)
        run("xcrun", "simctl", "install", device, str(args.app.resolve()), timeout=180)
        project_dir = args.output / "project"
        if project_dir.exists():
            shutil.rmtree(project_dir)
        project = test_project(project_dir, f"http://127.0.0.1:{server.server_port}")
        bundle = args.output / "Invocation.xcresult"
        if bundle.exists():
            shutil.rmtree(bundle)
        with (args.output / "xcodebuild.log").open("w") as log:
            completed = subprocess.run([
                "xcodebuild", "test", "-project", str(project.resolve()), "-scheme", "Invocation",
                "-destination", "id=" + device, "-derivedDataPath", str((args.output / "DerivedData").resolve()),
                "-resultBundlePath", str(bundle.resolve()), "-parallel-testing-enabled", "NO",
                "-testLanguage", "en", "-testRegion", "US",
            ], stdout=log, stderr=subprocess.STDOUT, timeout=480)
        run("xcrun", "xcresulttool", "export", "attachments", "--path", str(bundle),
            "--output-path", str(args.output / "attachments"))
        if completed.returncode:
            print((args.output / "xcodebuild.log").read_text()[-18000:])
            raise RuntimeError("XCTest invocation checks failed")
        report = {"platform": "iOS Simulator", "runtime": runtime, "device": "iPhone 16",
                  "xcode": run("xcodebuild", "-version"),
                  "applicationSha256": hashlib.sha256((args.app / info["CFBundleExecutable"]).read_bytes()).hexdigest(),
                  "actual": "passed", "checks": ["packaged afirma scheme", "Safari cold link", "warm pending protection",
                  "background return", "rejection", "warm cosign and language retention", "unsupported result",
                  "malformed request rejection", "fresh-process selectcert"],
                  "scope": "simulator invocation and review; no signing, intermediate services, browser return or physical-device proof"}
        result.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    except Exception:
        # Preserve setup/service evidence before deleting the disposable simulator.
        with (args.output / "simulator.log").open("w") as log:
            try:
                subprocess.run([
                    "xcrun", "simctl", "spawn", device, "log", "show", "--last", "5m",
                    "--style", "compact", "--predicate", 'process == "installd" OR process == "SpringBoard"',
                ], stdout=log, stderr=subprocess.STDOUT, timeout=30)
            except subprocess.TimeoutExpired:
                log.write("\nSimulator log collection timed out.\n")
        raise
    finally:
        server.shutdown()
        server.server_close()
        subprocess.run(["xcrun", "simctl", "shutdown", device], capture_output=True, timeout=30)
        subprocess.run(["xcrun", "simctl", "delete", device], capture_output=True, timeout=30)


if __name__ == "__main__":
    main()
