# Firmica

Rust electronic-signature client using Dioxus 0.7.10 and Tailwind CSS 4, targeting existing AutoFirma browser integrations.

The application accepts `afirma://` invocations and local TLS WebSocket requests for review. It cannot sign documents, access certificates, or validate signatures.

## Build

Use stable Rust, Dioxus CLI **0.7.10**, and the [native platform prerequisites](https://dioxuslabs.com/learn/0.7/guides/platforms/).

```sh
cargo install dioxus-cli --version 0.7.10 --locked
cd packages/desktop
dx serve --platform desktop
```

Native applications and shared UI live in `packages/desktop`, `packages/mobile`, `packages/web`, and `packages/ui`. Reusable Rust libraries live in `crates/`.

```sh
# From the workspace root:
dx build --package desktop --platform desktop --release
dx build --package web --platform web

# With the corresponding SDKs and native build host:
cd packages/mobile
dx serve --platform android
dx serve --platform ios
```

`dx` detects each package's `tailwind.css`, runs Tailwind 4.1.5, and writes `assets/tailwind.css` before collecting assets. All three entry files load that local asset. The shared source directory and theme are included explicitly. Plain `cargo check` does not compile CSS; run `dx build` first. Build tools may download dependencies; the local application UI requires no internet connection.

To build the Linux Debian package, run from `packages/desktop`:

```sh
dx bundle --locked --platform desktop --release --package-types deb
```

Dioxus 0.7.10 resolves the custom desktop-template path from the working directory. The package contains the `firmica` executable and its `afirma` desktop handler. Install runtime dependencies separately; the generated package does not declare them.

## Invocation

On Linux, use the packaged executable with a quoted URI:

```sh
./target/dx/firmica/release/linux/app/firmica 'afirma://sign?ver=4&format=CAdES&algorithm=SHA256withRSA&dat=c3ludGhldGlj'
```

Subsequent invocations are forwarded to the running instance through a private per-user Unix socket. A WSS review expires when its transport stops accepting decisions; asynchronous reconnects preserve the review within the session. Review cannot sign anything: **Reject** cancels, and **Acknowledge review** reports that the operation is unsupported.

To enable the local WSS listener, supply a TLS certificate/key and an exact allowed browser origin to the first process:

```sh
./target/dx/firmica/release/linux/app/firmica \
  --tls-cert /path/to/test-cert.pem --tls-key /path/to/test-key.pem \
  --origin http://127.0.0.1:8080 \
  'afirma://websocket?v=4&jvc=4&ports=49152,49153,49154&idsession=0123456789abcdef'
```

Browser certificate trust and URI-handler registration are not configured automatically. Do not install test certificates globally. Chromium tests pin one ephemeral public key. The Firefox OS-handler test trusts an ephemeral CA only in its disposable profile and checks that a fresh profile rejects it. Tests use an isolated XDG association without replacing the user's default handler.

## Verify

Generate the required assets before Cargo checks. The mobile command here checks its host entry point, not Android/iOS packaging.

```sh
dx build --locked --package desktop --platform desktop
dx build --locked --package mobile --platform desktop --features mobile
cargo fmt --all --check
cargo test -p firmica-protocol -p firmica-core -p firmica-transport -p desktop -p mobile
cargo clippy -p firmica-protocol -p firmica-core -p firmica-transport -p ui -p desktop -p mobile --all-targets -- -D warnings
cargo check -p desktop
cargo check -p mobile  # host check; native Android test described below
cargo doc -p firmica-protocol -p firmica-core -p firmica-transport --no-deps

npm ci
npx playwright install chromium firefox
cargo build -p firmica-transport --example probe
npm run test:autoscript
npm run test:desktop
# After building the Debian bundle above (x86-64):
FIRMICA_DEB=target/dx/firmica/bundle/linux/deb/firmica_0.1.0_amd64.deb npm run test:desktop
npm run test:native-interop
npm run test:os-handler
npm run test:lifecycle
```

The lifecycle test uses the 60 s synchronous-review and 120 s listener deadlines and takes about two minutes. Browser tests need OpenSSL and the selected browsers' system libraries. The Linux native smoke test additionally needs Xvfb, `xauth`, `xdotool`, `gio`, and `update-desktop-database`; it uses the release artifact built by `dx`. The extracted Debian payload test also needs `ar`, `tar`, `md5sum`, and `desktop-file-validate`. It uses the packaged desktop entry without rewriting it and leaves the system handler unchanged. The Firefox OS-handler test also needs `certutil` (NSS tools) and `dbus-run-session`. It preapproves `afirma` in a disposable profile. Results and a browser screenshot are saved under `.test-artifacts/linux-os-handler/`; `FIRMICA_SCREENSHOT=/absolute/path.png` adds a native-window screenshot when ImageMagick is installed. AutoScript is fetched at a pinned revision with a SHA-256 check and cached under `.test-artifacts/`. Set `FIRMICA_AUTOSCRIPT` to an existing unmodified file to run offline. It is not bundled with Firmica.

For native Android invocation checks, build a debug APK with `dx build --locked --package mobile --platform android --target x86_64-linux-android`, then run `python3 tests/interop/android.py --serial emulator-5554 --apk /path/to/app-debug.apk`. The script refuses physical devices. Add `--browser org.mozilla.firefox` to check browser links with Firefox already installed in the emulator.

On macOS with Xcode 16.4 and the iOS 18.5 Simulator runtime, run:

```sh
dx build --locked --package mobile --platform ios --target aarch64-apple-ios-sim
python3 tests/interop/ios.py --app target/dx/mobile/debug/ios/Mobile.app
```

The iOS test creates a temporary iPhone simulator and opens synthetic links from Safari. It saves XCTest results and screenshots under `.test-artifacts/ios/` and deletes the simulator when finished.

The dependency graph includes `glib 0.18.5` (RUSTSEC-2024-0429) and `rand 0.7.3` (RUSTSEC-2026-0097), which have known unsoundness advisories. Run `cargo audit --deny unsound` to check dependencies.

The signing libraries can be tested separately from the applications. They require patched OpenSSL development headers/libraries and the OpenSSL CLI; see the [OpenSSL build requirements](https://docs.rs/openssl/0.10.81/openssl/#building). Set `OPENSSL_DIR` and, when needed, `OPENSSL_LIB_DIR` for a native installation outside the compiler's search paths.

```sh
cargo test --locked -p firmica-signing -p firmica-certificates -p firmica-cades -p firmica-key-worker -p firmica-validation --features pkcs11
cargo doc --locked -p firmica-signing -p firmica-certificates -p firmica-cades -p firmica-key-worker -p firmica-validation --features pkcs11 --no-deps
# Java 17+; downloads checksum-pinned, test-only AutoFirma 1.9.1 reference jars:
python3 tests/interop/cades_reference.py
# With SoftHSM and softhsm2-util installed; use your platform's module path:
FIRMICA_PKCS11_MODULE=/path/to/libsofthsm2.so cargo test --locked -p firmica-certificates --features pkcs11 --test pkcs11 -- --ignored --test-threads=1
```

The SoftHSM test creates a disposable token store and uses synthetic, non-exportable RSA/P-256 keys. PKCS#12 tests cover encrypted containers, passwords, malformed input and message/digest signing. CAdES tests verify attached and detached signatures with the OpenSSL CLI, check certificate binding, and reject modified content. The token test also exercises CAdES encoding. No existing certificate store is opened.

The key worker keeps unlocked PKCS#12 keys in a separate Linux process with CPU, address-space and IPC deadline limits. Its tests cover import, CAdES signing, process termination and cleanup; they take about 30 seconds. Imports on other platforms are rejected. API contracts and import limitations are documented with rustdoc.

`firmica-validation` checks local leaf-certificate restrictions for document signing: validity, key usage, extended key usage, CA usage and private-key usage periods. It rejects unhandled critical extensions and malformed constraints. It does not verify certificate signatures, chain trust, revocation or legal qualification. The core CAdES review API binds approval to the selected document bytes, certificate identity, algorithm and content mode, then rechecks the certificate before using the key. Provider cleanup must succeed before publishing output. These library APIs are not connected to the application controls.

Original code targets GPL-3.0-or-later. Third-party dependencies and reference assets retain their own licences.
