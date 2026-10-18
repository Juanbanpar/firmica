# Firmica

Rust electronic-signature client using Dioxus 0.7.10 and Tailwind CSS 4, targeting existing AutoFirma browser integrations.

The Linux and Windows desktop applications sign local documents and supported AutoScript requests in CAdES format using PKCS#12 certificates. Browser signing requires local TLS setup, browser trust and certificate review. Bare `afirma://sign` invocations support review and cancellation only. Certificate trust, revocation and legal qualification are not validated.

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

For Linux document signing, build the application and its companion key worker together from the workspace root:

```sh
python3 tools/build-desktop.py build
./target/dx/firmica/debug/linux/app/firmica
# Release application and Debian package:
python3 tools/build-desktop.py bundle
```

The builder requires Python 3 and invokes Cargo and Dioxus from this checkout. It stages the worker for bundling and places it beside the development executable. The package includes `firmica`, `firmica-key-worker`, and the `afirma` desktop handler. Both executables must remain in a trusted installation directory. Install Linux runtime dependencies separately; the Debian package does not declare them. Linux file dialogs use a desktop portal or the `zenity` fallback.

On x64 Windows, install the MSVC build tools, WebView2 Runtime, and a patched shared OpenSSL 3 distribution with x64 import libraries. In PowerShell, set its build paths and build from the workspace root:

```powershell
$env:OPENSSL_DIR = 'C:\Program Files\OpenSSL'
$env:OPENSSL_LIB_DIR = "$env:OPENSSL_DIR\lib\VC\x64\MD"
$env:OPENSSL_STATIC = '0'
python tools/build-desktop.py build
.\target\dx\firmica\debug\windows\app\firmica.exe
# Release portable ZIP:
python tools/build-desktop.py bundle
```

The Windows builder copies `libcrypto-3-x64.dll`, `libssl-3-x64.dll` and the distribution's license from `OPENSSL_DIR` beside the application and worker. The ZIP is written under `target/dx/firmica/bundle/windows/`; extract it to a trusted directory and keep its contents together. WebView2 and the MSVC runtime must be installed separately. Update the bundled OpenSSL DLLs when rebuilding with security fixes. This portable bundle does not register an `afirma` URI handler. Windows dialogs use `rfd`; selected documents must be regular files, and file reparse points are rejected. Local signing is unavailable on macOS and mobile.

## Local signing

Open **Sign a document**, select a document and a `.p12`/`.pfx` certificate, and enter its password. Choose RSA PKCS#1 v1.5/SHA-256 or ECDSA P-256/SHA-256 and whether to embed the document. RSA keys must have at least 2048 bits. Documents are limited to 16 MiB and containers to 8 MiB. Empty documents and empty passwords are supported.

**Open and review** shows the frozen document's name, size and SHA-256, the certificate's claimed subject/issuer, serial, fingerprint and validity, and the signing choices. The certificate signature, chain trust, revocation and legal qualification remain unchecked. Approval requires acknowledging those unchecked items. **Sign and save** opens a destination dialog; cancelling it preserves the review. **Cancel** closes the certificate worker without signing.

Choose a new destination: existing files and symlinks are never replaced. Output is published only after signing and worker cleanup succeed. Linux outputs use mode 0600; Windows outputs inherit the destination directory ACL, so choose a private directory. For a detached signature, retain the exact original document alongside the `.csig` file. Changing the source file after review does not change the bytes signed. No system certificate store is opened, and browser requests cannot authorize this local workflow.

## Invocation

On Linux, use the packaged executable with a quoted URI:

```sh
./target/dx/firmica/release/linux/app/firmica 'afirma://sign?ver=4&format=CAdES&algorithm=SHA256withRSA&dat=c3ludGhldGlj'
```

Subsequent invocations are forwarded to the running instance through a private per-user Unix socket. A WSS review expires when its transport stops accepting decisions; asynchronous reconnects preserve the review within the session. Bare URI requests cannot receive a signature: **Reject** cancels, and **Acknowledge review** reports that the operation is unsupported.

On Windows, `firmica.exe "afirma://save?ver=4"` forwards subsequent launches to the running application through a local named pipe restricted to the same logon session. Delivery is acknowledged only after a valid URI enters the bounded application queue; busy or unresponsive instances cause the secondary process to fail. The portable bundle does not register an OS URI handler. Browser signing on Windows requires explicit `--tls-cert`, `--tls-key` and `--origin` arguments; automatic TLS-profile setup is available on Linux.

With an installed Linux package, create the per-user browser TLS profile once, using the exact website origin without a trailing slash:

```sh
firmica tls init --origin https://example.org
firmica tls status
```

The commands work without a graphical session. The profile lives in `$XDG_CONFIG_HOME/firmica/browser-tls`, or `$HOME/.config/firmica/browser-tls` when `XDG_CONFIG_HOME` is unset. Its directories are private and its files have mode `0600`. Setup never replaces an existing profile. It creates a unique CA and a server certificate for `127.0.0.1`, valid for 365 days. The CA includes name constraints for `localhost` and `127.0.0.1`; its signing key is discarded after issuing the server certificate. Only the server key is stored.

Setup prints the public `ca.pem` path and its SHA-256 fingerprint. Check that fingerprint before importing the CA into the intended browser profile for website authentication. In Firefox, use **Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**. Firmica does not install trust entries, change TLS verification or register a default URI handler. Keep browser trust scoped to the profile that needs it.

Restart Firmica after setup. The packaged `afirma` handler loads this profile automatically, including on a cold browser launch, and permits only the configured origin. To change websites, edit the profile's `origin` file to contain one exact HTTP(S) origin and restart. To renew an expired identity, stop Firmica, move the private `browser-tls` directory aside and run `tls init` again. Import the new CA and remove the old browser trust entry; renewal cannot reuse the discarded CA key. Missing, expired, mismatched or insecure profile files cause startup to fail.

Explicit TLS settings override the per-user profile. Supply all three options to the first process:

```sh
./target/dx/firmica/release/linux/app/firmica \
  --tls-cert /path/to/test-cert.pem --tls-key /path/to/test-key.pem \
  --origin http://127.0.0.1:8080 \
  'afirma://websocket?v=4&jvc=4&ports=49152,49153,49154&idsession=0123456789abcdef'
```

On Linux, protocol 4.x WSS `sign` requests can return a signature after certificate selection and explicit approval. Supported requests contain an inline Base64 document, `format=CAdES`, and `algorithm=SHA256withRSA` or `SHA256withECDSA` (P-256 only). The only supported extra property is `mode=explicit` (detached, also the default) or `mode=implicit` (attached). WebSocket documents may contain up to 16 MiB of decoded data. The encoded request is bounded by the Base64 size of that document plus 64 KiB of metadata; other parameters together remain limited to 64 KiB. Native OS invocations and control messages retain the 64 KiB limit. Only PKCS#12 selection is supported; a request may omit the store or specify `ksb64` encoding `PKCS12`. Firefox’s AutoScript default requests its Mozilla store, so a PKCS#12 integration must call `AutoScript.setKeyStore(AutoScript.KEYSTORE_PKCS12)`. Sticky certificate reuse, other certificate stores, remote document URLs, precomputed digests, signature policies and unknown options are unsupported. Other operations retain review/cancellation behavior.

The signing screen fixes the document and signing choices from the request, shows their hash and the selected certificate, and warns that the request origin is unauthenticated. **Sign and send to browser** returns the reviewed certificate and CMS result to that session after worker cleanup; no destination file is written. Navigating away cancels the request. Each bootstrap admits one operation, its result can be retrieved once, and the listener expires after 120 seconds. A new bootstrap can start after the listener ends.

Do not install test certificates globally. Chromium tests pin one ephemeral public key. The Firefox OS-handler test provisions TLS with `firmica tls init`, trusts its CA only in a disposable profile and checks that a fresh profile rejects it. Tests use an isolated XDG association without replacing the user's default handler.

## Verify

Generate the required assets before Cargo checks. The mobile command here checks its host entry point, not Android/iOS packaging.

```sh
dx build --locked --package desktop --platform desktop
dx build --locked --package mobile --platform desktop --features mobile
cargo fmt --all --check
cargo test -p firmica-protocol -p firmica-core -p firmica-transport -p desktop -p mobile
# Linux desktop signing integration tests:
cargo build --locked -p firmica-key-worker
FIRMICA_TEST_WORKER="$PWD/target/debug/firmica-key-worker" cargo test --locked -p desktop -- --ignored --test-threads=1
cargo clippy -p firmica-protocol -p firmica-core -p firmica-transport -p ui -p desktop -p mobile --all-targets -- -D warnings
cargo check -p desktop
cargo check -p mobile  # host check; native Android test described below
cargo doc -p firmica-protocol -p firmica-core -p firmica-transport --no-deps

npm ci
npx playwright install chromium firefox
cargo build -p firmica-transport --example probe
npm run test:autoscript
npm run test:desktop
npm run test:signing
npm run test:browser-signing
# After building the Debian bundle above (x86-64):
FIRMICA_DEB=target/dx/firmica/bundle/linux/deb/firmica_0.1.0_amd64.deb npm run test:desktop
FIRMICA_DEB=target/dx/firmica/bundle/linux/deb/firmica_0.1.0_amd64.deb npm run test:signing
FIRMICA_DEB=target/dx/firmica/bundle/linux/deb/firmica_0.1.0_amd64.deb npm run test:browser-signing
npm run test:native-interop
npm run test:os-handler
FIRMICA_DEB=target/dx/firmica/bundle/linux/deb/firmica_0.1.0_amd64.deb npm run test:os-handler
npm run test:lifecycle
```

The signing window tests additionally need `zenity`, `openbox`, `xclip`, and `dbus-run-session`. They use a disposable XDG profile, session bus, clipboard, and Xvfb display. Browser signing tests use unmodified AutoScript and Firefox’s OS handler, verify RSA/P-256 output with OpenSSL, and check that worker failure and navigation cancellation return no signature. They include 1 MiB detached and 16 MiB attached documents, reject oversized documents before opening a key, and sign using an automatically loaded TLS profile. Provisioning tests check permissions, symlinks, concurrent setup, mismatched keys, expiry and certificate constraints. Transport tests require the OpenSSL CLI and exercise whole/fragmented messages, session authentication and size limits over ephemeral TLS connections.

The lifecycle test uses the 60 s synchronous-review and 120 s listener deadlines and takes about two minutes. Browser tests need OpenSSL and the selected browsers' system libraries. The Linux native smoke test additionally needs Xvfb, `xauth`, `xdotool`, `gio`, and `update-desktop-database`; it uses the release artifact built by `dx`. The extracted Debian payload test also needs `ar`, `tar`, `md5sum`, and `desktop-file-validate`. It uses the packaged desktop entry without rewriting it and leaves the system handler unchanged. The Firefox OS-handler test also needs `certutil` (NSS tools) and `dbus-run-session`. It preapproves `afirma` in a disposable profile. Results and a browser screenshot are saved under `.test-artifacts/linux-os-handler/`; `FIRMICA_SCREENSHOT=/absolute/path.png` adds a native-window screenshot when ImageMagick is installed. AutoScript is fetched at a pinned revision with a SHA-256 check and cached under `.test-artifacts/`. Set `FIRMICA_AUTOSCRIPT` to an existing unmodified file to run offline. It is not bundled with Firmica.

For native Android invocation checks, build a debug APK with `dx build --locked --package mobile --platform android --target x86_64-linux-android`, then run `python3 tests/interop/android.py --serial emulator-5554 --apk /path/to/app-debug.apk`. The script refuses physical devices. Add `--browser org.mozilla.firefox` to check browser links with Firefox already installed in the emulator.

On Windows, run `python tests/interop/windows.py --app target/dx/firmica/debug/windows/app/firmica.exe` after the desktop build. It requires OpenSSL and a desktop session, opens the real application, checks warm URI delivery and crash recovery, and saves evidence under `.test-artifacts/windows/`. It uses a temporary TLS identity without changing trust stores or URI associations. This checks command-line invocation; installer and browser handler selection need separate testing.

On macOS with Xcode 16.4 and the iOS 18.5 Simulator runtime, run:

```sh
dx build --locked --package mobile --platform ios --target aarch64-apple-ios-sim
python3 tests/interop/ios.py --app target/dx/mobile/debug/ios/Mobile.app
```

The iOS test creates a temporary iPhone simulator and opens synthetic links from Safari. It saves XCTest results and screenshots under `.test-artifacts/ios/` and deletes the simulator when finished.

The GTK dependencies require `glib 0.18.5`. Its vendored source applies the [upstream iterator fix](https://github.com/gtk-rs/gtk-rs-core/commit/05dff0ee696f9bcd8617cd48c4b812d046d440cb) for RUSTSEC-2024-0429. The vendored `phf_generator 0.8.0` uses patched `rand 0.8` instead of `rand 0.7`. Both retain their upstream package versions; source provenance and exact diffs are recorded in `tools/backports.toml` and `tools/backports/`.

Run `python3 tools/audit-dependencies.py` with Python 3.11+ and `cargo-audit 0.22.2`. It verifies the complete vendored source fingerprints and audits their original registry identities, since plain `cargo audit` skips path dependencies. The raw report remains visible: the GLib version finding is accepted only for the verified fixed source; other unsoundness findings and vulnerabilities fail. Unmaintained dependency warnings remain visible. CI also runs `cargo test --release --locked -p firmica-dependency-checks` to exercise the fixes with compiler optimizations.

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

The key-worker library keeps unlocked PKCS#12 keys in a separate Linux or Windows process. Linux applies address-space and CPU limits. Windows starts the worker suspended, assigns a job with committed-memory, user CPU and child-process limits, and kills it when the parent loses its job handle. Pipe operations have deadlines, and successful close is required before consuming signatures. Other platforms reject worker imports. Windows requests WER no-heap/no-UI reporting; privileged dumps and machine dump policies remain outside that guarantee. API contracts and limits are documented with rustdoc. The desktop application uses this worker for document signing on Linux and Windows.

On Windows, build the process-control fixture with `cargo build --locked -p firmica-key-worker --example worker-fixture` before running the worker tests. They check native limit enforcement, blocked pipe deadlines, abandonment, process loss and RSA/P-256 CAdES output independently verified by OpenSSL. The fixture uses synthetic data and never opens a certificate store. After building the desktop application, set `FIRMICA_TEST_WORKER` to the absolute companion executable path and run `cargo test --locked -p desktop -- --ignored --test-threads=1` for the desktop signing and cleanup tests.

For native Windows dialog tests, install `playwright==1.58.0` and `pywinauto==0.6.9`, then run `python tests/interop/windows-signing.py --app /path/to/firmica.exe`. The test opens real file dialogs, checks consent and cancellation, and verifies RSA/P-256 output with OpenSSL. It enables WebView2 inspection only in its synthetic test process and saves evidence under `.test-artifacts/windows-signing/`. CI runs it against an extracted debug portable bundle (`python tools/build-desktop.py bundle --debug`).

`firmica-validation` checks local leaf-certificate restrictions for document signing: validity, key usage, extended key usage, CA usage and private-key usage periods. It rejects unhandled critical extensions and malformed constraints. It does not verify certificate signatures, chain trust, revocation or legal qualification. The core CAdES review API binds approval to the selected document bytes, certificate identity, algorithm and content mode, then rechecks the certificate before using the key. Provider cleanup must succeed before publishing output. The Linux desktop signing screen uses this review API.

Original code targets GPL-3.0-or-later. Third-party dependencies and reference assets retain their own licences.
