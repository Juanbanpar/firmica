# Firmica

Rust electronic-signature client using Dioxus 0.7.10 and Tailwind CSS 4, targeting existing AutoFirma browser integrations.

The Linux and Windows desktop applications sign local documents and supported AutoScript requests in CAdES, PAdES and XAdES formats using PKCS#12 certificates. Browser signing requires local TLS setup, browser trust and certificate review. Bare `afirma://sign` invocations support review and cancellation only. Certificate trust, revocation and legal qualification are not validated.

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
cargo xtask build
./target/dx/firmica/debug/linux/app/firmica
# Release application and Debian package:
cargo xtask bundle
```

The Rust build task invokes Cargo and Dioxus from this checkout. It stages the worker for bundling and places it beside the development executable. The package includes `firmica`, `firmica-key-worker`, and the `afirma` desktop handler. Both executables must remain in a trusted installation directory. Install Linux runtime dependencies separately; the Debian package does not declare them. Linux file dialogs use a desktop portal or the `zenity` fallback.

On x64 Windows, install the MSVC build tools, WebView2 Runtime, and a patched shared OpenSSL 3 distribution with x64 import libraries. In PowerShell, set its build paths and build from the workspace root:

```powershell
$env:OPENSSL_DIR = 'C:\Program Files\OpenSSL'
$env:OPENSSL_LIB_DIR = "$env:OPENSSL_DIR\lib\VC\x64\MD"
$env:OPENSSL_STATIC = '0'
cargo xtask build
.\target\dx\firmica\debug\windows\app\firmica.exe
# Release portable ZIP:
cargo xtask bundle
```

The Windows builder copies `libcrypto-3-x64.dll`, `libssl-3-x64.dll` and the distribution's license from `OPENSSL_DIR` beside the application and worker. The ZIP is written under `target/dx/firmica/bundle/windows/`; extract it to a trusted directory and keep its contents together. WebView2 and the MSVC runtime must be installed separately. Update the bundled OpenSSL DLLs when rebuilding with security fixes. Registration is an explicit per-user step using the included `handler.ps1`; extracting the ZIP does not change associations. Windows dialogs use `rfd`; selected documents must be regular files, and file reparse points are rejected. Local signing is unavailable on macOS and mobile.

## Local signing

Open **Sign a document**, select a document and a `.p12`/`.pfx` certificate, and enter its password. Choose a format and RSA PKCS#1 v1.5/SHA-256 or ECDSA P-256/SHA-256. RSA keys must have at least 2048 bits. Documents are limited to 16 MiB and containers to 8 MiB. Empty binary documents and empty passwords are supported.

- **CAdES:** attached or detached CMS signatures. Retain the original bytes when choosing detached.
- **PAdES:** incremental PDF approval signatures; earlier revisions remain intact. Choose an invisible signature or configure a page, rectangle and one-line ASCII label. Encrypted, certified, locked and XFA PDFs are rejected. Earlier PDF signatures are preserved but not validated.
- **XAdES:** enveloped UTF-8 XML, or exact binary content embedded inside the signature (enveloping) or alongside it (internally detached). Enveloped signatures cover canonical XML without comments. DTDs, duplicate/reserved IDs, `xml:base` and existing XML signatures are rejected. References and transforms are fixed; no external resources are resolved.

The encoders use baseline B-B building blocks; no conformance assessment, trusted timestamps, long-term validation evidence or signature policies are provided. Output extensions are `.csig`, `.pdf` and `.xsig` respectively.

**Open and review** shows the frozen document's name, size and SHA-256, the certificate's claimed subject/issuer, serial, fingerprint and validity, and the signing choices. The certificate signature, chain trust, revocation and legal qualification remain unchecked. Approval requires acknowledging those unchecked items. **Sign and save** opens a destination dialog; cancelling it preserves the review. **Cancel** closes the certificate worker without signing.

Choose a new destination: existing files and symlinks are never replaced. Output is published only after signing and worker cleanup succeed. Linux outputs use mode 0600; Windows outputs inherit the destination directory ACL, so choose a private directory. For a detached signature, retain the exact original document alongside the `.csig` file. Changing the source file after review does not change the bytes signed. No system certificate store is opened, and browser requests cannot authorize this local workflow.

## Invocation

On Linux, use the packaged executable with a quoted URI:

```sh
./target/dx/firmica/release/linux/app/firmica 'afirma://sign?ver=4&format=CAdES&algorithm=SHA256withRSA&dat=c3ludGhldGlj'
```

Subsequent invocations are forwarded to the running instance through a private per-user Unix socket. A WSS review expires when its transport stops accepting decisions; asynchronous reconnects preserve the review within the session. Bare URI requests cannot receive a signature: **Reject** cancels, and **Acknowledge review** reports that the operation is unsupported.

On Windows, `firmica.exe "afirma://save?ver=4"` forwards subsequent launches to the running application through a local named pipe restricted to the same logon session. Delivery is acknowledged only after a valid URI enters the bounded application queue; busy or unresponsive instances cause the secondary process to fail. From the extracted Windows bundle, create the private browser TLS profile and register the handler:

```powershell
.\firmica.exe tls init --origin 'https://example.org'
.\firmica.exe tls status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\handler.ps1 -Action Install
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\handler.ps1 -Action Status
# Before removing or moving this bundle:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\handler.ps1 -Action Uninstall
```

Registration adds Firmica to this user's applications and uses the quoted bundle executable for cold launches. Without TLS arguments it first validates the private profile, which the application loads automatically. An existing `afirma` handler and protected Windows default choices are preserved; select Firmica for `afirma` in **Settings > Apps > Default apps** when another application is selected. Uninstall removes only this bundle's registration. Re-register after moving the bundle. Static installation/TLS paths containing percent signs are rejected because Windows uses percent sequences as association placeholders.

Windows stores the profile under the current user's Local AppData known folder in `firmica-config\browser-tls`, separate from WebView2 data. Directories and files have protected ACLs granting access only to that user. Reparse points, public access, mismatched keys, incomplete profiles and invalid or expired identities are rejected. Administrative access remains outside this protection. Browser trust is an explicit import step using the printed CA fingerprint. Registration does not install trust or generate keys. To use an existing TLS identity instead, supply all of `-TlsCertificate`, `-TlsKey` and `-Origin` to `handler.ps1`, or launch with `--tls-cert`, `--tls-key` and `--origin`; its certificate must cover `127.0.0.1` and the requesting browser must trust its issuer.

With an installed Linux package, create the per-user browser TLS profile once, using the exact website origin without a trailing slash:

```sh
firmica tls init --origin https://example.org
firmica tls status
```

The TLS commands work without a graphical session on Linux and Windows. On Linux, the profile lives in `$XDG_CONFIG_HOME/firmica/browser-tls`, or `$HOME/.config/firmica/browser-tls` when `XDG_CONFIG_HOME` is unset. Its directories are private and its files have mode `0600`. On both platforms, setup never replaces an existing profile. It creates a unique CA and a server certificate for `127.0.0.1`, valid for 365 days. The CA includes name constraints for `localhost` and `127.0.0.1`; its signing key is discarded after issuing the server certificate. Only the server key is stored.

Setup prints the public `ca.pem` path and its SHA-256 fingerprint. Check that fingerprint before importing the CA into the intended browser profile for website authentication. In Firefox, use **Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**. The TLS commands do not install trust entries, change TLS verification or alter URI associations. Keep browser trust scoped to the profile that needs it.

Restart Firmica after setup. The packaged `afirma` handler loads this profile automatically, including on a cold browser launch, and permits only the configured origin. To change websites, edit the profile's `origin` file to contain one exact HTTP(S) origin and restart. To renew an expired identity, stop Firmica, move the private `browser-tls` directory aside and run `tls init` again. Import the new CA and remove the old browser trust entry; renewal cannot reuse the discarded CA key. Missing, expired, mismatched or insecure profile files cause startup to fail.

Explicit TLS settings override the per-user profile. Supply all three options to the first process:

```sh
./target/dx/firmica/release/linux/app/firmica \
  --tls-cert /path/to/test-cert.pem --tls-key /path/to/test-key.pem \
  --origin http://127.0.0.1:8080 \
  'afirma://websocket?v=4&jvc=4&ports=49152,49153,49154&idsession=0123456789abcdef'
```

On Linux and Windows, protocol 4.x WSS `sign` requests can return a signature after certificate selection and explicit approval. Supported requests contain an inline Base64 document and `algorithm=SHA256withRSA` or `SHA256withECDSA` (P-256 only). WebSocket documents may contain up to 16 MiB of decoded data. The encoded request is bounded by the Base64 size of that document plus 64 KiB of metadata; other parameters together remain limited to 64 KiB. Native OS invocations and control messages retain the 64 KiB limit. Only PKCS#12 selection is supported; a request may omit the store or specify `ksb64` encoding `PKCS12`. Firefox’s AutoScript default requests its Mozilla store, so a PKCS#12 integration must call `AutoScript.setKeyStore(AutoScript.KEYSTORE_PKCS12)`. Sticky certificate reuse, other certificate stores, remote document URLs, precomputed digests, signature policies and unknown options are unsupported. Other operations retain review/cancellation behavior.

The signing screen fixes the document and signing choices from the request, shows their hash and the selected certificate, and warns that the request origin is unauthenticated. **Sign and send to browser** returns the reviewed certificate and signed result to that session after worker cleanup; no destination file is written. Navigating away cancels the request. Each bootstrap admits one operation, its result can be retrieved once, and the listener expires after 120 seconds. A new bootstrap can start after the listener ends.

Do not install test certificates globally. Chromium tests pin one ephemeral public key. The Firefox OS-handler test provisions TLS with `firmica tls init`, trusts its CA only in a disposable profile and checks that a fresh profile rejects it. Tests use an isolated XDG association without replacing the user's default handler.

Supported format properties are deliberately limited:

| Request format | Extra properties |
| --- | --- |
| `CAdES` | `mode=explicit` (detached, default) or `mode=implicit` (attached) |
| `PAdES` | Invisible by default. A visible appearance requires `signaturePage` (positive, one-based), all four coordinates (`signaturePositionOnPageLowerLeftX`, `signaturePositionOnPageLowerLeftY`, `signaturePositionOnPageUpperRightX`, `signaturePositionOnPageUpperRightY`) and `layer2Text` (printable ASCII, at most 120 characters). The rectangle must fit the page. |
| `XAdES` | `format=XAdES Enveloped`, `XAdES Enveloping` (default) or `XAdES Detached`. These names are also accepted as the request format. Optional `mode=implicit`; explicit/prehashed XML mode is rejected. |

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

The signing window tests additionally need `zenity`, `openbox`, `xclip`, and `dbus-run-session`. They use a disposable XDG profile, session bus, clipboard, and Xvfb display. Browser signing tests use unmodified AutoScript and Firefox’s OS handler, verify CAdES with OpenSSL, PAdES with Poppler and XAdES with XMLSec, and check that worker failure and navigation cancellation return no signature. They include 1 MiB detached and 16 MiB attached documents, reject oversized documents before opening a key, and sign using an automatically loaded TLS profile. Provisioning tests check permissions, symlinks, concurrent setup, mismatched keys, expiry and certificate constraints. Transport tests require the OpenSSL CLI and exercise whole/fragmented messages, session authentication and size limits over ephemeral TLS connections.

The lifecycle test uses the 60 s synchronous-review and 120 s listener deadlines and takes about two minutes. Browser tests need OpenSSL and the selected browsers' system libraries. The Linux native smoke test additionally needs Xvfb, `xauth`, `xdotool`, `gio`, and `update-desktop-database`; it uses the release artifact built by `dx`. The extracted Debian payload test also needs `ar`, `tar`, `md5sum`, and `desktop-file-validate`. It uses the packaged desktop entry without rewriting it and leaves the system handler unchanged. The Firefox OS-handler test also needs `certutil` (NSS tools) and `dbus-run-session`. It preapproves `afirma` in a disposable profile. Results and a browser screenshot are saved under `.test-artifacts/linux-os-handler/`; `FIRMICA_SCREENSHOT=/absolute/path.png` adds a native-window screenshot when ImageMagick is installed. AutoScript is fetched at a pinned revision with a SHA-256 check and cached under `.test-artifacts/`. Set `FIRMICA_AUTOSCRIPT` to an existing unmodified file to run offline. It is not bundled with Firmica.

For native Android invocation checks, build a debug APK with `dx build --locked --package mobile --platform android --target x86_64-linux-android`, then run `FIRMICA_TEST_APK=/path/to/app-debug.apk ANDROID_SERIAL=emulator-5554 cargo test --locked -p xtask --test android -- --ignored --nocapture`. The test refuses physical devices. Set `FIRMICA_TEST_BROWSER=org.mozilla.firefox` to check browser links with Firefox already installed in the emulator.

On Windows, set `$env:FIRMICA_TEST_APP = 'target/dx/firmica/debug/windows/app/firmica.exe'` and run `cargo test --locked -p xtask --test windows_invocation -- --ignored --nocapture` after the desktop build. It requires OpenSSL and a desktop session, opens the real application, checks warm URI delivery and crash recovery, and saves evidence under `.test-artifacts/windows/`. It uses a temporary TLS identity without changing trust stores or URI associations. This checks command-line invocation; installer and browser handler selection need separate testing.

On macOS with Xcode 16.4 and the iOS 18.5 Simulator runtime, run:

```sh
dx build --locked --package mobile --platform ios --target aarch64-apple-ios-sim
FIRMICA_TEST_APP=target/dx/mobile/debug/ios/Mobile.app cargo test --locked -p xtask --test ios -- --ignored --nocapture
```

The Rust iOS test runs the native Swift XCTest scenario in a temporary iPhone simulator and opens synthetic links from Safari. It saves XCTest results and screenshots under `.test-artifacts/ios/` and deletes the simulator when finished.

Dependencies use upstream crates without local patches. The transitive GTK dependencies include accepted unsoundness advisories for [GLib (RUSTSEC-2024-0429)](https://rustsec.org/advisories/RUSTSEC-2024-0429.html) and [rand (RUSTSEC-2026-0097)](https://rustsec.org/advisories/RUSTSEC-2026-0097.html). Run `cargo audit --deny unsound` with `cargo-audit 0.22.2` to see all findings. CI accepts these two advisories with explicit `--ignore` arguments; other vulnerabilities and unsoundness findings still fail.

Domain logic, protocol, transport, signing, build tooling and OS invocation checks use Cargo tests. JavaScript is limited to browser/WebView automation with Playwright and the upstream AutoScript fixture. Python is limited to Windows GUI automation with Playwright/pywinauto. Swift XCTest exercises Safari and native iOS dialogs. These end-to-end checks complement the Rust tests.

The signing libraries can be tested separately from the applications. They require patched OpenSSL development headers/libraries and the OpenSSL CLI; see the [OpenSSL build requirements](https://docs.rs/openssl/0.10.81/openssl/#building). Set `OPENSSL_DIR` and, when needed, `OPENSSL_LIB_DIR` for a native installation outside the compiler's search paths.

```sh
cargo test --locked -p firmica-signing -p firmica-certificates -p firmica-cades -p firmica-pades -p firmica-xades -p firmica-key-worker -p firmica-validation --features pkcs11
cargo doc --locked -p firmica-signing -p firmica-certificates -p firmica-cades -p firmica-pades -p firmica-xades -p firmica-key-worker -p firmica-validation --features pkcs11 --no-deps
# Java 17+; downloads checksum-pinned, test-only AutoFirma 1.9.1 reference jars:
cargo test --locked -p firmica-cades --test encoding autofirma_reference -- --ignored --test-threads=1
# Poppler and XMLSec (OpenSSL backend) independently verify PDF/XML output:
cargo test --locked -p firmica-pades --test encoding poppler_ -- --ignored
cargo test --locked -p firmica-xades --test encoding xmlsec_ -- --ignored
# With SoftHSM and softhsm2-util installed; use your platform's module path:
FIRMICA_PKCS11_MODULE=/path/to/libsofthsm2.so cargo test --locked -p firmica-certificates --features pkcs11 --test pkcs11 -- --ignored --test-threads=1
```

The SoftHSM test creates a disposable token store and uses synthetic, non-exportable RSA/P-256 keys. PKCS#12 tests cover encrypted containers, passwords, malformed input and message/digest signing. CAdES tests verify attached and detached signatures with the OpenSSL CLI, check certificate binding, and reject modified content. The token test also exercises CAdES encoding. No existing certificate store is opened.

The key-worker library keeps unlocked PKCS#12 keys in a separate Linux or Windows process. Linux applies address-space and CPU limits. Windows starts the worker suspended, assigns a job with committed-memory, user CPU and child-process limits, and kills it when the parent loses its job handle. Pipe operations have deadlines, and successful close is required before consuming signatures. Other platforms reject worker imports. Windows requests WER no-heap/no-UI reporting; privileged dumps and machine dump policies remain outside that guarantee. API contracts and limits are documented with rustdoc. The desktop application uses this worker for document signing on Linux and Windows.

On Windows, build the process-control fixture with `cargo build --locked -p firmica-key-worker --example worker-fixture` before running the worker tests. They check native limit enforcement, blocked pipe deadlines, abandonment, process loss and RSA/P-256 CAdES output independently verified by OpenSSL. The fixture uses synthetic data and never opens a certificate store. After building the desktop application, set `FIRMICA_TEST_WORKER` to the absolute companion executable path and run `cargo test --locked -p desktop -- --ignored --test-threads=1` for the desktop signing and cleanup tests.

For native Windows dialog tests, install `playwright==1.58.0`, `pywinauto==0.6.9` and `Pillow==12.1.0`, then run `python tests/interop/windows-signing.py --app /path/to/firmica.exe`. The test opens real file dialogs, checks consent and cancellation, and verifies RSA/P-256 output with OpenSSL. It enables WebView2 inspection only in its synthetic test process and saves evidence under `.test-artifacts/windows-signing/`. CI runs it against an extracted debug portable bundle (`cargo xtask bundle --debug`).

`firmica-validation` checks local leaf-certificate restrictions for document signing: validity, key usage, extended key usage, CA usage and private-key usage periods. It rejects unhandled critical extensions and malformed constraints. It does not verify certificate signatures, chain trust, revocation or legal qualification. The core signing review API binds approval to the selected document bytes, certificate identity, algorithm and format choices, then rechecks the certificate before using the key. Provider cleanup must succeed before publishing output. The Linux and Windows desktop signing screens use this review API.

Original code targets GPL-3.0-or-later. Third-party dependencies and reference assets retain their own licences.

The manually dispatched **Windows bundle QA** workflow can replay the native dialog and browser tests against a CI run’s `windows-invocation` artifact. It checks that the application and builder sources match the current checkout before testing the extracted ZIP.

For Windows browser interoperability tests, install the native UI test tooling above and Firefox with `python -m playwright install firefox`, then run `python tests/interop/windows-browser.py --app /path/to/firmica.exe` on a disposable Windows account with no existing `afirma` association. The test uses the bundled registration script, unmodified pinned AutoScript, the packaged TLS provisioning commands, a private Firefox copy/profile trusting the generated CA, real native consent, and OpenSSL verification. A separate fresh Firefox profile must reject that CA. It checks cold launch, warm delivery, cancellation and RSA/P-256 results, then removes its newly generated TLS profile and registration. The test refuses an existing Firmica configuration and takes about five minutes because it waits for two actual listener lifetimes. It does not reset protected Windows defaults or alter OS trust. Evidence is saved under `.test-artifacts/windows-browser/`.
