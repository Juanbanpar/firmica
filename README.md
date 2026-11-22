# Firmica

Rust electronic-signature client using Dioxus 0.7.10 and Tailwind CSS 4, targeting existing AutoFirma browser integrations.

The Linux, macOS and Windows desktop applications sign local documents and supported AutoScript requests in CAdES, PAdES and XAdES formats using PKCS#12 certificates. Browser signing requires local TLS setup, browser trust and certificate review. Bare `afirma://sign` invocations support review and cancellation only. Certificate trust, revocation and legal qualification are not validated.

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
# Release application and Debian package (Debian or Ubuntu with dpkg-dev):
cargo xtask bundle
```

The build task stages the worker beside the development executable. Debian packaging uses `dpkg-shlibdeps` from `dpkg-dev` to declare the libraries and minimum versions required by both executables, including WebKitGTK and OpenSSL. Build on the oldest Debian or Ubuntu release you intend to support and use APT to resolve the package dependencies. The `.deb` includes both executables under `/usr/bin`, the `afirma` desktop entry, an icon and the project license notice. File dialogs use a desktop portal with a backend for the current desktop session, or the `zenity` fallback. [Debian shared-library dependencies](https://manpages.debian.org/dpkg-shlibdeps)

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

The ZIP under `target/dx/firmica/bundle/windows/` includes the x64 application and worker, both OpenSSL 3 DLLs, their license, the project license, generated assets and `handler.ps1`. Extract it to a trusted directory and keep its contents together. Install the Evergreen WebView2 Runtime and the x64 Visual C++ Redistributable separately. Rebuild with patched OpenSSL to update the bundled DLLs. [WebView2 Runtime](https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution), [Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist/)

Registration is an explicit per-user step using `handler.ps1`, which resolves the adjacent executable from the script's location. Windows dialogs use `rfd`, and file inputs must be regular files without reparse points. Local signing is unavailable on mobile.

On macOS 15 or later, install Xcode command-line tools and OpenSSL development libraries, then build natively for Apple Silicon or Intel:

```sh
brew install openssl@3
export OPENSSL_DIR="$(brew --prefix openssl@3)"
cargo xtask build
# Release development bundle:
cargo xtask bundle
```

The macOS packager statically links OpenSSL and places the worker in `Contents/MacOS`. It checks both executables' architecture, deployment target and system library dependencies, then applies ad-hoc signatures. It extracts the architecture-specific ZIP under `target/dx/firmica/bundle/macos/` to verify the relocated app, its resources and its signatures. Extract the whole `.app` into a trusted directory, such as `~/Applications`, and launch it with `open`. The app uses native `rfd` file dialogs. Worker binaries, private TLS entries and new signature files must have no extended ACLs because those grants can bypass POSIX mode restrictions. Rebuild to incorporate OpenSSL security updates.

CI produces ad-hoc signed development bundles. Distribution outside the Mac App Store requires a Developer ID Application certificate, Hardened Runtime and a secure timestamp. Sign the worker before signing the enclosing app, then notarize with Apple's `notarytool` and staple the ticket to the app before creating the final ZIP. [Apple Developer ID](https://developer.apple.com/developer-id/), [Apple notarization workflow](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)

The application declares the `afirma` URL scheme for LaunchServices. Launch the installed application once and select Firmica when the browser asks which application should open `afirma` links. Existing default-handler choices are not changed by Firmica. Cold and warm URL deliveries use the native application event loop. Configure browser TLS using the executable inside the installed bundle:

```sh
"$HOME/Applications/Firmica.app/Contents/MacOS/firmica" tls init --origin https://example.org
"$HOME/Applications/Firmica.app/Contents/MacOS/firmica" tls status
```

## Local signing

Open **Sign a document** and select a document up to 16 MiB. For a `.p12` or `.pfx` file up to 8 MiB, enter its password and choose the matching algorithm. Empty binary documents and PKCS#12 passwords are supported.

On Windows, **Certificate source** also offers **Windows · Current User** and **Windows · Local Machine**. Select a store, then a certificate. Firmica displays its signing algorithm and can refresh the list without opening a private key. Windows may request authorization when you sign after review. Machine-store keys must already be accessible to your account.

Firmica supports RSA PKCS#1 v1.5/SHA-256 with keys of at least 2048 bits and ECDSA P-256/SHA-256. Choose a signature format:

- **CAdES:** attached or detached CMS signatures. Retain the original bytes when choosing detached.
- **PAdES:** incremental PDF approval signatures; earlier revisions remain intact. Choose an invisible signature or configure a page, rectangle and one-line ASCII label. Encrypted, certified, locked and XFA PDFs are rejected. Earlier PDF signatures are preserved but not validated.
- **XAdES:** enveloped UTF-8 XML, or exact binary content embedded inside the signature (enveloping) or alongside it (internally detached). Enveloped signatures cover canonical XML without comments; this mode rejects DTDs, duplicate/reserved IDs, `xml:base` and existing XML signatures. References and transforms are fixed; no external resources are resolved.

The encoders use baseline B-B building blocks; no conformance assessment, trusted timestamps, long-term validation evidence or signature policies are provided. Output extensions are `.csig`, `.pdf` and `.xsig` respectively.

**Open and review** shows the frozen document's name, size and SHA-256, the certificate's claimed subject/issuer, serial, fingerprint and validity, and the signing choices. The certificate signature, chain trust, revocation and legal qualification remain unchecked. Approval requires acknowledging those unchecked items. **Sign and save** opens a destination dialog. Dismissing it preserves the review. **Cancel** closes the signing session and returns to selection. PKCS#12 requires its password again for each new review. **Stop operation** requests cancellation while Firmica is opening the certificate or signing.

Choose a new destination: existing files and symlinks are never replaced. Output is published only after signing and provider cleanup succeed. Linux and macOS outputs use mode 0600; Windows outputs inherit the destination directory ACL, so choose a private directory. For a detached signature, retain the exact original document alongside the `.csig` file. Changing the source file after review does not change the bytes signed. Browser requests use the separate browser review flow.

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

The TLS commands work without a graphical session on Linux, macOS and Windows. On Linux, the profile lives in `$XDG_CONFIG_HOME/firmica/browser-tls`, or `$HOME/.config/firmica/browser-tls` when `XDG_CONFIG_HOME` is unset. Its directories are private and its files have mode `0600`. On macOS, the profile lives in `$HOME/Library/Application Support/org.firmica.client/browser-tls`, with the same private directory and file permissions. Setup never replaces an existing profile. It creates a unique CA and a server certificate for `127.0.0.1`, valid for 365 days. The CA includes name constraints for `localhost` and `127.0.0.1`; its signing key is discarded after issuing the server certificate. Only the server key is stored.

Setup prints the public `ca.pem` path and its SHA-256 fingerprint. Check that fingerprint before importing the CA into the intended browser profile for website authentication. In Firefox, use **Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import**. The TLS commands do not install trust entries, change TLS verification or alter URI associations. Keep browser trust scoped to the profile that needs it.

Open **Browser setup** to create the profile, check its status and expiration, and authorize or revoke website origins. This screen shows the public trust certificate path and fingerprint for manual browser import. The packaged `afirma` handler loads the profile automatically, including on a cold browser launch. Origin entries require an exact HTTP(S) origin including any non-default port. Wildcards and paths are rejected. The same list is available from the command line.

```sh
firmica tls origins list
firmica tls origins add https://signing.example.org
firmica tls origins remove https://example.org
```

All origins use the same loopback TLS identity and existing browser trust. Firmica reads the current list for each new listener. Changes take effect on the next listener, after any active listener ends or Firmica quits. Each session stays bound to the origin of its first authenticated message, including when the browser reconnects to retrieve the result. Removing every origin disables new browser sessions.

To renew an expired identity, stop Firmica, move the private `browser-tls` directory aside, and create a new profile. Re-add any other authorized origins. Import the new CA and remove the old browser trust entry, since renewal cannot reuse the discarded CA key. Missing, expired, mismatched or insecure profiles prevent browser signing and can be diagnosed in **Browser setup**.

Explicit TLS settings override the per-user profile. Supply all three options to the first process:

```sh
./target/dx/firmica/release/linux/app/firmica \
  --tls-cert /path/to/test-cert.pem --tls-key /path/to/test-key.pem \
  --origin http://127.0.0.1:8080 \
  'afirma://websocket?v=4&jvc=4&ports=49152,49153,49154&idsession=0123456789abcdef'
```

On Linux, macOS and Windows, protocol 4.x WSS `sign` requests can return a signature after certificate selection and explicit approval. Supported requests contain an inline Base64 document and `algorithm=SHA256withRSA` or `SHA256withECDSA` (P-256 only). WebSocket documents may contain up to 16 MiB of decoded data. The encoded request is bounded by the Base64 size of that document plus 64 KiB of metadata; other parameters together remain limited to 64 KiB. Native OS invocations and control messages retain the 64 KiB limit. Only PKCS#12 selection is supported; a request may omit the store or specify `ksb64` encoding `PKCS12`. Firefox’s AutoScript default requests its Mozilla store, so a PKCS#12 integration must call `AutoScript.setKeyStore(AutoScript.KEYSTORE_PKCS12)`. Sticky certificate reuse, other certificate stores, remote document URLs, precomputed digests, signature policies and unknown options are unsupported. Other operations retain review/cancellation behavior.

AutoScript 1.10.1 advertises `v=4&jvc=4`, which selects asynchronous protocol 4.1 and structured error codes. Older script codes can use synchronous protocol 4 with legacy errors. Signing properties accept UTF-8, comments, and Java property separators such as `mode=explicit` and `mode : explicit`. Escapes, continuations and duplicate keys are rejected. Unsupported sign options return an error before review.

The signing screen shows the browser origin checked by the listener, the document hash, the fixed signing choices and the selected certificate. Direct URI invocations do not provide a verified browser origin. **Sign and send to browser** returns the reviewed certificate and signed result to that session after worker cleanup. Navigating away cancels the request. Each bootstrap admits one operation, its result can be retrieved once, and the listener expires after 120 seconds. A new bootstrap can start after the listener ends.

Do not install test certificates globally. Chromium tests pin one ephemeral public key. The Firefox OS-handler test provisions TLS with `firmica tls init`, trusts its CA only in a disposable profile and checks that a fresh profile rejects it. Tests use an isolated XDG association without replacing the user's default handler.

Supported format properties are deliberately limited:

| Request format | Extra properties |
| --- | --- |
| `CAdES` | `mode=explicit` (detached, default) or `mode=implicit` (attached) |
| `PAdES` | Invisible by default. A visible appearance requires `signaturePage` (positive, one-based), all four coordinates (`signaturePositionOnPageLowerLeftX`, `signaturePositionOnPageLowerLeftY`, `signaturePositionOnPageUpperRightX`, `signaturePositionOnPageUpperRightY`) and `layer2Text` (printable ASCII, at most 120 characters). The rectangle must fit the page. |
| `XAdES` | `format=XAdES Enveloped`, `XAdES Enveloping` (default) or `XAdES Detached`. These names are also accepted as the request format. Optional `mode=implicit`; explicit/prehashed XML mode is rejected. |

## Verify

Generate the required assets before Cargo checks. The mobile build checks its host entry point.

```sh
dx build --locked --package desktop --platform desktop
dx build --locked --package mobile --platform desktop --features mobile
cargo fmt --all --check
cargo test --locked -p firmica-protocol -p firmica-core -p firmica-transport -p xtask -p desktop -p mobile
cargo clippy --locked -p firmica-protocol -p firmica-core -p firmica-transport -p xtask -p ui -p desktop -p mobile --all-targets -- -D warnings
cargo doc --locked -p firmica-protocol -p firmica-core -p firmica-transport --no-deps
```

Rust tests cover signing review, certificate validation, worker cleanup and safe output. Transport tests use the OpenSSL CLI to create ephemeral TLS credentials and exercise authentication, deadlines, replay, message size limits and fragmentation.

On Linux, run the headless browser protocol checks:

```sh
npm ci
npx playwright install --with-deps chromium firefox
cargo build --locked -p firmica-transport --example probe
npm run test:autoscript
cargo test --locked -p firmica-transport protocol_41_in_chromium_and_firefox -- --ignored --nocapture
```

The AutoScript test captures the URI emitted by unmodified AutoScript and hands it to a headless Rust peer. The fixture is checksum-verified and cached under `.test-artifacts/`. Set `FIRMICA_AUTOSCRIPT` to an existing copy to use it offline. The Chromium and Firefox wire tests exercise protocol 4.1 outcomes, reconnects and one-time result delivery. Firefox needs `certutil` (NSS tools) for its temporary trust store. Results are saved under `.test-artifacts/protocol41/`.

After building the x86-64 Debian bundle, inspect its dependency metadata, checksums, desktop entry, icon and file permissions with `dpkg-deb`, `md5sum` and `desktop-file-validate`:

```sh
FIRMICA_DEB="$PWD/target/dx/firmica/bundle/linux/deb/firmica_0.1.0_amd64.deb" \
    cargo test --locked -p xtask --test debian -- --ignored
```

Native dialog behavior, operating-system handler registration and delivery, browser-to-desktop signing, and Android and iOS invocation require manual verification.

### Parser regression corpus and fuzzing

Ordinary CI checks synthetic accepted and rejected inputs for invocation URIs, signing properties, WebSocket messages, worker IPC, and PDF and XML preflight.

```sh
cargo test --locked --manifest-path fuzz/Cargo.toml --lib
```

On Linux, install a C++ compiler and OpenSSL development headers. Use the pinned nightly and `cargo-fuzz` to run a bounded AddressSanitizer session. List the available target names with `cargo +nightly-2026-11-14 fuzz list`.

```sh
rustup toolchain install nightly-2026-11-14 --profile minimal
cargo install cargo-fuzz --locked --version 0.13.2
cargo +nightly-2026-11-14 fetch --locked --manifest-path fuzz/Cargo.toml
target=uri_query
sandbox=$(mktemp -d)
mkdir -p "$sandbox/corpus" "$sandbox/artifacts"
CARGO_NET_OFFLINE=true cargo +nightly-2026-11-14 fuzz run --features libfuzzer "$target" \
  "$sandbox/corpus" "fuzz/corpus/$target" -- \
  -seed=1 -max_len=65536 -runs=20000 -max_total_time=15 -timeout=5 \
  -rss_limit_mb=1024 -malloc_limit_mb=128 -artifact_prefix="$sandbox/artifacts/"
```

The targets parse in memory without opening keys, spawning workers or opening network connections. Keep generated inputs and sanitizer artifacts in the temporary directory. Add a small, synthetic regression to the corpus when it captures a parser behavior worth preserving. To run all six targets in GitHub Actions, select **Also run bounded parser fuzzing** when dispatching CI manually.

Dependencies use upstream crates and checked-in lockfiles. CI runs `cargo-audit 0.23.0` with unsoundness denied. The main workspace has two explicit exceptions. The fuzz workspace has none. Run `cargo audit --deny unsound` to see the unfiltered workspace findings and `cargo audit --file fuzz/Cargo.lock --deny unsound` to check the fuzz workspace.

- Dioxus Desktop's Linux GTK 3 and WebKitGTK bindings require `glib 0.18`. The affected `VariantStrIter` API remains present in that dependency, and Firmica has no direct calls to it. The fix starts at `glib 0.20`, outside the GTK 3 bindings' requirement. [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html)
- Wry's Android HTML parser, `kuchikiki`, pulls in `rand 0.7.3` through the `selectors` build dependency on `phf_codegen` and `phf_generator`. The generator uses a fixed-seed `SmallRng` for compile-time tables. Its path does not use the affected thread-local RNG. The first patched series starts at `rand 0.8.6`, outside the generator's `0.7` requirement. [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html)

The stable Dioxus 0.7 stack has no compatible lockfile-only fix for either advisory. Recheck the exceptions when upgrading Dioxus or Wry. Run `cargo tree --locked --workspace --target all -i glib@0.18.5` and the same command with `-i rand@0.7.3` to verify the dependency paths. [Dioxus releases](https://github.com/DioxusLabs/dioxus/releases)

The signing libraries can be tested separately from the applications. They require patched OpenSSL development headers and libraries, plus the OpenSSL CLI. Set `OPENSSL_DIR` and, when needed, `OPENSSL_LIB_DIR` for a native installation outside the compiler's search paths. [OpenSSL build requirements](https://docs.rs/openssl/0.10.82/openssl/#building)

```sh
cargo test --locked -p firmica-signing -p firmica-certificates -p firmica-providers -p firmica-cades -p firmica-pades -p firmica-xades -p firmica-key-worker -p firmica-validation
cargo doc --locked -p firmica-signing -p firmica-certificates -p firmica-providers -p firmica-cades -p firmica-pades -p firmica-xades -p firmica-key-worker -p firmica-validation --no-deps
# Java 17+; downloads checksum-pinned, test-only AutoFirma 1.9.1 reference jars:
cargo test --locked -p firmica-cades --test encoding autofirma_reference -- --ignored --test-threads=1
# Poppler and XMLSec (OpenSSL backend) independently verify PDF/XML output:
cargo test --locked -p firmica-pades --test encoding poppler_ -- --ignored
cargo test --locked -p firmica-xades --test encoding xmlsec_ -- --ignored
# With SoftHSM and softhsm2-util installed; use your platform's module path:
FIRMICA_PKCS11_MODULE=/path/to/libsofthsm2.so cargo test --locked -p firmica-certificates --features pkcs11 --test pkcs11 -- --ignored --test-threads=1
```

PKCS#12 tests cover encrypted containers, passwords, malformed input and message/digest signing. CAdES tests verify attached and detached signatures with the OpenSSL CLI, check certificate binding, and reject modified content. The optional SoftHSM test uses a disposable store and synthetic, non-exportable RSA/P-256 keys to exercise signing and CAdES encoding.

The key-worker library keeps unlocked PKCS#12 keys in a separate Linux, macOS or Windows process. Linux applies address-space and CPU limits. Windows starts the worker suspended, assigns a job with committed-memory, user CPU and child-process limits, and kills it when the parent loses its job handle. Pipe operations have deadlines, and successful close is required before consuming signatures. Other platforms reject worker imports. Windows requests WER no-heap/no-UI reporting; privileged dumps and machine dump policies remain outside that guarantee. API contracts and limits are documented with rustdoc. macOS installs a five-second cumulative CPU limit, disables core files and denies debugger attachment before accepting credentials. Its parent samples physical footprint every 50 ms, terminating and reaping workers above 256 MiB or on accounting failure, including while idle. This is a supervised threshold with possible brief overshoot, rather than a hard allocation cap. Native crash reporting and privileged inspection remain outside this guarantee. The desktop application uses this worker for document signing on Linux, macOS and Windows.

Native worker tests build their process-control fixture through Cargo and locate it from the reported executable path. They check native limit enforcement, blocked pipe deadlines, abandonment, process loss and RSA/P-256 CAdES output independently verified by OpenSSL. The fixture uses synthetic data and never opens a certificate store. After building the desktop application, set `FIRMICA_TEST_WORKER` to the absolute companion executable path and run `cargo test --locked -p desktop -- --ignored --test-threads=1` for the desktop signing and cleanup tests. The Linux desktop tests additionally use Poppler `pdfsig` and XMLSec to verify PAdES and XAdES output. On Windows, the ignored test `windows_selection_reviews_and_saves_with_native_keys` adds and removes disposable synthetic identities in the test account's Current User personal store and checks selection, review, signing and publication.

`firmica-validation` checks local leaf-certificate restrictions for document signing, including validity, key usage, extended key usage, CA usage and private-key usage periods. It accepts the Microsoft Document Signing EKU used by FNMT citizen profiles and blocks certificates declaring the DNIe authentication policy. It rejects unhandled critical extensions and malformed constraints. Issuer signatures, chain trust, revocation and legal qualification remain outside the assessment. [FNMT citizen profiles](https://www.sede.fnmt.gob.es/documents/10445900/10575386/perfiles_certificados_ac_usuarios.pdf), [DNIe certificate profiles](https://www.dnielectronico.es/PDFs/Politicas_de_certificacion_v3.4.pdf)

The core signing review API binds approval to the selected document bytes, certificate identity, algorithm and format choices, then rechecks the certificate before using the key. The desktop keeps the selected provider and key reference in a `firmica-providers` signing session through review and signing. Checked session cleanup must succeed before publishing output. The Linux, macOS and Windows desktop signing screens use this review API.

Original code targets GPL-3.0-or-later. Third-party dependencies and reference assets retain their own licences.

### CI baseline

CI runs for pull requests and pushes to `main`. Linux runs the shared Rust tests, independent cryptographic verification and headless browser interoperability. The build matrix verifies release packages on Ubuntu 24.04, x64 Windows, Apple Silicon and Intel macOS. Worker integration tests run on Linux, Windows and Apple Silicon. Linux also builds the web app and checks the mobile host entry point. To run the optional PKCS#11 integration test, select **Also test the optional PKCS#11 provider with SoftHSM** when dispatching CI manually.

Record the commit SHA, run URLs and attempt numbers when comparing baselines. For a cancelled job, inspect its check annotations and step list. A runner-acquisition error before any steps start has no test logs or artifacts. Retry that job on the same SHA with `gh run rerun RUN_ID --job JOB_ID`. The Linux interoperability job uploads protocol 4.1 evidence as `protocol41-browsers`.

For a ruleset targeting `main`, require a pull request and select GitHub Actions as the expected source of these minimum status checks.

- `audit`, `rust-quality`, `cryptography` and `protocol-interop`
- `build (ubuntu-24.04)`, `build (windows-latest)`, `build (macos-latest)` and `build (macos-15-intel)`

Reserve required checks for jobs that run automatically on every PR. [GitHub required status checks](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
