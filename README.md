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

Native applications and shared UI live in `packages/desktop`, `packages/mobile`, `packages/web`, and `packages/ui`. Reusable protocol, review-state, and transport libraries live in `crates/`.

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

The dependency graph includes `glib 0.18.5` (RUSTSEC-2024-0429) and `rand 0.7.3` (RUSTSEC-2026-0097), which have known unsoundness advisories. Run `cargo audit --deny unsound` to check dependencies.

Original code targets GPL-3.0-or-later. Third-party dependencies and reference assets retain their own licences.
