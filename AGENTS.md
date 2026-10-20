# Firmica

Firmica is a Rust electronic-signature client targeting existing AutoFirma integrations. Prefer small, independently verified changes over adding several formats, providers or platforms at once.

## Workspace

- `crates/` contains reusable protocol, domain, transport, certificate, signing and validation libraries. Keep these independent of Dioxus.
- `packages/` contains the Dioxus desktop, mobile, web and shared UI packages. Follow `packages/AGENTS.md` there.
- `tools/xtask/` contains the existing Rust packaging tasks and platform smoke tests; `tests/interop/` contains browser, native UI and reference fixtures.
- Keep the official Dioxus Workspace structure. Add crates only when an implemented responsibility needs one.

## Implementation

- Inspect the relevant implementation, tests and public contracts before editing. Verify compatibility against pinned upstream source, official documentation and executable tests; distinguish observations from assumptions.
- Use idiomatic Rust, cohesive modules, explicit errors and the simplest correct implementation. Avoid speculative abstractions, placeholder APIs, unrelated refactoring and unnecessary dependencies.
- Prefer established cryptographic libraries and standards. Keep format encoding, key providers, transport and UI responsibilities separate.
- Document public contracts, invariants and error conditions with rustdoc. Comments should explain non-obvious constraints, not narrate the code.
- Communicate decisions, verification results and limitations concisely. Ask only when ambiguity materially affects the result.

## Signing and native integration

- Bind consent to the reviewed document bytes, certificate, algorithm, content mode and requesting session. New invocations must not replace or authorize a pending review.
- Preserve cancellation, deadlines, size bounds and fail-closed handling of unsupported operations and platforms.
- Keep private keys in their provider or controlled worker. Worker cleanup must succeed before publishing a signature. Never add an in-process fallback for an unsupported worker platform.
- Do not log passwords, private keys, containers, document contents or complete invocation URIs. Use synthetic credentials and documents in tests.
- Distinguish cryptographic validity, certificate restrictions, chain trust, revocation and legal qualification. Do not claim checks the implementation does not perform.
- Preserve private file permissions, safe output publication, browser trust isolation and association ownership checks. Prefer existing cross-platform pickers; evaluate mobile document providers separately.

## Build and verification

- Prefer native Cargo commands for compilation, tests, formatting, Clippy and rustdoc. Use Dioxus `dx` for assets and application bundles.
- Use the existing `cargo xtask build` / `cargo xtask bundle` when companion-worker staging or portable packaging is required. Keep custom tooling limited to work Cargo and Dioxus do not already handle; do not make `build.rs` install tools or package applications.
- Write behavior-focused Rust unit and integration tests, including relevant edge cases and failures. Use external automation only where an actual browser, native dialog, platform SDK or independent reference implementation is needed.
- Run `cargo fmt --all --check` and the affected packages' `cargo test --locked -p <package>`, `cargo clippy --locked -p <package> --all-targets -- -D warnings`, and `cargo doc --locked -p <package> --no-deps` as appropriate.
- Select native and interoperability checks from the README and CI workflows for the behavior changed. Host compilation does not establish Android, iOS, Windows or macOS runtime support. Report what could not be verified.
- For instruction-only changes, check scope, links and consistency with the repository; application rebuilds are unnecessary.

## Documentation and publication

- Keep usage and build instructions in the README and API documentation beside the code. Preserve unrelated documentation when making narrow edits.
- Keep ignored `docs/` notes local. Do not add internal-document links, implementation stages or progress reports to the README.
- The GLib and rand advisories explicitly accepted in CI remain accepted. Do not introduce local dependency patches, vendored backports or custom audit-policy scripts. Keep the standard audit and its explicit exceptions visible.
- Follow the user's commit and publication authorization. Make focused GPG-signed commits, preserve the configured signing identity and SSH remote, and verify GitHub signature status after pushing. Report relevant CI results without claiming unrun checks passed.
