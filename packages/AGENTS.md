# Dioxus application and UI guidance

Applies to the application packages and shared UI under `packages/`, together with the root `AGENTS.md`.

Adapted from the [official Dioxus 0.7 Workspace template instructions](https://github.com/DioxusLabs/dioxus-template/blob/1308c32cd5bbb16a66640a0f08e641a84ebc2c30/Workspace/AGENTS.md). Use the [Dioxus 0.7 documentation](https://dioxuslabs.com/learn/0.7/) and its [llms.txt entry point](https://dioxuslabs.com/learn/0.7/llms.txt). Follow linked topic documentation and inspect the locked crate source when API details are unclear; the entry point alone is not a complete API reference.

## Project constraints

- Dioxus and its CLI are pinned to **0.7.10**. Use the workspace dependency and existing per-package features; do not substitute the template's older dependency examples or enable unrelated platforms.
- Preserve the default WebView renderer, generated entry-point structure and shared Android/iOS mobile package. Do not add another application shell or experimental renderer.
- Dioxus owns presentation, navigation and reactive UI state. Keep cryptography, protocol parsing, transport and certificate policy in the reusable crates; entry points provide native adapters.
- This application does not use Dioxus Fullstack, server functions or SSR hydration. Do not add them merely because the upstream template documents them.

## Components, RSX and state

- Use `#[component]` functions returning `Element` and `rsx!` for markup. Use direct RSX `for` and `if` blocks for repeated and conditional elements.
- Use Dioxus 0.7 signals and hooks. Do not use the removed `cx`, `Scope` or `use_state` APIs.
- Component props should be owned, cloneable values with `PartialEq`. Use `String` and `Vec<T>` for owned data; use `Signal<T>` or `ReadOnlySignal<T>` when the prop must participate in reactive state.
- Use `use_signal` for local state, `use_memo` for derived values when useful, and `use_context_provider` / `use_context` for shared context. Read signal dependencies where reactivity is intended.
- Call hooks unconditionally in a stable order. Release signal read/write guards before awaiting or invoking code that can access the same signal.
- Use `use_resource` for reactive asynchronous reads and explicit event tasks for user-authorized operations. A re-running resource or effect must never authorize signing.
- Keep blocking file access, key import, signing and worker cleanup off the UI event loop. Preserve the existing cancellation and stale-result guards.
- Use the existing `Routable` enums, `Router` and layout `Outlet` patterns. Preserve native launch and URI-delivery wiring when editing entry points.

## Assets and interaction

- Reference assets through `asset!` and the existing document stylesheet components. Paths are relative to the owning package's asset configuration.
- Use Tailwind CSS 4 through the existing Dioxus asset pipeline. Preserve shared theme imports and scanning of `packages/ui`; do not edit generated `assets/tailwind.css` or introduce a CDN dependency.
- Share reusable Rust components and styles in `packages/ui`. Keep platform-specific file, key and lifecycle integration in the native entry points.
- Keep Spanish and English behavior consistent. Preserve semantic controls, labels, keyboard operation, visible focus, responsive layouts and light/dark styles.
- Keep the reviewed document and signing choices visible and fixed during consent. Navigation, cancellation or session expiry must invalidate the corresponding pending operation.

## Verification

- Run the affected Rust tests and Clippy checks. Build with the matching Dioxus CLI when changing RSX, assets, styles or platform entry points; `cargo check` does not generate Tailwind CSS or package assets.
- Use the existing native/browser tests when changing dialogs, consent, URI delivery, focus or lifecycle behavior. Keep browser inspection and synthetic fixtures confined to tests.
- For shared UI changes, check the affected desktop, web and mobile targets rather than assuming one host build proves every platform.
