use crate::run as checked;
use anyhow::{bail, Context, Result};
use clap::Args;
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(windows, test))]
mod windows;

#[derive(Args)]
pub struct Options {
    #[arg(long, conflicts_with = "debug")]
    release: bool,
    /// Allow a debug portable bundle.
    #[arg(long, conflicts_with = "release")]
    debug: bool,
}

#[derive(Deserialize)]
struct Metadata {
    target_directory: PathBuf,
}

pub fn run(root: &Path, bundle: bool, options: Options) -> Result<()> {
    if !cfg!(any(target_os = "linux", target_os = "macos", windows)) {
        bail!("desktop packaging requires a native Linux, macOS or Windows host");
    }
    #[cfg(target_os = "linux")]
    if bundle {
        linux::check_tools()?;
    }
    let windows_host = cfg!(windows);
    let suffix = if windows_host { ".exe" } else { "" };
    let release = options.release || (bundle && !options.debug);
    let profile = if release { "release" } else { "debug" };
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let metadata = Command::new(&cargo)
        .current_dir(root)
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .output()?;
    if !metadata.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&metadata.stderr)
        );
    }
    let target = serde_json::from_slice::<Metadata>(&metadata.stdout)?.target_directory;
    let mut build = Command::new(&cargo);
    build
        .current_dir(root)
        .args(["build", "--locked", "-p", "firmica-key-worker"]);
    if release {
        build.arg("--release");
    }
    #[cfg(target_os = "macos")]
    macos::configure(&mut build)?;
    checked(&mut build)?;
    let version = Command::new("rustc").arg("-vV").output()?;
    if !version.status.success() {
        bail!("rustc -vV failed");
    }
    let version = String::from_utf8(version.stdout)?;
    let triple = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("rustc did not report its host target")?;
    if windows_host && triple != "x86_64-pc-windows-msvc" {
        bail!("Windows runtime staging requires an x64 MSVC host");
    }
    let worker = target
        .join(profile)
        .join(format!("firmica-key-worker{suffix}"));
    // external_bin in Dioxus.toml is relative to the checkout, independent of CARGO_TARGET_DIR.
    let sidecars = root.join("target/sidecars");
    fs::create_dir_all(&sidecars)?;
    fs::copy(
        &worker,
        sidecars.join(format!("firmica-key-worker-{triple}{suffix}")),
    )?;
    let mut dx = Command::new("dx");
    dx.current_dir(root.join("packages/desktop")).args([
        if bundle && !windows_host {
            "bundle"
        } else {
            "build"
        },
        "--locked",
        "--platform",
        "desktop",
    ]);
    if release {
        dx.arg("--release");
    }
    if bundle && !windows_host {
        dx.args([
            "--package-types",
            if cfg!(target_os = "macos") {
                "macos"
            } else {
                "deb"
            },
        ]);
    }
    #[cfg(target_os = "macos")]
    macos::configure(&mut dx)?;
    checked(&mut dx)?;
    #[cfg(target_os = "macos")]
    {
        macos::stage(root, &target, profile, triple, &worker, bundle)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let platform = if windows_host { "windows" } else { "linux" };
        let application = target
            .join("dx/firmica")
            .join(profile)
            .join(platform)
            .join("app");
        if !application.join(format!("firmica{suffix}")).is_file() {
            bail!("Dioxus did not produce the expected desktop executable");
        }
        fs::copy(
            &worker,
            application.join(format!("firmica-key-worker{suffix}")),
        )?;
        #[cfg(windows)]
        windows::stage(root, &target, triple, &application, bundle)?;
        #[cfg(target_os = "linux")]
        if bundle {
            linux::finish(&target)?;
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn output(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("cannot run {command:?}"))?;
    if !output.status.success() {
        bail!("{command:?}: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(any(target_os = "macos", windows, test))]
fn stylesheet(assets: &Path) -> Result<PathBuf> {
    let mut entries = fs::read_dir(assets)
        .with_context(|| format!("cannot read application assets at {}", assets.display()))?;
    let entry = entries.next().context("missing desktop stylesheet")??;
    let filename = entry.file_name();
    let hash = filename
        .to_str()
        .and_then(|name| name.strip_prefix("tailwind-"))
        .and_then(|name| name.strip_suffix(".css"));
    let metadata = entry.metadata()?;
    if entries.next().is_some()
        || !metadata.is_file()
        || metadata.len() == 0
        || !hash.is_some_and(|hash| {
            !hash.is_empty() && hash.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        bail!(
            "expected just the generated Tailwind stylesheet in {}",
            assets.display()
        );
    }
    Ok(entry.path())
}
