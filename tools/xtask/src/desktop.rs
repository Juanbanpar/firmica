use crate::run as checked;
use anyhow::{bail, Context, Result};
use clap::Args;
use serde::Deserialize;
#[cfg(any(not(target_os = "macos"), test))]
use std::io;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
#[cfg(any(not(target_os = "macos"), test))]
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};
#[cfg(target_os = "macos")]
mod macos;

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
    let windows = cfg!(windows);
    let suffix = if windows { ".exe" } else { "" };
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
    if windows && triple != "x86_64-pc-windows-msvc" {
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
        if bundle && !windows {
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
    if bundle && !windows {
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
        let platform = if windows { "windows" } else { "linux" };
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
        if windows {
            fs::copy(root.join("LICENSE"), application.join("LICENSE"))?;
            fs::copy(
                root.join("tools/windows/handler.ps1"),
                application.join("handler.ps1"),
            )?;
            let openssl =
                PathBuf::from(env::var_os("OPENSSL_DIR").context("OPENSSL_DIR is required")?);
            for name in ["libcrypto-3-x64.dll", "libssl-3-x64.dll"] {
                let source = [openssl.join("bin").join(name), openssl.join(name)]
                    .into_iter()
                    .find(|path| path.is_file())
                    .with_context(|| {
                        format!(
                            "missing x64 OpenSSL runtime {name} under {}",
                            openssl.display()
                        )
                    })?;
                fs::copy(source, application.join(name))?;
            }
            let license = ["license.txt", "LICENSE.txt", "LICENSE"]
                .into_iter()
                .map(|name| openssl.join(name))
                .find(|path| path.is_file())
                .context("OpenSSL distribution license is missing")?;
            fs::copy(license, application.join("OpenSSL-LICENSE.txt"))?;
            if bundle {
                let destination = target.join("dx/firmica/bundle/windows");
                fs::create_dir_all(&destination)?;
                let archive = destination.join(format!("firmica-{triple}.zip"));
                archive_directory(&application, &archive)?;
                println!("{}", archive.display());
            }
        }
        Ok(())
    }
}

#[cfg(any(not(target_os = "macos"), test))]
fn archive_directory(source: &Path, destination: &Path) -> Result<()> {
    fn append(zip: &mut ZipWriter<fs::File>, root: &Path, directory: &Path) -> Result<()> {
        let mut entries = fs::read_dir(directory)?.collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let name = path
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF-8 bundle path")?
                .replace('\\', "/");
            let kind = entry.file_type()?;
            if kind.is_dir() {
                zip.add_directory(format!("{name}/"), SimpleFileOptions::default())?;
                append(zip, root, &path)?;
            } else if kind.is_file() {
                zip.start_file(
                    name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
                )?;
                io::copy(&mut fs::File::open(path)?, zip)?;
            } else {
                bail!("non-regular bundle entry: {}", path.display());
            }
        }
        Ok(())
    }
    let mut zip = ZipWriter::new(fs::File::create(destination)?);
    append(&mut zip, source, source)?;
    zip.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn portable_zip_preserves_nested_assets_and_empty_directories() {
        let temp = tempfile::tempdir().unwrap();
        let app = temp.path().join("App space & 'apostrophe'");
        fs::create_dir_all(app.join("assets/empty")).unwrap();
        fs::write(app.join("firmica.exe"), b"application fixture").unwrap();
        fs::write(app.join("assets/style.css"), b"stylesheet fixture").unwrap();
        let archive = temp.path().join("portable.zip");
        archive_directory(&app, &archive).unwrap();
        let mut zip = zip::ZipArchive::new(fs::File::open(archive).unwrap()).unwrap();
        assert_eq!(zip.len(), 4);
        assert!(zip.by_name("assets/empty/").unwrap().is_dir());
        let mut content = String::new();
        zip.by_name("assets/style.css")
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "stylesheet fixture");
        assert!(zip.by_name("firmica.exe").is_ok());
    }
}
