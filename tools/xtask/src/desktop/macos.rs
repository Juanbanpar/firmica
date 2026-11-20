use super::*;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;

pub(super) fn configure(command: &mut Command) -> Result<()> {
    if env::var_os("OPENSSL_DIR").is_none() {
        bail!("set OPENSSL_DIR to a patched OpenSSL installation with static libraries");
    }
    command
        .env("OPENSSL_STATIC", "1")
        .env("MACOSX_DEPLOYMENT_TARGET", "15.0");
    Ok(())
}

fn bundle_info(app: &Path) -> Result<Value> {
    Ok(serde_json::from_str(&output(
        Command::new("plutil")
            .args(["-convert", "json", "-o", "-"])
            .arg(app.join("Contents/Info.plist")),
    )?)?)
}

fn validate_binary(path: &Path, architecture: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        bail!("not a regular executable: {}", path.display());
    }
    let actual = output(Command::new("lipo").arg("-archs").arg(path))?;
    if actual.trim() != architecture {
        bail!("unexpected Mach-O architecture in {}", path.display());
    }
    let commands = output(Command::new("otool").arg("-l").arg(path))?;
    if !commands
        .lines()
        .any(|line| line.split_whitespace().eq(["minos", "15.0"]))
    {
        bail!("unexpected deployment target in {}", path.display());
    }
    let libraries = output(Command::new("otool").arg("-L").arg(path))?;
    for line in libraries.lines().skip(1) {
        let library = line.trim().split(" (compatibility").next().unwrap_or("");
        if !library.starts_with("/usr/lib/") && !library.starts_with("/System/Library/") {
            bail!("application depends on an external library: {library}");
        }
    }
    Ok(())
}

fn stage_app(
    app: &Path,
    root: &Path,
    openssl_license: &Path,
    worker: &Path,
    architecture: &str,
) -> Result<()> {
    let metadata = bundle_info(app)?;
    if metadata["CFBundleIdentifier"] != "org.firmica.client"
        || metadata["CFBundleExecutable"] != "firmica"
    {
        bail!("unexpected macOS bundle identity or executable name");
    }
    let contents = app.join("Contents");
    let info = contents.join("Info.plist");
    // dx 0.7.10 regenerates distributable bundle metadata without the build's deep links.
    checked(
        Command::new("plutil")
            .arg(if metadata.get("CFBundleURLTypes").is_some() { "-replace" } else { "-insert" })
            .args(["CFBundleURLTypes", "-json", r#"[{"CFBundleURLName":"org.firmica.client.afirma","CFBundleURLSchemes":["afirma"]}]"#])
            .arg(&info),
    )?;
    checked(
        Command::new("plutil")
            .args(["-replace", "LSMinimumSystemVersion", "-string", "15.0"])
            .arg(&info),
    )?;
    let executable = contents.join("MacOS/firmica");
    let companion = contents.join("MacOS/firmica-key-worker");
    fs::copy(worker, &companion)?;
    let resources = contents.join("Resources");
    fs::create_dir_all(&resources)?;
    fs::copy(root.join("LICENSE"), resources.join("LICENSE"))?;
    fs::copy(openssl_license, resources.join("OpenSSL-LICENSE.txt"))?;
    // Intel linkers may leave the companion unsigned. Seal nested code first.
    for path in [&companion, &executable] {
        validate_binary(path, architecture)?;
        ad_hoc_sign(path)?;
    }
    ad_hoc_sign(app)?;
    verify_signature(app)
}

fn ad_hoc_sign(path: &Path) -> Result<()> {
    checked(
        Command::new("codesign")
            .args(["--force", "--sign", "-", "--options", "runtime"])
            .arg(path),
    )
}

fn verify_signature(app: &Path) -> Result<()> {
    checked(
        Command::new("codesign")
            .args(["--verify", "--deep", "--strict"])
            .arg(app),
    )
}

fn verify_archive(archive: &Path, directory: &Path) -> Result<()> {
    checked(
        Command::new("ditto")
            .args(["-x", "-k"])
            .arg(archive)
            .arg(directory),
    )?;
    let app = directory.join("Firmica.app");
    let metadata = bundle_info(&app)?;
    if metadata["CFBundlePackageType"] != "APPL"
        || metadata["CFBundleIconFile"] != "Firmica.icns"
        || metadata["LSMinimumSystemVersion"] != "15.0"
        || metadata["CFBundleURLTypes"][0]["CFBundleURLSchemes"][0] != "afirma"
    {
        bail!("unexpected metadata in the macOS archive");
    }
    let contents = app.join("Contents");
    exact_entries(
        &contents,
        &[
            "Info.plist",
            "MacOS",
            "PkgInfo",
            "Resources",
            "_CodeSignature",
        ],
    )?;
    exact_entries(&contents.join("MacOS"), &["firmica", "firmica-key-worker"])?;
    let resources = contents.join("Resources");
    exact_entries(
        &resources,
        &["assets", "Firmica.icns", "LICENSE", "OpenSSL-LICENSE.txt"],
    )?;
    for name in ["Firmica.icns", "LICENSE", "OpenSSL-LICENSE.txt"] {
        let metadata = fs::symlink_metadata(resources.join(name))?;
        if !metadata.is_file() || metadata.len() == 0 {
            bail!("missing regular bundle resource: {name}");
        }
    }
    stylesheet(&resources.join("assets"))?;
    verify_signature(&app)
}

fn exact_entries(directory: &Path, expected: &[&str]) -> Result<()> {
    let entries: std::collections::BTreeSet<_> = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<_>>()?;
    if entries.len() != expected.len()
        || expected
            .iter()
            .any(|name| !entries.contains(std::ffi::OsStr::new(name)))
    {
        bail!("unexpected entries in {}: {entries:?}", directory.display());
    }
    Ok(())
}

pub(super) fn stage(
    root: &Path,
    target: &Path,
    profile: &str,
    triple: &str,
    worker: &Path,
    bundle: bool,
) -> Result<()> {
    let architecture = match triple {
        "aarch64-apple-darwin" => "arm64",
        "x86_64-apple-darwin" => "x86_64",
        _ => bail!("unsupported macOS build target: {triple}"),
    };
    let openssl = PathBuf::from(env::var_os("OPENSSL_DIR").context("OPENSSL_DIR is required")?);
    let license = [
        "LICENSE.txt",
        "LICENSE",
        "share/doc/openssl@3/LICENSE.txt",
        "share/doc/openssl/LICENSE.txt",
    ]
    .into_iter()
    .map(|name| openssl.join(name))
    .find(|path| path.is_file())
    .context("OpenSSL installation license is missing")?;

    let build = target
        .join("dx/firmica")
        .join(profile)
        .join("macos/Firmica.app");
    stage_app(&build, root, &license, worker, architecture)?;
    if bundle {
        let destination = target.join("dx/firmica/bundle/macos");
        let app = destination.join("macos/Firmica.app");
        stage_app(&app, root, &license, worker, architecture)?;
        let scratch = tempfile::tempdir_in(&destination)?;
        let archive = scratch.path().join("firmica.zip");
        checked(
            Command::new("ditto")
                .args(["-c", "-k", "--sequesterRsrc", "--keepParent"])
                .arg(app)
                .arg(&archive),
        )?;
        let relocated = scratch.path().join("Firmica space & 'apostrophe'");
        fs::create_dir(&relocated)?;
        verify_archive(&archive, &relocated)?;
        let output = destination.join(format!("firmica-{triple}.zip"));
        fs::rename(archive, &output)?;
        println!("{}", output.display());
    }
    Ok(())
}
