use super::*;

pub(super) fn configure(command: &mut Command) -> Result<()> {
    if env::var_os("OPENSSL_DIR").is_none() {
        bail!("set OPENSSL_DIR to a patched OpenSSL installation with static libraries");
    }
    command
        .env("OPENSSL_STATIC", "1")
        .env("MACOSX_DEPLOYMENT_TARGET", "15.0");
    Ok(())
}

fn output(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("cannot run {command:?}"))?;
    if !output.status.success() {
        bail!("{command:?}: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn applications(directory: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        if path.extension().is_some_and(|value| value == "app") {
            found.push(path);
        } else {
            applications(&path, found)?;
        }
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
    let mut apps = Vec::new();
    applications(
        &target.join("dx/firmica").join(profile).join("macos"),
        &mut apps,
    )?;
    if bundle {
        let directory = target.join("dx/firmica/bundle/macos");
        if directory.exists() {
            applications(&directory, &mut apps)?;
        }
    }
    apps.sort();
    apps.dedup();
    if apps.is_empty() {
        bail!("Dioxus did not produce a macOS application bundle");
    }
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
    for app in &apps {
        let contents = app.join("Contents");
        let info = contents.join("Info.plist");
        // dx 0.7.10 regenerates bundle metadata without the build's deep links.
        let metadata: serde_json::Value = serde_json::from_str(&output(
            Command::new("plutil")
                .args(["-convert", "json", "-o", "-"])
                .arg(&info),
        )?)?;
        if metadata["CFBundleIdentifier"] != "org.firmica.client" {
            bail!("unexpected bundle identifier");
        }
        checked(Command::new("plutil").args([if metadata.get("CFBundleURLTypes").is_some() { "-replace" } else { "-insert" }, "CFBundleURLTypes", "-json", r#"[{"CFBundleURLName":"org.firmica.client.afirma","CFBundleURLSchemes":["afirma"]}]"#]).arg(&info))?;
        checked(
            Command::new("plutil")
                .args(["-replace", "LSMinimumSystemVersion", "-string", "15.0"])
                .arg(&info),
        )?;
        let name = metadata["CFBundleExecutable"]
            .as_str()
            .context("missing bundle executable")?;
        if Path::new(name).components().count() != 1 {
            bail!("invalid bundle executable");
        }
        let executable = contents.join("MacOS").join(name);
        let companion = contents.join("MacOS/firmica-key-worker");
        fs::copy(worker, &companion)?;
        let resources = contents.join("Resources");
        fs::create_dir_all(&resources)?;
        fs::copy(root.join("LICENSE"), resources.join("LICENSE"))?;
        fs::copy(&license, resources.join("OpenSSL-LICENSE.txt"))?;
        // Intel linkers may leave the companion unsigned. Seal nested code first.
        for path in [&companion, &executable] {
            let architecture = output(Command::new("lipo").arg("-archs").arg(path))?;
            let expected = if triple.starts_with("aarch64-") {
                "arm64"
            } else {
                "x86_64"
            };
            if architecture.trim() != expected {
                bail!("unexpected Mach-O architecture");
            }
            let commands = output(Command::new("otool").arg("-l").arg(path))?;
            if !commands
                .lines()
                .any(|line| line.split_whitespace().eq(["minos", "15.0"]))
            {
                bail!("unexpected Mach-O deployment target");
            }
            let libraries = output(Command::new("otool").arg("-L").arg(path))?;
            for line in libraries.lines().skip(1) {
                let library = line.trim().split(" (compatibility").next().unwrap_or("");
                if !library.starts_with("/usr/lib/") && !library.starts_with("/System/Library/") {
                    bail!("application depends on an external library: {library}");
                }
            }
            checked(
                Command::new("codesign")
                    .args(["--force", "--sign", "-", "--options", "runtime"])
                    .arg(path),
            )?;
        }
        checked(
            Command::new("codesign")
                .args(["--force", "--sign", "-", "--options", "runtime"])
                .arg(app),
        )?;
        checked(
            Command::new("codesign")
                .args(["--verify", "--deep", "--strict"])
                .arg(app),
        )?;
    }
    if bundle {
        // Prefer the distributable bundle; the build app may have different asset paths.
        let app = apps
            .iter()
            .find(|path| path.components().any(|part| part.as_os_str() == "bundle"))
            .context("Dioxus did not produce its distributable .app")?;
        let destination = target.join("dx/firmica/bundle/macos");
        fs::create_dir_all(&destination)?;
        let archive = destination.join(format!("firmica-{triple}.zip"));
        checked(
            Command::new("ditto")
                .args(["-c", "-k", "--sequesterRsrc", "--keepParent"])
                .arg(app)
                .arg(&archive),
        )?;
        println!("{}", archive.display());
    }
    Ok(())
}
