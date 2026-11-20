use super::*;
use std::io::Write;

pub(super) fn check_tools() -> Result<()> {
    for tool in ["dpkg-deb", "dpkg-shlibdeps"] {
        output(Command::new(tool).arg("--version")).context(
            "Debian packages require dpkg and dpkg-dev on a Debian or Ubuntu build host",
        )?;
    }
    Ok(())
}

pub(super) fn finish(target: &Path) -> Result<()> {
    let directory = target.join("dx/firmica/bundle/linux/deb");
    let packages = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
    let mut packages = packages
        .iter()
        .map(fs::DirEntry::path)
        .filter(|path| path.extension().is_some_and(|extension| extension == "deb"));
    let package = packages
        .next()
        .context("Dioxus produced no Debian package")?;
    if packages.next().is_some() {
        bail!("expected exactly one Dioxus Debian package");
    }

    let scratch = tempfile::tempdir_in(&directory)?;
    let original = scratch.path().join("dioxus.deb");
    fs::rename(&package, &original)?;
    let payload = scratch.path().join("payload");
    checked(
        Command::new("dpkg-deb")
            .arg("--raw-extract")
            .arg(original)
            .arg(&payload),
    )?;

    // dpkg-shlibdeps needs a source stanza even when it writes dependencies to stdout.
    // Resolve both ELF files against the build host's package and symbol metadata.
    let control = payload.join("DEBIAN/control");
    let debian = scratch.path().join("debian");
    fs::create_dir(&debian)?;
    let fields = fs::read_to_string(&control)?;
    fs::write(
        debian.join("control"),
        format!("Source: firmica\n\n{fields}"),
    )?;
    let dependencies = output(
        Command::new("dpkg-shlibdeps")
            .current_dir(scratch.path())
            .arg("-O")
            .arg("-e")
            .arg(payload.join("usr/bin/firmica"))
            .arg("-e")
            .arg(payload.join("usr/bin/firmica-key-worker")),
    )?;
    let depends = dependencies
        .lines()
        .find_map(|line| line.strip_prefix("shlibs:Depends="))
        .filter(|value| !value.is_empty())
        .context("dpkg-shlibdeps found no runtime dependencies")?;
    if fields.lines().any(|line| line.starts_with("Depends:")) {
        bail!("unexpected Depends field in the Dioxus Debian package");
    }
    writeln!(
        fs::OpenOptions::new().append(true).open(control)?,
        "Depends: {depends}"
    )?;

    let finished = scratch.path().join("firmica.deb");
    checked(
        Command::new("dpkg-deb")
            .args(["--root-owner-group", "--build"])
            .arg(&payload)
            .arg(&finished),
    )?;
    fs::rename(finished, &package)?;
    println!("{}", package.display());
    Ok(())
}
