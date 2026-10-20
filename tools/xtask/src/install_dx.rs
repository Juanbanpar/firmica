use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{Cursor, Read, Write},
    path::PathBuf,
    time::Duration,
};

pub fn run() -> Result<()> {
    let (name, expected) = match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => (
            "dx-x86_64-unknown-linux-gnu.zip",
            "61d2132eaf3cd70ca1ac89a7ecc891fcd770e917a5869e29d465459371b26c83",
        ),
        ("windows", "x86_64") => (
            "dx-x86_64-pc-windows-msvc.zip",
            "45eb4f87b7f86fdba8508ee7e0ef1f9e13cf8f2ffcc6a2d5858d0e8ea7dd1531",
        ),
        ("macos", "aarch64") => (
            "dx-aarch64-apple-darwin.zip",
            "4aff37aea6b8fbce7bee3f8bbbea1bd71f60e0fa09537f35759f6494da861e37",
        ),
        ("macos", "x86_64") => (
            "dx-x86_64-apple-darwin.zip",
            "b2751a700b8b02f85fcdd8fe6e63c20876b4af9f0921c5be4c703e6f872b67ee",
        ),
        _ => bail!("no pinned Dioxus archive for this host"),
    };
    let url = format!("https://github.com/DioxusLabs/dioxus/releases/download/v0.7.10/{name}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    let mut bytes = Vec::new();
    client
        .get(url)
        .send()?
        .error_for_status()?
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected {
        bail!("Dioxus archive checksum mismatch");
    }
    let directory = PathBuf::from(env::var_os("RUNNER_TEMP").context("RUNNER_TEMP is required")?)
        .join("dioxus-bin");
    fs::create_dir_all(&directory)?;
    let name = if cfg!(windows) { "dx.exe" } else { "dx" };
    let executable = directory.join(name);
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    std::io::copy(
        &mut archive.by_name(name)?,
        &mut fs::File::create(&executable)?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
    }
    let github_path = env::var_os("GITHUB_PATH").context("GITHUB_PATH is required")?;
    writeln!(
        fs::OpenOptions::new().append(true).open(github_path)?,
        "{}",
        directory.display()
    )?;
    crate::run(std::process::Command::new(executable).arg("--version"))
}
