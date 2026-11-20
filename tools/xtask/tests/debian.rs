#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
};

#[test]
#[ignore = "requires a Firmica Debian package (FIRMICA_DEB) and desktop-file-utils"]
fn debian_payload_and_desktop_entry() {
    let package = PathBuf::from(std::env::var_os("FIRMICA_DEB").expect("set FIRMICA_DEB"));
    let directory = tempfile::tempdir().unwrap();
    let version = Command::new("ar")
        .arg("p")
        .arg(&package)
        .arg("debian-binary")
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "cannot read {}: {}",
        package.display(),
        String::from_utf8_lossy(&version.stderr)
    );
    assert_eq!(version.stdout, b"2.0\n");

    let control = directory.path().join("control");
    let payload = directory.path().join("payload");
    for (member, destination) in [("control.tar.gz", &control), ("data.tar.gz", &payload)] {
        fs::create_dir(destination).unwrap();
        let mut archive = Command::new("ar")
            .arg("p")
            .arg(&package)
            .arg(member)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let extraction = Command::new("tar")
            .args(["-xz", "-C"])
            .arg(destination)
            .stdin(archive.stdout.take().unwrap())
            .status();
        assert!(archive.wait().unwrap().success(), "cannot read {member}");
        assert!(extraction.unwrap().success(), "cannot extract {member}");
    }

    let metadata = fs::read_to_string(control.join("control")).unwrap();
    assert!(metadata.lines().any(|line| line == "Package: firmica"));
    assert!(metadata
        .lines()
        .any(|line| line == "Description: Firmica electronic-signature client"));
    assert!(Command::new("md5sum")
        .args(["--check", "--strict"])
        .arg(control.join("md5sums"))
        .current_dir(&payload)
        .status()
        .unwrap()
        .success());

    let desktop = payload.join("usr/share/applications/firmica.desktop");
    assert!(Command::new("desktop-file-validate")
        .arg(&desktop)
        .status()
        .unwrap()
        .success());
    let entry = fs::read_to_string(desktop).unwrap();
    for expected in [
        "Name=Firmica",
        "Exec=firmica %u",
        "MimeType=x-scheme-handler/afirma;",
    ] {
        assert!(
            entry.lines().any(|line| line == expected),
            "missing {expected}"
        );
    }
    for name in ["firmica", "firmica-key-worker"] {
        let binary = fs::symlink_metadata(payload.join("usr/bin").join(name)).unwrap();
        assert!(binary.is_file() && binary.permissions().mode() & 0o111 != 0);
    }
}
