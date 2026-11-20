#![cfg(target_os = "linux")]

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

#[test]
#[ignore = "requires a Firmica Debian package (FIRMICA_DEB), dpkg and desktop-file-utils"]
fn debian_payload_and_desktop_entry() {
    let package = PathBuf::from(std::env::var_os("FIRMICA_DEB").expect("set FIRMICA_DEB"));
    let directory = tempfile::tempdir().unwrap();
    let tree = directory.path();
    assert!(Command::new("dpkg-deb")
        .arg("--raw-extract")
        .arg(&package)
        .arg(tree)
        .status()
        .unwrap()
        .success());

    let control = fs::read_to_string(tree.join("DEBIAN/control")).unwrap();
    for field in [
        "Package: firmica",
        "Description: Firmica electronic-signature client",
        "Homepage: https://github.com/Juanbanpar/firmica",
        "Maintainer: Firmica contributors",
        "Recommends: xdg-desktop-portal, zenity",
    ] {
        assert!(control.lines().any(|line| line == field), "missing {field}");
    }
    let architecture = Command::new("dpkg")
        .arg("--print-architecture")
        .output()
        .unwrap();
    assert!(architecture.status.success());
    let architecture = String::from_utf8(architecture.stdout).unwrap();
    assert!(control
        .lines()
        .any(|line| line == format!("Architecture: {}", architecture.trim())));
    let dependencies = control
        .lines()
        .find_map(|line| line.strip_prefix("Depends: "))
        .expect("no runtime dependency metadata");
    for prefix in ["libc6 (>= ", "libwebkit2gtk-4.1-0", "libssl"] {
        assert!(
            dependencies.split(", ").any(|dep| dep.starts_with(prefix)),
            "missing {prefix} in {dependencies}"
        );
    }
    assert!(Command::new("md5sum")
        .args(["--check", "--strict"])
        .arg(tree.join("DEBIAN/md5sums"))
        .current_dir(tree)
        .status()
        .unwrap()
        .success());

    let desktop = "usr/share/applications/firmica.desktop";
    let icon = "usr/share/icons/hicolor/256x256/apps/firmica.png";
    let copyright = "usr/share/doc/firmica/copyright";
    assert!(Command::new("desktop-file-validate")
        .arg(tree.join(desktop))
        .status()
        .unwrap()
        .success());
    let entry = fs::read_to_string(tree.join(desktop)).unwrap();
    for expected in [
        "Name=Firmica",
        "Exec=firmica %u",
        "Icon=firmica",
        "MimeType=x-scheme-handler/afirma;",
    ] {
        assert!(
            entry.lines().any(|line| line == expected),
            "missing {expected}"
        );
    }
    assert_eq!(
        fs::read(tree.join(icon)).unwrap(),
        include_bytes!("../../../packages/desktop/assets/firmica.png")
    );
    assert_eq!(
        fs::read(tree.join(copyright)).unwrap(),
        include_bytes!("../../../packages/desktop/debian/copyright")
    );

    let assets = tree.join("usr/lib/Firmica/assets");
    let style = fs::read_dir(assets)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let name = style.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with("tailwind-") && name.ends_with(".css"));
    let mut expected = [
        "DEBIAN/control",
        "DEBIAN/md5sums",
        desktop,
        icon,
        copyright,
        "usr/bin/firmica",
        "usr/bin/firmica-key-worker",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect::<BTreeSet<_>>();
    expected.insert(style.strip_prefix(tree).unwrap().to_owned());
    assert_eq!(files(tree, tree), expected);
    for path in expected {
        let metadata = fs::symlink_metadata(tree.join(&path)).unwrap();
        let mode = if path.starts_with("usr/bin") {
            0o755
        } else {
            0o644
        };
        assert!(
            metadata.is_file() && metadata.len() != 0,
            "invalid file {path:?}"
        );
        assert_eq!(
            metadata.permissions().mode() & 0o7777,
            mode,
            "wrong mode for {path:?}"
        );
    }

    let listing = Command::new("dpkg-deb")
        .arg("--contents")
        .arg(package)
        .output()
        .unwrap();
    assert!(listing.status.success());
    assert!(String::from_utf8(listing.stdout)
        .unwrap()
        .lines()
        .all(|line| { line.split_whitespace().nth(1) == Some("root/root") }));
}

fn files(root: &Path, directory: &Path) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            paths.extend(files(root, &path));
        } else {
            paths.insert(path.strip_prefix(root).unwrap().to_owned());
        }
    }
    paths
}
