use super::*;
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    process::Command,
};

const ORIGIN: &str = "https://example.invalid";

#[test]
fn provisioning_is_private_unique_and_verifiable_without_a_retained_ca_key() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().join("config");
    let profile = initialize(&base, ORIGIN).unwrap();
    let directory = base.join("firmica/browser-tls");
    assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
    let mut names = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert_eq!(entry.metadata().unwrap().mode() & 0o777, 0o600);
            entry.file_name().into_string().unwrap()
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["ca.pem", "certificate.pem", "origin", "private-key.pem"]
    );
    assert_eq!(load(&base).unwrap().unwrap().origin, ORIGIN);
    assert!(firmica_transport::load_tls(&profile.certificate, &profile.key).is_ok());
    let output = Command::new("openssl")
        .args([
            "verify",
            "-x509_strict",
            "-purpose",
            "sslserver",
            "-verify_ip",
            "127.0.0.1",
            "-CAfile",
        ])
        .arg(directory.join("ca.pem"))
        .arg(&profile.certificate)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(profile.authority.to_text().unwrap()).unwrap();
    assert!(text.contains("CA:TRUE, pathlen:0"));
    assert!(text.contains("X509v3 Name Constraints: critical"));
    assert!(text.contains("DNS:localhost"));
    assert!(text.contains("IP:127.0.0.1/255.255.255.255"));
    let later = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + LIFETIME_SECONDS as u64
        + 60)
        .to_string();
    assert!(!Command::new("openssl")
        .args(["verify", "-attime", &later, "-CAfile"])
        .arg(directory.join("ca.pem"))
        .arg(&profile.certificate)
        .output()
        .unwrap()
        .status
        .success());
    let another = initialize(&temporary.path().join("another"), ORIGIN).unwrap();
    assert_ne!(
        profile.authority.to_der().unwrap(),
        another.authority.to_der().unwrap()
    );
    assert_ne!(
        profile.leaf.to_der().unwrap(),
        another.leaf.to_der().unwrap()
    );
}

#[test]
fn root_constraints_reject_an_otherwise_valid_non_loopback_certificate() {
    let temporary = tempfile::tempdir().unwrap();
    let (issuer, authority) = authority().unwrap();
    let key = key().unwrap();
    let mut builder = certificate(&key, "Synthetic forbidden host").unwrap();
    builder.set_issuer_name(authority.subject_name()).unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder
        .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    let context = builder.x509v3_context(Some(&authority), None);
    let names = SubjectAlternativeName::new()
        .ip("203.0.113.1")
        .dns("example.invalid")
        .build(&context)
        .unwrap();
    let identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&context)
        .unwrap();
    builder.append_extension(names).unwrap();
    builder.append_extension(identifier).unwrap();
    builder.sign(&issuer, MessageDigest::sha256()).unwrap();
    let bad = builder.build();
    assert!(bad.verify(&issuer).unwrap());
    fs::write(temporary.path().join("ca.pem"), authority.to_pem().unwrap()).unwrap();
    fs::write(temporary.path().join("bad.pem"), bad.to_pem().unwrap()).unwrap();
    let output = Command::new("openssl")
        .current_dir(temporary.path())
        .args([
            "verify",
            "-purpose",
            "sslserver",
            "-verify_ip",
            "203.0.113.1",
            "-CAfile",
            "ca.pem",
            "bad.pem",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("permitted subtree violation"));
}

#[test]
fn existing_and_concurrently_created_profiles_are_never_replaced() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().join("config");
    let first = std::thread::scope(|scope| {
        let tasks = [
            scope.spawn(|| initialize(&base, ORIGIN)),
            scope.spawn(|| initialize(&base, ORIGIN)),
        ];
        let results = tasks.map(|task| task.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(Error::Exists)))
                .count(),
            1
        );
        results.into_iter().find_map(Result::ok).unwrap()
    });
    assert!(matches!(
        initialize(&base, "https://other.invalid"),
        Err(Error::Exists)
    ));
    assert_eq!(
        load(&base).unwrap().unwrap().leaf.to_der().unwrap(),
        first.leaf.to_der().unwrap()
    );
    assert_eq!(fs::read_dir(base.join("firmica")).unwrap().count(), 1);
}

#[test]
fn unsafe_permissions_symlinks_and_partial_profiles_fail_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().join("config");
    assert!(load(&base).unwrap().is_none());
    let profile = initialize(&base, ORIGIN).unwrap();
    let directory = base.join("firmica/browser-tls");
    for path in [&base.join("firmica"), &directory, &profile.key] {
        let original = fs::metadata(path).unwrap().permissions();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(load(&base), Err(Error::Permissions)));
        fs::set_permissions(path, original).unwrap();
    }
    let saved = directory.join("saved-key");
    fs::rename(&profile.key, &saved).unwrap();
    symlink(&saved, &profile.key).unwrap();
    assert!(load(&base).is_err());
    fs::remove_file(&profile.key).unwrap();
    fs::rename(saved, &profile.key).unwrap();
    fs::write(
        directory.join("origin"),
        vec![b'x'; MAX_FILE_BYTES as usize + 1],
    )
    .unwrap();
    assert!(matches!(load(&base), Err(Error::Invalid)));
    fs::write(directory.join("origin"), ORIGIN).unwrap();
    fs::remove_file(&profile.certificate).unwrap();
    assert!(load(&base).is_err());
}

#[test]
fn mismatched_keys_and_trust_certificates_are_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().join("config");
    let profile = initialize(&base, ORIGIN).unwrap();
    let other = initialize(&temporary.path().join("another"), ORIGIN).unwrap();
    fs::copy(&other.key, &profile.key).unwrap();
    assert!(matches!(load(&base), Err(Error::Invalid)));
    fs::copy(&other.certificate, &profile.certificate).unwrap();
    assert!(matches!(load(&base), Err(Error::Invalid)));
}

#[test]
fn configuration_paths_and_origins_are_explicit() {
    assert_eq!(
        config_home(Some("/tmp/private-config".into()), None).unwrap(),
        Path::new("/tmp/private-config")
    );
    assert_eq!(
        config_home(None, Some("/tmp/private-home".into())).unwrap(),
        Path::new("/tmp/private-home/.config")
    );
    assert!(config_home(Some("relative".into()), Some("/tmp/home".into())).is_err());
    assert!(config_home(None, None).is_err());
    let temporary = tempfile::tempdir().unwrap();
    let base = temporary.path().join("config");
    assert!(matches!(
        initialize(&base, "https://example.invalid/path"),
        Err(Error::Origin)
    ));
    assert!(!base.exists());
}
