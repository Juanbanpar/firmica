#![cfg(target_os = "linux")]

use firmica_key_worker::{discover_pkcs11, WorkerError};
use pkcs11_client::{
    Authentication, CertificateDocument, Pin, Pkcs11Uri, Provider, SecretText, SessionMode,
};
use std::{env, fs, path::Path, process::Command};

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_firmica-key-worker"))
}

#[test]
fn discovery_rejects_a_relative_module_path_before_starting_the_worker() {
    let result = discover_pkcs11(worker(), Path::new("relative-module.so"));
    assert!(matches!(result, Err(WorkerError::InvalidInput)));
}

#[test]
#[ignore = "requires FIRMICA_PKCS11_MODULE pointing to SoftHSM and softhsm2-util"]
fn discovery_returns_visible_certificates_from_a_disposable_token_store(
) -> Result<(), Box<dyn std::error::Error>> {
    let module = env::var("FIRMICA_PKCS11_MODULE")?;
    let module = Path::new(&module);
    let temporary = tempfile::tempdir()?;
    let tokens = temporary.path().join("tokens");
    fs::create_dir(&tokens)?;
    let config = temporary.path().join("softhsm2.conf");
    fs::write(
        &config,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )?;
    // This integration binary has no other test that opens a module or reads this variable.
    env::set_var("SOFTHSM2_CONF", &config);
    assert!(discover_pkcs11(worker(), module)?.is_empty());
    const PIN: &str = "synthetic-user-1234";
    for label in ["firmica-discovery", "firmica-empty"] {
        let output = Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                label,
                "--so-pin",
                "synthetic-so-1234",
                "--pin",
                PIN,
            ])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let certificate = CertificateDocument::from_der(
        include_bytes!("../../core/src/signing/fixtures/document-signer.der").to_vec(),
    )?;
    let provider = Provider::load(module)?;
    assert!(provider.info().manufacturer_id().contains("SoftHSM"));
    let token = "pkcs11:token=firmica-discovery".parse()?;
    let pin = SecretText::from(PIN);
    let mut session = provider.management(
        &token,
        SessionMode::ReadWrite,
        Authentication::User(Pin::Value(&pin)),
    )?;
    session.import_certificate(&certificate, &[0x01], b"same-label")?;
    session.import_certificate(&certificate, &[0xff], b"same-label")?;
    session.import_data(b"synthetic data", b"id", b"same-label")?;
    session.close()?;
    provider.finalize()?;

    let discovered = discover_pkcs11(worker(), module)?;
    assert_eq!(discovered.len(), 2);
    let mut ids = Vec::new();
    for token in discovered {
        let uri: Pkcs11Uri = token.uri.parse()?;
        assert!(uri
            .path_attribute("serial")
            .is_some_and(|serial| !serial.is_empty()));
        assert!(uri.path_attribute("slot-id").is_none());
        if uri.path_attribute("token") == Some(b"firmica-empty") {
            assert!(token.certificates.is_empty());
            continue;
        }
        assert_eq!(
            uri.path_attribute("token"),
            Some(b"firmica-discovery".as_slice())
        );
        for object in token.certificates {
            let locator: Pkcs11Uri = object.uri.parse()?;
            assert_eq!(
                locator.path_attribute("serial"),
                uri.path_attribute("serial")
            );
            assert_eq!(locator.path_attribute("type"), Some(b"cert".as_slice()));
            assert_eq!(
                locator.path_attribute("object"),
                Some(b"same-label".as_slice())
            );
            assert_eq!(object.der, certificate.der());
            ids.push(locator.path_attribute("id").unwrap().to_vec());
        }
    }
    ids.sort();
    assert_eq!(ids, [vec![0x01], vec![0xff]]);

    let provider = Provider::load(module)?;
    let mut session = provider.management(
        &token,
        SessionMode::ReadWrite,
        Authentication::User(Pin::Value(&pin)),
    )?;
    session.import_certificate(&certificate, &[0x01], b"same-label")?;
    session.close()?;
    provider.finalize()?;
    assert!(matches!(
        discover_pkcs11(worker(), module),
        Err(WorkerError::Unavailable)
    ));
    Ok(())
}
