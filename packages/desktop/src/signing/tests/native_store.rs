use super::*;
use crate::signing::native::{discover, NativeSource};
use openssl::cms::{CMSOptions, CmsContentInfo};

pub(super) fn exercise(
    source: NativeSource,
    algorithm: SignatureAlgorithm,
    profile: &str,
    der: &[u8],
    remove: impl FnOnce(),
) {
    let pdf = include_bytes!("../../../../../crates/pades/tests/fixtures/document.pdf");
    let candidate = discover(source)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.identity().certificate_der == der)
        .expect("synthetic certificate must be listed by its exact DER");
    assert_eq!(candidate.capabilities()[0].algorithm, algorithm);

    let evidence = std::env::var_os("FIRMICA_TEST_NATIVE_SIGNATURES")
        .filter(|path| !path.is_empty())
        .map(|path| {
            let path = PathBuf::from(path).join(profile);
            fs::create_dir_all(&path).unwrap();
            let certificate = X509::from_der(der).unwrap().to_pem().unwrap();
            fs::write(path.join("certificate.pem"), certificate).unwrap();
            path
        });

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("document");
    let cancelled = AtomicBool::new(false);
    for (format, document) in [
        (Format::Cades(ContentMode::Attached), DOCUMENT),
        (Format::Pades(PdfOptions::default()), pdf.as_slice()),
        (Format::Xades(XmlMode::Enveloped), b"<document/>".as_slice()),
    ] {
        fs::write(&input, document).unwrap();
        let pending = Prepared::open_native(
            &input,
            source,
            &candidate,
            firmica_providers::Credentials::None,
            format.clone(),
        )
        .unwrap();
        assert_eq!(pending.native_source(), Some(source));
        assert_eq!(
            pending.review().certificate().fingerprint(),
            candidate.fingerprint()
        );
        assert_eq!(pending.review().algorithm(), algorithm);
        assert_eq!(pending.review().format(), &format);
        fs::write(&input, b"changed after review").unwrap();

        let target = directory
            .path()
            .join(format!("signature.{}", format.extension()));
        pending.sign_and_save(&target, &cancelled).unwrap();
        let bytes = fs::read(&target).unwrap();
        if let Some(path) = &evidence {
            fs::write(path.join(target.file_name().unwrap()), &bytes).unwrap();
        }
        match format {
            Format::Cades(_) => {
                let mut signature = CmsContentInfo::from_der(&bytes).unwrap();
                let mut content = Vec::new();
                signature
                    .verify(
                        None,
                        None,
                        None,
                        Some(&mut content),
                        CMSOptions::NO_SIGNER_CERT_VERIFY,
                    )
                    .unwrap();
                assert_eq!(content, DOCUMENT);
            }
            Format::Pades(_) => assert!(bytes.starts_with(pdf) && bytes.len() > pdf.len()),
            Format::Xades(_) => assert!(String::from_utf8(bytes)
                .unwrap()
                .contains("<ds:SignatureValue>")),
        }
    }

    let cancelled_output = directory.path().join("cancelled.csig");
    let format = Format::Cades(ContentMode::Attached);
    assert!(matches!(
        Prepared::open_native(
            &input,
            source,
            &candidate,
            firmica_providers::Credentials::None,
            format.clone()
        )
        .unwrap()
        .sign_and_save(&cancelled_output, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert!(!cancelled_output.exists());
    let pending = Prepared::open_native(
        &input,
        source,
        &candidate,
        firmica_providers::Credentials::None,
        format.clone(),
    )
    .unwrap();
    remove();
    let stale_output = directory.path().join("stale.csig");
    assert!(pending.sign_and_save(&stale_output, &cancelled).is_err());
    assert!(!stale_output.exists());
    assert!(matches!(
        Prepared::open_native(
            &input,
            source,
            &candidate,
            firmica_providers::Credentials::None,
            format
        ),
        Err(Error::Provider(firmica_providers::Error::StaleIdentity))
    ));
}
