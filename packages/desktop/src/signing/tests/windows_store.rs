use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use firmica_providers::windows::SystemStore;
use openssl::cms::{CMSOptions, CmsContentInfo};

const STORE: SystemStore = SystemStore::CurrentUserPersonal;

#[test]
#[ignore = "creates and removes synthetic keys and certificates in the Windows Current User MY store"]
fn windows_selection_reviews_and_saves_with_native_keys() {
    let pdf = include_bytes!("../../../../../crates/pades/tests/fixtures/document.pdf");
    for (algorithm, legacy) in [(RSA, false), (EC, false), (RSA, true)] {
        let (mut fixture, der) = CertificateFixture::new(algorithm, legacy);
        let candidate = crate::signing::windows::discover(STORE)
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.identity().certificate_der == der)
            .expect("synthetic certificate must be listed by its exact DER");
        assert_eq!(candidate.capabilities()[0].algorithm, algorithm);

        let evidence = std::env::var_os("FIRMICA_TEST_WINDOWS_SIGNATURES")
            .filter(|path| !path.is_empty())
            .map(|path| {
                let profile = match (algorithm, legacy) {
                    (RSA, true) => "capi-rsa",
                    (RSA, false) => "cng-rsa",
                    (EC, _) => "cng-p256",
                };
                let path = PathBuf::from(path).join(profile);
                fs::create_dir_all(&path).unwrap();
                let certificate = X509::from_der(&der).unwrap().to_pem().unwrap();
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
            let pending =
                Prepared::open_windows(&input, STORE, &candidate, algorithm, format.clone())
                    .unwrap();
            assert_eq!(pending.windows_store(), Some(STORE));
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
            Prepared::open_windows(&input, STORE, &candidate, algorithm, format.clone())
                .unwrap()
                .sign_and_save(&cancelled_output, &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
        assert!(!cancelled_output.exists());
        let pending =
            Prepared::open_windows(&input, STORE, &candidate, algorithm, format.clone()).unwrap();
        fixture.remove();
        let stale_output = directory.path().join("stale.csig");
        assert!(pending.sign_and_save(&stale_output, &cancelled).is_err());
        assert!(!stale_output.exists());
        assert!(matches!(
            Prepared::open_windows(&input, STORE, &candidate, algorithm, format),
            Err(Error::Provider(firmica_providers::Error::StaleIdentity))
        ));
    }
}

struct CertificateFixture {
    subject: String,
    active: bool,
}

impl CertificateFixture {
    fn new(algorithm: SignatureAlgorithm, legacy: bool) -> (Self, Vec<u8>) {
        let mut random = [0; 16];
        openssl::rand::rand_bytes(&mut random).unwrap();
        let fixture = Self {
            subject: format!("CN=FirmicaDesktopTest-{:032x}", u128::from_ne_bytes(random)),
            active: true,
        };
        let output = fixture
            .powershell(
                r#"
$ErrorActionPreference = 'Stop'
$params = @{
    Subject = $env:FIRMICA_TEST_SUBJECT
    CertStoreLocation = 'Cert:\CurrentUser\My'
    Type = 'Custom'
    Provider = $env:FIRMICA_TEST_PROVIDER
    KeyExportPolicy = 'NonExportable'
    KeyUsage = 'DigitalSignature'
    KeyAlgorithm = $env:FIRMICA_TEST_ALGORITHM
    HashAlgorithm = 'SHA256'
    NotBefore = (Get-Date).AddMinutes(-2)
}
if ($env:FIRMICA_TEST_ALGORITHM -eq 'RSA') {
    $params.KeyLength = 2048
} else {
    $params.CurveExport = 'CurveName'
}
if ($env:FIRMICA_TEST_LEGACY -eq 'true') { $params.KeySpec = 'Signature' }
$cert = New-SelfSignedCertificate @params
[Console]::WriteLine([Convert]::ToBase64String($cert.RawData))
"#,
            )
            .env(
                "FIRMICA_TEST_ALGORITHM",
                if algorithm == RSA {
                    "RSA"
                } else {
                    "ECDSA_nistP256"
                },
            )
            .env("FIRMICA_TEST_LEGACY", if legacy { "true" } else { "false" })
            .env(
                "FIRMICA_TEST_PROVIDER",
                if legacy {
                    "Microsoft Enhanced RSA and AES Cryptographic Provider"
                } else {
                    "Microsoft Software Key Storage Provider"
                },
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let der = STANDARD
            .decode(std::str::from_utf8(&output.stdout).unwrap().trim())
            .unwrap();
        (fixture, der)
    }

    fn powershell(&self, script: &str) -> Command {
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ]);
        command.env("FIRMICA_TEST_SUBJECT", &self.subject);
        command
    }

    fn clean(&self) -> std::io::Result<std::process::Output> {
        self.powershell(
            r#"
$ErrorActionPreference = 'Stop'
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $env:FIRMICA_TEST_SUBJECT } |
    ForEach-Object { Remove-Item -Path $_.PSPath -DeleteKey -Confirm:$false }
"#,
        )
        .output()
    }

    fn remove(&mut self) {
        let output = self.clean().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.active = false;
    }
}

impl Drop for CertificateFixture {
    fn drop(&mut self) {
        if self.active {
            let _ = self.clean();
        }
    }
}
