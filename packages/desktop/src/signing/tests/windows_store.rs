use super::*;
use crate::signing::native::NativeSource;
use base64::{engine::general_purpose::STANDARD, Engine};

const STORE: NativeSource = NativeSource::CurrentUser;

#[test]
#[ignore = "creates and removes synthetic keys and certificates in the Windows Current User MY store"]
fn windows_selection_reviews_and_saves_with_native_keys() {
    for (algorithm, legacy) in [(RSA, false), (EC, false), (RSA, true)] {
        let (mut fixture, der) = CertificateFixture::new(algorithm, legacy);
        let profile = match (algorithm, legacy) {
            (RSA, true) => "capi-rsa",
            (RSA, false) => "cng-rsa",
            (EC, _) => "cng-p256",
        };
        super::native_store::exercise(STORE, algorithm, profile, &der, || fixture.remove());
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
