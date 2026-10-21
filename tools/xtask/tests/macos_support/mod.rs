use super::*;
use base64::engine::general_purpose::URL_SAFE;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509Name, X509,
    },
};
use std::{
    ffi::c_void,
    io::Write,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
};
pub const PASSWORD: &str = "synthetic-native-test";

pub fn identities(directory: &Path) -> PathBuf {
    for algorithm in ["rsa", "ec"] {
        let key = if algorithm == "rsa" {
            PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
        } else {
            PKey::from_ec_key(
                EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
            )
            .unwrap()
        };
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, "Firmica synthetic macOS signer")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(17).unwrap()).unwrap())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        certificate
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = certificate.build();
        let bytes = Pkcs12::builder()
            .pkey(&key)
            .cert(&certificate)
            .build2(PASSWORD)
            .unwrap()
            .to_der()
            .unwrap();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(format!("{algorithm}.p12")))
            .unwrap();
        file.write_all(&bytes).unwrap();
        fs::write(
            directory.join(format!("{algorithm}.pem")),
            certificate.to_pem().unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join(format!("{algorithm}.der")),
            certificate.to_der().unwrap(),
        )
        .unwrap();
    }
    directory.to_owned()
}

pub fn decode(encoded: &str) -> Vec<u8> {
    STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE.decode(encoded))
        .unwrap()
}

pub fn verify(case: &Value, signature: &Path, certificates: &Path, directory: &Path) {
    let certificate = certificates.join(format!("{}.pem", case["algorithm"].as_str().unwrap()));
    let original = decode(case["content"].as_str().unwrap());
    match case["mode"].as_str().unwrap() {
        "cades" => {
            let reference = directory.join("reference.bin");
            let verified = directory.join("verified.bin");
            fs::write(&reference, &original).unwrap();
            checked(
                Command::new("openssl")
                    .args([
                        "cms", "-verify", "-cades", "-binary", "-inform", "DER", "-in",
                    ])
                    .arg(signature)
                    .args(["-CAfile"])
                    .arg(certificate)
                    .args([
                        "-no-CApath",
                        "-no-CAstore",
                        "-partial_chain",
                        "-purpose",
                        "any",
                        "-content",
                    ])
                    .arg(reference)
                    .arg("-out")
                    .arg(&verified),
                30,
            );
            assert_eq!(fs::read(verified).unwrap(), original);
        }
        "pades" => {
            assert!(fs::read(signature).unwrap().starts_with(&original));
            let result = checked(Command::new("pdfsig").arg("-nocert").arg(signature), 30);
            assert!(
                result.contains("Signature is Valid"),
                "PDF signature verification failed"
            );
        }
        _ => {
            checked(
                Command::new("xmlsec1")
                    .args(["--verify", "--pubkey-cert-pem"])
                    .arg(certificate)
                    .args([
                        "--enabled-reference-uris",
                        "empty,same-doc",
                        "--id-attr:Id",
                        "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
                        "--id-attr:Id",
                        "http://www.w3.org/2000/09/xmldsig#:Object",
                    ])
                    .arg(signature),
                30,
            );
            let xml = fs::read_to_string(signature).unwrap();
            let parsed = roxmltree::Document::parse(&xml).unwrap();
            if case["mode"] == "enveloped" {
                let expected =
                    roxmltree::Document::parse(std::str::from_utf8(&original).unwrap()).unwrap();
                assert_eq!(
                    parsed.root_element().tag_name(),
                    expected.root_element().tag_name()
                );
                assert_eq!(parsed.root_element().text(), expected.root_element().text());
            } else {
                let object = parsed
                    .descendants()
                    .find(|node| node.attribute("Id") == Some("Firmica-Content"))
                    .unwrap();
                assert_eq!(decode(object.text().unwrap()), original);
            }
        }
    }
    if signature == Path::new(case["output"].as_str().unwrap()) {
        assert_eq!(
            signature.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
use std::os::unix::fs::PermissionsExt;

pub struct Profile {
    pub path: PathBuf,
}
impl Profile {
    pub fn initialize(executable: &Path, origin: &str) -> Self {
        let parent = PathBuf::from(env::var_os("HOME").unwrap())
            .join("Library/Application Support/org.firmica.client");
        assert!(
            !parent.exists(),
            "requires an account without a Firmica configuration"
        );
        // Own cleanup before running provisioning so assertion failures also remove our profile.
        let profile = Self { path: parent };
        checked(
            Command::new(executable).args(["tls", "init", "--origin", origin]),
            30,
        );
        checked(Command::new(executable).args(["tls", "status"]), 30);
        profile
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// LaunchServices has no command-line default-handler API. Keep the native FFI
// inside this disposable-runner test; the application never changes defaults.
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: bool,
    ) -> *const c_void;
    fn CFStringGetCString(
        string: *const c_void,
        buffer: *mut u8,
        size: isize,
        encoding: u32,
    ) -> bool;
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        directory: bool,
    ) -> *const c_void;
    fn CFRelease(value: *const c_void);
}
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn LSCopyDefaultHandlerForURLScheme(scheme: *const c_void) -> *const c_void;
    fn LSSetDefaultHandlerForURLScheme(scheme: *const c_void, bundle: *const c_void) -> i32;
    fn LSRegisterURL(url: *const c_void, update: bool) -> i32;
}
struct OwnedCf(*const c_void);
impl Drop for OwnedCf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CFRelease(self.0);
            }
        }
    }
}
fn cf_string(value: &str) -> OwnedCf {
    // SAFETY: valid UTF-8 bytes remain alive until CoreFoundation copies them.
    let string = OwnedCf(unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            value.as_ptr(),
            value.len() as isize,
            0x08000100,
            false,
        )
    });
    assert!(!string.0.is_null());
    string
}
fn default_handler(scheme: &OwnedCf) -> Option<String> {
    // SAFETY: scheme is a live CFString, and the Copy result is owned here.
    let result = OwnedCf(unsafe { LSCopyDefaultHandlerForURLScheme(scheme.0) });
    if result.0.is_null() {
        return None;
    }
    let mut bytes = [0u8; 512];
    assert!(unsafe {
        CFStringGetCString(
            result.0,
            bytes.as_mut_ptr(),
            bytes.len() as isize,
            0x08000100,
        )
    });
    Some(
        std::ffi::CStr::from_bytes_until_nul(&bytes)
            .unwrap()
            .to_str()
            .unwrap()
            .into(),
    )
}
pub struct Handler {
    app: PathBuf,
}
impl Handler {
    pub fn register(app: &Path) -> Self {
        let scheme = cf_string("afirma");
        let previous = default_handler(&scheme);
        assert!(
            previous
                .as_deref()
                .is_none_or(|id| id == "org.firmica.client"),
            "refusing to replace another afirma handler"
        );
        let bytes = app.as_os_str().as_bytes();
        let url = OwnedCf(unsafe {
            CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len() as isize,
                true,
            )
        });
        assert!(!url.0.is_null());
        let handler = Self { app: app.into() };
        assert_eq!(unsafe { LSRegisterURL(url.0, true) }, 0);
        let bundle = cf_string("org.firmica.client");
        assert_eq!(
            unsafe { LSSetDefaultHandlerForURLScheme(scheme.0, bundle.0) },
            0
        );
        assert_eq!(
            default_handler(&scheme).as_deref(),
            Some("org.firmica.client")
        );
        handler
    }
}
impl Drop for Handler {
    fn drop(&mut self) {
        if default_handler(&cf_string("afirma")).as_deref() == Some("org.firmica.client") {
            let _=Command::new("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister").arg("-u").arg(&self.app).output();
        }
    }
}
