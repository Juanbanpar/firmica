//! Per-user browser TLS provisioning. Only the server key is persisted; the issuing
//! CA key is discarded. Trust-store changes remain an explicit external action.
use clap::Subcommand;
use der::{
    asn1::{Ia5String, OctetString},
    Encode,
};
use openssl::{
    asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rand::rand_bytes,
    stack::Stack,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
        store::X509StoreBuilder,
        verify::{X509VerifyFlags, X509VerifyParam},
        X509Builder, X509Extension, X509Name, X509PurposeId, X509StoreContext, X509,
    },
};
use secrecy::{ExposeSecret, SecretBox};
use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use x509_cert::ext::pkix::{
    constraints::name::{GeneralSubtree, NameConstraints},
    name::GeneralName,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "linux")]
use linux as storage;
use storage::{check_directory, read_private, write_private};
#[cfg(windows)]
use windows as storage;

const MAX_FILE_BYTES: u64 = 64 * 1024;
const LIFETIME_SECONDS: i64 = 365 * 24 * 60 * 60;

#[derive(Subcommand)]
pub enum Command {
    /// Create a unique local TLS identity. Existing profiles are never replaced.
    Init {
        /// Exact browser origin, such as `https://example.org` (without a trailing slash).
        #[arg(long)]
        origin: String,
    },
    /// Validate the configured identity and show its trust certificate fingerprint.
    Status,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot locate an absolute per-user configuration directory")]
    Directory,
    #[error("TLS profile paths must have private user access and no symlinks or reparse points")]
    Permissions,
    #[error("cannot access the local TLS profile")]
    Io(#[from] io::Error),
    #[error("cannot generate or parse the local TLS identity")]
    Crypto(#[from] openssl::error::ErrorStack),
    #[error("cannot encode the local TLS certificate constraints")]
    Encoding(#[from] der::Error),
    #[error(
        "expected one exact HTTP(S) browser origin, without credentials, path, query or fragment"
    )]
    Origin,
    #[error("local TLS profile already exists; it was not replaced")]
    Exists,
    #[error("local TLS is not configured; use firmica tls init --origin <origin>")]
    Missing,
    #[error("local TLS identity is invalid or expired; re-provision it and update browser trust")]
    Invalid,
}

pub struct Profile {
    pub origin: String,
    pub certificate: PathBuf,
    pub key: PathBuf,
    authority: X509,
    leaf: X509,
}

pub fn execute(command: Command) -> Result<(), Error> {
    let base = storage::config_base()?;
    let profile = match command {
        Command::Init { origin } => initialize(&base, &origin)?,
        Command::Status => load(&base)?.ok_or(Error::Missing)?,
    };
    println!("Origin: {}", profile.origin);
    println!(
        "Trust certificate: {}",
        profile.certificate.with_file_name("ca.pem").display()
    );
    let fingerprint = profile.authority.digest(MessageDigest::sha256())?;
    let fingerprint = fingerprint
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    println!("CA SHA-256: {fingerprint}");
    println!("Expires: {}", profile.leaf.not_after());
    println!("No trust store was changed. The CA signing key is not retained.");
    Ok(())
}

pub fn load_default() -> Result<Option<Profile>, Error> {
    load(&storage::config_base()?)
}

fn initialize(base: &Path, origin: &str) -> Result<Profile, Error> {
    firmica_transport::validate_origin(origin).map_err(|_| Error::Origin)?;
    let parent = storage::prepare(base)?;
    let destination = parent.join("browser-tls");
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(Error::Exists);
    }
    let staging = storage::staging(&parent)?;
    let (authority_key, authority) = authority()?;
    let (server_key, server) = listener(&authority_key, &authority)?;
    // No CA key bytes are serialized, even into the temporary profile.
    drop(authority_key);
    let server_key = SecretBox::new(Box::new(server_key.private_key_to_pem_pkcs8()?));
    write_private(&staging.path().join("ca.pem"), &authority.to_pem()?)?;
    write_private(&staging.path().join("certificate.pem"), &server.to_pem()?)?;
    write_private(
        &staging.path().join("private-key.pem"),
        server_key.expose_secret(),
    )?;
    write_private(
        &staging.path().join("origin"),
        format!("{origin}\n").as_bytes(),
    )?;
    // Publish only a complete, validated identity; concurrent initialization never overwrites it.
    read_profile(staging.path())?;
    storage::publish(staging.path(), &destination)?;
    read_profile(&destination)
}

fn load(base: &Path) -> Result<Option<Profile>, Error> {
    for (path, private) in [
        (base.to_path_buf(), false),
        (base.join("firmica"), true),
        (base.join("firmica/browser-tls"), true),
    ] {
        match check_directory(&path, private) {
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            result => result?,
        }
    }
    read_profile(&base.join("firmica/browser-tls")).map(Some)
}

fn read_profile(directory: &Path) -> Result<Profile, Error> {
    check_directory(directory, true)?;
    let origin = read_private(&directory.join("origin"))?;
    let origin = std::str::from_utf8(origin.expose_secret()).map_err(|_| Error::Origin)?;
    let origin = origin.strip_suffix('\n').unwrap_or(origin).to_owned();
    firmica_transport::validate_origin(&origin).map_err(|_| Error::Origin)?;
    let certificate = directory.join("certificate.pem");
    let key = directory.join("private-key.pem");
    let leaf = one_certificate(read_private(&certificate)?.expose_secret())?;
    let authority = one_certificate(read_private(&directory.join("ca.pem"))?.expose_secret())?;
    let private_key = PKey::private_key_from_pem(read_private(&key)?.expose_secret())?;
    if !leaf.public_key()?.public_eq(&private_key) || !verify(&leaf, &authority)? {
        return Err(Error::Invalid);
    }
    Ok(Profile {
        origin,
        certificate,
        key,
        authority,
        leaf,
    })
}

fn one_certificate(pem: &[u8]) -> Result<X509, Error> {
    let mut certificates = X509::stack_from_pem(pem)?;
    if certificates.len() != 1 {
        return Err(Error::Invalid);
    }
    Ok(certificates.remove(0))
}

fn verify(leaf: &X509, authority: &X509) -> Result<bool, Error> {
    let mut parameters = X509VerifyParam::new()?;
    parameters.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    parameters.set_purpose(X509PurposeId::SSL_SERVER)?;
    parameters.set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::CHECK_SS_SIGNATURE)?;
    let mut store = X509StoreBuilder::new()?;
    store.set_param(&parameters)?;
    store.add_cert(authority.clone())?;
    let mut context = X509StoreContext::new()?;
    let chain = Stack::new()?;
    Ok(context.init(&store.build(), leaf, &chain, |context| {
        context.verify_cert()
    })?)
}

fn key() -> Result<PKey<Private>, Error> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

fn certificate(key: &PKey<Private>, common_name: &str) -> Result<X509Builder, Error> {
    let mut serial = [0; 16];
    rand_bytes(&mut serial)?;
    serial[0] |= 1;
    let serial = BigNum::from_slice(&serial)?;
    let serial = Asn1Integer::from_bn(&serial)?;
    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| Error::Invalid)?;
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_serial_number(&serial)?;
    let name = name.build();
    certificate.set_subject_name(&name)?;
    certificate.set_issuer_name(&name)?;
    certificate.set_pubkey(key)?;
    let not_before = Asn1Time::from_unix(now - 300)?;
    let not_after = Asn1Time::from_unix(now + LIFETIME_SECONDS)?;
    certificate.set_not_before(&not_before)?;
    certificate.set_not_after(&not_after)?;
    Ok(certificate)
}

fn authority() -> Result<(PKey<Private>, X509), Error> {
    let key = key()?;
    let mut builder = certificate(&key, "Firmica local browser CA")?;
    let name = builder.x509v3_context(None, None);
    let identifier = SubjectKeyIdentifier::new().build(&name)?;
    builder.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    builder.append_extension(identifier)?;
    let constraints = NameConstraints {
        permitted_subtrees: Some(vec![
            GeneralSubtree {
                base: GeneralName::DnsName(Ia5String::new("localhost")?),
                minimum: 0,
                maximum: None,
            },
            GeneralSubtree {
                base: GeneralName::IpAddress(OctetString::new([127, 0, 0, 1, 255, 255, 255, 255])?),
                minimum: 0,
                maximum: None,
            },
        ]),
        excluded_subtrees: None,
    };
    let oid = Asn1Object::from_str("2.5.29.30")?;
    let constraints = Asn1OctetString::new_from_bytes(&constraints.to_der()?)?;
    builder.append_extension(X509Extension::new_from_der(&oid, true, &constraints)?)?;
    builder.sign(&key, MessageDigest::sha256())?;
    Ok((key, builder.build()))
}

fn listener(issuer: &PKey<Private>, authority: &X509) -> Result<(PKey<Private>, X509), Error> {
    let key = key()?;
    let mut builder = certificate(&key, "Firmica loopback listener")?;
    builder.set_issuer_name(authority.subject_name())?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    let context = builder.x509v3_context(Some(authority), None);
    let subject = SubjectAlternativeName::new()
        .ip("127.0.0.1")
        .build(&context)?;
    let identifier = AuthorityKeyIdentifier::new().keyid(true).build(&context)?;
    builder.append_extension(subject)?;
    builder.append_extension(identifier)?;
    builder.sign(issuer, MessageDigest::sha256())?;
    Ok((key, builder.build()))
}

#[cfg(test)]
mod tests;
