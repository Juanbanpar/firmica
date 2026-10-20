//! Single-signer CMS/CAdES encoding through opaque signing keys.
//!
//! Produces DER SignedData with SHA-256, content-type, message-digest, signing-time
//! and SigningCertificateV2 attributes. The attribute set follows the minimal
//! CAdES-B-B structure in ETSI EN 319 122-1 V1.3.1, clauses 5 and 6.3. This is an
//! encoder, not a certificate validator or a baseline conformance assessment.
//! Trust, validity, revocation, key usage and consent remain caller responsibilities.
//! Signing time is a caller's claim, not a trusted timestamp. No policy identifier,
//! revocation evidence, timestamp, co-signature or countersignature is added.
//!
//! Encoding references: [CMS](https://www.rfc-editor.org/rfc/rfc5652),
//! [ESSCertIDv2](https://www.rfc-editor.org/rfc/rfc5035), and
//! [CAdES](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf).
//!
//! Providers may block for cryptography or token I/O. Call outside the UI loop and
//! complete the provider's required cleanup before publishing the returned bytes.
//!
//! # Example
//! ```no_run
//! use firmica_cades::{sign, ContentMode, SigningOptions};
//! use firmica_signing::{SignatureAlgorithm, SigningKey};
//! use std::time::SystemTime;
//!
//! fn encode(key: &mut dyn SigningKey, document: &[u8]) -> Result<Vec<u8>, firmica_cades::CadesError> {
//!     // The caller has already selected an identity and authorized this operation.
//!     sign(key, document, SigningOptions {
//!         algorithm: SignatureAlgorithm::RsaPkcs1v15Sha256,
//!         mode: ContentMode::Detached,
//!         signing_time: SystemTime::now(),
//!     })
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedAttributes, SignedData, SignerIdentifier,
        SignerInfo, SignerInfos,
    },
};
use der::{
    asn1::{GeneralizedTime, ObjectIdentifier, OctetString, SetOfVec, UtcTime},
    Any, Decode, Encode, Sequence,
};
use firmica_signing::{
    InputKind, SignatureAlgorithm, SigningCapability, SigningError, SigningInput, SigningKey,
};
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use x509_cert::{attr::Attribute, spki::AlgorithmIdentifierOwned, time::Time, Certificate};

const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;

/// Maximum input content length, including content used for a detached signature (16 MiB).
pub const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of supplied certificates, including duplicates and the leaf.
pub const MAX_CERTIFICATES: usize = 32;
/// Maximum DER length of each supplied certificate (64 KiB).
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

pub use firmica_signing::format::ContentMode;

/// Explicit choices for one signing operation; no algorithm or clock defaults.
#[derive(Clone, Copy, Debug)]
pub struct SigningOptions {
    /// Required algorithm, as advertised by the selected key.
    pub algorithm: SignatureAlgorithm,
    /// Embed or omit the content.
    pub mode: ContentMode,
    /// Claimed time, truncated to whole seconds. Supported range is 1970 through 9999.
    /// Uses UTCTime through 2049 and GeneralizedTime from 2050, per RFC 5652 §11.3.
    pub signing_time: SystemTime,
}

/// Static failures without document bytes, identities or native diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CadesError {
    /// Content, certificate count or certificate size exceeds the documented limits.
    #[error("CAdES input exceeds a resource limit")]
    InputTooLarge,
    /// A supplied certificate is malformed or does not round-trip as canonical DER.
    #[error("invalid DER certificate")]
    InvalidCertificate,
    /// Claimed time is outside the encoder's supported range.
    #[error("unsupported signing time")]
    InvalidTime,
    /// The provider rejected the operation or returned invalid output.
    #[error(transparent)]
    Signing(#[from] SigningError),
    /// ASN.1 encoding failed; no partial signature is returned.
    #[error("CAdES encoding failed")]
    Encoding,
}

impl From<der::Error> for CadesError {
    fn from(_: der::Error) -> Self {
        Self::Encoding
    }
}

// RFC 5035 §4: SHA-256 is the DEFAULT and must be omitted in DER. issuerSerial
// is optional because SignerInfo identifies issuer/serial; ETSI §6.3(g) recommends
// omitting it. Policies are deliberately absent (ETSI §5.2.2.3).
#[derive(Sequence)]
struct EssCertIdV2 {
    cert_hash: OctetString,
}

#[derive(Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}

/// Encode a CAdES signature, invoking the key exactly once after validating inputs.
///
/// Signs the DER **SET OF** attributes (RFC 5652 §5.4), never the context-specific
/// field encoding. Prefers the provider's message operation; otherwise supplies its
/// SHA-256 digest. No document normalization, file access or network access occurs.
/// Includes the leaf and all distinct supplied additional certificates, without
/// claiming that they form a trusted chain. The leaf is bound by its full DER hash.
///
/// # Errors
/// Input limits, invalid certificates/time and unsupported capabilities are rejected
/// before invoking the key. Provider and encoding failures return no output. The
/// provider contract requires verification against the selected certificate; this
/// function also rejects an empty, over-64-KiB or incorrectly labelled signature.
pub fn sign(
    key: &mut dyn SigningKey,
    content: &[u8],
    options: SigningOptions,
) -> Result<Vec<u8>, CadesError> {
    if content.len() > MAX_CONTENT_BYTES {
        return Err(CadesError::InputTooLarge);
    }
    encode(
        key,
        content,
        Sha256::digest(content).into(),
        options.algorithm,
        options.mode,
        Some(options.signing_time),
    )
}

/// Encode the detached CMS value for a PDF signature's SHA-256 ByteRange digest.
///
/// Omits the CMS signing-time attribute, as required by ETSI EN 319 142-1 §6.3;
/// the PDF signature dictionary must supply `/M` instead. This is a format-layer
/// interface, not authorization to sign a caller-provided digest. The PDF encoder
/// must compute the digest itself from the reviewed document and incremental update.
/// Certificate limits, provider verification and errors are the same as [`sign`].
pub fn sign_pdf_digest(
    key: &mut dyn SigningKey,
    digest: [u8; 32],
    algorithm: SignatureAlgorithm,
) -> Result<Vec<u8>, CadesError> {
    encode(key, &[], digest, algorithm, ContentMode::Detached, None)
}

fn encode(
    key: &mut dyn SigningKey,
    content: &[u8],
    content_digest: [u8; 32],
    algorithm: SignatureAlgorithm,
    mode: ContentMode,
    signing_time: Option<SystemTime>,
) -> Result<Vec<u8>, CadesError> {
    let identity = key.identity();
    if identity.additional_certificates.len() >= MAX_CERTIFICATES
        || std::iter::once(&identity.certificate_der)
            .chain(&identity.additional_certificates)
            .any(|der| der.len() > MAX_CERTIFICATE_BYTES)
    {
        return Err(CadesError::InputTooLarge);
    }
    let input_kind = [InputKind::Message, InputKind::Sha256Digest]
        .into_iter()
        .find(|input| {
            key.capabilities().contains(&SigningCapability {
                algorithm,
                input: *input,
            })
        })
        .ok_or(SigningError::UnsupportedOperation)?;
    let leaf = decode_certificate(&identity.certificate_der)?;
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: leaf.tbs_certificate.issuer.clone(),
        serial_number: leaf.tbs_certificate.serial_number.clone(),
    });
    let mut certificates = vec![CertificateChoices::Certificate(leaf)];
    for encoded in &identity.additional_certificates {
        let certificate = CertificateChoices::Certificate(decode_certificate(encoded)?);
        if !certificates.contains(&certificate) {
            certificates.push(certificate);
        }
    }
    let certificates = Some(CertificateSet::try_from(certificates)?);
    let time = signing_time
        .map(|time| {
            let time =
                GeneralizedTime::from_system_time(time).map_err(|_| CadesError::InvalidTime)?;
            Ok::<_, CadesError>(if time.to_date_time().year() <= UtcTime::MAX_YEAR {
                Time::UtcTime(
                    UtcTime::from_date_time(time.to_date_time())
                        .map_err(|_| CadesError::InvalidTime)?,
                )
            } else {
                Time::GeneralTime(time)
            })
        })
        .transpose()?;
    let binding = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            cert_hash: OctetString::new(Sha256::digest(&identity.certificate_der).to_vec())?,
        }],
    };
    let mut attributes = vec![
        attribute(CONTENT_TYPE, Any::encode_from(&DATA)?)?,
        attribute(
            MESSAGE_DIGEST,
            Any::encode_from(&OctetString::new(content_digest.to_vec())?)?,
        )?,
        attribute(SIGNING_CERTIFICATE_V2, Any::encode_from(&binding)?)?,
    ];
    if let Some(time) = time {
        attributes.push(attribute(SIGNING_TIME, Any::encode_from(&time)?)?);
    }
    let attrs = SignedAttributes::try_from(attributes)?;
    let signed_bytes = attrs.to_der()?;
    let digest = Sha256::digest(&signed_bytes).into();
    let input = match input_kind {
        InputKind::Message => SigningInput::Message(&signed_bytes),
        InputKind::Sha256Digest => SigningInput::Sha256Digest(&digest),
    };
    // Prepare the potentially large content encoding before touching the private key.
    let econtent = match mode {
        ContentMode::Attached => Some(Any::encode_from(&OctetString::new(content)?)?),
        ContentMode::Detached => None,
    };
    let signature = key.sign(algorithm, input)?;
    if signature.algorithm != algorithm
        || signature.value.is_empty()
        || signature.value.len() > MAX_SIGNATURE_BYTES
    {
        return Err(SigningError::InvalidSignature.into());
    }
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: SHA256,
        parameters: None,
    };
    let signature_algorithm = match algorithm {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
            parameters: Some(Any::null()),
        },
        SignatureAlgorithm::EcdsaP256Sha256 => AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        },
    };
    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![digest_algorithm.clone()])?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: DATA,
            econtent,
        },
        certificates,
        crls: None,
        signer_infos: SignerInfos::try_from(vec![SignerInfo {
            version: CmsVersion::V1,
            sid,
            digest_alg: digest_algorithm,
            signed_attrs: Some(attrs),
            signature_algorithm,
            signature: OctetString::new(signature.value)?,
            unsigned_attrs: None,
        }])?,
    };
    Ok(ContentInfo {
        content_type: SIGNED_DATA,
        content: Any::encode_from(&signed_data)?,
    }
    .to_der()?)
}

fn attribute(oid: ObjectIdentifier, value: Any) -> der::Result<Attribute> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![value])?,
    })
}

fn decode_certificate(encoded: &[u8]) -> Result<Certificate, CadesError> {
    let certificate = Certificate::from_der(encoded).map_err(|_| CadesError::InvalidCertificate)?;
    if certificate
        .to_der()
        .map_err(|_| CadesError::InvalidCertificate)?
        != encoded
    {
        return Err(CadesError::InvalidCertificate);
    }
    Ok(certificate)
}
