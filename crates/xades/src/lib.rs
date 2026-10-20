//! XAdES B-B building blocks with local references and opaque signing keys.
//!
//! Uses W3C XMLDSig, exclusive C14N without comments, SHA-256, SigningTime and
//! SigningCertificateV2 (ETSI EN 319 132-1 §6.3). No conformance, trust, timestamp,
//! signature-policy or revocation claim is made. Enveloped signatures cover the
//! canonical XML document (comments excluded); other modes cover exact binary
//! bytes through a base64 transform. Never resolves external entities, files,
//! URLs, XPath or XSLT. Existing XML signatures and ambiguous IDs are rejected.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bergshamra_c14n::{canonicalize, canonicalize_doc, C14nMode};
use bergshamra_xml::{NodeSet, XmlDocument};
use der::{asn1::UintRef, Decode, Encode, Sequence};
use firmica_signing::{
    InputKind, SignatureAlgorithm, SigningCapability, SigningError, SigningInput, SigningKey,
};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, time::SystemTime};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const BASE64: &str = "http://www.w3.org/2000/09/xmldsig#base64";
const PREFIX: &str = "Firmica-";

/// Maximum reviewed input size (16 MiB).
pub const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;
/// Bound including base64 content, certificates and XML markup.
pub const MAX_SIGNATURE_BYTES: usize = 26 * 1024 * 1024;

pub use firmica_signing::format::XmlMode;

/// Static failures, without document contents or native diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum XadesError {
    /// Input, node count, nesting, certificates or output exceeds a limit.
    #[error("XML signature exceeds a resource limit")]
    InputTooLarge,
    /// Invalid UTF-8/XML, DTD, existing signature, duplicate/reserved ID or xml:base.
    #[error("unsupported or unsafe XML document")]
    InvalidXml,
    /// A supplied certificate is not canonical DER.
    #[error("invalid DER certificate")]
    InvalidCertificate,
    /// Claimed time cannot be encoded.
    #[error("unsupported XML signing time")]
    InvalidTime,
    /// Canonicalization, serialization or signature encoding failed.
    #[error("XML signature encoding failed")]
    Encoding,
    /// The provider rejected the operation or returned invalid output.
    #[error(transparent)]
    Signing(#[from] SigningError),
}

/// Preflight without using a private key or resolving references.
///
/// Enveloped input must be UTF-8 XML 1.0 with no DTD, existing XML signature,
/// xml:base, reserved Firmica IDs, duplicate Id/ID/id/xml:id, over 100,000 nodes
/// or nesting beyond 128 elements. Other modes treat input as opaque bytes.
pub fn preflight(content: &[u8], mode: XmlMode) -> Result<(), XadesError> {
    if content.len() > MAX_CONTENT_BYTES {
        return Err(XadesError::InputTooLarge);
    }
    if mode == XmlMode::Enveloped {
        parse(content)?;
    }
    Ok(())
}

fn parse(content: &[u8]) -> Result<roxmltree::Document<'_>, XadesError> {
    let text = std::str::from_utf8(content).map_err(|_| XadesError::InvalidXml)?;
    // roxmltree disables DTD parsing by default. Reject before the C14N parser
    // sees input, including external subsets and internal entity declarations.
    let doc = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 100_000,
        },
    )
    .map_err(|_| XadesError::InvalidXml)?;
    let mut ids = HashSet::new();
    for node in doc.descendants() {
        if node.ancestors().take(130).count() > 129 {
            return Err(XadesError::InputTooLarge);
        }
        if node.has_tag_name((DS, "Signature")) {
            return Err(XadesError::InvalidXml);
        }
        for attr in node.attributes() {
            if attr.namespace() == Some("http://www.w3.org/XML/1998/namespace")
                && attr.name() == "base"
            {
                return Err(XadesError::InvalidXml);
            }
            if matches!(attr.name(), "Id" | "ID" | "id")
                && (attr.value().starts_with(PREFIX) || !ids.insert(attr.value()))
            {
                return Err(XadesError::InvalidXml);
            }
        }
    }
    Ok(doc)
}

fn digest(data: &[u8]) -> String {
    B64.encode(Sha256::digest(data))
}

fn subtree(xml: &str, ns: &str, name: &str) -> Result<Vec<u8>, XadesError> {
    let doc = bergshamra_xml::uppsala::parse(xml).map_err(|_| XadesError::Encoding)?;
    let elements = XmlDocument::find_elements(&doc, ns, name);
    if elements.len() != 1 {
        return Err(XadesError::Encoding);
    }
    let nodes = NodeSet::tree_without_comments(elements[0], &doc);
    canonicalize_doc::<&str>(&doc, C14nMode::Exclusive, Some(&nodes), &[])
        .map_err(|_| XadesError::Encoding)
}

fn envelop(xml: &str, signature: &str) -> Result<String, XadesError> {
    let doc = parse(xml.as_bytes())?;
    let root = doc.root_element();
    let range = root.range();
    let end = &xml[range.clone()];
    let mut out = String::with_capacity(xml.len() + signature.len() + 50);
    if end.ends_with("/>") {
        let tag = root.tag_name().name();
        // Recover the original qualified name; namespace prefixes must be preserved.
        let name_end = end[1..]
            .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
            .ok_or(XadesError::InvalidXml)?
            + 1;
        let qualified = &end[1..name_end];
        if qualified.rsplit(':').next() != Some(tag) {
            return Err(XadesError::InvalidXml);
        }
        out.push_str(&xml[..range.end - 2]);
        out.push('>');
        out.push_str(signature);
        out.push_str("</");
        out.push_str(qualified);
        out.push('>');
        out.push_str(&xml[range.end..]);
    } else {
        let close = end.rfind("</").ok_or(XadesError::InvalidXml)? + range.start;
        out.push_str(&xml[..close]);
        out.push_str(signature);
        out.push_str(&xml[close..]);
    }
    Ok(out)
}

fn reference(uri: &str, transforms: &str, hash: &str, properties: bool) -> String {
    let kind = if properties {
        " Type=\"http://uri.etsi.org/01903#SignedProperties\""
    } else {
        " Id=\"Firmica-Reference\""
    };
    format!("<ds:Reference URI=\"{uri}\"{kind}><ds:Transforms>{transforms}</ds:Transforms><ds:DigestMethod Algorithm=\"{SHA256}\"/><ds:DigestValue>{hash}</ds:DigestValue></ds:Reference>")
}

fn transform(uri: &str) -> String {
    format!("<ds:Transform Algorithm=\"{uri}\"/>")
}

#[derive(Sequence)]
struct EcSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

fn xml_signature(algorithm: SignatureAlgorithm, bytes: &[u8]) -> Result<Vec<u8>, XadesError> {
    if algorithm == SignatureAlgorithm::RsaPkcs1v15Sha256 {
        return Ok(bytes.to_vec());
    }
    let sig = EcSignature::from_der(bytes).map_err(|_| SigningError::InvalidSignature)?;
    let mut raw = vec![0; 64];
    for (integer, half) in [sig.r, sig.s].into_iter().zip(raw.chunks_exact_mut(32)) {
        let b = integer.as_bytes();
        if b.len() > 32 || b.iter().all(|b| *b == 0) {
            return Err(SigningError::InvalidSignature.into());
        }
        half[32 - b.len()..].copy_from_slice(b);
    }
    Ok(raw)
}

/// Sign one document with an existing provider; never exports private keys.
///
/// All parsing, certificate checks, reference digests and SignedInfo encoding
/// complete before the one private-key call. Uses only fixed same-document
/// references and known transforms. The provider verifies its signature against
/// the selected certificate; ECDSA DER is converted to XMLDSig's fixed r||s form.
/// Caller enforces consent and certificate restrictions, then completes provider
/// cleanup before publishing. Claimed time does not establish trusted time.
pub fn sign(
    key: &mut dyn SigningKey,
    content: &[u8],
    algorithm: SignatureAlgorithm,
    mode: XmlMode,
    signing_time: SystemTime,
) -> Result<Vec<u8>, XadesError> {
    preflight(content, mode)?;
    let identity = key.identity();
    if identity.additional_certificates.len() >= 32
        || std::iter::once(&identity.certificate_der)
            .chain(&identity.additional_certificates)
            .any(|c| c.len() > 64 * 1024)
    {
        return Err(XadesError::InputTooLarge);
    }
    let mut certificates = String::new();
    for cert in std::iter::once(&identity.certificate_der).chain(&identity.additional_certificates)
    {
        let parsed =
            x509_cert::Certificate::from_der(cert).map_err(|_| XadesError::InvalidCertificate)?;
        if parsed
            .to_der()
            .map_err(|_| XadesError::InvalidCertificate)?
            != *cert
        {
            return Err(XadesError::InvalidCertificate);
        }
        certificates.push_str(&format!(
            "<ds:X509Certificate>{}</ds:X509Certificate>",
            B64.encode(cert)
        ));
    }
    let time =
        der::DateTime::from_system_time(signing_time).map_err(|_| XadesError::InvalidTime)?;
    let properties = format!("<xades:SignedProperties Id=\"Firmica-Properties\"><xades:SignedSignatureProperties><xades:SigningTime>{time}</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm=\"{SHA256}\"/><ds:DigestValue>{}</ds:DigestValue></xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference=\"#Firmica-Reference\"><xades:MimeType>{}</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties>", digest(&identity.certificate_der), if mode==XmlMode::Enveloped {"text/xml"} else {"application/octet-stream"});
    let (uri, transforms, content_hash) = if mode == XmlMode::Enveloped {
        let text = std::str::from_utf8(content).map_err(|_| XadesError::InvalidXml)?;
        let canonical = canonicalize::<&str>(text, C14nMode::Exclusive, None, &[])
            .map_err(|_| XadesError::Encoding)?;
        (
            "",
            format!(
                "{}{}",
                transform("http://www.w3.org/2000/09/xmldsig#enveloped-signature"),
                transform(EXC)
            ),
            digest(&canonical),
        )
    } else {
        ("#Firmica-Content", transform(BASE64), digest(content))
    };
    let method = match algorithm {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        }
        SignatureAlgorithm::EcdsaP256Sha256 => {
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        }
    };
    let data = if mode == XmlMode::Enveloped {
        String::new()
    } else {
        format!("<ds:Object Id=\"Firmica-Content\" MimeType=\"application/octet-stream\" Encoding=\"{BASE64}\">{}</ds:Object>",B64.encode(content))
    };
    let build = |property_hash: &str, value: &str| -> Result<String, XadesError> {
        let info = format!("<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{EXC}\"/><ds:SignatureMethod Algorithm=\"{method}\"/>{}{}</ds:SignedInfo>", reference(uri,&transforms,&content_hash,false),reference("#Firmica-Properties",&transform(EXC),property_hash,true));
        let sig = format!("<ds:Signature xmlns:ds=\"{DS}\" xmlns:xades=\"{XADES}\" Id=\"Firmica-Signature\">{info}<ds:SignatureValue>{value}</ds:SignatureValue><ds:KeyInfo><ds:X509Data>{certificates}</ds:X509Data></ds:KeyInfo>{}<ds:Object><xades:QualifyingProperties Target=\"#Firmica-Signature\">{properties}</xades:QualifyingProperties></ds:Object></ds:Signature>",if mode==XmlMode::Enveloping {data.as_str()} else {""});
        match mode {
            XmlMode::Enveloped => envelop(
                std::str::from_utf8(content).map_err(|_| XadesError::InvalidXml)?,
                &sig,
            ),
            XmlMode::Enveloping => Ok(sig),
            XmlMode::Detached => Ok(format!("<AFIRMA xmlns:ds=\"{DS}\">{data}{sig}</AFIRMA>")),
        }
    };
    let properties_hash = digest(&subtree(&build("", "")?, XADES, "SignedProperties")?);
    let template = build(&properties_hash, "")?;
    if template.len() + 128 * 1024 > MAX_SIGNATURE_BYTES {
        return Err(XadesError::InputTooLarge);
    }
    let signed_info = subtree(&template, DS, "SignedInfo")?;
    let hash: [u8; 32] = Sha256::digest(&signed_info).into();
    let input = if key.capabilities().contains(&SigningCapability {
        algorithm,
        input: InputKind::Message,
    }) {
        SigningInput::Message(&signed_info)
    } else if key.capabilities().contains(&SigningCapability {
        algorithm,
        input: InputKind::Sha256Digest,
    }) {
        SigningInput::Sha256Digest(&hash)
    } else {
        return Err(SigningError::UnsupportedOperation.into());
    };
    let signature = key.sign(algorithm, input)?;
    if signature.algorithm != algorithm
        || signature.value.is_empty()
        || signature.value.len() > 64 * 1024
    {
        return Err(SigningError::InvalidSignature.into());
    }
    let value = B64.encode(xml_signature(algorithm, &signature.value)?);
    Ok(build(&properties_hash, &value)?.into_bytes())
}
