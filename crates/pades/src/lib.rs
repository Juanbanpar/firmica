//! Incremental PDF approval signatures using an opaque signing provider.
//!
//! Uses the PAdES B-B building blocks of ETSI EN 319 142-1 §6.3: detached DER
//! CMS, SHA-256, SigningCertificateV2, `/M`, and `/ETSI.CAdES.detached`. This is
//! not a conformance assessment, trust decision or timestamp service. Existing
//! revisions remain byte-for-byte intact; existing signatures are not validated.
//! Encrypted PDFs, certification permissions, field locks and XFA are rejected.
//! No JavaScript, actions, embedded files or page content are executed or rendered.
//! Run parsing and signing outside the UI loop; close the provider before publication.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use firmica_signing::{SignatureAlgorithm, SigningKey};
use lopdf::{
    dictionary, Dictionary, Document, IncrementalDocument, LoadOptions, Object, Stream,
    StringFormat,
};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

/// Maximum original PDF size (16 MiB).
pub const MAX_CONTENT_BYTES: usize = firmica_cades::MAX_CONTENT_BYTES;
/// Maximum output size, including certificate space and the incremental revision.
pub const MAX_SIGNATURE_BYTES: usize = MAX_CONTENT_BYTES + 5 * 1024 * 1024;
const RANGE: &[u8] = b"[0 9999999999 9999999999 9999999999]";

pub use firmica_signing::format::{Appearance, PdfOptions};

/// Static failures with no PDF contents or native diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PadesError {
    /// The PDF, output or a decompressed structural stream exceeds a limit.
    #[error("PDF exceeds a resource limit")]
    InputTooLarge,
    /// Invalid structure, cross references, page tree or unsupported PDF version.
    #[error("invalid PDF")]
    InvalidPdf,
    /// Encryption, certification restrictions, field locks or XFA are present.
    #[error("unsupported PDF restrictions")]
    UnsupportedPdf,
    /// Invalid page, rectangle or appearance text.
    #[error("invalid PDF signature appearance")]
    InvalidAppearance,
    /// Claimed signing time cannot be encoded.
    #[error("unsupported PDF signing time")]
    InvalidTime,
    /// The existing CMS encoder or provider rejected the operation.
    #[error(transparent)]
    Cades(#[from] firmica_cades::CadesError),
    /// Failed to serialize or locate the reserved signature dictionary.
    #[error("PDF signature encoding failed")]
    Encoding,
}

impl From<lopdf::Error> for PadesError {
    fn from(_: lopdf::Error) -> Self {
        Self::InvalidPdf
    }
}

/// Validate the PDF and appearance without accessing a private key.
///
/// Uses strict parsing, a 16-MiB per-structural-stream decompression limit and
/// rejects more than 100,000 loaded objects. These are parser limits, not a
/// process memory/CPU sandbox. No streams containing page graphics are decoded.
pub fn preflight(pdf: &[u8], options: &PdfOptions) -> Result<(), PadesError> {
    parse(pdf, options).map(|_| ())
}

fn parse(pdf: &[u8], options: &PdfOptions) -> Result<Document, PadesError> {
    if pdf.len() > MAX_CONTENT_BYTES {
        return Err(PadesError::InputTooLarge);
    }
    if !pdf.starts_with(b"%PDF-") || !pdf.trim_ascii_end().ends_with(b"%%EOF") {
        return Err(PadesError::InvalidPdf);
    }
    let doc = Document::load_mem_with_options(
        pdf,
        LoadOptions {
            strict: true,
            max_decompressed_size: Some(MAX_CONTENT_BYTES),
            ..Default::default()
        },
    )?;
    if doc.objects.len() > 100_000 {
        return Err(PadesError::InputTooLarge);
    }
    if doc.is_encrypted() || doc.trailer.has(b"Encrypt") || doc.encryption_state.is_some() {
        return Err(PadesError::UnsupportedPdf);
    }
    if !matches!(
        doc.version.as_str(),
        "1.3" | "1.4" | "1.5" | "1.6" | "1.7" | "2.0"
    ) {
        return Err(PadesError::InvalidPdf);
    }
    let catalog = doc.catalog()?;
    if catalog.has(b"Perms") {
        return Err(PadesError::UnsupportedPdf);
    }
    if dictionary_value(&doc, catalog, b"AcroForm")?.has(b"XFA") {
        return Err(PadesError::UnsupportedPdf);
    }
    inspect_objects(&doc, None)?;
    let pages = doc.get_pages();
    if pages.is_empty() {
        return Err(PadesError::InvalidPdf);
    }
    if let Some(appearance) = &options.appearance {
        let page = *pages
            .get(&appearance.page)
            .ok_or(PadesError::InvalidAppearance)?;
        let [x0, y0, x1, y1] = appearance.rectangle;
        if ![x0, y0, x1, y1].iter().all(|v| v.is_finite())
            || x1 <= x0
            || y1 <= y0
            || appearance.text.is_empty()
            || appearance.text.len() > 120
            || !appearance.text.bytes().all(|b| (32..=126).contains(&b))
        {
            return Err(PadesError::InvalidAppearance);
        }
        // Resolve inherited page geometry with a bounded parent walk.
        let mut current = page;
        let mut media_box = None;
        for _ in 0..100 {
            let dict = doc.get_dictionary(current)?;
            if let Ok(value) = dict.get(b"MediaBox") {
                let (_, value) = doc.dereference(value)?;
                let values = value.as_array()?;
                if values.len() != 4 {
                    return Err(PadesError::InvalidPdf);
                }
                media_box = Some([
                    values[0].as_float()?,
                    values[1].as_float()?,
                    values[2].as_float()?,
                    values[3].as_float()?,
                ]);
                break;
            }
            current = dict.get(b"Parent")?.as_reference()?;
        }
        let [mx0, my0, mx1, my1] = media_box.ok_or(PadesError::InvalidPdf)?;
        if x0 < mx0 || y0 < my0 || x1 > mx1 || y1 > my1 {
            return Err(PadesError::InvalidAppearance);
        }
    }
    Ok(doc)
}

fn dictionary_value(
    doc: &Document,
    dict: &Dictionary,
    key: &[u8],
) -> Result<Dictionary, PadesError> {
    if !dict.has(key) {
        return Ok(Dictionary::new());
    }
    Ok(doc.dereference(dict.get(key)?)?.1.as_dict()?.clone())
}

fn inspect_objects(doc: &Document, new_field: Option<&str>) -> Result<(), PadesError> {
    let mut stack: Vec<_> = doc.objects.values().map(|object| (object, 0)).collect();
    let mut count = 0;
    while let Some((object, depth)) = stack.pop() {
        count += 1;
        if count > 1_000_000 || depth > 128 {
            return Err(PadesError::InputTooLarge);
        }
        let dictionary = match object {
            Object::Dictionary(dictionary) => Some(dictionary),
            Object::Stream(stream) => Some(&stream.dict),
            Object::Array(values) => {
                stack.extend(values.iter().map(|v| (v, depth + 1)));
                None
            }
            _ => None,
        };
        if let Some(dictionary) = dictionary {
            if dictionary.has(b"Lock")
                || dictionary.has(b"XFA")
                || dictionary.has(b"TransformMethod")
            {
                return Err(PadesError::UnsupportedPdf);
            }
            if let (Some(name), Ok(value)) = (new_field, dictionary.get(b"T")) {
                if lopdf::decode_text_string(doc.dereference(value)?.1)
                    .ok()
                    .as_deref()
                    == Some(name)
                {
                    return Err(PadesError::UnsupportedPdf);
                }
            }
            stack.extend(dictionary.iter().map(|(_, value)| (value, depth + 1)));
        }
    }
    Ok(())
}

fn array_value(doc: &Document, dict: &Dictionary, key: &[u8]) -> Result<Vec<Object>, PadesError> {
    if !dict.has(key) {
        return Ok(Vec::new());
    }
    Ok(doc.dereference(dict.get(key)?)?.1.as_array()?.clone())
}

/// Append one approval signature; invokes the provider once after PDF preflight.
///
/// Hashes the complete final revision except the hexadecimal `/Contents` value,
/// including its delimiters. Fixed-width ByteRange replacement preserves offsets.
/// No earlier revision is reserialized. Adds a fresh field; does not fill an
/// existing signature field or modify a certified/locked document.
///
/// `signing_time` is a caller claim, not trusted time. Provider verification and
/// certificate restrictions/consent are caller responsibilities. Errors return
/// no partial output. Close the provider successfully before publishing bytes.
pub fn sign(
    key: &mut dyn SigningKey,
    pdf: &[u8],
    algorithm: SignatureAlgorithm,
    options: &PdfOptions,
    signing_time: SystemTime,
) -> Result<Vec<u8>, PadesError> {
    let doc = parse(pdf, options)?;
    let identity = key.identity();
    if identity.additional_certificates.len() >= firmica_cades::MAX_CERTIFICATES
        || std::iter::once(&identity.certificate_der)
            .chain(&identity.additional_certificates)
            .any(|cert| cert.len() > firmica_cades::MAX_CERTIFICATE_BYTES)
    {
        return Err(PadesError::InputTooLarge);
    }
    // Leave room for ASN.1, signed attributes and the provider's 64-KiB signature cap.
    let reserve = std::iter::once(&identity.certificate_der)
        .chain(&identity.additional_certificates)
        .map(Vec::len)
        .sum::<usize>()
        + 128 * 1024;
    let time =
        der::DateTime::from_system_time(signing_time).map_err(|_| PadesError::InvalidTime)?;
    let date = format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minutes(),
        time.seconds()
    );
    let root = doc.trailer.get(b"Root")?.as_reference()?;
    let mut catalog = doc.catalog()?.clone();
    let mut acroform = dictionary_value(&doc, &catalog, b"AcroForm")?;
    if acroform.has(b"XFA") {
        return Err(PadesError::UnsupportedPdf);
    }
    let mut fields = array_value(&doc, &acroform, b"Fields")?;
    let page_id = *doc
        .get_pages()
        .get(&options.appearance.as_ref().map_or(1, |a| a.page))
        .ok_or(PadesError::InvalidPdf)?;
    let mut page = doc.get_dictionary(page_id)?.clone();
    let mut annotations = array_value(&doc, &page, b"Annots")?;
    let mut update = IncrementalDocument::create_from(pdf.to_vec(), doc);
    let new = &mut update.new_document;
    let sig = new.add_object(dictionary! {
        "Type" => "Sig", "Filter" => "Adobe.PPKLite", "SubFilter" => "ETSI.CAdES.detached",
        "M" => Object::string_literal(date),
        "ByteRange" => vec![0_i64.into(), 9_999_999_999_i64.into(), 9_999_999_999_i64.into(), 9_999_999_999_i64.into()],
        "Contents" => Object::String(vec![0; reserve], StringFormat::Hexadecimal),
    });
    let rectangle = options
        .appearance
        .as_ref()
        .map_or([0.0; 4], |a| a.rectangle);
    // Object numbers are unique across all revisions; the name avoids earlier field names.
    let field_name = format!("FirmicaSignature{}", sig.0);
    inspect_objects(update.get_prev_documents(), Some(&field_name))?;
    let new = &mut update.new_document;
    let mut widget = dictionary! {
        "Type" => "Annot", "Subtype" => "Widget", "FT" => "Sig", "F" => 132,
        "T" => Object::string_literal(field_name), "V" => sig, "P" => page_id,
        "Rect" => rectangle.into_iter().map(Object::Real).collect::<Vec<_>>(),
    };
    if let Some(appearance) = &options.appearance {
        let width = rectangle[2] - rectangle[0];
        let height = rectangle[3] - rectangle[1];
        let font = new.add_object(
            dictionary! {"Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica"},
        );
        let text = appearance
            .text
            .replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)");
        let size = (width / (appearance.text.len() as f32 * 0.65))
            .min(height * 0.5)
            .min(12.0);
        let graphics =
            format!("q 0 0 {width} {height} re W n BT /F1 {size} Tf 2 2 Td ({text}) Tj ET Q");
        let stream = new.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Form", "FormType" => 1,
                "BBox" => vec![0.into(), 0.into(), Object::Real(width), Object::Real(height)],
                "Resources" => dictionary! {"Font" => dictionary! {"F1" => font}},
            },
            graphics.into_bytes(),
        ));
        widget.set("AP", dictionary! {"N" => stream});
    }
    let widget_id = new.add_object(widget);
    fields.push(widget_id.into());
    annotations.push(widget_id.into());
    let flags = acroform
        .get(b"SigFlags")
        .and_then(Object::as_i64)
        .unwrap_or(0)
        | 3;
    acroform.set("SigFlags", flags);
    acroform.set("Fields", fields);
    catalog.set("AcroForm", new.add_object(acroform));
    // PDF 1.7 defines the ETSI subfilter through the Adobe extension dictionary.
    if update.get_prev_documents().version != "2.0"
        && catalog.get(b"Version").and_then(Object::as_name).ok() != Some(b"2.0")
    {
        catalog.set("Version", Object::Name(b"1.7".to_vec()));
    }
    let extensions = catalog.get(b"Extensions").ok().cloned();
    let mut extensions = if let Some(value) = extensions {
        update
            .get_prev_documents()
            .dereference(&value)?
            .1
            .as_dict()?
            .clone()
    } else {
        Dictionary::new()
    };
    if dictionary_value(update.get_prev_documents(), &extensions, b"ESIC")?
        .get(b"ExtensionLevel")
        .and_then(Object::as_i64)
        .unwrap_or(0)
        < 2
    {
        extensions.set(
            "ESIC",
            dictionary! {"BaseVersion" => "1.7", "ExtensionLevel" => 2},
        );
    }
    catalog.set("Extensions", extensions);
    page.set("Annots", annotations);
    update.new_document.set_object(root, catalog);
    update.new_document.set_object(page_id, page);
    let mut output = Vec::new();
    update
        .save_to(&mut output)
        .map_err(|_| PadesError::Encoding)?;
    if output.len() > MAX_SIGNATURE_BYTES {
        return Err(PadesError::InputTooLarge);
    }
    // Locate only within our own new signature object, never in untrusted original bytes.
    let object_header = format!("\n{} 0 obj", sig.0);
    let object_start = unique(&output[pdf.len()..], object_header.as_bytes())? + pdf.len();
    let object_end = output[object_start..]
        .windows(6)
        .position(|v| v == b"endobj")
        .ok_or(PadesError::Encoding)?
        + object_start;
    let range_start = unique(&output[object_start..object_end], RANGE)? + object_start;
    let contents_key = unique(&output[object_start..object_end], b"/Contents")?
        + object_start
        + b"/Contents".len();
    let start = output[contents_key..object_end]
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .ok_or(PadesError::Encoding)?
        + contents_key;
    let end = start + reserve * 2 + 2;
    if output.get(start) != Some(&b'<')
        || output.get(end - 1) != Some(&b'>')
        || end > object_end
        || !output[start + 1..end - 1].iter().all(|b| *b == b'0')
    {
        return Err(PadesError::Encoding);
    }
    let range = format!("[0 {start} {end} {}]", output.len() - end);
    if range.len() > RANGE.len() {
        return Err(PadesError::Encoding);
    }
    output[range_start..range_start + RANGE.len()].fill(b' ');
    output[range_start..range_start + range.len()].copy_from_slice(range.as_bytes());
    let mut hash = Sha256::new();
    hash.update(&output[..start]);
    hash.update(&output[end..]);
    let cms = firmica_cades::sign_pdf_digest(key, hash.finalize().into(), algorithm)?;
    if cms.len() > reserve {
        return Err(PadesError::Encoding);
    }
    const HEX: &[u8] = b"0123456789ABCDEF";
    for (byte, pair) in cms
        .iter()
        .zip(output[start + 1..end - 1].as_chunks_mut::<2>().0)
    {
        pair[0] = HEX[(byte >> 4) as usize];
        pair[1] = HEX[(byte & 15) as usize];
    }
    Ok(output)
}

fn unique(haystack: &[u8], needle: &[u8]) -> Result<usize, PadesError> {
    let mut found = haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(i, v)| (v == needle).then_some(i));
    let first = found.next().ok_or(PadesError::Encoding)?;
    if found.next().is_some() {
        return Err(PadesError::Encoding);
    }
    Ok(first)
}
