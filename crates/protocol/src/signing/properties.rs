use super::{decode, RequestError};
use firmica_signing::format::{Appearance, ContentMode, Format, PdfOptions, XmlMode};
use std::collections::BTreeMap;

const PROPERTY_WHITESPACE: [char; 3] = [' ', '\t', '\x0c'];

pub(super) fn properties(encoded: Option<&str>) -> Result<BTreeMap<String, String>, RequestError> {
    let mut properties = BTreeMap::new();
    if let Some(encoded) = encoded {
        if encoded.len() > 4096 {
            return Err(RequestError::Invalid);
        }
        let bytes = decode(encoded)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| RequestError::Invalid)?;
        for line in text.split(['\r', '\n']) {
            let line = line.trim_start_matches(PROPERTY_WHITESPACE);
            if line.is_empty() || line.starts_with(['#', '!']) {
                continue;
            }
            // Java properties escapes and continuations need their full
            // semantics to preserve the requested text.
            if line.contains('\\') {
                return Err(RequestError::Unsupported);
            }
            let separator = line
                .find(|c| matches!(c, '=' | ':') || PROPERTY_WHITESPACE.contains(&c))
                .unwrap_or(line.len());
            let (key, rest) = line.split_at(separator);
            let rest = rest.trim_start_matches(PROPERTY_WHITESPACE);
            let value = rest
                .strip_prefix(['=', ':'])
                .unwrap_or(rest)
                .trim_start_matches(PROPERTY_WHITESPACE);
            if key.is_empty()
                || key.chars().any(char::is_control)
                || value.chars().any(|c| c.is_control() && c != '\t')
            {
                return Err(RequestError::Invalid);
            }
            if properties
                .insert(key.to_owned(), value.to_owned())
                .is_some()
            {
                return Err(RequestError::Invalid);
            }
        }
    }
    Ok(properties)
}

pub(super) fn decode_format(
    name: &str,
    mut properties: BTreeMap<String, String>,
) -> Result<Format, RequestError> {
    let format = match name {
        "CAdES" => {
            let mode = match properties.remove("mode") {
                None => ContentMode::Detached,
                Some(mode) if mode.eq_ignore_ascii_case("explicit") => ContentMode::Detached,
                Some(mode) if mode.eq_ignore_ascii_case("implicit") => ContentMode::Attached,
                _ => return Err(RequestError::Unsupported),
            };
            Format::Cades(mode)
        }
        "PAdES" => {
            let appearance = if properties.contains_key("signaturePage") {
                let page = properties
                    .remove("signaturePage")
                    .unwrap()
                    .parse::<u32>()
                    .map_err(|_| RequestError::Invalid)?;
                if page == 0 {
                    return Err(RequestError::Unsupported);
                }
                let mut rectangle = [0.; 4];
                for (coordinate, name) in rectangle.iter_mut().zip([
                    "signaturePositionOnPageLowerLeftX",
                    "signaturePositionOnPageLowerLeftY",
                    "signaturePositionOnPageUpperRightX",
                    "signaturePositionOnPageUpperRightY",
                ]) {
                    *coordinate = properties
                        .remove(name)
                        .ok_or(RequestError::Unsupported)?
                        .parse::<f32>()
                        .map_err(|_| RequestError::Invalid)?;
                    if !coordinate.is_finite() {
                        return Err(RequestError::Invalid);
                    }
                }
                let text = properties
                    .remove("layer2Text")
                    .ok_or(RequestError::Unsupported)?;
                if text.is_empty()
                    || text.len() > 120
                    || !text.bytes().all(|b| (32..=126).contains(&b))
                    || rectangle[0] >= rectangle[2]
                    || rectangle[1] >= rectangle[3]
                {
                    return Err(RequestError::Unsupported);
                }
                Some(Appearance {
                    page,
                    rectangle,
                    text,
                })
            } else {
                None
            };
            Format::Pades(PdfOptions { appearance })
        }
        "XAdES" | "XAdES Enveloped" | "XAdES Enveloping" | "XAdES Detached" => {
            let placement = properties.remove("format");
            if name != "XAdES" && placement.as_ref().is_some_and(|value| value != name) {
                return Err(RequestError::Unsupported);
            }
            let placement = placement.as_deref().unwrap_or(if name == "XAdES" {
                "XAdES Enveloping"
            } else {
                name
            });
            let mode = match placement {
                "XAdES Enveloped" => XmlMode::Enveloped,
                "XAdES Enveloping" => XmlMode::Enveloping,
                "XAdES Detached" => XmlMode::Detached,
                _ => return Err(RequestError::Unsupported),
            };
            // Explicit XML mode can request caller-provided digests upstream.
            if properties
                .remove("mode")
                .is_some_and(|m| !m.eq_ignore_ascii_case("implicit"))
            {
                return Err(RequestError::Unsupported);
            }
            Format::Xades(mode)
        }
        _ => return Err(RequestError::Unsupported),
    };
    if !properties.is_empty() {
        return Err(RequestError::Unsupported);
    }
    Ok(format)
}
