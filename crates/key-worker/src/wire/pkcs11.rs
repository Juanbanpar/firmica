use super::{frame, put, Decoder, Frame, MAX_CERTIFICATE_BYTES, MAX_REPLY_BYTES};
use crate::{Pkcs11Certificate, Pkcs11Token, WorkerError};
use std::path::Path;

pub(super) const DISCOVER: u8 = 9;
pub(super) const DISCOVERED: u8 = 10;
pub(super) const DISCOVERY_ERROR: u8 = 11;
const MAX_MODULE_PATH_BYTES: usize = 4096;
const MAX_URI_BYTES: usize = 4096;
const MAX_TOKENS: usize = 32;
const MAX_OBJECTS: usize = 128;
const FAILURE: u8 = 1;
const CLEANUP_FAILURE: u8 = 2;

pub(crate) fn request(module: &Path) -> Result<Frame, WorkerError> {
    let path = module
        .to_str()
        .filter(|path| module.is_absolute() && path.len() <= MAX_MODULE_PATH_BYTES)
        .filter(|path| !path.contains('\0'))
        .ok_or(WorkerError::InvalidInput)?;
    let mut bytes = vec![DISCOVER];
    put(&mut bytes, path.as_bytes())?;
    Ok(frame(bytes))
}

pub(super) fn decode_request(bytes: &[u8]) -> Result<&Path, WorkerError> {
    let mut decoder = Decoder(bytes);
    if decoder.byte()? != DISCOVER {
        return Err(WorkerError::Protocol);
    }
    let path = std::str::from_utf8(decoder.blob(MAX_MODULE_PATH_BYTES)?)
        .map_err(|_| WorkerError::Protocol)?;
    decoder.end()?;
    if !Path::new(path).is_absolute() || path.contains('\0') {
        return Err(WorkerError::Protocol);
    }
    Ok(Path::new(path))
}

pub(super) fn discover_reply(module: &Path) -> Frame {
    match crate::pkcs11::discover(module, MAX_TOKENS, MAX_OBJECTS)
        .and_then(|tokens| encode_reply(&tokens))
    {
        Ok(response) => response,
        Err(WorkerError::CleanupFailed) => frame(vec![DISCOVERY_ERROR, CLEANUP_FAILURE]),
        Err(_) => frame(vec![DISCOVERY_ERROR, FAILURE]),
    }
}

fn encode_reply(tokens: &[Pkcs11Token]) -> Result<Frame, WorkerError> {
    let mut bytes = vec![DISCOVERED, tokens.len() as u8];
    for token in tokens {
        put(&mut bytes, token.uri.as_bytes())?;
        bytes.push(token.certificates.len() as u8);
        for certificate in &token.certificates {
            put(&mut bytes, certificate.uri.as_bytes())?;
            put(&mut bytes, &certificate.der)?;
        }
    }
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(WorkerError::Protocol);
    }
    Ok(frame(bytes))
}

pub(crate) fn decode_reply(bytes: &[u8]) -> Result<Vec<Pkcs11Token>, WorkerError> {
    let mut decoder = Decoder(bytes);
    match decoder.byte()? {
        DISCOVERY_ERROR => {
            let error = match decoder.byte()? {
                FAILURE => WorkerError::Unavailable,
                CLEANUP_FAILURE => WorkerError::CleanupFailed,
                _ => return Err(WorkerError::Protocol),
            };
            decoder.end()?;
            return Err(error);
        }
        DISCOVERED => (),
        _ => return Err(WorkerError::Protocol),
    }
    let count = usize::from(decoder.byte()?);
    if count > MAX_TOKENS {
        return Err(WorkerError::Protocol);
    }
    let mut tokens = Vec::with_capacity(count);
    let mut remaining = MAX_OBJECTS;
    for _ in 0..count {
        let uri = decode_uri(&mut decoder)?;
        let count = usize::from(decoder.byte()?);
        remaining = remaining.checked_sub(count).ok_or(WorkerError::Protocol)?;
        let mut certificates = Vec::with_capacity(count);
        for _ in 0..count {
            let uri = decode_uri(&mut decoder)?;
            let der = decoder.blob(MAX_CERTIFICATE_BYTES)?;
            if der.is_empty() {
                return Err(WorkerError::Protocol);
            }
            certificates.push(Pkcs11Certificate {
                uri,
                der: der.to_vec(),
            });
        }
        tokens.push(Pkcs11Token { uri, certificates });
    }
    decoder.end()?;
    Ok(tokens)
}

fn decode_uri(decoder: &mut Decoder<'_>) -> Result<String, WorkerError> {
    let uri =
        std::str::from_utf8(decoder.blob(MAX_URI_BYTES)?).map_err(|_| WorkerError::Protocol)?;
    if !uri.starts_with("pkcs11:")
        || uri.contains('?')
        || !uri.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(WorkerError::Protocol);
    }
    Ok(uri.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn discovery_reply_requires_bounded_complete_records_and_public_uris() {
        let mut tokens = [Pkcs11Token {
            uri: "pkcs11:serial=123".into(),
            certificates: vec![Pkcs11Certificate {
                uri: "pkcs11:serial=123;id=%01;type=cert".into(),
                der: vec![1, 2, 3],
            }],
        }];
        let encoded = encode_reply(&tokens).unwrap();
        let encoded = encoded.expose_secret();
        assert!(decode_reply(encoded).unwrap() == tokens);
        assert!(matches!(
            decode_reply(&encoded[..encoded.len() - 1]),
            Err(WorkerError::Protocol)
        ));
        assert!(matches!(
            decode_reply(&[DISCOVERED, (MAX_TOKENS + 1) as u8]),
            Err(WorkerError::Protocol)
        ));
        tokens[0].certificates[0]
            .uri
            .push_str("?pin-value=synthetic");
        let encoded = encode_reply(&tokens).unwrap();
        assert!(matches!(
            decode_reply(encoded.expose_secret()),
            Err(WorkerError::Protocol)
        ));
    }
}
