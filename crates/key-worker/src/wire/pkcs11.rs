use super::{
    frame, identity_response, put, signing_requests, write_frame, Decoder, Frame,
    MAX_CERTIFICATE_BYTES, MAX_PASSWORD_BYTES, MAX_REPLY_BYTES,
};
use crate::{pkcs11::signing::with_key, Pkcs11Certificate, Pkcs11Pins, Pkcs11Token, WorkerError};
use pkcs11_client::SecretText;
use secrecy::ExposeSecret;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(super) const DISCOVER: u8 = 9;
pub(super) const DISCOVERED: u8 = 10;
pub(super) const DISCOVERY_ERROR: u8 = 11;
pub(super) const OPEN: u8 = 12;
const MAX_MODULE_PATH_BYTES: usize = 4096;
const MAX_URI_BYTES: usize = 4096;
const MAX_TOKENS: usize = 32;
const MAX_OBJECTS: usize = 128;
const FAILURE: u8 = 1;
const CLEANUP_FAILURE: u8 = 2;
const AUTH_FAILURE: u8 = 3;
const IDENTITY_FAILURE: u8 = 4;
const UNSUPPORTED: u8 = 5;

fn module_text(module: &Path) -> Result<&str, WorkerError> {
    module
        .to_str()
        .filter(|path| module.is_absolute() && path.len() <= MAX_MODULE_PATH_BYTES)
        .filter(|path| !path.contains('\0'))
        .ok_or(WorkerError::InvalidInput)
}

pub(crate) fn request(module: &Path) -> Result<Frame, WorkerError> {
    let mut bytes = vec![DISCOVER];
    put(&mut bytes, module_text(module)?.as_bytes())?;
    Ok(frame(bytes))
}

fn decode_module<'a>(decoder: &mut Decoder<'a>) -> Result<&'a Path, WorkerError> {
    let path = std::str::from_utf8(decoder.blob(MAX_MODULE_PATH_BYTES)?)
        .map_err(|_| WorkerError::Protocol)?;
    module_text(Path::new(path)).map_err(|_| WorkerError::Protocol)?;
    Ok(Path::new(path))
}

pub(super) fn decode_request(bytes: &[u8]) -> Result<&Path, WorkerError> {
    let mut decoder = Decoder(bytes);
    if decoder.byte()? != DISCOVER {
        return Err(WorkerError::Protocol);
    }
    let path = decode_module(&mut decoder)?;
    decoder.end()?;
    Ok(path)
}

pub(crate) fn open_request(
    module: &Path,
    locator: &str,
    pins: &Pkcs11Pins,
) -> Result<Frame, WorkerError> {
    let context = pins
        .context
        .as_ref()
        .map_or("", ExposeSecret::expose_secret);
    let user = pins.user.expose_secret();
    if !valid_uri(locator)
        || locator.len() > MAX_URI_BYTES
        || !valid_pin(user)
        || !valid_pin(context)
    {
        return Err(WorkerError::InvalidInput);
    }
    let fields = [module_text(module)?, locator, user, context];
    let capacity = 1 + fields.iter().map(|value| 4 + value.len()).sum::<usize>();
    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(OPEN);
    for field in fields {
        put(&mut bytes, field.as_bytes())?;
    }
    Ok(frame(bytes))
}

pub(super) struct OpenRequest {
    module: PathBuf,
    locator: String,
    user: SecretText,
    context: Option<SecretText>,
}

pub(super) fn decode_open(bytes: &[u8]) -> Result<OpenRequest, WorkerError> {
    let mut decoder = Decoder(bytes);
    if decoder.byte()? != OPEN {
        return Err(WorkerError::Protocol);
    }
    let module = decode_module(&mut decoder)?.to_owned();
    let locator = decode_uri(&mut decoder)?;
    let user = std::str::from_utf8(decoder.blob(MAX_PASSWORD_BYTES)?)
        .map_err(|_| WorkerError::Protocol)?;
    let context = std::str::from_utf8(decoder.blob(MAX_PASSWORD_BYTES)?)
        .map_err(|_| WorkerError::Protocol)?;
    decoder.end()?;
    if !valid_pin(user) || !valid_pin(context) {
        return Err(WorkerError::Protocol);
    }
    Ok(OpenRequest {
        module,
        locator,
        user: SecretText::from(user),
        context: (!context.is_empty()).then(|| SecretText::from(context)),
    })
}

fn valid_pin(pin: &str) -> bool {
    pin.len() <= MAX_PASSWORD_BYTES && !pin.contains('\0')
}

pub(super) fn serve_open(
    request: OpenRequest,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), WorkerError> {
    let outcome = with_key(
        &request.module,
        &request.locator,
        request.user,
        request.context,
        |mut key| {
            write_frame(output, identity_response(&key)?.expose_secret())?;
            signing_requests(&mut key, input, output)
        },
    );
    match outcome {
        Ok(end) => end.reply(output),
        Err(error) => write_frame(output, &error_reply(error)),
    }
}

fn error_reply(error: WorkerError) -> [u8; 2] {
    let code = match error {
        WorkerError::CleanupFailed => CLEANUP_FAILURE,
        WorkerError::TokenAuthentication => AUTH_FAILURE,
        WorkerError::TokenIdentity => IDENTITY_FAILURE,
        WorkerError::TokenUnsupported => UNSUPPORTED,
        _ => FAILURE,
    };
    [DISCOVERY_ERROR, code]
}

pub(crate) fn decode_error(bytes: &[u8]) -> Option<WorkerError> {
    match bytes {
        [DISCOVERY_ERROR, FAILURE] => Some(WorkerError::Unavailable),
        [DISCOVERY_ERROR, CLEANUP_FAILURE] => Some(WorkerError::CleanupFailed),
        [DISCOVERY_ERROR, AUTH_FAILURE] => Some(WorkerError::TokenAuthentication),
        [DISCOVERY_ERROR, IDENTITY_FAILURE] => Some(WorkerError::TokenIdentity),
        [DISCOVERY_ERROR, UNSUPPORTED] => Some(WorkerError::TokenUnsupported),
        _ => None,
    }
}

pub(super) fn discover_reply(module: &Path) -> Frame {
    match crate::pkcs11::discover(module, MAX_TOKENS, MAX_OBJECTS)
        .and_then(|tokens| encode_reply(&tokens))
    {
        Ok(response) => response,
        Err(error) => frame(error_reply(error).to_vec()),
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
        DISCOVERY_ERROR => return Err(decode_error(bytes).unwrap_or(WorkerError::Protocol)),
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
    if !valid_uri(uri) {
        return Err(WorkerError::Protocol);
    }
    Ok(uri.to_owned())
}

fn valid_uri(uri: &str) -> bool {
    uri.starts_with("pkcs11:")
        && !uri.contains('?')
        && uri.bytes().all(|byte| byte.is_ascii_graphic())
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
