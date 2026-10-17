use crate::{
    WorkerError, MAX_ADDRESS_SPACE_BYTES, MAX_CERTIFICATES, MAX_CERTIFICATE_BYTES, MAX_CPU_SECONDS,
    MAX_PASSWORD_BYTES, MAX_SIGNING_INPUT_BYTES,
};
use firmica_certificates::{CertificateError, Pkcs12Key, MAX_PKCS12_BYTES};
use firmica_signing::{
    CertificateIdentity, InputKind, Signature, SignatureAlgorithm, SigningCapability, SigningInput,
    SigningKey,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use std::io::{Read, Write};

pub(crate) const HELLO: &[u8] = b"FRMKEY\x01";
pub(crate) const CLOSE: u8 = 3;
pub(crate) const CLOSED: u8 = 4;
const IMPORT: u8 = 1;
const SIGN: u8 = 2;
const IDENTITY: u8 = 5;
const SIGNATURE: u8 = 6;
const IMPORT_ERROR: u8 = 7;
const SIGNING_ERROR: u8 = 8;
const MAX_SIGNATURE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_REPLY_BYTES: usize = MAX_CERTIFICATES * (MAX_CERTIFICATE_BYTES + 4) + 64;
const MAX_REQUEST_BYTES: usize = MAX_PKCS12_BYTES + MAX_PASSWORD_BYTES + 16;

type Frame = SecretBox<Vec<u8>>;

fn frame(bytes: Vec<u8>) -> Frame {
    SecretBox::new(Box::new(bytes))
}

pub(crate) fn import_request(container: &[u8], password: &str) -> Result<Frame, WorkerError> {
    let mut payload = Vec::with_capacity(9 + container.len() + password.len());
    payload.push(IMPORT);
    let mut bytes = frame(payload);
    put(bytes.expose_secret_mut(), container)?;
    put(bytes.expose_secret_mut(), password.as_bytes())?;
    Ok(bytes)
}

pub(crate) fn sign_request(
    algorithm: SignatureAlgorithm,
    input: SigningInput<'_>,
) -> Result<Frame, WorkerError> {
    let payload = match input {
        SigningInput::Message(bytes) => bytes,
        SigningInput::Sha256Digest(bytes) => bytes,
    };
    let mut bytes = Vec::with_capacity(7 + payload.len());
    bytes.extend([SIGN, algorithm_code(algorithm), input_code(input.kind())]);
    let mut bytes = frame(bytes);
    put(bytes.expose_secret_mut(), payload)?;
    Ok(bytes)
}

fn put(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WorkerError> {
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| WorkerError::Protocol)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

struct Decoder<'a>(&'a [u8]);
impl<'a> Decoder<'a> {
    fn byte(&mut self) -> Result<u8, WorkerError> {
        let (value, tail) = self.0.split_first().ok_or(WorkerError::Protocol)?;
        self.0 = tail;
        Ok(*value)
    }
    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], WorkerError> {
        let header: [u8; 4] = self
            .0
            .get(..4)
            .ok_or(WorkerError::Protocol)?
            .try_into()
            .map_err(|_| WorkerError::Protocol)?;
        let length = u32::from_be_bytes(header) as usize;
        self.0 = &self.0[4..];
        if length > maximum {
            return Err(WorkerError::Protocol);
        }
        let value = self.0.get(..length).ok_or(WorkerError::Protocol)?;
        self.0 = &self.0[length..];
        Ok(value)
    }
    fn end(&self) -> Result<(), WorkerError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(WorkerError::Protocol)
        }
    }
}

fn algorithm_code(algorithm: SignatureAlgorithm) -> u8 {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15Sha256 => 1,
        SignatureAlgorithm::EcdsaP256Sha256 => 2,
    }
}
fn decode_algorithm(code: u8) -> Result<SignatureAlgorithm, WorkerError> {
    match code {
        1 => Ok(SignatureAlgorithm::RsaPkcs1v15Sha256),
        2 => Ok(SignatureAlgorithm::EcdsaP256Sha256),
        _ => Err(WorkerError::Protocol),
    }
}
fn input_code(input: InputKind) -> u8 {
    match input {
        InputKind::Message => 1,
        InputKind::Sha256Digest => 2,
    }
}
fn decode_input(code: u8) -> Result<InputKind, WorkerError> {
    match code {
        1 => Ok(InputKind::Message),
        2 => Ok(InputKind::Sha256Digest),
        _ => Err(WorkerError::Protocol),
    }
}

fn identity_response(key: &Pkcs12Key) -> Result<Frame, WorkerError> {
    let identity = key.identity();
    if identity.additional_certificates.len() >= MAX_CERTIFICATES {
        return Err(WorkerError::Protocol);
    }
    let mut bytes = vec![IDENTITY, (identity.additional_certificates.len() + 1) as u8];
    for certificate in
        std::iter::once(&identity.certificate_der).chain(&identity.additional_certificates)
    {
        if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
            return Err(WorkerError::Protocol);
        }
        put(&mut bytes, certificate)?;
    }
    bytes.push(key.capabilities().len() as u8);
    for capability in key.capabilities() {
        bytes.extend([
            algorithm_code(capability.algorithm),
            input_code(capability.input),
        ]);
    }
    Ok(frame(bytes))
}

pub(crate) fn decode_identity(
    encoded: &[u8],
) -> Result<(CertificateIdentity, Vec<SigningCapability>), WorkerError> {
    let mut decoder = Decoder(encoded);
    match decoder.byte()? {
        IMPORT_ERROR => {
            let error = decode_import_error(decoder.byte()?)?;
            decoder.end()?;
            return Err(WorkerError::Import(error));
        }
        IDENTITY => (),
        _ => return Err(WorkerError::Protocol),
    }
    let count = usize::from(decoder.byte()?);
    if count == 0 || count > MAX_CERTIFICATES {
        return Err(WorkerError::Protocol);
    }
    let mut certificates = Vec::with_capacity(count);
    for _ in 0..count {
        let certificate = decoder.blob(MAX_CERTIFICATE_BYTES)?;
        if certificate.is_empty() {
            return Err(WorkerError::Protocol);
        }
        certificates.push(certificate.to_vec());
    }
    let count = decoder.byte()?;
    if count == 0 || count > 4 {
        return Err(WorkerError::Protocol);
    }
    let mut capabilities = Vec::with_capacity(count.into());
    for _ in 0..count {
        let capability = SigningCapability {
            algorithm: decode_algorithm(decoder.byte()?)?,
            input: decode_input(decoder.byte()?)?,
        };
        if capabilities.contains(&capability) {
            return Err(WorkerError::Protocol);
        }
        capabilities.push(capability);
    }
    decoder.end()?;
    let leaf = certificates.remove(0);
    Ok((
        CertificateIdentity {
            certificate_der: leaf,
            additional_certificates: certificates,
        },
        capabilities,
    ))
}

pub(crate) fn decode_signature(
    encoded: &[u8],
    requested: SignatureAlgorithm,
) -> Result<Signature, WorkerError> {
    let mut decoder = Decoder(encoded);
    match decoder.byte()? {
        SIGNATURE => (),
        SIGNING_ERROR => {
            decoder.end()?;
            return Err(WorkerError::Unavailable);
        }
        _ => return Err(WorkerError::Protocol),
    }
    let algorithm = decode_algorithm(decoder.byte()?)?;
    let value = decoder.blob(MAX_SIGNATURE_BYTES)?;
    if algorithm != requested || value.is_empty() {
        return Err(WorkerError::Protocol);
    }
    decoder.end()?;
    Ok(Signature {
        algorithm,
        value: value.to_vec(),
    })
}

fn import_error(error: CertificateError) -> u8 {
    match error {
        CertificateError::InvalidContainer => 1,
        CertificateError::InvalidPassword => 2,
        CertificateError::UnlockFailed => 3,
        CertificateError::MissingIdentity => 4,
        CertificateError::KeyMismatch => 5,
        CertificateError::UnsupportedKey => 6,
        CertificateError::BackendFailure => 7,
    }
}
fn decode_import_error(code: u8) -> Result<CertificateError, WorkerError> {
    match code {
        1 => Ok(CertificateError::InvalidContainer),
        2 => Ok(CertificateError::InvalidPassword),
        3 => Ok(CertificateError::UnlockFailed),
        4 => Ok(CertificateError::MissingIdentity),
        5 => Ok(CertificateError::KeyMismatch),
        6 => Ok(CertificateError::UnsupportedKey),
        7 => Ok(CertificateError::BackendFailure),
        _ => Err(WorkerError::Protocol),
    }
}

fn read_frame(input: &mut impl Read) -> Result<Option<Frame>, WorkerError> {
    let mut length = [0; 4];
    loop {
        match input.read(&mut length[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(WorkerError::Unavailable),
        }
    }
    input
        .read_exact(&mut length[1..])
        .map_err(|_| WorkerError::Protocol)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_REQUEST_BYTES {
        return Err(WorkerError::Protocol);
    }
    let mut bytes = frame(vec![0; length]);
    input
        .read_exact(bytes.expose_secret_mut())
        .map_err(|_| WorkerError::Protocol)?;
    Ok(Some(bytes))
}

fn write_frame(output: &mut impl Write, bytes: &[u8]) -> Result<(), WorkerError> {
    let length = u32::try_from(bytes.len()).map_err(|_| WorkerError::Protocol)?;
    output
        .write_all(&length.to_be_bytes())
        .and_then(|_| output.write_all(bytes))
        .and_then(|_| output.flush())
        .map_err(|_| WorkerError::Unavailable)
}

fn import_key(input: &mut impl Read) -> Result<Pkcs12Key, WorkerError> {
    let bytes = read_frame(input)?.ok_or(WorkerError::Protocol)?;
    let mut decoder = Decoder(bytes.expose_secret());
    if decoder.byte()? != IMPORT {
        return Err(WorkerError::Protocol);
    }
    let container = decoder.blob(MAX_PKCS12_BYTES)?;
    let password = decoder.blob(MAX_PASSWORD_BYTES)?;
    decoder.end()?;
    let password = std::str::from_utf8(password).map_err(|_| WorkerError::Protocol)?;
    let password = SecretString::from(password.to_owned());
    Ok(Pkcs12Key::from_der(container, &password)?)
}

pub(crate) fn serve() -> Result<(), WorkerError> {
    use rustix::process::{set_dumpable_behavior, setrlimit, DumpableBehavior, Resource, Rlimit};
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|_| WorkerError::Unavailable)?;
    for (resource, value) in [
        (Resource::Core, 0),
        (Resource::As, MAX_ADDRESS_SPACE_BYTES),
        (Resource::Cpu, MAX_CPU_SECONDS),
    ] {
        setrlimit(
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(|_| WorkerError::Unavailable)?;
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    write_frame(&mut output, HELLO)?;
    let mut key = match import_key(&mut input) {
        Ok(key) => key,
        Err(WorkerError::Import(error)) => {
            write_frame(&mut output, &[IMPORT_ERROR, import_error(error)])?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    write_frame(&mut output, identity_response(&key)?.expose_secret())?;
    while let Some(bytes) = read_frame(&mut input)? {
        let mut decoder = Decoder(bytes.expose_secret());
        match decoder.byte()? {
            CLOSE => {
                decoder.end()?;
                drop(key);
                write_frame(&mut output, &[CLOSED])?;
                return Ok(());
            }
            SIGN => {
                let algorithm = decode_algorithm(decoder.byte()?)?;
                let kind = decode_input(decoder.byte()?)?;
                let message = decoder.blob(MAX_SIGNING_INPUT_BYTES)?;
                decoder.end()?;
                let input = match kind {
                    InputKind::Message => SigningInput::Message(message),
                    InputKind::Sha256Digest => SigningInput::Sha256Digest(
                        message.try_into().map_err(|_| WorkerError::Protocol)?,
                    ),
                };
                match key.sign(algorithm, input) {
                    Ok(signature) => {
                        if signature.value.is_empty() || signature.value.len() > MAX_SIGNATURE_BYTES
                        {
                            return Err(WorkerError::Protocol);
                        }
                        let mut response =
                            frame(vec![SIGNATURE, algorithm_code(signature.algorithm)]);
                        put(response.expose_secret_mut(), &signature.value)?;
                        write_frame(&mut output, response.expose_secret())?;
                    }
                    Err(_) => {
                        write_frame(&mut output, &[SIGNING_ERROR])?;
                        return Ok(());
                    }
                }
            }
            _ => return Err(WorkerError::Protocol),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_oversized_truncated_and_trailing_frames() {
        for mut input in [
            &[0xff; 4][..],
            &[0; 4][..],
            &[0, 0, 0, 2, 1][..],
            &[0, 0][..],
        ] {
            assert!(read_frame(&mut input).is_err());
        }
        for input in [
            &[IDENTITY, 0][..],
            &[IDENTITY, 33][..],
            &[IMPORT_ERROR, 255][..],
            &[IMPORT_ERROR, 1, 0][..],
        ] {
            assert_eq!(decode_identity(input).err(), Some(WorkerError::Protocol));
        }
        assert!(decode_signature(
            &[SIGNATURE, 2, 0, 0, 0, 1, 9],
            SignatureAlgorithm::RsaPkcs1v15Sha256
        )
        .is_err());
        assert!(decode_signature(
            &[SIGNATURE, 1, 0, 0, 0, 1, 9, 0],
            SignatureAlgorithm::RsaPkcs1v15Sha256
        )
        .is_err());
    }
}
