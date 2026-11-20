use crate::TransportError;
use std::{path::Path, sync::Arc};
use tokio_rustls::rustls::{
    self,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
};

/// Loads a caller-provided certificate chain and matching PKCS#8/PKCS#1/SEC1 key.
/// No certificate is installed into a browser or system trust store.
pub fn load_tls(
    certificate: &Path,
    key: &Path,
) -> Result<Arc<rustls::ServerConfig>, TransportError> {
    let certificates =
        CertificateDer::pem_file_iter(certificate)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key)?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certificates, key)?;
    Ok(Arc::new(config))
}

/// Checks that a setting is exactly one canonical HTTP(S) browser origin.
/// Wildcards, paths, credentials, queries, fragments and opaque origins are rejected.
pub fn validate_origin(origin: &str) -> Result<(), TransportError> {
    if origin.len() > 2048 || origin.contains('*') {
        return Err(TransportError::Origin);
    }
    let parsed = url::Url::parse(origin).map_err(|_| TransportError::Origin)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(TransportError::Origin);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_origin_settings_are_exact_and_canonical() {
        for origin in [
            "https://example.invalid",
            "http://127.0.0.1:8080",
            "https://example.invalid:8443",
        ] {
            assert!(validate_origin(origin).is_ok());
        }
        for origin in [
            "null",
            "file:///tmp",
            "https://example.invalid/",
            "https://example.invalid/path",
            "https://user@example.invalid",
            "https://example.invalid?query",
            "https://example.invalid#fragment",
            "https://example.invalid\r\n",
            "https://example.invalid:443",
            "https://EXAMPLE.invalid",
            "https://example.invalid ",
            "https://*.example.invalid",
            "https://*",
        ] {
            assert!(validate_origin(origin).is_err(), "{origin:?}");
        }
    }
}
