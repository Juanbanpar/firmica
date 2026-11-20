//! Shared size limits for reviewed signing input and provider certificates.

/// Maximum document byte length, including content used for a detached signature (16 MiB).
pub const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of supplied certificates, including duplicates and the leaf.
pub const MAX_CERTIFICATES: usize = 32;
/// Maximum DER length of each supplied certificate (64 KiB).
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
