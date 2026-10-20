//! Owned format choices shared by protocol decoding, review and encoders.
//! Contains no parsers, platform dependencies or authorization decisions.

/// Whether CMS embeds the exact document bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentMode {
    /// Include an OCTET STRING, including for empty content.
    Attached,
    /// Omit eContent; verification requires the original document.
    Detached,
}

/// Optional PDF signature appearance in page user-space coordinates.
#[derive(Clone, Debug, PartialEq)]
pub struct Appearance {
    /// One-based page number.
    pub page: u32,
    /// Lower-left x/y and upper-right x/y, within the page MediaBox.
    pub rectangle: [f32; 4],
    /// One line of printable ASCII, up to 120 characters; no trust claim.
    pub text: String,
}

/// PDF signature placement.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PdfOptions {
    /// None creates an invisible widget on the first page.
    pub appearance: Option<Appearance>,
}

/// Placement of content relative to an XML Signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmlMode {
    /// Insert into UTF-8 XML; sign canonical XML without comments.
    Enveloped,
    /// Embed exact bytes in a base64 ds:Object inside the signature.
    Enveloping,
    /// Embed exact bytes outside the signature in the same output document.
    /// AutoFirma's internally detached form, not an external URI.
    Detached,
}

/// Complete format choices bound to an immutable document review.
#[derive(Clone, Debug, PartialEq)]
pub enum Format {
    /// CMS/CAdES content placement.
    Cades(ContentMode),
    /// Incremental PDF signature and optional visible widget.
    Pades(PdfOptions),
    /// XML signature with fixed local references and transforms.
    Xades(XmlMode),
}

impl From<ContentMode> for Format {
    fn from(mode: ContentMode) -> Self {
        Self::Cades(mode)
    }
}

impl Format {
    /// User-visible format and content placement, without a trust/profile claim.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Cades(ContentMode::Attached) => "CAdES (attached)",
            Self::Cades(ContentMode::Detached) => "CAdES (detached)",
            Self::Pades(_) => "PAdES",
            Self::Xades(XmlMode::Enveloped) => "XAdES (enveloped)",
            Self::Xades(XmlMode::Enveloping) => "XAdES (enveloping)",
            Self::Xades(XmlMode::Detached) => "XAdES (internally detached)",
        }
    }
    /// Suggested output extension, without a leading dot.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Cades(_) => "csig",
            Self::Pades(_) => "pdf",
            Self::Xades(_) => "xsig",
        }
    }
}
