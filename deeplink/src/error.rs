use std::io;

/// Result type alias for deep-link operations.
pub type Result<T> = std::result::Result<T, DeepLinkError>;

/// Errors that can occur during deep-link encoding or decoding.
#[derive(Debug, thiserror::Error)]
pub enum DeepLinkError {
    /// The URI payload is not valid URL-safe base64.
    #[error("Invalid base64url encoding: {0}")]
    InvalidBase64(String),

    /// A TLV field declares more bytes than remain in the payload.
    #[error(
        "Truncated TLV entry: tag {tag:#04x} expects {expected} bytes but only {got} remaining"
    )]
    TruncatedTlv {
        /// The field's wire-format tag.
        tag: u8,
        /// The declared value length.
        expected: usize,
        /// The number of bytes remaining in the payload.
        got: usize,
    },

    /// A required configuration field is absent or empty.
    #[error("Missing required field: {0}")]
    MissingRequiredField(&'static str),

    /// The subscription URL does not use HTTPS.
    #[error("Invalid subscription URL '{0}': must use the https:// scheme")]
    InvalidSubscriptionUrl(String),

    /// The protocol byte does not identify a supported upstream protocol.
    #[error("Invalid protocol byte: {0:#04x} (expected 0x01 for http2 or 0x02 for http3)")]
    InvalidProtocol(u8),

    /// The payload version is newer than the supported format.
    #[error("Unsupported deep link version: {found} (max supported: {max_supported})")]
    UnsupportedVersion {
        /// The version read from the payload.
        found: u64,
        /// The newest supported format version.
        max_supported: u64,
    },

    /// A string-array entry declares more bytes than remain in the field.
    #[error("Truncated list entry: expected {expected} bytes but only {got} remaining")]
    TruncatedListEntry {
        /// The declared string length.
        expected: usize,
        /// The number of bytes remaining in the field.
        got: usize,
    },

    /// The value exceeds the QUIC variable-length integer range.
    #[error("Varint value too large: {0} (max: 2^62-1)")]
    VarintOverflow(u64),

    /// A certificate cannot be parsed or converted.
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    /// A string field contains invalid UTF-8.
    #[error("Invalid UTF-8 string: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// An address, protocol name, or hexadecimal field is invalid.
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    /// A boolean field has an invalid value or length.
    #[error("Invalid boolean value: expected 0x00 or 0x01, got {0:#04x}")]
    InvalidBoolean(u8),

    /// The URI does not begin with the deep-link scheme.
    #[error("Invalid URI scheme: expected 'tt://', got '{0}'")]
    InvalidScheme(String),

    /// An underlying I/O operation or variable-length integer read failed.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// An underlying base64 decoder rejected its input.
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// An underlying network address parser rejected its input.
    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
}
