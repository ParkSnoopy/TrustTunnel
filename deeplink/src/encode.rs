use crate::error::Result;
use crate::types::{DeepLinkConfig, Protocol, TlvTag, CURRENT_VERSION};
use crate::varint::encode_varint;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

static PREFIX: &str = "tt://?";

/// Encode a Tag-Length-Value entry.
fn encode_tlv(tag: TlvTag, value: &[u8]) -> Result<Vec<u8>> {
    let mut result = encode_varint(u64::from(tag.as_u8()))?;
    result.extend(encode_varint(value.len() as u64)?);
    result.extend_from_slice(value);
    Ok(result)
}

/// Encode a string field as TLV.
fn encode_string_field(tag: TlvTag, value: &str) -> Result<Vec<u8>> {
    encode_tlv(tag, value.as_bytes())
}

/// Encode a boolean field as TLV (1 byte: 0x01 for true, 0x00 for false).
fn encode_bool_field(tag: TlvTag, value: bool) -> Result<Vec<u8>> {
    encode_tlv(tag, if value { &[0x01] } else { &[0x00] })
}

/// Encode upstream protocol as TLV (1 byte: 0x01 for http2, 0x02 for http3).
fn encode_protocol_field(protocol: Protocol) -> Result<Vec<u8>> {
    encode_tlv(TlvTag::UpstreamProtocol, &[protocol.as_u8()])
}

/// Encode a String[] value: each element is a varint length followed by UTF-8 bytes.
fn encode_string_array(strings: &[String]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    for s in strings {
        let bytes = s.as_bytes();
        buf.extend(encode_varint(bytes.len() as u64)?);
        buf.extend_from_slice(bytes);
    }
    Ok(buf)
}

/// Encode binary payload to base64url (URL-safe base64 without padding).
fn encode_base64url(payload: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(payload)
}

/// Encode a `DeepLinkConfig` into TLV binary payload.
///
/// # Errors
///
/// Returns [`crate::DeepLinkError`] if configuration validation fails or a
/// field length exceeds the variable-length integer range.
pub fn encode_tlv_payload(config: &DeepLinkConfig) -> Result<Vec<u8>> {
    config.validate()?;

    let mut payload = Vec::new();

    // Version tag
    let version_bytes = encode_varint(CURRENT_VERSION)?;
    payload.extend(encode_tlv(TlvTag::Version, &version_bytes)?);

    // Static connection parameters: emitted when present (omitted in the
    // subscription-only variant). Order matches the Python reference
    // implementation.
    if let Some(ref hostname) = config.hostname {
        payload.extend(encode_string_field(TlvTag::Hostname, hostname)?);
    }
    if let Some(ref username) = config.username {
        payload.extend(encode_string_field(TlvTag::Username, username)?);
    }
    if let Some(ref password) = config.password {
        payload.extend(encode_string_field(TlvTag::Password, password)?);
    }

    for addr in &config.addresses {
        payload.extend(encode_string_field(TlvTag::Address, addr)?);
    }

    // client_random_prefix: include if present and non-empty
    if let Some(ref prefix) = config.client_random_prefix {
        if !prefix.is_empty() {
            payload.extend(encode_string_field(TlvTag::ClientRandomPrefix, prefix)?);
        }
    }

    // client_random_auth_key: include if present and non-empty
    if let Some(ref auth_key) = config.client_random_auth_key {
        if !auth_key.is_empty() {
            payload.extend(encode_string_field(TlvTag::ClientRandomAuthKey, auth_key)?);
        }
    }

    // Optional fields (omit if default value or None) - order matches Python
    if let Some(custom_sni) = &config.custom_sni {
        payload.extend(encode_string_field(TlvTag::CustomSni, custom_sni)?);
    }

    // has_ipv6 default is true, so only encode if false
    if !config.has_ipv6 {
        payload.extend(encode_bool_field(TlvTag::HasIpv6, false)?);
    }

    // skip_verification default is false, so only encode if true
    if config.skip_verification {
        payload.extend(encode_bool_field(TlvTag::SkipVerification, true)?);
    }

    // anti_dpi default is false, so only encode if true
    if config.anti_dpi {
        payload.extend(encode_bool_field(TlvTag::AntiDpi, true)?);
    }

    // Certificate: include if present
    if let Some(cert_der) = &config.certificate {
        payload.extend(encode_tlv(TlvTag::Certificate, cert_der)?);
    }

    // upstream_protocol default is Http2, so only encode if Http3
    if config.upstream_protocol != Protocol::Http2 {
        payload.extend(encode_protocol_field(config.upstream_protocol)?);
    }

    // name (optional)
    if let Some(ref name) = config.name {
        payload.extend(encode_string_field(TlvTag::Name, name)?);
    }

    // dns_upstreams (optional, String[] encoding)
    if !config.dns_upstreams.is_empty() {
        let value = encode_string_array(&config.dns_upstreams)?;
        payload.extend(encode_tlv(TlvTag::DnsUpstreams, &value)?);
    }

    // subscription_url (optional, format v2)
    if let Some(ref url) = config.subscription_url {
        payload.extend(encode_string_field(TlvTag::SubscriptionUrl, url)?);
    }

    Ok(payload)
}

/// Encode a configuration into a deep-link URI (`tt://?...`).
///
/// # Errors
///
/// Returns `DeepLinkError` if encoding fails (e.g., missing required fields,
/// invalid data, varint overflow).
pub fn encode(config: &DeepLinkConfig) -> Result<String> {
    let payload = encode_tlv_payload(config)?;
    let encoded = encode_base64url(&payload);
    Ok(format!("{PREFIX}{encoded}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prop_assert, prop_assert_eq, prop_assert_ne};

    type TestResult = proptest::test_runner::TestCaseResult;

    #[test]
    fn test_encode_tlv() -> TestResult {
        let result = encode_tlv(TlvTag::Hostname, b"example.com")?;
        prop_assert_eq!(result[0], 0x01); // tag
        prop_assert_eq!(result[1], 11); // length
        prop_assert_eq!(&result[2..], b"example.com");
        Ok(())
    }

    #[test]
    fn test_encode_string_field() -> TestResult {
        let result = encode_string_field(TlvTag::Username, "alice")?;
        prop_assert_eq!(result[0], 0x05); // Username tag
        prop_assert_eq!(result[1], 5); // length
        prop_assert_eq!(&result[2..], b"alice");
        Ok(())
    }

    #[test]
    fn test_encode_bool_field() -> TestResult {
        let result_true = encode_bool_field(TlvTag::HasIpv6, true)?;
        prop_assert_eq!(result_true[0], 0x04); // HasIpv6 tag
        prop_assert_eq!(result_true[1], 1); // length
        prop_assert_eq!(result_true[2], 0x01); // true

        let result_false = encode_bool_field(TlvTag::SkipVerification, false)?;
        prop_assert_eq!(result_false[0], 0x07); // SkipVerification tag
        prop_assert_eq!(result_false[1], 1); // length
        prop_assert_eq!(result_false[2], 0x00); // false
        Ok(())
    }

    #[test]
    fn test_encode_protocol_field() -> TestResult {
        let result_http2 = encode_protocol_field(Protocol::Http2)?;
        prop_assert_eq!(result_http2[0], 0x09); // UpstreamProtocol tag
        prop_assert_eq!(result_http2[1], 1); // length
        prop_assert_eq!(result_http2[2], 0x01); // http2

        let result_http3 = encode_protocol_field(Protocol::Http3)?;
        prop_assert_eq!(result_http3[2], 0x02); // http3
        Ok(())
    }

    #[test]
    fn test_encode_base64url() -> TestResult {
        let data = b"hello world";
        let encoded = encode_base64url(data);
        prop_assert_eq!(encoded.as_str(), "aGVsbG8gd29ybGQ");
        prop_assert!(!encoded.contains('='));
        Ok(())
    }

    #[test]
    fn test_encode_tlv_payload_minimal() -> TestResult {
        let config = DeepLinkConfig::builder()
            .hostname("vpn.example.com".to_string())
            .addresses(vec!["1.2.3.4:443".to_string()])
            .username("alice".to_string())
            .password("secret".to_string())
            .build()?;

        let payload = encode_tlv_payload(&config)?;

        // Should contain required fields only (has_ipv6=true is default, so omitted)
        prop_assert_ne!(payload, Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn test_encode_tlv_payload_with_optional_fields() -> TestResult {
        let config = DeepLinkConfig::builder()
            .hostname("vpn.example.com".to_string())
            .addresses(vec!["1.2.3.4:443".to_string()])
            .username("alice".to_string())
            .password("secret".to_string())
            .custom_sni(Some("example.org".to_string()))
            .has_ipv6(false)
            .skip_verification(true)
            .upstream_protocol(Protocol::Http3)
            .anti_dpi(true)
            .build()?;

        let payload = encode_tlv_payload(&config)?;

        // Should contain all fields
        prop_assert_ne!(payload, Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn test_encode_full_uri() -> TestResult {
        let config = DeepLinkConfig::builder()
            .hostname("vpn.example.com".to_string())
            .addresses(vec!["1.2.3.4:443".to_string()])
            .username("alice".to_string())
            .password("secret".to_string())
            .build()?;

        let uri = encode(&config)?;

        prop_assert!(uri.starts_with(PREFIX));
        prop_assert!(!uri.contains('='));
        Ok(())
    }

    #[test]
    fn test_encode_tlv_payload_subscription_only() -> TestResult {
        let url = "https://alice:s3cret@vpn.example.com/subscription";
        let config = DeepLinkConfig::builder()
            .subscription_url(Some(url.to_string()))
            .build()?;

        let payload = encode_tlv_payload(&config)?;

        // Version-2 TLV (tag 0x00, len 1, value 2) comes first.
        prop_assert_eq!(&payload[..3], &[0x00, 0x01, 0x02]);

        // The whole payload is exactly these two TLVs; anything appended
        // afterwards (e.g. a new default-emitted field) fails here.
        let mut tags = Vec::new();
        let mut offset = 0;
        while offset < payload.len() {
            let (tag, after_tag) = crate::varint::decode_varint(&payload, offset)?;
            let (len, after_len) = crate::varint::decode_varint(&payload, after_tag)?;
            tags.push(TlvTag::from_u8(tag as u8));
            offset = after_len + len as usize;
        }
        prop_assert_eq!(tags, [Some(TlvTag::Version), Some(TlvTag::SubscriptionUrl)]);

        let decoded = crate::decode::decode_tlv_payload(&payload)?;
        prop_assert_eq!(decoded.subscription_url.as_deref(), Some(url));
        prop_assert_eq!(decoded.hostname, None);
        Ok(())
    }
}
