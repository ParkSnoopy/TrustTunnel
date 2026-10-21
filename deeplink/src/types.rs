use crate::error::{DeepLinkError, Result};
use std::fmt;
use std::str::FromStr;

/// TLV tag identifiers (per `DEEP_LINK.md` specification)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlvTag {
    /// Deep-link format version.
    Version = 0x00,
    /// Endpoint hostname.
    Hostname = 0x01,
    /// Endpoint address; this tag may repeat.
    Address = 0x02,
    /// Custom TLS server name.
    CustomSni = 0x03,
    /// Whether `IPv6` is available.
    HasIpv6 = 0x04,
    /// Authentication username.
    Username = 0x05,
    /// Authentication password.
    Password = 0x06,
    /// Whether TLS certificate verification is skipped.
    SkipVerification = 0x07,
    /// Concatenated DER certificates.
    Certificate = 0x08,
    /// Upstream HTTP protocol.
    UpstreamProtocol = 0x09,
    /// Whether anti-DPI measures are enabled.
    AntiDpi = 0x0A,
    /// Hexadecimal TLS client random prefix.
    ClientRandomPrefix = 0x0B,
    /// Display name.
    Name = 0x0C,
    /// Length-prefixed DNS upstream strings.
    DnsUpstreams = 0x0D,
    /// HTTPS subscription URL.
    SubscriptionUrl = 0x0E,
    /// Hexadecimal client random authentication key.
    ClientRandomAuthKey = 0x0F,
}

impl TlvTag {
    /// Return the wire-format tag byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Return the known tag for a byte, or `None` for an unknown tag.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Version),
            0x01 => Some(Self::Hostname),
            0x02 => Some(Self::Address),
            0x03 => Some(Self::CustomSni),
            0x04 => Some(Self::HasIpv6),
            0x05 => Some(Self::Username),
            0x06 => Some(Self::Password),
            0x07 => Some(Self::SkipVerification),
            0x08 => Some(Self::Certificate),
            0x09 => Some(Self::UpstreamProtocol),
            0x0A => Some(Self::AntiDpi),
            0x0B => Some(Self::ClientRandomPrefix),
            0x0C => Some(Self::Name),
            0x0D => Some(Self::DnsUpstreams),
            0x0E => Some(Self::SubscriptionUrl),
            0x0F => Some(Self::ClientRandomAuthKey),
            _ => None,
        }
    }
}

/// Protocol type for upstream connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Default)]
pub enum Protocol {
    /// HTTP/2 transport, the default upstream protocol.
    #[default]
    Http2 = 0x01,
    /// HTTP/3 transport.
    Http3 = 0x02,
}

impl Protocol {
    /// Return the wire-format protocol byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode the wire-format protocol byte.
    ///
    /// # Errors
    ///
    /// Returns [`DeepLinkError::InvalidProtocol`] for an unsupported byte.
    pub const fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::Http2),
            0x02 => Ok(Self::Http3),
            _ => Err(DeepLinkError::InvalidProtocol(value)),
        }
    }
}

impl FromStr for Protocol {
    type Err = DeepLinkError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "http2" => Ok(Self::Http2),
            "http3" => Ok(Self::Http3),
            _ => Err(DeepLinkError::InvalidAddress(format!(
                "unknown upstream_protocol: {s}"
            ))),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http2 => write!(f, "http2"),
            Self::Http3 => write!(f, "http3"),
        }
    }
}

/// The newest deep-link format version emitted and accepted by this library.
pub const CURRENT_VERSION: u64 = 2;

/// `TrustTunnel` deep-link configuration.
///
/// This struct represents all configuration fields that can be encoded into
/// or decoded from a `tt://?` deep-link URI.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeepLinkConfig {
    /// Endpoint hostname, required without a subscription URL.
    pub hostname: Option<String>,
    /// Endpoint addresses, required without a subscription URL.
    pub addresses: Vec<String>,
    /// Authentication username, required without a subscription URL.
    pub username: Option<String>,
    /// Authentication password, required without a subscription URL.
    pub password: Option<String>,
    /// Optional hexadecimal TLS client random prefix.
    pub client_random_prefix: Option<String>,
    /// Optional hexadecimal client random authentication key.
    pub client_random_auth_key: Option<String>,
    /// Optional custom TLS server name.
    pub custom_sni: Option<String>,
    /// Whether `IPv6` is available; defaults to `true`.
    pub has_ipv6: bool,
    /// Whether TLS certificate verification is skipped; defaults to `false`.
    pub skip_verification: bool,
    /// Optional concatenated DER certificates.
    pub certificate: Option<Vec<u8>>,
    /// Upstream transport; defaults to [`Protocol::Http2`].
    pub upstream_protocol: Protocol,
    /// Whether anti-DPI measures are enabled; defaults to `false`.
    pub anti_dpi: bool,
    /// Optional display name.
    pub name: Option<String>,
    /// DNS upstream addresses, in their encoded order.
    pub dns_upstreams: Vec<String>,
    /// HTTPS subscription URL (may embed HTTP Basic Auth credentials).
    /// When present, the static connection parameters are optional fallback
    /// for the initial connection attempt (format version 2).
    pub subscription_url: Option<String>,
}

impl DeepLinkConfig {
    /// Create a new builder for constructing a `DeepLinkConfig`.
    pub fn builder() -> DeepLinkConfigBuilder {
        DeepLinkConfigBuilder::default()
    }

    /// Validate that required fields are present and the subscription URL
    /// uses HTTPS. When `subscription_url` is present, the static connection
    /// parameters are optional fallback; otherwise they are all required.
    ///
    /// # Errors
    ///
    /// Returns [`DeepLinkError::InvalidSubscriptionUrl`] for a non-HTTPS URL,
    /// or [`DeepLinkError::MissingRequiredField`] for missing static fields.
    pub fn validate(&self) -> Result<()> {
        if let Some(ref url) = self.subscription_url {
            if !url.starts_with("https://") {
                return Err(DeepLinkError::InvalidSubscriptionUrl(url.clone()));
            }
            return Ok(());
        }
        if self.hostname.as_deref().is_none_or(str::is_empty) {
            return Err(DeepLinkError::MissingRequiredField("hostname"));
        }
        if self.addresses.is_empty() {
            return Err(DeepLinkError::MissingRequiredField("addresses"));
        }
        if self.username.as_deref().is_none_or(str::is_empty) {
            return Err(DeepLinkError::MissingRequiredField("username"));
        }
        if self.password.as_deref().is_none_or(str::is_empty) {
            return Err(DeepLinkError::MissingRequiredField("password"));
        }
        Ok(())
    }
}

/// Builder for constructing a `DeepLinkConfig`.
#[derive(Debug, Default)]
#[must_use]
pub struct DeepLinkConfigBuilder {
    hostname: Option<String>,
    addresses: Option<Vec<String>>,
    username: Option<String>,
    password: Option<String>,
    client_random_prefix: Option<String>,
    client_random_auth_key: Option<String>,
    custom_sni: Option<String>,
    has_ipv6: Option<bool>,
    skip_verification: Option<bool>,
    certificate: Option<Vec<u8>>,
    upstream_protocol: Option<Protocol>,
    anti_dpi: Option<bool>,
    name: Option<String>,
    dns_upstreams: Option<Vec<String>>,
    subscription_url: Option<String>,
}

impl DeepLinkConfigBuilder {
    /// Set the endpoint hostname.
    pub fn hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    /// Set the ordered endpoint addresses.
    pub fn addresses(mut self, addresses: Vec<String>) -> Self {
        self.addresses = Some(addresses);
        self
    }

    /// Set the authentication username.
    pub fn username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    /// Set the authentication password.
    pub fn password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }

    /// Set or clear the custom TLS server name.
    pub fn custom_sni(mut self, custom_sni: Option<String>) -> Self {
        self.custom_sni = custom_sni;
        self
    }

    /// Set whether `IPv6` is available.
    pub const fn has_ipv6(mut self, has_ipv6: bool) -> Self {
        self.has_ipv6 = Some(has_ipv6);
        self
    }

    /// Set whether TLS certificate verification is skipped.
    pub const fn skip_verification(mut self, skip_verification: bool) -> Self {
        self.skip_verification = Some(skip_verification);
        self
    }

    /// Set or clear the concatenated DER certificates.
    pub fn certificate(mut self, certificate: Option<Vec<u8>>) -> Self {
        self.certificate = certificate;
        self
    }

    /// Set the upstream transport protocol.
    pub const fn upstream_protocol(mut self, upstream_protocol: Protocol) -> Self {
        self.upstream_protocol = Some(upstream_protocol);
        self
    }

    /// Set whether anti-DPI measures are enabled.
    pub const fn anti_dpi(mut self, anti_dpi: bool) -> Self {
        self.anti_dpi = Some(anti_dpi);
        self
    }

    /// Set or clear the hexadecimal TLS client random prefix.
    pub fn client_random_prefix(mut self, client_random_prefix: Option<String>) -> Self {
        self.client_random_prefix = client_random_prefix;
        self
    }

    /// Set or clear the hexadecimal client random authentication key.
    pub fn client_random_auth_key(mut self, client_random_auth_key: Option<String>) -> Self {
        self.client_random_auth_key = client_random_auth_key;
        self
    }

    /// Set or clear the display name.
    pub fn name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// Set the ordered DNS upstream addresses.
    pub fn dns_upstreams(mut self, dns_upstreams: Vec<String>) -> Self {
        self.dns_upstreams = Some(dns_upstreams);
        self
    }

    /// Set or clear the HTTPS subscription URL.
    pub fn subscription_url(mut self, subscription_url: Option<String>) -> Self {
        self.subscription_url = subscription_url;
        self
    }

    /// Build and validate the configuration, applying omitted defaults.
    ///
    /// # Errors
    ///
    /// Returns [`DeepLinkError::InvalidAddress`] for invalid hexadecimal
    /// fields, or the errors described by [`DeepLinkConfig::validate`].
    pub fn build(self) -> Result<DeepLinkConfig> {
        // Validate client_random_prefix is valid hex if provided
        if let Some(ref prefix) = self.client_random_prefix {
            if !prefix.is_empty() {
                hex::decode(prefix).map_err(|e| {
                    DeepLinkError::InvalidAddress(format!(
                        "client_random_prefix must be valid hex: {e}"
                    ))
                })?;
            }
        }

        // Validate client_random_auth_key is valid hex if provided
        if let Some(ref auth_key) = self.client_random_auth_key {
            if !auth_key.is_empty() {
                hex::decode(auth_key).map_err(|e| {
                    DeepLinkError::InvalidAddress(format!(
                        "client_random_auth_key must be valid hex: {e}"
                    ))
                })?;
            }
        }

        let config = DeepLinkConfig {
            hostname: self.hostname,
            addresses: self.addresses.unwrap_or_default(),
            username: self.username,
            password: self.password,
            client_random_prefix: self.client_random_prefix,
            client_random_auth_key: self.client_random_auth_key,
            custom_sni: self.custom_sni,
            has_ipv6: self.has_ipv6.unwrap_or(true),
            skip_verification: self.skip_verification.unwrap_or(false),
            certificate: self.certificate,
            upstream_protocol: self.upstream_protocol.unwrap_or_default(),
            anti_dpi: self.anti_dpi.unwrap_or(false),
            name: self.name,
            dns_upstreams: self.dns_upstreams.unwrap_or_default(),
            subscription_url: self.subscription_url,
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prop_assert, prop_assert_eq};

    type TestResult = proptest::test_runner::TestCaseResult;

    #[test]
    fn test_tlv_tag_conversions() -> TestResult {
        prop_assert_eq!(TlvTag::Hostname.as_u8(), 0x01);
        prop_assert_eq!(TlvTag::from_u8(0x01), Some(TlvTag::Hostname));
        prop_assert_eq!(TlvTag::from_u8(0x00), Some(TlvTag::Version));
        prop_assert_eq!(TlvTag::from_u8(0xFF), None);
        Ok(())
    }

    #[test]
    fn test_protocol_conversions() -> TestResult {
        prop_assert_eq!(Protocol::Http2.as_u8(), 0x01);
        prop_assert_eq!(Protocol::from_u8(0x01)?, Protocol::Http2);
        prop_assert!(Protocol::from_u8(0xFF).is_err());
        Ok(())
    }

    #[test]
    fn test_protocol_from_str() -> TestResult {
        prop_assert_eq!("http2".parse::<Protocol>()?, Protocol::Http2);
        prop_assert_eq!("http3".parse::<Protocol>()?, Protocol::Http3);
        prop_assert!("http1".parse::<Protocol>().is_err());
        Ok(())
    }

    #[test]
    fn test_protocol_display() -> TestResult {
        prop_assert_eq!(Protocol::Http2.to_string(), "http2");
        prop_assert_eq!(Protocol::Http3.to_string(), "http3");
        Ok(())
    }

    #[test]
    fn test_builder_success() -> TestResult {
        let config = DeepLinkConfig::builder()
            .hostname("vpn.example.com".to_string())
            .addresses(vec!["1.2.3.4:443".to_string()])
            .username("alice".to_string())
            .password("secret".to_string())
            .build()?;

        prop_assert_eq!(config.hostname.as_deref(), Some("vpn.example.com"));
        prop_assert_eq!(config.addresses.len(), 1);
        prop_assert!(config.has_ipv6);
        prop_assert_eq!(config.upstream_protocol, Protocol::Http2);
        Ok(())
    }

    #[test]
    fn test_builder_missing_required_field() -> TestResult {
        let result = DeepLinkConfig::builder()
            .hostname("vpn.example.com".to_string())
            .username("alice".to_string())
            .password("secret".to_string())
            .build();

        prop_assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_builder_domain_address() -> TestResult {
        let config = DeepLinkConfig::builder()
            .hostname("vpn.example.com".to_string())
            .addresses(vec!["vpn.example.com:443".to_string()])
            .username("alice".to_string())
            .password("secret".to_string())
            .build()?;
        prop_assert_eq!(&config.addresses[0], "vpn.example.com:443");
        Ok(())
    }

    #[test]
    fn test_builder_rejects_invalid_auth_key_hex() -> TestResult {
        let result = DeepLinkConfig::builder()
            .hostname("vpn.example.com".to_string())
            .addresses(vec!["1.2.3.4:443".to_string()])
            .username("alice".to_string())
            .password("secret".to_string())
            .client_random_auth_key(Some("not-hex".to_string()))
            .build();

        prop_assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_builder_auth_key_empty_is_allowed() -> TestResult {
        let config = DeepLinkConfig::builder()
            .hostname("vpn.example.com".to_string())
            .addresses(vec!["1.2.3.4:443".to_string()])
            .username("alice".to_string())
            .password("secret".to_string())
            .client_random_auth_key(Some(String::new()))
            .build()?;
        prop_assert_eq!(config.client_random_auth_key, Some(String::new()));
        Ok(())
    }

    #[test]
    fn test_validate_empty_hostname() -> TestResult {
        let config = DeepLinkConfig {
            hostname: Some(String::new()),
            addresses: vec!["1.2.3.4:443".to_string()],
            username: Some("alice".to_string()),
            password: Some("secret".to_string()),
            custom_sni: None,
            has_ipv6: true,
            skip_verification: false,
            certificate: None,
            upstream_protocol: Protocol::Http2,
            anti_dpi: false,
            client_random_prefix: None,
            client_random_auth_key: None,
            name: None,
            dns_upstreams: vec![],
            subscription_url: None,
        };

        prop_assert!(config.validate().is_err());
        Ok(())
    }

    #[test]
    fn test_tlv_tag_subscription_url() -> TestResult {
        prop_assert_eq!(TlvTag::SubscriptionUrl.as_u8(), 0x0E);
        prop_assert_eq!(TlvTag::from_u8(0x0E), Some(TlvTag::SubscriptionUrl));
        Ok(())
    }

    #[test]
    fn test_builder_subscription_only() -> TestResult {
        let config = DeepLinkConfig::builder()
            .subscription_url(Some(
                "https://alice:s3cret@vpn.example.com/subscription".to_string(),
            ))
            .build()?;

        prop_assert_eq!(config.hostname, None);
        prop_assert_eq!(config.addresses, Vec::<String>::new());
        prop_assert_eq!(
            config.subscription_url.as_deref(),
            Some("https://alice:s3cret@vpn.example.com/subscription")
        );
        Ok(())
    }

    #[test]
    fn test_builder_rejects_non_https_subscription_url() -> TestResult {
        let result = DeepLinkConfig::builder()
            .subscription_url(Some("http://vpn.example.com/subscription".to_string()))
            .build();

        prop_assert!(matches!(
            result,
            Err(DeepLinkError::InvalidSubscriptionUrl(_))
        ));
        Ok(())
    }

    #[test]
    fn test_builder_full_config_with_subscription_url() -> TestResult {
        let config = DeepLinkConfig::builder()
            .hostname("vpn.example.com".to_string())
            .addresses(vec!["1.2.3.4:443".to_string()])
            .username("alice".to_string())
            .password("secret".to_string())
            .subscription_url(Some(
                "https://alice:s3cret@vpn.example.com/subscription".to_string(),
            ))
            .build()?;

        prop_assert!(config.validate().is_ok());
        Ok(())
    }
}
