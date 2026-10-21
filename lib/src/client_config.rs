//! Client configuration and subscription-link exports.

use crate::{
    authentication::registry_based, cert_verification::CertificateVerifier,
    settings::TlsHostsSettings, utils::ToTomlComment,
};
#[cfg(feature = "rt_doc")]
use macros::{Getter, RuntimeDoc};
use once_cell::sync::Lazy;
use std::io;
use toml_edit::{value, Document};

/// Percent-encode a username/password for the `userinfo` component of a URL
/// per RFC 3986. Encodes any byte outside the unreserved set `A-Za-z0-9-._~`.
fn percent_encode_userinfo(s: &str) -> String {
    const fn is_unreserved(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if is_unreserved(b) {
            out.push(char::from(b));
        } else {
            out.extend([
                '%',
                char::from(HEX[usize::from(b >> 4)]),
                char::from(HEX[usize::from(b & 0x0f)]),
            ]);
        }
    }
    out
}

/// Split the part of a URL following the scheme into the authority component
/// and the remaining tail (path, query, fragment). The authority ends at the
/// first `/`, `?`, or `#` per RFC 3986.
fn split_authority(url: &str) -> (&str, &str) {
    let authority_end = url.find(['/', '?', '#']).unwrap_or(url.len());
    url.split_at(authority_end)
}

/// Build the subscription URL `https://<user>:<pass>@<host><path>`.
///
/// `base` is `https://<host><path>` (optionally overridden via `--subscription-url`,
/// in which case any embedded userinfo is stripped). Credentials are always
/// appended and percent-encoded.
#[must_use]
pub fn build_subscription_url(base: &str, username: &str, password: &str) -> String {
    let rest = base.strip_prefix("https://").unwrap_or(base);
    // Strip userinfo only from the authority part: a '@' in the path or query
    // is valid and must be preserved.
    let (authority, tail) = split_authority(rest);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host_path = format!("{authority}{tail}");
    format!(
        "https://{}:{}@{host_path}",
        percent_encode_userinfo(username),
        percent_encode_userinfo(password),
    )
}

/// Validate a `--subscription-url` override.
///
/// The override is the host+path base only: an `https://` URL with no embedded
/// userinfo. Credentials are always appended from `credentials.toml`, so an
/// override carrying `user:pass@` is rejected to surface the misuse rather than
/// silently stripping it. A `@` outside the authority (i.e. in the path or
/// query) is left alone.
///
/// # Errors
/// Returns an error for a non-HTTPS URL, missing host, or embedded credentials.
pub fn validate_subscription_url_override(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "--subscription-url must be an https:// URL".to_string())?;

    let (authority, _) = split_authority(rest);
    if authority.is_empty() {
        return Err("--subscription-url must specify a host".to_string());
    }
    if authority.contains('@') {
        return Err("--subscription-url must not contain credentials; \
             they are appended from credentials.toml"
            .to_string());
    }
    Ok(())
}

/// Derive the subscription URL port from `[subscription] address`.
///
/// Returns `None` — the port is omitted from the URL — when `address`
/// is `None`, carries no valid non-zero port, or the port is the HTTPS
/// default (443).
#[must_use]
pub fn subscription_url_port(address: Option<&str>) -> Option<u16> {
    let port: u16 = address?.rsplit_once(':')?.1.parse().ok()?;
    (port != 0 && port != 443).then_some(port)
}

/// Optional values included in an exported client configuration.
#[derive(Default)]
pub struct BuildOptions {
    /// Custom TLS server name.
    pub custom_sni: Option<String>,
    /// Client-random prefix and optional mask.
    pub client_random_prefix: Option<String>,
    /// Auth key used to derive the TLS client random.
    pub client_random_auth_key: Option<String>,
    /// Human-readable endpoint label.
    pub name: Option<String>,
    /// Suggested DNS upstreams.
    pub dns_upstreams: Vec<String>,
    /// Subscription URL including the client's encoded credentials.
    pub subscription_url: Option<String>,
}

impl std::fmt::Debug for BuildOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildOptions").finish_non_exhaustive()
    }
}

/// Build a client configuration from the selected client and main TLS host.
///
/// # Errors
/// Returns an error if the client or host is absent or the certificate cannot be read.
pub fn build(
    client: &str,
    addresses: Vec<String>,
    username: &[registry_based::Client],
    hostsettings: &TlsHostsSettings,
    options: BuildOptions,
) -> io::Result<ClientConfig> {
    let user = username
        .iter()
        .find(|x| x.username == client)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "There is no user config for specified username",
            )
        })?;

    let host = hostsettings.main_hosts.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Can't find main host inside hosts config",
        )
    })?;

    let certificate = std::fs::read_to_string(&host.cert_chain_path)?;

    // Check if certificate is system-verifiable
    let cert_is_system_verifiable = CertificateVerifier::new()
        .is_ok_and(|verifier| verifier.is_system_verifiable(&host.cert_chain_path, &host.hostname));

    Ok(ClientConfig {
        hostname: host.hostname.clone(),
        addresses,
        custom_sni: options.custom_sni.unwrap_or_default(),
        has_ipv6: true, // Hardcoded to true, client could change this himself
        username: user.username.clone(),
        password: user.password.clone(),
        client_random_prefix: options.client_random_prefix.unwrap_or_default(),
        client_random_auth_key: options.client_random_auth_key.unwrap_or_default(),
        skip_verification: false,
        server_certificate: ClientCertificate {
            pem: certificate,
            system_verifiable: cert_is_system_verifiable,
        },
        upstream_protocol: "http2".into(),
        anti_dpi: false,
        name: options.name.unwrap_or_default(),
        dns_upstreams: options.dns_upstreams,
        subscription_url: options.subscription_url,
    })
}

/// Connection, authentication, and export settings for one client.
#[cfg_attr(feature = "rt_doc", derive(Getter, RuntimeDoc))]
pub struct ClientConfig {
    /// Endpoint host name, used for TLS session establishment
    hostname: String,
    /// Endpoint addresses in `IP:port` or `hostname:port` format
    addresses: Vec<String>,
    /// Custom SNI value for TLS handshake.
    /// If set, this value is used as the TLS SNI instead of the hostname.
    custom_sni: String,
    /// Whether `IPv6` traffic can be routed through the endpoint
    has_ipv6: bool,
    /// Username for authorization
    username: String,
    /// Password for authorization
    password: String,
    /// TLS client random hex prefix for connection filtering.
    /// Must have a corresponding rule in rules.toml.
    client_random_prefix: String,
    /// TLS client random auth key (hex string for HKDF+AES `client_random` derivation).
    /// Must have a corresponding rule with `client_random_auth_key` in rules.toml.
    client_random_auth_key: String,
    /// Skip the endpoint certificate verification?
    /// That is, any certificate is accepted with this one set to true.
    skip_verification: bool,
    /// Endpoint certificate and its system-trust result.
    server_certificate: ClientCertificate,
    /// Protocol to be used to communicate with the endpoint [http2, http3]
    upstream_protocol: String,
    /// Is anti-DPI measures should be enabled
    anti_dpi: bool,
    /// Human-readable server display name
    name: String,
    /// DNS upstreams to use when connected to this endpoint
    dns_upstreams: Vec<String>,
    /// Subscription URL (HTTPS, credentials embedded). Present only when
    /// `[subscription]` is enabled on the endpoint. Included in both TOML and
    /// deep-link exports.
    subscription_url: Option<String>,
}

/// Endpoint certificate and its system-trust result for configuration exports.
#[derive(Debug)]
pub struct ClientCertificate {
    pem: String,
    system_verifiable: bool,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("hostname", &self.hostname)
            .field("addresses", &self.addresses)
            .finish_non_exhaustive()
    }
}

impl ClientConfig {
    /// Borrow the endpoint's PEM certificate.
    #[must_use]
    pub const fn get_certificate(&self) -> &String {
        &self.server_certificate.pem
    }

    /// Borrow the certificate's system-trust result.
    #[must_use]
    pub const fn get_cert_is_system_verifiable(&self) -> &bool {
        &self.server_certificate.system_verifiable
    }

    /// Return the certificate field documentation.
    #[must_use]
    pub const fn doc_certificate() -> &'static str {
        "Endpoint certificate in PEM format.\nIf not specified, the endpoint certificate is verified using the system storage."
    }

    /// Return the certificate system-trust documentation.
    #[must_use]
    pub const fn doc_cert_is_system_verifiable() -> &'static str {
        "True if cert can be verified by system CAs (used to omit cert from deep-link)"
    }

    /// Export this configuration as commented TOML.
    #[must_use]
    pub fn compose_toml(&self) -> String {
        let mut doc = TEMPLATE.clone();
        doc["hostname"] = value(&self.hostname);
        let vec = toml_edit::Array::from_iter(self.addresses.iter().map(String::as_str));
        doc["addresses"] = value(vec);
        doc["custom_sni"] = value(&self.custom_sni);
        doc["has_ipv6"] = value(self.has_ipv6);
        doc["username"] = value(&self.username);
        doc["password"] = value(&self.password);
        doc["client_random_prefix"] = value(&self.client_random_prefix);
        doc["client_random_auth_key"] = value(&self.client_random_auth_key);
        doc["skip_verification"] = value(self.skip_verification);
        if self.server_certificate.system_verifiable {
            doc["certificate"] = value("");
        } else {
            doc["certificate"] = value(&self.server_certificate.pem);
        }
        doc["upstream_protocol"] = value(&self.upstream_protocol);
        doc["anti_dpi"] = value(self.anti_dpi);
        if !self.name.is_empty() {
            doc["name"] = value(&self.name);
        }
        if !self.dns_upstreams.is_empty() {
            let vec = toml_edit::Array::from_iter(self.dns_upstreams.iter().map(String::as_str));
            doc["dns_upstreams"] = value(vec);
        }
        if let Some(url) = self.subscription_url.as_ref() {
            doc["subscription_url"] = value(url);
        }
        doc.to_string()
    }

    /// Generate a deep-link URI (tt://?) for this client configuration.
    ///
    /// # Errors
    /// Returns an error for an invalid certificate, protocol, or encoded configuration.
    pub fn compose_deeplink(&self) -> std::io::Result<String> {
        use trusttunnel_deeplink::{DeepLinkConfig, Protocol};

        // Convert certificate from PEM to DER if needed
        let certificate = if !self.server_certificate.system_verifiable
            && !self.server_certificate.pem.is_empty()
        {
            Some(
                trusttunnel_deeplink::cert::pem_to_der(&self.server_certificate.pem)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            )
        } else {
            None
        };

        // Parse protocol
        let upstream_protocol: Protocol = self
            .upstream_protocol
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        // Build deep-link config
        let config = DeepLinkConfig {
            hostname: Some(self.hostname.clone()),
            addresses: self.addresses.clone(),
            username: Some(self.username.clone()),
            password: Some(self.password.clone()),
            client_random_prefix: if self.client_random_prefix.is_empty() {
                None
            } else {
                Some(self.client_random_prefix.clone())
            },
            client_random_auth_key: if self.client_random_auth_key.is_empty() {
                None
            } else {
                Some(self.client_random_auth_key.clone())
            },
            custom_sni: if self.custom_sni.is_empty() {
                None
            } else {
                Some(self.custom_sni.clone())
            },
            has_ipv6: self.has_ipv6,
            skip_verification: self.skip_verification,
            certificate,
            upstream_protocol,
            anti_dpi: self.anti_dpi,
            name: if self.name.is_empty() {
                None
            } else {
                Some(self.name.clone())
            },
            dns_upstreams: self.dns_upstreams.clone(),
            subscription_url: self.subscription_url.clone(),
        };

        trusttunnel_deeplink::encode(&config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Generate a subscription-only deep-link URI (format v2) containing just
    /// the subscription URL. Clients must fetch the subscription before they
    /// can connect; there are no static fallback parameters.
    ///
    /// # Errors
    /// Returns an error if the subscription URL is absent or cannot be encoded.
    pub fn compose_deeplink_subscription_only(&self) -> std::io::Result<String> {
        let subscription_url = self.subscription_url.clone().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "subscription is not enabled on the endpoint",
            )
        })?;

        let config = trusttunnel_deeplink::DeepLinkConfig::builder()
            .subscription_url(Some(subscription_url))
            .build()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        trusttunnel_deeplink::encode(&config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

macro_rules! client_doc {
    ($method:ident) => {{
        #[cfg(feature = "rt_doc")]
        {
            ClientConfig::$method()
        }
        #[cfg(not(feature = "rt_doc"))]
        {
            ""
        }
    }};
}

static TEMPLATE: Lazy<Document> = Lazy::new(|| {
    let mut doc = Document::new();
    let fields = [
        ("hostname", value(""), client_doc!(doc_hostname)),
        (
            "addresses",
            value(toml_edit::Array::new()),
            client_doc!(doc_addresses),
        ),
        ("custom_sni", value(""), client_doc!(doc_custom_sni)),
        ("has_ipv6", value(true), client_doc!(doc_has_ipv6)),
        ("username", value(""), client_doc!(doc_username)),
        ("password", value(""), client_doc!(doc_password)),
        (
            "client_random_prefix",
            value(""),
            client_doc!(doc_client_random_prefix),
        ),
        (
            "client_random_auth_key",
            value(""),
            client_doc!(doc_client_random_auth_key),
        ),
        (
            "skip_verification",
            value(false),
            client_doc!(doc_skip_verification),
        ),
        ("certificate", value(""), client_doc!(doc_certificate)),
        (
            "upstream_protocol",
            value(""),
            client_doc!(doc_upstream_protocol),
        ),
        ("anti_dpi", value(false), client_doc!(doc_anti_dpi)),
        ("name", value(""), client_doc!(doc_name)),
        (
            "dns_upstreams",
            value(toml_edit::Array::new()),
            client_doc!(doc_dns_upstreams),
        ),
    ];
    for (index, (name, value, comment)) in fields.into_iter().enumerate() {
        let mut key = toml_edit::Key::new(name);
        let header = if index == 0 {
            "\n# This file was automatically generated by endpoint and could be used in vpn client.\n"
        } else {
            ""
        };
        let comment = match name {
            "has_ipv6" | "client_random_auth_key" => comment.replace('`', ""),
            _ => comment.to_owned(),
        };
        key.decor_mut()
            .set_prefix(format!("{header}\n{}\n", comment.to_toml_comment()));
        doc.as_table_mut().insert_formatted(&key, value);
    }
    doc
});

#[cfg(test)]
static ORIGINAL_TEMPLATE: Lazy<String> = Lazy::new(|| {
    format!(
        r#"
# This file was automatically generated by endpoint and could be used in vpn client.

{}
hostname = ""

{}
addresses = []

{}
custom_sni = ""

{}
has_ipv6 = true

{}
username = ""

{}
password = ""

{}
client_random_prefix = ""

{}
client_random_auth_key = ""

{}
skip_verification = false

{}
certificate = ""

{}
upstream_protocol = ""

{}
anti_dpi = false

{}
name = ""

{}
dns_upstreams = []
"#,
        client_doc!(doc_hostname).to_toml_comment(),
        client_doc!(doc_addresses).to_toml_comment(),
        client_doc!(doc_custom_sni).to_toml_comment(),
        if cfg!(feature = "rt_doc") { "Whether IPv6 traffic can be routed through the endpoint" } else { "" }.to_toml_comment(),
        client_doc!(doc_username).to_toml_comment(),
        client_doc!(doc_password).to_toml_comment(),
        client_doc!(doc_client_random_prefix).to_toml_comment(),
        if cfg!(feature = "rt_doc") { "TLS client random auth key (hex string for HKDF+AES client_random derivation).\nMust have a corresponding rule with client_random_auth_key in rules.toml." } else { "" }.to_toml_comment(),
        client_doc!(doc_skip_verification).to_toml_comment(),
        client_doc!(doc_certificate).to_toml_comment(),
        client_doc!(doc_upstream_protocol).to_toml_comment(),
        client_doc!(doc_anti_dpi).to_toml_comment(),
        client_doc!(doc_name).to_toml_comment(),
        client_doc!(doc_dns_upstreams).to_toml_comment(),
    )
});
#[cfg(test)]
mod tests {
    use super::*;

    impl ClientConfig {
        fn test_config(certificate: String, cert_is_system_verifiable: bool) -> Self {
            Self {
                hostname: "vpn.example.com".into(),
                addresses: vec!["1.2.3.4:443".into()],
                custom_sni: String::new(),
                has_ipv6: true,
                username: "alice".into(),
                password: "secret".into(),
                client_random_prefix: String::new(),
                client_random_auth_key: String::new(),
                skip_verification: false,
                server_certificate: ClientCertificate {
                    pem: certificate,
                    system_verifiable: cert_is_system_verifiable,
                },
                upstream_protocol: "http2".into(),
                anti_dpi: false,
                name: String::new(),
                dns_upstreams: vec![],
                subscription_url: None,
            }
        }
    }

    // Two-certificate PEM chain: leaf (CN=vpn.example.com) + CA (CN=Test CA)
    const TWO_CERT_PEM_CHAIN: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIC/DCCAeSgAwIBAgIUCI9VIilTMYZq4JfFnFjCuQsAiGIwDQYJKoZIhvcNAQEL\n\
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjAyMjYxMzEyMDBaFw0yNzAyMjYx\n\
MzEyMDBaMBoxGDAWBgNVBAMMD3Zwbi5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN\n\
AQEBBQADggEPADCCAQoCggEBAKnrz9FwFq2xRpOu0D+2hFwymMaixPr556MuB4P1\n\
nLv8vqRQ3MBZn7p48QTywO5OAqIDL27hpigM1e2tc45UuAuaMYoz+Ryty3O75k9X\n\
sdYaVaupOLNWBtbjNntRzFgMpYwbz+lZYuaKqwdRmCJM71Af2jt7aPGSUXeMMR/A\n\
QZZNlRfQuA6NdmhzNsXjaA6xLDBYPk1nGYnFpMxOTlOD9jhM/lImrAMDBATEoMXO\n\
CyhEclgbJtYla6D5Q5Go3NlbMLPr6zOddoL5g7MkQmerODiWlLAlMPIvC33Bz9FU\n\
Dn5wVJ8G5gSFDjq66cL30a9Gq8lWStuy9d3WeXSY5WcBzoMCAwEAAaNCMEAwHQYD\n\
VR0OBBYEFB/yEYFRHwyDdA8/EaeiIi/padZgMB8GA1UdIwQYMBaAFGuqVmspjq2L\n\
h+FhwZJL3VYEm58DMA0GCSqGSIb3DQEBCwUAA4IBAQBqloNE2yxi/6x3KMOVS4bN\n\
+576mpwU+Kx3bDvAvEP8kNtnvOvLKYATaIHsWK+uHvVjYPf7Nw1InUg3GKnE86IH\n\
mr1PgUri9ECKucg9UkOyzdS2VdeWeL+ME2POpg3ARXici5vUngzcKPQmVBu27PSK\n\
dUgkNHQPSxWkBytrxLBi3dynL5qnyoOfzmXkl1odV5XPE77NtvoR4LD5z1/Tn4a1\n\
StvzAN22qiDLkP4MwOir5r21bShJt4otXyNXFZHA0gE19AjLxmknms8D2v3L4ytx\n\
UGXW9acA8MoG1D+TT6jQjGqupznNL/73xMRYazqFjaVCpmaaSYGP41AkLsHuiMti\n\
-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\n\
MIIDBTCCAe2gAwIBAgIUJQlOhwer2yHQbyhVtk86+1587qowDQYJKoZIhvcNAQEL\n\
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjAyMjYxMzEyMDBaFw0yNzAyMjYx\n\
MzEyMDBaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n\
DwAwggEKAoIBAQCbWJQG4lT5uK571FUQqgZuPcfeCtuvI+WCIfxmGk58zI0wmBDS\n\
zaZroUVvcEV4qva+03hDENsKNTypDDlMrd83qzc3rEOLBezNrSQVlbiTNG7lYHU1\n\
3lw9//BlvNmjVBHcQ0643Q+XilG7sDSt3KuqoAT2CiLxm4A/xVN/uzfAoBZhFn5h\n\
oik448kqXXNh6PsofoZO3jTh+4JZuD++xvj+cVdKzH25UIWWCJxBrNqR9zXo8WO5\n\
UFcxxVWnHSqpS8dvpFGVj6B7kyjZZb7TSYYuEJoMplN3uR25nMHgrXse0mvatCRi\n\
uDygNx6Vzg2R7akQXD0bqBVyRmzKY/xAO7CLAgMBAAGjUzBRMB0GA1UdDgQWBBRr\n\
qlZrKY6ti4fhYcGSS91WBJufAzAfBgNVHSMEGDAWgBRrqlZrKY6ti4fhYcGSS91W\n\
BJufAzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCII03BWTUn\n\
nT2HJrh67ywq34UwWFqqJA0AQIetpS933waW01yr7YJxq3TAznVgsiXKkU/9bFvx\n\
9u4mnzMHy+LJeGw5TtveDmKz22Jr45KH0ug3kikqdPVqB+ur2Kx73ao0SXFCyeIi\n\
6E57QnwyAWmSxIKzjIDreMr0Y2tWRfwvgsRkxZZP3Ps+SQakz6yfYoSJesJxJ0o2\n\
OzTTMTfK4lR2f/QP4MGp8E0dImkfm9eLq6be8VoaNt2nx1MqiD2AxMF3w7FAXmCS\n\
jhjuhML7Zp8c0/3g+r/60sv/9x4DrPeXTYrGCK+qLgZ1qxpwIARNbl780fGnZCIf\n\
omxU7kknZApM\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn test_compose_toml_self_signed_cert_chain() -> Result<(), Box<dyn std::error::Error>> {
        let config = ClientConfig::test_config(TWO_CERT_PEM_CHAIN.to_string(), false);
        let toml_output = config.compose_toml();

        let doc: Document = toml_output.parse()?;
        let cert_value = doc["certificate"].as_str().ok_or("missing TOML string")?;

        if !(cert_value.contains("-----BEGIN CERTIFICATE-----")) {
            return Err("TOML should contain certificate when not system-verifiable".into());
        }
        let (actual, expected) = (
            &(cert_value.matches("-----BEGIN CERTIFICATE-----").count()),
            &(2),
        );
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "TOML should contain both certs from the chain"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn test_compose_toml_system_verifiable_cert_omitted() -> Result<(), Box<dyn std::error::Error>>
    {
        let config = ClientConfig::test_config(TWO_CERT_PEM_CHAIN.to_string(), true);
        let toml_output = config.compose_toml();

        let doc: Document = toml_output.parse()?;
        let cert_value = doc["certificate"].as_str().ok_or("missing TOML string")?;

        let (actual, expected) = (&(cert_value), &(""));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "TOML certificate should be empty when cert is system-verifiable"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn test_compose_deeplink_self_signed_cert_chain() -> Result<(), Box<dyn std::error::Error>> {
        let config = ClientConfig::test_config(TWO_CERT_PEM_CHAIN.to_string(), false);
        let uri = config.compose_deeplink()?;

        let decoded = trusttunnel_deeplink::decode(&uri)?;
        let cert_der = decoded
            .certificate
            .ok_or("Deep-link should contain certificate when not system-verifiable")?;

        let pem = trusttunnel_deeplink::cert::der_to_pem(&cert_der)?;
        let (actual, expected) = (&(pem.matches("-----BEGIN CERTIFICATE-----").count()), &(2));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "Deep-link DER should contain both certs from the chain"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn test_compose_deeplink_system_verifiable_cert_omitted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = ClientConfig::test_config(TWO_CERT_PEM_CHAIN.to_string(), true);
        let uri = config.compose_deeplink()?;

        let decoded = trusttunnel_deeplink::decode(&uri)?;
        if decoded.certificate.is_some() {
            return Err(
                "Deep-link should not contain certificate when cert is system-verifiable".into(),
            );
        }
        Ok(())
    }

    #[test]
    fn percent_encode_reserved_chars_in_userinfo() {
        assert_eq!(percent_encode_userinfo("alice"), "alice");
        assert_eq!(percent_encode_userinfo("a:b@/"), "a%3Ab%40%2F");
    }

    #[test]
    fn build_subscription_url_appends_credentials() {
        let url = build_subscription_url("https://vpn.example.com/subscription", "alice", "s3cret");
        assert_eq!(url, "https://alice:s3cret@vpn.example.com/subscription");
    }

    #[test]
    fn build_subscription_url_strips_existing_userinfo_in_override() {
        let url = build_subscription_url("https://old:old@sub.example.com/sub", "alice", "p@ss");
        assert_eq!(url, "https://alice:p%40ss@sub.example.com/sub");
    }

    #[test]
    fn build_subscription_url_preserves_at_in_path_and_query(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // `@` after the authority is not userinfo and must be preserved,
        // matching what `validate_subscription_url_override` allows.
        let url = build_subscription_url("https://vpn.example.com/p@ath", "alice", "s3cret");
        let (actual, expected) = (&(url), &("https://alice:s3cret@vpn.example.com/p@ath"));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        let url =
            build_subscription_url("https://vpn.example.com/sub?next=/p@ath", "alice", "s3cret");
        let (actual, expected) = (
            &(url),
            &("https://alice:s3cret@vpn.example.com/sub?next=/p@ath"),
        );
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        // The authority ends at the first `?` or `#` even without a path.
        let url = build_subscription_url("https://vpn.example.com?next=@x", "alice", "s3cret");
        let (actual, expected) = (&(url), &("https://alice:s3cret@vpn.example.com?next=@x"));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn compose_toml_emits_subscription_url_when_set() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = ClientConfig::test_config(TWO_CERT_PEM_CHAIN.to_string(), false);
        config.subscription_url =
            Some("https://alice:s3cret@vpn.example.com/subscription".to_string());
        let toml_output = config.compose_toml();

        let doc: Document = toml_output.parse()?;
        let (actual, expected) = (
            &(doc["subscription_url"]
                .as_str()
                .ok_or("missing TOML string")?),
            &("https://alice:s3cret@vpn.example.com/subscription"),
        );
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn compose_deeplink_includes_subscription_url() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = ClientConfig::test_config(TWO_CERT_PEM_CHAIN.to_string(), false);
        let url = "https://alice:s3cret@vpn.example.com/subscription".to_string();
        config.subscription_url = Some(url.clone());
        let uri = config.compose_deeplink()?;

        let decoded = trusttunnel_deeplink::decode(&uri)?;
        let (actual, expected) = (
            &(decoded.subscription_url.as_deref()),
            &(Some(url.as_str())),
        );
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        // Static fallback parameters are still present.
        let (actual, expected) = (&(decoded.hostname.as_deref()), &(Some("vpn.example.com")));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        let (actual, expected) = (&(decoded.username.as_deref()), &(Some("alice")));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn compose_deeplink_without_subscription_url() -> Result<(), Box<dyn std::error::Error>> {
        let config = ClientConfig::test_config(TWO_CERT_PEM_CHAIN.to_string(), false);
        let uri = config.compose_deeplink()?;

        let decoded = trusttunnel_deeplink::decode(&uri)?;
        let (actual, expected) = (&(decoded.subscription_url), &(None));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn compose_deeplink_subscription_only_minimal() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = ClientConfig::test_config(TWO_CERT_PEM_CHAIN.to_string(), false);
        let url = "https://alice:s3cret@vpn.example.com/subscription".to_string();
        config.subscription_url = Some(url.clone());
        let uri = config.compose_deeplink_subscription_only()?;

        let decoded = trusttunnel_deeplink::decode(&uri)?;
        let (actual, expected) = (
            &(decoded.subscription_url.as_deref()),
            &(Some(url.as_str())),
        );
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        let (actual, expected) = (&(decoded.hostname), &(None));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        if !(decoded.addresses.is_empty()) {
            return Err(format!(
                "assertion failed: {}",
                stringify!(decoded.addresses.is_empty())
            )
            .into());
        }
        let (actual, expected) = (&(decoded.username), &(None));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        let (actual, expected) = (&(decoded.password), &(None));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        let (actual, expected) = (&(decoded.certificate), &(None));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn compose_deeplink_subscription_only_requires_url() {
        let config = ClientConfig::test_config(TWO_CERT_PEM_CHAIN.to_string(), false);
        assert!(config.compose_deeplink_subscription_only().is_err());
    }

    #[test]
    fn validate_override_accepts_plain_https() {
        assert!(validate_subscription_url_override("https://vpn.example.com/subscription").is_ok());
        assert!(validate_subscription_url_override("https://vpn.example.com").is_ok());
        assert!(validate_subscription_url_override("https://1.2.3.4:443/subscription").is_ok());
    }

    #[test]
    fn validate_override_rejects_non_https() {
        let err = validate_subscription_url_override("http://vpn.example.com/subscription");
        assert!(err.is_err());
        assert!(err.is_err_and(|error| error.contains("https")));
    }

    #[test]
    fn validate_override_rejects_embedded_credentials() {
        let err =
            validate_subscription_url_override("https://alice:s3cret@vpn.example.com/subscription");
        assert!(err.is_err());
        assert!(err.is_err_and(|error| error.contains("credential")));
    }

    #[test]
    fn validate_override_accepts_at_outside_authority() -> Result<(), Box<dyn std::error::Error>> {
        // `@` in the path or query is not userinfo and is allowed.
        if validate_subscription_url_override("https://vpn.example.com/p@ath").is_err() {
            return Err(format!(
                "assertion failed: {}",
                stringify!(
                    validate_subscription_url_override("https://vpn.example.com/p@ath").is_ok()
                )
            )
            .into());
        }
        if validate_subscription_url_override("https://vpn.example.com/sub?next=@x").is_err() {
            return Err(format!(
                "assertion failed: {}",
                stringify!(validate_subscription_url_override(
                    "https://vpn.example.com/sub?next=@x"
                )
                .is_ok())
            )
            .into());
        }
        // The authority ends at the first `?` or `#` even without a path.
        if validate_subscription_url_override("https://vpn.example.com?next=@x").is_err() {
            return Err(format!(
                "assertion failed: {}",
                stringify!(
                    validate_subscription_url_override("https://vpn.example.com?next=@x").is_ok()
                )
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn validate_override_rejects_empty_host() {
        assert!(validate_subscription_url_override("https://").is_err());
        assert!(validate_subscription_url_override("https:///subscription").is_err());
    }

    #[test]
    fn subscription_url_port_included_for_non_default_port() {
        assert_eq!(subscription_url_port(Some("1.2.3.4:8000")), Some(8000));
        assert_eq!(
            subscription_url_port(Some("vpn.example.com:8443")),
            Some(8443)
        );
        assert_eq!(
            subscription_url_port(Some("[2001:db8::1]:8000")),
            Some(8000)
        );
    }

    #[test]
    fn subscription_url_port_omitted_when_address_absent() {
        assert_eq!(subscription_url_port(None), None);
    }

    #[test]
    fn subscription_url_port_omitted_for_default_port() {
        assert_eq!(subscription_url_port(Some("1.2.3.4:443")), None);
        assert_eq!(subscription_url_port(Some("vpn.example.com:443")), None);
    }

    #[test]
    fn subscription_url_port_omitted_when_port_invalid() {
        assert_eq!(subscription_url_port(Some("vpn.example.com")), None);
        assert_eq!(
            subscription_url_port(Some("vpn.example.com:notaport")),
            None
        );
        assert_eq!(subscription_url_port(Some("1.2.3.4:0")), None);
        assert_eq!(subscription_url_port(Some("1.2.3.4:99999")), None);
    }

    #[test]
    fn test_compose_toml_auth_key() {
        let mut config = ClientConfig::test_config(String::new(), true);
        config.client_random_auth_key = "aabbccdd".into();
        let toml = config.compose_toml();
        assert!(toml.contains("client_random_auth_key = \"aabbccdd\""));
    }

    #[test]
    fn template_preserves_original_export_format() -> Result<(), Box<dyn std::error::Error>> {
        let original: Document = ORIGINAL_TEMPLATE.parse()?;
        let (actual, expected) = (&(TEMPLATE.to_string()), &(original.to_string()));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn build_reports_missing_client_and_host() {
        let hosts = TlsHostsSettings::default();
        let result = build("alice", vec![], &[], &hosts, BuildOptions::default());
        assert!(result.is_err_and(|error| error.kind() == io::ErrorKind::InvalidInput));
        let clients = [registry_based::Client {
            username: "alice".into(),
            password: "secret".into(),
            max_http2_conns: None,
            max_http3_conns: None,
        }];
        let result = build("alice", vec![], &clients, &hosts, BuildOptions::default());
        assert!(result.is_err_and(|error| error.kind() == io::ErrorKind::InvalidInput));
    }

    #[test]
    fn debug_scrubs_export_credentials() {
        let mut config = ClientConfig::test_config(String::new(), false);
        config.client_random_auth_key = "secret_auth_key".into();
        config.subscription_url = Some("https://alice:secret@vpn.example.com/subscription".into());
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("secret_auth_key"));
        assert!(!debug.contains("alice:secret"));
    }

    #[test]
    fn certificate_getters_preserve_pem_and_system_trust() {
        for system_verifiable in [false, true] {
            let config = ClientConfig::test_config("certificate PEM".into(), system_verifiable);
            assert_eq!(config.get_certificate(), "certificate PEM");
            assert_eq!(*config.get_cert_is_system_verifiable(), system_verifiable);
        }
    }

    #[test]
    fn export_preserves_independent_client_switches() -> Result<(), Box<dyn std::error::Error>> {
        for has_ipv6 in [false, true] {
            for skip_verification in [false, true] {
                for anti_dpi in [false, true] {
                    let mut config = ClientConfig::test_config(String::new(), false);
                    config.has_ipv6 = has_ipv6;
                    config.skip_verification = skip_verification;
                    config.anti_dpi = anti_dpi;
                    let doc: Document = config.compose_toml().parse()?;
                    if (
                        doc["has_ipv6"].as_bool(),
                        doc["skip_verification"].as_bool(),
                        doc["anti_dpi"].as_bool(),
                    ) != (Some(has_ipv6), Some(skip_verification), Some(anti_dpi))
                    {
                        return Err("TOML changed independent client switches".into());
                    }
                    let decoded = trusttunnel_deeplink::decode(&config.compose_deeplink()?)?;
                    if (
                        decoded.has_ipv6,
                        decoded.skip_verification,
                        decoded.anti_dpi,
                    ) != (has_ipv6, skip_verification, anti_dpi)
                    {
                        return Err("deep-link changed independent client switches".into());
                    }
                }
            }
        }
        Ok(())
    }
}
