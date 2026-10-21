//! Default endpoint configuration for ping, speed-test, and tunnel scenarios.

use crate::common::{self, TestResult};
use std::net::SocketAddr;
use trusttunnel::settings::{
    Http1Settings, Http2Settings, ListenProtocolSettings, QuicSettings, Settings, TlsHostInfo,
    TlsHostsSettings,
};

/// Run the default endpoint while retaining its disposable certificate.
///
/// # Errors
/// Returns configuration, certificate-generation, and endpoint listener errors.
pub async fn run_endpoint(listen_address: &SocketAddr) -> TestResult {
    let settings = Settings::builder()
        .listen_address(listen_address)?
        .listen_protocols(ListenProtocolSettings {
            http1: Some(Http1Settings::builder().build()),
            http2: Some(Http2Settings::builder().build()),
            quic: Some(QuicSettings::builder().build()),
        })
        .allow_private_network_connections(true)
        .speedtest_enable(true)
        .ping_enable(true)
        .ping_path("/ping")
        .speedtest_path("/speed")
        .build()?;

    let cert_key_file = common::make_cert_key_file()?;
    let cert_key_path = cert_key_file
        .path()
        .to_str()
        .ok_or("certificate path is not UTF-8")?;
    let hosts_settings = TlsHostsSettings::builder()
        .main_hosts(vec![TlsHostInfo {
            hostname: common::MAIN_DOMAIN_NAME.to_string(),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
            allowed_sni: vec![],
        }])
        .ping_hosts(vec![TlsHostInfo {
            hostname: format!("ping.{}", common::MAIN_DOMAIN_NAME),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
            allowed_sni: vec![],
        }])
        .speedtest_hosts(vec![TlsHostInfo {
            hostname: format!("speed.{}", common::MAIN_DOMAIN_NAME),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
            allowed_sni: vec![],
        }])
        .reverse_proxy_hosts(vec![TlsHostInfo {
            hostname: format!("hello.{}", common::MAIN_DOMAIN_NAME),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
            allowed_sni: vec![],
        }])
        .build()?;

    common::run_endpoint_with_settings(settings, &hosts_settings).await
}
