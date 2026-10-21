//! Fallible, hermetic fixtures shared by every integration-test crate.

use boring::asn1::Asn1Time;
use boring::hash::MessageDigest;
use boring::pkey::PKey;
use boring::rsa::Rsa;
use boring::x509::extension::SubjectAlternativeName;
use boring::x509::{X509NameBuilder, X509};
use log::LevelFilter;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use std::fmt::Display;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use trusttunnel::authentication::{registry_based::RegistryBasedAuthenticator, Authenticator};
use trusttunnel::core::Core;
use trusttunnel::log_utils;
use trusttunnel::settings::{Settings, TlsHostsSettings};
use trusttunnel::shutdown::Shutdown;

/// Error propagated by integration tests, setup tasks, and transport drivers.
pub type TestError = Box<dyn std::error::Error + Send + Sync>;

/// A fallible test or fixture operation.
pub type TestResult<T = ()> = Result<T, TestError>;

/// Hostname shared by the generated certificate and endpoint fixtures.
pub const MAIN_DOMAIN_NAME: &str = "localhost";

static NEXT_ENDPOINT_PORT: AtomicU16 = AtomicU16::new(9128);

/// Install the integration-test logger once per test executable.
///
/// # Errors
/// Returns an error if another logger was already installed.
pub fn set_up_logger() -> TestResult {
    static LOGGER: std::sync::OnceLock<Result<(), log::SetLoggerError>> =
        std::sync::OnceLock::new();
    let result = LOGGER.get_or_init(|| {
        log::set_max_level(LevelFilter::Debug);
        log::set_logger(log_utils::make_stdout_logger())
    });
    result
        .as_ref()
        .map_err(|error| std::io::Error::other(error.to_string()).into())
        .copied()
}

/// Allocate a distinct loopback endpoint address in this test executable.
pub fn make_endpoint_address() -> SocketAddr {
    (
        Ipv4Addr::LOCALHOST,
        NEXT_ENDPOINT_PORT.fetch_add(1, Ordering::Relaxed),
    )
        .into()
}

/// Validate a test predicate without panicking in a fallible test or fixture.
///
/// # Errors
/// Returns the supplied diagnostic when the predicate is false.
pub fn check(condition: bool, diagnostic: impl Display) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::other(diagnostic.to_string()).into())
    }
}

/// Generate a disposable self-signed localhost certificate and private key.
///
/// # Errors
/// Returns certificate-generation, temporary-file creation, or write errors.
pub fn make_cert_key_file() -> TestResult<NamedTempFile> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", MAIN_DOMAIN_NAME)?;
    let name = name.build();
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_subject_name(&name)?;
    certificate.set_issuer_name(&name)?;
    certificate.set_pubkey(&key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    certificate.set_not_before(&not_before)?;
    certificate.set_not_after(&not_after)?;
    let alternative_names = SubjectAlternativeName::new()
        .dns(MAIN_DOMAIN_NAME)
        .dns("localhost.localdomain")
        .ip("127.0.0.1")
        .build(&certificate.x509v3_context(None, None))?;
    certificate.append_extension(alternative_names)?;
    certificate.sign(&key, MessageDigest::sha256())?;
    let mut file = NamedTempFile::new()?;
    file.write_all(&certificate.build().to_pem()?)?;
    file.write_all(&key.private_key_to_pem_pkcs8()?)?;
    file.flush()?;
    Ok(file)
}

/// Establish TLS to a loopback fixture without validating its disposable certificate.
///
/// # Errors
/// Returns invalid server-name, TLS configuration, connection, or handshake errors.
pub async fn establish_tls_connection(
    server_name: &str,
    peer: &SocketAddr,
    alpn: Option<&[u8]>,
) -> TestResult<TlsStream<TcpStream>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        aws_lc_rs::kx_group::X25519MLKEM768,
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::SECP256R1,
        aws_lc_rs::kx_group::SECP384R1,
    ];
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoopVerifier))
        .with_no_client_auth();
    if let Some(alpn) = alpn {
        config.alpn_protocols.push(alpn.to_vec());
    }
    Ok(TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from(server_name.to_owned())?,
            TcpStream::connect(peer).await?,
        )
        .await?)
}

#[derive(Debug, Clone, Copy)]
struct NoopVerifier;

impl ServerCertVerifier for NoopVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Run an endpoint with the supplied settings until it stops or its future is dropped.
///
/// # Errors
/// Returns endpoint initialization and listener errors.
pub async fn run_endpoint_with_settings(
    settings: Settings,
    hosts_settings: &TlsHostsSettings,
) -> TestResult {
    let shutdown = Shutdown::new();
    let authenticator: Option<Arc<dyn Authenticator>> = if settings.get_clients().is_empty() {
        None
    } else {
        Some(Arc::new(RegistryBasedAuthenticator::new(
            settings.get_clients(),
        )))
    };
    let endpoint = Core::new(settings, authenticator, hosts_settings, shutdown)?;
    endpoint.listen().await?;
    Err(std::io::Error::other("endpoint listener stopped unexpectedly").into())
}
