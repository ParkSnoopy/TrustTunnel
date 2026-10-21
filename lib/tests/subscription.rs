//! Authenticated subscription output, routing, reload, and secrecy checks.

use futures::future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use trusttunnel::authentication::registry_based::Client;
use trusttunnel::authentication::{registry_based::RegistryBasedAuthenticator, Authenticator};
use trusttunnel::core::Core;
use trusttunnel::net_utils;
use trusttunnel::settings::{
    Http1Settings, Http2Settings, ListenProtocolSettings, QuicSettings, Settings, TlsHostInfo,
    TlsHostsSettings,
};
use trusttunnel::shutdown::Shutdown;
use trusttunnel::subscription::SubscriptionSettings;

mod common;
use common::TestResult;
#[path = "common/http_get.rs"]
mod http_get;
#[path = "common/http_post.rs"]
mod http_post;

fn make_settings(
    listen_address: &SocketAddr,
    subscription_address: &str,
    enabled: bool,
    users: Vec<Client>,
) -> TestResult<Settings> {
    let mut builder = Settings::builder()
        .listen_address(listen_address)?
        .listen_protocols(ListenProtocolSettings {
            http1: Some(Http1Settings::builder().build()),
            http2: Some(Http2Settings::builder().build()),
            quic: Some(QuicSettings::builder().build()),
        })
        .allow_private_network_connections(true)
        .clients(users);

    if enabled {
        builder = builder.subscription(SubscriptionSettings {
            enabled: true,
            hostname: Some(common::MAIN_DOMAIN_NAME.to_string()),
            path: SubscriptionSettings::default_path(),
            address: Some(subscription_address.to_string()),
            name: Some("Acme Corp VPN".to_string()),
            dns_upstreams: vec!["tls://1.1.1.1".to_string()],
            custom_sni: Some(common::MAIN_DOMAIN_NAME.to_string()),
            client_random_prefix: Some("aabbcc/ff00ff".to_string()),
        });
    }

    Ok(builder.build()?)
}

fn make_hosts(cert_path: &str) -> TestResult<TlsHostsSettings> {
    make_hosts_with_names(cert_path, &[common::MAIN_DOMAIN_NAME])
}

fn make_hosts_with_names(cert_path: &str, names: &[&str]) -> TestResult<TlsHostsSettings> {
    let main_hosts: Vec<TlsHostInfo> = names
        .iter()
        .map(|&name| TlsHostInfo {
            hostname: name.to_string(),
            cert_chain_path: cert_path.to_string(),
            private_key_path: cert_path.to_string(),
            allowed_sni: vec![],
        })
        .collect();
    Ok(TlsHostsSettings::builder().main_hosts(main_hosts).build()?)
}

/// Like [`make_settings`] with an enabled subscription, but with the optional
/// `custom_sni` / `client_random_prefix` / `name` / `dns_upstreams` fields
/// unset, so omission in the JSON response can be asserted.
fn make_minimal_subscription_settings(
    listen_address: &SocketAddr,
    subscription_address: &str,
    users: Vec<Client>,
) -> TestResult<Settings> {
    Ok(Settings::builder()
        .listen_address(listen_address)?
        .listen_protocols(ListenProtocolSettings {
            http1: Some(Http1Settings::builder().build()),
            http2: Some(Http2Settings::builder().build()),
            quic: Some(QuicSettings::builder().build()),
        })
        .allow_private_network_connections(true)
        .clients(users)
        .subscription(SubscriptionSettings {
            enabled: true,
            hostname: Some(common::MAIN_DOMAIN_NAME.to_string()),
            path: SubscriptionSettings::default_path(),
            address: Some(subscription_address.to_string()),
            name: None,
            dns_upstreams: vec![],
            custom_sni: None,
            client_random_prefix: None,
        })
        .build()?)
}

fn alice_bob() -> Vec<Client> {
    vec![
        Client {
            username: "alice".to_string(),
            password: "secret".to_string(),
            max_http2_conns: None,
            max_http3_conns: None,
        },
        Client {
            username: "bob".to_string(),
            password: "passwd".to_string(),
            max_http2_conns: None,
            max_http3_conns: None,
        },
    ]
}

// base64("alice:secret") and base64("bob:passwd")
const ALICE_BASIC: &str = "Basic YWxpY2U6c2VjcmV0";
const BOB_BASIC: &str = "Basic Ym9iOnBhc3N3ZA==";

async fn fetch(
    endpoint_address: &SocketAddr,
    auth: Option<&str>,
    extra: &[(&str, &str)],
) -> TestResult<(http::StatusCode, bytes::Bytes)> {
    let stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, endpoint_address, None).await?;
    let url = format!(
        "https://{}:{}/subscription",
        common::MAIN_DOMAIN_NAME,
        endpoint_address.port()
    );
    let mut headers: Vec<(&str, &str)> = Vec::new();
    if let Some(a) = auth {
        headers.push(("authorization", a));
    }
    headers.extend_from_slice(extra);
    let (parts, body) =
        http_get::do_get_request(stream, http::Version::HTTP_11, &url, &headers).await?;
    Ok((parts.status, body))
}

#[tokio::test]
async fn get_with_valid_credentials_returns_200_and_user_fields() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let cert_path = cert_file
        .path()
        .to_str()
        .ok_or("certificate path is not UTF-8")?;
    let settings = make_settings(&endpoint_address, "203.0.113.1:443", true, alice_bob())?;
    let hosts = make_hosts(cert_path)?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (status, body) = fetch(&endpoint_address, Some(ALICE_BASIC), &[]).await?;
        common::check(
            status == http::StatusCode::OK,
            "assertion failed: status == http::StatusCode::OK",
        )?;
        let body = String::from_utf8(body.to_vec())?;
        common::check(
            body.contains("\"version\":1"),
            "assertion failed: body.contains(\"\\\"version\\\":1\")",
        )?;
        common::check(
            body.contains("\"hostname\":\"localhost\""),
            "assertion failed: body.contains(\"\\\"hostname\\\":\\\"localhost\\\"\")",
        )?;
        common::check(
            body.contains("\"address\":\"203.0.113.1:443\""),
            "assertion failed: body.contains(\"\\\"address\\\":\\\"203.0.113.1:443\\\"\")",
        )?;
        common::check(
            body.contains("\"username\":\"alice\""),
            "assertion failed: body.contains(\"\\\"username\\\":\\\"alice\\\"\")",
        )?;
        common::check(
            body.contains("\"password\":\"secret\""),
            "assertion failed: body.contains(\"\\\"password\\\":\\\"secret\\\"\")",
        )?;
        common::check(
            body.contains("\"name\":\"Acme Corp VPN\""),
            "assertion failed: body.contains(\"\\\"name\\\":\\\"Acme Corp VPN\\\"\")",
        )?;
        common::check(
            body.contains("\"dns_upstreams\":[\"tls://1.1.1.1\"]"),
            "assertion failed: body.contains(\"\\\"dns_upstreams\\\":[\\\"tls://1.1.1.1\\\"]\")",
        )?;
        common::check(
            body.contains("\"custom_sni\":\"localhost\""),
            "assertion failed: body.contains(\"\\\"custom_sni\\\":\\\"localhost\\\"\")",
        )?;
        common::check(body.contains("\"client_random_prefix\":\"aabbcc/ff00ff\""), "assertion failed: body.contains(\"\\\"client_random_prefix\\\":\\\"aabbcc/ff00ff\\\"\")")?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn get_without_credentials_returns_401() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let settings = make_settings(&endpoint_address, "203.0.113.1:443", true, alice_bob())?;
    let hosts = make_hosts(
        cert_file
            .path()
            .to_str()
            .ok_or("certificate path is not UTF-8")?,
    )?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (status, body) = fetch(&endpoint_address, None, &[]).await?;
        common::check(
            status == http::StatusCode::UNAUTHORIZED,
            "assertion failed: status == http::StatusCode::UNAUTHORIZED",
        )?;
        common::check(
            !body.windows(6).any(|w| w == b"secret"),
            "assertion failed: !body.windows(6).any(|w| w == b\"secret\")",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn get_as_bob_returns_bobs_credentials_not_alices() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let settings = make_settings(&endpoint_address, "203.0.113.1:443", true, alice_bob())?;
    let hosts = make_hosts(
        cert_file
            .path()
            .to_str()
            .ok_or("certificate path is not UTF-8")?,
    )?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (status, body) = fetch(&endpoint_address, Some(BOB_BASIC), &[]).await?;
        common::check(
            status == http::StatusCode::OK,
            "assertion failed: status == http::StatusCode::OK",
        )?;
        let body = String::from_utf8(body.to_vec())?;
        common::check(
            body.contains("\"username\":\"bob\""),
            "assertion failed: body.contains(\"\\\"username\\\":\\\"bob\\\"\")",
        )?;
        common::check(
            body.contains("\"password\":\"passwd\""),
            "assertion failed: body.contains(\"\\\"password\\\":\\\"passwd\\\"\")",
        )?;
        common::check(
            !body.contains("secret"),
            "assertion failed: !body.contains(\"secret\")",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn post_without_credentials_returns_401() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let settings = make_settings(&endpoint_address, "203.0.113.1:443", true, alice_bob())?;
    let hosts = make_hosts(
        cert_file
            .path()
            .to_str()
            .ok_or("certificate path is not UTF-8")?,
    )?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let stream =
            common::establish_tls_connection(common::MAIN_DOMAIN_NAME, &endpoint_address, None)
                .await?;
        let url = format!(
            "https://{}:{}/subscription",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        );
        let response = http_post::do_post_request(stream, http::Version::HTTP_11, &url, 0).await?;
        // Auth runs before the method check, so an unauthenticated non-GET
        // request gets 401 (not 405) and does not confirm the path.
        common::check(
            response.status() == http::StatusCode::UNAUTHORIZED,
            "assertion failed: response.status() == http::StatusCode::UNAUTHORIZED",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn post_with_credentials_returns_405() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let settings = make_settings(&endpoint_address, "203.0.113.1:443", true, alice_bob())?;
    let hosts = make_hosts(
        cert_file
            .path()
            .to_str()
            .ok_or("certificate path is not UTF-8")?,
    )?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let stream =
            common::establish_tls_connection(common::MAIN_DOMAIN_NAME, &endpoint_address, None)
                .await?;
        let url = format!(
            "https://{}:{}/subscription",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        );
        let (mut request, conn) = hyper::client::conn::Builder::new()
            .handshake(stream)
            .await?;
        let exchange = async {
            let req = hyper::Request::post(&url)
                .version(http::Version::HTTP_11)
                .header("authorization", ALICE_BASIC)
                .body(hyper::Body::empty())?;
            Ok::<_, common::TestError>(request.send_request(req).await?)
        };
        futures::pin_mut!(exchange);
        let response = match future::select(conn, exchange).await {
            future::Either::Left((result, exchange)) => {
                result?;
                exchange.await
            }
            future::Either::Right((response, _)) => response,
        }?;
        common::check(
            response.status() == http::StatusCode::METHOD_NOT_ALLOWED,
            "assertion failed: response.status() == http::StatusCode::METHOD_NOT_ALLOWED",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn disabled_subscription_does_not_serve_data() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    // Absent section (make_settings with enabled=false adds no [subscription]);
    // the path is not reserved, so the request falls through to the tunnel.
    let settings = make_settings(&endpoint_address, "203.0.113.1:443", false, alice_bob())?;
    let hosts = make_hosts(
        cert_file
            .path()
            .to_str()
            .ok_or("certificate path is not UTF-8")?,
    )?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (status, body) = fetch(&endpoint_address, Some(ALICE_BASIC), &[]).await?;
        common::check(
            status != http::StatusCode::OK,
            "assertion failed: status != http::StatusCode::OK",
        )?;
        common::check(
            !body.windows(6).any(|w| w == b"secret"),
            "assertion failed: !body.windows(6).any(|w| w == b\"secret\")",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn present_disabled_section_returns_403() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let cert_path = cert_file
        .path()
        .to_str()
        .ok_or("certificate path is not UTF-8")?;
    // Section present but disabled: the path is reserved and the handler
    // returns 403 instead of falling through to the tunnel.
    let settings = Settings::builder()
        .listen_address(endpoint_address)?
        .listen_protocols(ListenProtocolSettings {
            http1: Some(Http1Settings::builder().build()),
            http2: Some(Http2Settings::builder().build()),
            quic: Some(QuicSettings::builder().build()),
        })
        .allow_private_network_connections(true)
        .clients(alice_bob())
        // Fully specified even though disabled: `validate` checks `address`
        // unconditionally now, so a staged disabled section must be valid to load.
        .subscription(SubscriptionSettings {
            enabled: false,
            hostname: Some(common::MAIN_DOMAIN_NAME.to_string()),
            path: SubscriptionSettings::default_path(),
            address: Some("203.0.113.1:443".to_string()),
            name: None,
            dns_upstreams: vec![],
            custom_sni: None,
            client_random_prefix: None,
        })
        .build()?;
    let hosts = make_hosts(cert_path)?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (status, body) = fetch(&endpoint_address, Some(ALICE_BASIC), &[]).await?;
        common::check(
            status == http::StatusCode::FORBIDDEN,
            "assertion failed: status == http::StatusCode::FORBIDDEN",
        )?;
        common::check(
            !body.windows(6).any(|w| w == b"secret"),
            "assertion failed: !body.windows(6).any(|w| w == b\"secret\")",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

async fn fetch_address(endpoint_address: &SocketAddr, auth: &str) -> TestResult<String> {
    let stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, endpoint_address, None).await?;
    let url = format!(
        "https://{}:{}/subscription",
        common::MAIN_DOMAIN_NAME,
        endpoint_address.port()
    );
    let (parts, body) = http_get::do_get_request(
        stream,
        http::Version::HTTP_11,
        &url,
        &[("authorization", auth)],
    )
    .await?;
    common::check(
        parts.status == http::StatusCode::OK,
        "assertion failed: parts.status == http::StatusCode::OK",
    )?;
    let body = String::from_utf8(body.to_vec())?;
    Ok(body
        .split("\"address\":\"")
        .nth(1)
        .ok_or("subscription response has no address")?
        .split('"')
        .next()
        .ok_or("subscription address is not terminated")?
        .to_string())
}

#[tokio::test]
async fn get_h2_authenticated_returns_json() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let cert_path = cert_file
        .path()
        .to_str()
        .ok_or("certificate path is not UTF-8")?;
    let settings = make_settings(&endpoint_address, "203.0.113.1:443", true, alice_bob())?;
    let hosts = make_hosts(cert_path)?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let stream = common::establish_tls_connection(
            common::MAIN_DOMAIN_NAME,
            &endpoint_address,
            Some(net_utils::HTTP2_ALPN.as_bytes()),
        )
        .await?;
        let url = format!(
            "https://{}:{}/subscription",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        );
        // Verify the HTTP/2 path routes to the subscription handler and
        // authenticates. The test harness cannot read a streamed H2 response
        // body (the connection driver is an independent task), so body content
        // is asserted over HTTP/1.1 in get_with_valid_credentials_*.
        let (mut request_sender, conn) = hyper::client::conn::Builder::new()
            .http2_only(true)
            .handshake(stream)
            .await?;
        let exchange = async {
            let req = hyper::Request::builder()
                .method("GET")
                .uri(&url)
                .version(http::Version::HTTP_2)
                .header("authorization", ALICE_BASIC)
                .body(hyper::Body::empty())?;
            Ok::<_, common::TestError>(request_sender.send_request(req).await?)
        };
        futures::pin_mut!(exchange);
        let response = match future::select(conn, exchange).await {
            future::Either::Left((result, exchange)) => {
                result?;
                exchange.await
            }
            future::Either::Right((response, _)) => response,
        }?;
        common::check(
            response.status() == http::StatusCode::OK,
            "assertion failed: response.status() == http::StatusCode::OK",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn omits_optional_fields_when_unset() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let cert_path = cert_file
        .path()
        .to_str()
        .ok_or("certificate path is not UTF-8")?;
    let settings =
        make_minimal_subscription_settings(&endpoint_address, "203.0.113.1:443", alice_bob())?;
    let hosts = make_hosts(cert_path)?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (status, body) = fetch(&endpoint_address, Some(ALICE_BASIC), &[]).await?;
        common::check(
            status == http::StatusCode::OK,
            "assertion failed: status == http::StatusCode::OK",
        )?;
        let body = String::from_utf8(body.to_vec())?;
        common::check(
            body.contains("\"version\":1"),
            "assertion failed: body.contains(\"\\\"version\\\":1\")",
        )?;
        common::check(
            body.contains("\"has_ipv6\":true"),
            "assertion failed: body.contains(\"\\\"has_ipv6\\\":true\")",
        )?;
        common::check(
            !body.contains("custom_sni"),
            "assertion failed: !body.contains(\"custom_sni\")",
        )?;
        common::check(
            !body.contains("client_random_prefix"),
            "assertion failed: !body.contains(\"client_random_prefix\")",
        )?;
        common::check(
            !body.contains("\"name\""),
            "assertion failed: !body.contains(\"\\\"name\\\"\")",
        )?;
        common::check(
            !body.contains("dns_upstreams"),
            "assertion failed: !body.contains(\"dns_upstreams\")",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn get_sni_mismatch_returns_404() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let cert_path = cert_file
        .path()
        .to_str()
        .ok_or("certificate path is not UTF-8")?;
    // Subscription hostname is MAIN_DOMAIN_NAME; serve a second main host so a
    // connection with a different SNI is still accepted by TLS.
    let settings = make_settings(&endpoint_address, "203.0.113.1:443", true, alice_bob())?;
    let hosts = make_hosts_with_names(cert_path, &[common::MAIN_DOMAIN_NAME, "other.test"])?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let stream =
            common::establish_tls_connection("other.test", &endpoint_address, None).await?;
        let url = format!(
            "https://other.test:{}/subscription",
            endpoint_address.port()
        );
        let (parts, body) = http_get::do_get_request(
            stream,
            http::Version::HTTP_11,
            &url,
            &[("authorization", ALICE_BASIC)],
        )
        .await?;
        common::check(
            parts.status == http::StatusCode::NOT_FOUND,
            "assertion failed: parts.status == http::StatusCode::NOT_FOUND",
        )?;
        common::check(
            !body.windows(6).any(|w| w == b"secret"),
            "assertion failed: !body.windows(6).any(|w| w == b\"secret\")",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = common::run_endpoint_with_settings(settings, &hosts) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn reload_updates_served_address_and_keeps_old_on_error() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let cert_file = common::make_cert_key_file()?;
    let cert_path = cert_file
        .path()
        .to_str()
        .ok_or("certificate path is not UTF-8")?;
    let settings = make_settings(&endpoint_address, "203.0.113.1:443", true, alice_bob())?;
    let hosts = make_hosts(cert_path)?;
    let hosts_for_reload = make_hosts(cert_path)?;

    let shutdown = Shutdown::new();
    let authenticator: Option<Arc<dyn Authenticator>> = Some(Arc::new(
        RegistryBasedAuthenticator::new(settings.get_clients()),
    ));
    let core = Arc::new(Core::new(settings, authenticator, &hosts, shutdown)?);

    let core_for_listen = Arc::clone(&core);
    let mut listeners = tokio::task::JoinSet::new();
    listeners.spawn(async move { core_for_listen.listen().await });
    let test_result = async {

    tokio::time::sleep(Duration::from_secs(1)).await;
    common::check(fetch_address(&endpoint_address, ALICE_BASIC).await? == "203.0.113.1:443", "assertion failed: fetch_address(&endpoint_address, ALICE_BASIC).await? == \"203.0.113.1:443\"")?;

    let updated = SubscriptionSettings {
        enabled: true,
        hostname: Some(common::MAIN_DOMAIN_NAME.to_string()),
        path: SubscriptionSettings::default_path(),
        address: Some("198.51.100.7:443".to_string()),
        name: None,
        dns_upstreams: vec![],
        custom_sni: None,
        client_random_prefix: None,
    };
    core.reload_subscription_settings(Some(updated), &hosts_for_reload)
        ?;
    common::check(fetch_address(&endpoint_address, ALICE_BASIC).await? == "198.51.100.7:443", "assertion failed: fetch_address(&endpoint_address, ALICE_BASIC).await? == \"198.51.100.7:443\"")?;

    let bad = SubscriptionSettings {
        enabled: true,
        hostname: Some("nope.invalid".to_string()),
        path: SubscriptionSettings::default_path(),
        address: Some("0.0.0.0:0".to_string()),
        name: None,
        dns_upstreams: vec![],
        custom_sni: None,
        client_random_prefix: None,
    };
    common::check(core
        .reload_subscription_settings(Some(bad), &hosts_for_reload)
        .is_err(), "assertion failed: core\n        .reload_subscription_settings(Some(bad), &hosts_for_reload)\n        .is_err()")?;
    common::check(fetch_address(&endpoint_address, ALICE_BASIC).await? == "198.51.100.7:443", "assertion failed: fetch_address(&endpoint_address, ALICE_BASIC).await? == \"198.51.100.7:443\"")?;

        Ok::<(), common::TestError>(())
    }.await;
    listeners.abort_all();
    while let Some(result) = listeners.join_next().await {
        match result {
            Err(error) if error.is_cancelled() => (),
            result => {
                result??;
            }
        }
    }
    cert_file.close()?;
    test_result
}
