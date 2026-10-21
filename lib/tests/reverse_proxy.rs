//! Reverse-proxy SNI/path routing and complete streamed response checks.

use bytes::Bytes;
use futures::stream;
use http::{Request, Response};
use log::info;
use ring::digest::{digest, SHA256};
use std::future::{ready, Future, Ready};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::net::TcpListener;
use trusttunnel::net_utils;
use trusttunnel::settings::{
    Http1Settings, Http2Settings, ListenProtocolSettings, QuicSettings, ReverseProxySettings,
    Settings, TlsHostInfo, TlsHostsSettings,
};

mod common;
use common::TestResult;
#[path = "common/http_get.rs"]
mod http_get;
#[path = "common/quic.rs"]
pub mod quic;

// Use a larger body to catch partial responses without flooding logs.
static RESPONSE_BODY: LazyLock<Bytes> = LazyLock::new(|| Bytes::from(vec![b'x'; 1024 * 1024]));

macro_rules! reverse_proxy_tests {
    ($($name:ident: $client_fn:expr,)*) => {
    $(
        #[tokio::test]
        async fn $name() -> TestResult {
            common::set_up_logger()?;
            let endpoint_address = common::make_endpoint_address();
            let (proxy_address, proxy_task) = run_proxy()?;

            let client_task = async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let (response, body) = $client_fn(&endpoint_address).await?;
                common::check(response.status == http::StatusCode::OK, "assertion failed: response.status == http::StatusCode::OK")?;
                assert_body_matches(&body)
            };
            let endpoint_task = run_endpoint(&endpoint_address, &proxy_address, true);

            // Pin tasks so they can be polled across multiple select! invocations
            // without being dropped (dropping run_endpoint mid-transfer would tear
            // down the QuicMultiplexer and abort in-flight H3 streams).
            tokio::pin!(client_task);
            tokio::pin!(proxy_task);
            tokio::pin!(endpoint_task);

            tokio::select! {
                result = &mut endpoint_task => { result?; Err("task completed unexpectedly".into()) },
                () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
                // Wait for client_task first; if proxy_task completes, continue waiting for client
                result = &mut client_task => result,
                result = &mut proxy_task => {
                    result?;
                    // Proxy completed (expected after handling request); keep endpoint
                    // alive while we wait for the client to finish draining the response.
                    tokio::select! {
                        result = client_task => result,
                        result = &mut endpoint_task => { result?; Err("task completed unexpectedly".into()) },
                        () = tokio::time::sleep(Duration::from_secs(5)) => Err(std::io::Error::other("Client timed out after proxy completed").into()),
                    }
                },
            }
        }
    )*
    }
}

reverse_proxy_tests! {
    sni_h1: sni_h1_client,
    sni_h3: sni_h3_client,
    path_h1: path_h1_client,
    path_h2: path_h2_client,
    path_h3: path_h3_client,
}

#[tokio::test]
async fn path_h2_chunked() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let (proxy_address, proxy_task) = run_proxy_chunked()?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (response, body) = path_h2_client(&endpoint_address).await?;
        common::check(
            response.status == http::StatusCode::OK,
            "assertion failed: response.status == http::StatusCode::OK",
        )?;
        assert_body_matches(&body)
    };
    let endpoint_task = run_endpoint(&endpoint_address, &proxy_address, true);

    tokio::pin!(client_task);
    tokio::pin!(proxy_task);
    tokio::pin!(endpoint_task);

    tokio::select! {
        result = &mut endpoint_task => { result?; Err("task completed unexpectedly".into()) },
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
        result = &mut client_task => result,
        result = &mut proxy_task => {
                    result?;
            tokio::select! {
                result = client_task => result,
                result = &mut endpoint_task => { result?; Err("task completed unexpectedly".into()) },
                () = tokio::time::sleep(Duration::from_secs(5)) => {
                    Err(std::io::Error::other("Client timed out after proxy completed").into())
                }
            }
        },
    }
}

#[tokio::test]
async fn path_h3_chunked() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let (proxy_address, proxy_task) = run_proxy_chunked()?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (response, body) = path_h3_client(&endpoint_address).await?;
        common::check(
            response.status == http::StatusCode::OK,
            "assertion failed: response.status == http::StatusCode::OK",
        )?;
        assert_body_matches(&body)
    };
    let endpoint_task = run_endpoint(&endpoint_address, &proxy_address, true);

    tokio::pin!(client_task);
    tokio::pin!(proxy_task);
    tokio::pin!(endpoint_task);

    tokio::select! {
        result = &mut endpoint_task => { result?; Err("task completed unexpectedly".into()) },
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
        result = &mut client_task => result,
        result = &mut proxy_task => {
                    result?;
            tokio::select! {
                result = client_task => result,
                result = &mut endpoint_task => { result?; Err("task completed unexpectedly".into()) },
                () = tokio::time::sleep(Duration::from_secs(5)) => {
                    Err(std::io::Error::other("Client timed out after proxy completed").into())
                }
            }
        },
    }
}

// The reverse proxy server address comes from the endpoint configuration, so it must be
// reachable even if it belongs to a private network and client connections to private
// networks are forbidden.
#[tokio::test]
async fn path_h1_private_network_disallowed() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();
    let (proxy_address, proxy_task) = run_proxy()?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (response, body) = path_h1_client(&endpoint_address).await?;
        common::check(
            response.status == http::StatusCode::OK,
            "assertion failed: response.status == http::StatusCode::OK",
        )?;
        assert_body_matches(&body)
    };
    let endpoint_task = run_endpoint(&endpoint_address, &proxy_address, false);

    tokio::pin!(client_task);
    tokio::pin!(proxy_task);
    tokio::pin!(endpoint_task);

    tokio::select! {
        result = &mut endpoint_task => { result?; Err("task completed unexpectedly".into()) },
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
        result = &mut client_task => result,
        result = &mut proxy_task => {
                    result?;
            tokio::select! {
                result = client_task => result,
                result = &mut endpoint_task => { result?; Err("task completed unexpectedly".into()) },
                () = tokio::time::sleep(Duration::from_secs(5)) => {
                    Err(std::io::Error::other("Client timed out after proxy completed").into())
                }
            }
        },
    }
}

fn assert_body_matches(body: &Bytes) -> TestResult {
    common::check(
        body.len() == RESPONSE_BODY.len(),
        format_args!("response length mismatch"),
    )?;
    let expected_hash = digest(&SHA256, RESPONSE_BODY.as_ref());
    let actual_hash = digest(&SHA256, body.as_ref());
    common::check(
        actual_hash.as_ref() == expected_hash.as_ref(),
        "response hash mismatch",
    )
}

async fn sni_h1_client(
    endpoint_address: &SocketAddr,
) -> TestResult<(http::response::Parts, Bytes)> {
    let stream = common::establish_tls_connection(
        &format!("hello.{}", common::MAIN_DOMAIN_NAME),
        endpoint_address,
        None,
    )
    .await?;

    http_get::do_get_request(
        stream,
        http::Version::HTTP_11,
        &format!(
            "https://hello.{}:{}",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ),
        &[],
    )
    .await
}

async fn sni_h3_client(
    endpoint_address: &SocketAddr,
) -> TestResult<(http::response::Parts, Bytes)> {
    let mut conn = quic::Http3Session::connect(
        endpoint_address,
        &format!("hello.{}", common::MAIN_DOMAIN_NAME),
        None,
    )
    .await?;

    conn.exchange(
        Request::get(format!(
            "https://hello.{}:{}",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ))
        .body(hyper::Body::empty())?,
    )
    .await
}

async fn path_h1_client(
    endpoint_address: &SocketAddr,
) -> TestResult<(http::response::Parts, Bytes)> {
    let stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, endpoint_address, None).await?;

    http_get::do_get_request(
        stream,
        http::Version::HTTP_11,
        &format!(
            "https://{}:{}/hello/haha",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ),
        &[(http::header::UPGRADE.as_str(), "1")],
    )
    .await
}

async fn path_h2_client(
    endpoint_address: &SocketAddr,
) -> TestResult<(http::response::Parts, Bytes)> {
    let stream = common::establish_tls_connection(
        common::MAIN_DOMAIN_NAME,
        endpoint_address,
        Some(net_utils::HTTP2_ALPN.as_bytes()),
    )
    .await?;

    http_get::do_get_request(
        stream,
        http::Version::HTTP_2,
        &format!(
            "https://{}:{}/hello/haha",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ),
        &[],
    )
    .await
}

async fn path_h3_client(
    endpoint_address: &SocketAddr,
) -> TestResult<(http::response::Parts, Bytes)> {
    let mut conn =
        quic::Http3Session::connect(endpoint_address, common::MAIN_DOMAIN_NAME, None).await?;

    conn.exchange(
        Request::get(format!(
            "https://{}:{}/hello/haha",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ))
        .body(hyper::Body::empty())?,
    )
    .await
}

async fn run_endpoint(
    endpoint_address: &SocketAddr,
    proxy_address: &SocketAddr,
    allow_private_network_connections: bool,
) -> TestResult {
    let settings = Settings::builder()
        .listen_address(endpoint_address)?
        .listen_protocols(ListenProtocolSettings {
            http1: Some(Http1Settings::builder().build()),
            http2: Some(Http2Settings::builder().build()),
            quic: Some(QuicSettings::builder().build()),
        })
        .reverse_proxy(
            ReverseProxySettings::builder()
                .server_address(proxy_address)?
                .path_mask("/hello".to_string())
                .build()?,
        )
        .allow_private_network_connections(allow_private_network_connections)
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
        .reverse_proxy_hosts(vec![TlsHostInfo {
            hostname: format!("hello.{}", common::MAIN_DOMAIN_NAME),
            cert_chain_path: cert_key_path.to_string(),
            private_key_path: cert_key_path.to_string(),
            allowed_sni: vec![],
        }])
        .build()?;

    common::run_endpoint_with_settings(settings, &hosts_settings).await
}

fn run_proxy() -> TestResult<(SocketAddr, impl Future<Output = TestResult>)> {
    let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_nonblocking(true)?;
    let server_addr = server.local_addr()?;
    Ok((server_addr, async move {
        let (socket, peer) = TcpListener::from_std(server)?.accept().await?;
        info!("New connection from {peer}");
        hyper::server::conn::Http::new()
            .http1_only(true)
            .serve_connection(
                socket,
                hyper::service::service_fn(|request| request_handler(&request)),
            )
            .await?;
        Ok(())
    }))
}

fn run_proxy_chunked() -> TestResult<(SocketAddr, impl Future<Output = TestResult>)> {
    let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_nonblocking(true)?;
    let server_addr = server.local_addr()?;
    Ok((server_addr, async move {
        let (socket, peer) = TcpListener::from_std(server)?.accept().await?;
        info!("New connection from {peer}");
        hyper::server::conn::Http::new()
            .http1_only(true)
            .serve_connection(
                socket,
                hyper::service::service_fn(|request| request_handler_chunked(&request)),
            )
            .await?;
        Ok(())
    }))
}

fn request_handler(
    request: &Request<hyper::Body>,
) -> Ready<Result<Response<hyper::Body>, std::convert::Infallible>> {
    info!("Received request: {request:?}");
    ready(Ok(Response::new(hyper::Body::from(RESPONSE_BODY.clone()))))
}

fn request_handler_chunked(
    request: &Request<hyper::Body>,
) -> Ready<Result<Response<hyper::Body>, std::convert::Infallible>> {
    info!("Received request: {request:?}");
    let chunk_size = 16 * 1024;
    let chunks = RESPONSE_BODY
        .chunks(chunk_size)
        .map(|c| Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(c)))
        .collect::<Vec<_>>();

    ready(Ok(Response::new(hyper::Body::wrap_stream(stream::iter(
        chunks,
    )))))
}
