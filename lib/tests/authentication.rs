//! Authentication, SOCKS negotiation, and connection-slot lifecycle checks.

use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use futures::future;
use http::Request;
use log::info;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use trusttunnel::authentication;
use trusttunnel::settings::{
    ForwardProtocolSettings, Http1Settings, ListenProtocolSettings, Settings,
    Socks5ForwarderSettings, TlsHostInfo, TlsHostsSettings,
};

mod common;
use common::TestResult;

#[tokio::test]
async fn registry_proxy_auth_success() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let status = do_connect_request(&endpoint_address, Some("a:b".into())).await?;
        common::check(
            status != http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "assertion failed: status != http::StatusCode::PROXY_AUTHENTICATION_REQUIRED",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = run_endpoint(&endpoint_address, true, None) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn registry_proxy_auth_failure() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let status = do_connect_request(&endpoint_address, None).await?;
        common::check(
            status == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "assertion failed: status == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED",
        )?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = run_endpoint(&endpoint_address, true, None) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn no_authenticator_socks_standard_auth() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let (socks_addr, socks_task) = make_socks_server_harness()?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = do_connect_request(&endpoint_address, Some("a:b".into())).await?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = run_endpoint(&endpoint_address, true, Some(socks_addr)) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => { result?; Err("task completed unexpectedly".into()) },
        result = socks_task => { let methods = result?; common::check(methods.contains(&0x02), format_args!("{methods:?}")) },
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn no_authenticator_no_socks_auth() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let (socks_addr, socks_task) = make_socks_server_harness()?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = do_connect_request(&endpoint_address, None).await?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = run_endpoint(&endpoint_address, false, Some(socks_addr)) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => { result?; Err("task completed unexpectedly".into()) },
        result = socks_task => { let methods = result?; common::check(methods.iter().all(|method| *method == 0x00), format_args!("Must not contain non-NoAuth methods: {methods:?}")) },
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn authenticator_present_socks_standard_auth() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let (socks_addr, socks_task) = make_socks_server_harness()?;

    let client_task = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = do_connect_request(&endpoint_address, Some("a:b".into())).await?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = run_endpoint(&endpoint_address, true, Some(socks_addr)) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => { result?; Err("task completed unexpectedly".into()) },
        result = socks_task => { let methods = result?; common::check(methods.contains(&0x02), format_args!("{methods:?}")) },
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

async fn run_endpoint(
    listen_address: &SocketAddr,
    with_auth: bool,
    socks_proxy: Option<SocketAddr>,
) -> TestResult {
    let mut builder = Settings::builder()
        .listen_address(listen_address)?
        .listen_protocols(ListenProtocolSettings {
            http1: Some(Http1Settings::builder().build()),
            ..Default::default()
        })
        .allow_private_network_connections(true);

    if with_auth {
        builder = builder.clients(Vec::from_iter(std::iter::once(
            authentication::registry_based::Client {
                username: "a".into(),
                password: "b".into(),
                max_http2_conns: None,
                max_http3_conns: None,
            },
        )));
    }

    if let Some(address) = socks_proxy {
        builder = builder.forwarder_settings(ForwardProtocolSettings::Socks5(
            Socks5ForwarderSettings::builder()
                .server_address(address)?
                .build()?,
        ));
    }

    let settings = builder.build()?;

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
        .build()?;

    common::run_endpoint_with_settings(settings, &hosts_settings).await
}

async fn do_connect_request(
    endpoint_address: &SocketAddr,
    proxy_auth: Option<String>,
) -> TestResult<http::StatusCode> {
    let stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, endpoint_address, None).await?;

    let (mut request, conn_driver) = hyper::client::conn::Builder::new()
        .handshake(stream)
        .await?;

    let destination = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let destination_address = destination.local_addr()?;
    let exchange = async move {
        let mut rr = Request::builder()
            .version(http::Version::HTTP_11)
            .method(http::Method::CONNECT)
            .uri(destination_address.to_string());

        if let Some(x) = proxy_auth {
            rr = rr.header(
                http::header::PROXY_AUTHORIZATION,
                format!("Basic {}", BASE64_ENGINE.encode(x)),
            );
        }

        let rr = rr.body(hyper::Body::empty())?;
        let response = request.send_request(rr).await?;
        info!("CONNECT response: {response:?}");
        Ok::<_, common::TestError>(response.status())
    };

    futures::pin_mut!(conn_driver);
    futures::pin_mut!(exchange);
    match future::select(conn_driver, exchange).await {
        future::Either::Left((result, exchange)) => {
            result?;
            exchange.await
        }
        future::Either::Right((x, _)) => x,
    }
}

/// Sends a raw HTTP CONNECT and returns the status, or `None` when the server closes the
/// connection before sending a complete response (also treated as a rejection).
async fn try_connect_raw(
    endpoint_address: &SocketAddr,
    proxy_auth: &str,
    dest: &str,
) -> TestResult<Option<http::StatusCode>> {
    let mut stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, endpoint_address, None).await?;

    let request = format!(
        "CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        BASE64_ENGINE.encode(proxy_auth),
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read_exact(&mut byte).await {
            Ok(_) => {
                response.push(byte[0]);
                if response.ends_with(b"\r\n\r\n") {
                    let line = std::str::from_utf8(&response)?;
                    let code: u16 = line
                        .split_whitespace()
                        .nth(1)
                        .ok_or("missing HTTP status")?
                        .parse()?;
                    return Ok(Some(http::StatusCode::from_u16(code)?));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    }
}

/// Sends a raw HTTP CONNECT over a TLS stream, signals `ready_tx` with the status code as
/// soon as the response headers arrive, then holds the TLS stream open until `release` fires.
/// Using raw I/O avoids hyper closing the connection after the CONNECT 200 exchange, which
/// would cause the server-side tunnel to drop the connection guard prematurely.
async fn connect_and_hold(
    endpoint_address: &SocketAddr,
    proxy_auth: &str,
    dest: &str,
    ready_tx: oneshot::Sender<http::StatusCode>,
    release: oneshot::Receiver<()>,
) -> TestResult {
    let mut stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, endpoint_address, None).await?;

    let request = format!(
        "CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        BASE64_ENGINE.encode(proxy_auth),
    );
    stream.write_all(request.as_bytes()).await?;

    // Read until the end of the response headers (\r\n\r\n).
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let status_str = std::str::from_utf8(&response)?;
    let code: u16 = status_str
        .split_whitespace()
        .nth(1)
        .ok_or("missing HTTP status")?
        .parse()?;
    ready_tx
        .send(http::StatusCode::from_u16(code)?)
        .map_err(|_| "ready receiver dropped")?;

    // Hold the raw TLS stream open so the server's tunnel stays alive with the guard held.
    release.await?;
    drop(stream);
    Ok(())
}

#[tokio::test]
async fn connection_limit_blocks_excess_and_releases_on_disconnect() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    // A local TCP listener acts as a stable tunnel destination so the server's pipe
    // keeps running and the connection slot stays held.
    let dest_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0u16)).await?;
    let dest_addr = format!("127.0.0.1:{}", dest_listener.local_addr()?.port());

    let (release_tx, release_rx) = oneshot::channel::<()>();
    let (ready_tx, ready_rx) = oneshot::channel::<http::StatusCode>();

    let conn1_task = {
        let addr = endpoint_address;
        let dest = dest_addr.clone();
        async move { connect_and_hold(&addr, "a:b", &dest, ready_tx, release_rx).await }
    };

    let test_task = async move {
        // Give the endpoint time to start.
        tokio::time::sleep(Duration::from_millis(1200)).await;

        // conn1: open and hold (slot = 1/1)
        let mut held_connections = tokio::task::JoinSet::new();
        held_connections.spawn(conn1_task);

        // Wait until conn1's CONNECT has been processed and slot is held.
        let status1 = ready_rx.await?;
        common::check(
            status1 != http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            format_args!("conn1 must succeed"),
        )?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // conn2: should be denied — limit already reached.
        // The server may send 407 or drop the connection without a response (if the
        // response buffer isn't flushed before the tunnel drops), so both count as rejection.
        let result2 = try_connect_raw(&endpoint_address, "a:b", "127.0.0.1:1").await?;
        common::check(
            result2.is_none() || result2 == Some(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED),
            format_args!("conn2 must be rejected while limit is held, got: {result2:?}"),
        )?;

        // Release conn1 and give the server time to free the slot.
        release_tx
            .send(())
            .map_err(|()| "held connection stopped before release")?;
        held_connections
            .join_next()
            .await
            .ok_or("held connection task missing")???;
        tokio::time::sleep(Duration::from_millis(300)).await;

        // conn3: slot released — must succeed now.
        let status3 = do_connect_request(&endpoint_address, Some("a:b".into())).await?;
        common::check(
            status3 != http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            format_args!("conn3 must succeed after slot is released"),
        )?;

        drop(dest_listener);
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = run_endpoint_with_conn_limit(&endpoint_address, 1) => { result?; Err("task completed unexpectedly".into()) },
        result = test_task => result,
        () = tokio::time::sleep(Duration::from_secs(15)) => Err(std::io::Error::other("Timed out").into()),
    }
}

async fn run_endpoint_with_conn_limit(
    listen_address: &SocketAddr,
    max_http2_conns: u32,
) -> TestResult {
    let settings = Settings::builder()
        .listen_address(listen_address)?
        .listen_protocols(ListenProtocolSettings {
            http1: Some(Http1Settings::builder().build()),
            ..Default::default()
        })
        .allow_private_network_connections(true)
        .clients(vec![authentication::registry_based::Client {
            username: "a".into(),
            password: "b".into(),
            max_http2_conns: Some(max_http2_conns),
            max_http3_conns: None,
        }])
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
        .build()?;

    common::run_endpoint_with_settings(settings, &hosts_settings).await
}

fn make_socks_server_harness() -> TestResult<(SocketAddr, impl Future<Output = TestResult<Vec<u8>>>)>
{
    let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    server.set_nonblocking(true)?;
    let server_addr = server.local_addr()?;

    let task = async move {
        let server = TcpListener::from_std(server)?;
        let (mut socket, peer) = server.accept().await?;
        info!("New connection from {peer}");

        let mut buf = vec![0; 1024];
        let n = socket.read(&mut buf).await?;
        common::check(n > 0, format_args!("n = {n}"))?;
        common::check(buf[0] == 0x05, format_args!("Unexpected version number"))?;
        common::check(
            usize::from(buf[1]) == n.checked_sub(2).ok_or("truncated SOCKS greeting")?,
            format_args!("Unexpected number of methods"),
        )?;
        Ok(Vec::from(&buf[2..n]))
    };

    Ok((server_addr, task))
}
