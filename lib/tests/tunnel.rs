//! TCP and UDP tunnel transfer matrices with joined local server fixtures.

use bytes::BufMut;
use futures::{future, FutureExt, StreamExt};
use http::Request;
use log::info;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use trusttunnel::net_utils;

mod common;
use common::TestResult;
#[path = "common/chunks.rs"]
mod chunks;
#[path = "common/endpoint.rs"]
mod endpoint;
#[path = "common/quic.rs"]
pub mod quic;

type TunnelDriver = Pin<Box<dyn Future<Output = TestResult> + Send>>;
type TunnelIo = Pin<Box<dyn Future<Output = TestResult<hyper::upgrade::Upgraded>> + Send>>;

const TCP_CONTENT_SIZE: usize = 2 * 1024 * 1024;
const UDP_CHUNK_SIZE: usize = 1024;
const UDP_CONTENT_SIZE: usize = 8 * UDP_CHUNK_SIZE;
const MANGLED_UDP_HEADER_LENGTH: usize = 4 + 2 * (16 + 2);
const EXPECTED_MANGLED_UDP_LENGTH: usize =
    UDP_CONTENT_SIZE + (UDP_CONTENT_SIZE / UDP_CHUNK_SIZE) * MANGLED_UDP_HEADER_LENGTH;

macro_rules! tcp_download_tests {
    ($($name:ident: $make_tunnel_fn:expr,)*) => {
    $(
        #[tokio::test]
        async fn $name() -> TestResult {
            common::set_up_logger()?;
            let endpoint_address = common::make_endpoint_address();

            let client_task = async {
                let (server_address, server_task) = run_tcp_server(true).await?;
                let transfer = async {
                tokio::time::sleep(Duration::from_secs(1)).await;

                let (conn_driver, io) = $make_tunnel_fn(endpoint_address, server_address.to_string()).await?;

                let exchange = async {
                    let mut io = io.await?;
                    let mut total = 0;
                    let mut buf = vec![0; 64 * 1024];
                    while total < TCP_CONTENT_SIZE {
                        match io.read(&mut buf).await? {
                            0 => break,
                            n => total += n,
                        }
                    }
                    common::check(total == TCP_CONTENT_SIZE, "assertion failed: total == TCP_CONTENT_SIZE")
                };

                futures::pin_mut!(exchange);
                match future::select(conn_driver, exchange).await {
                    future::Either::Left((r, exchange)) => {
                        info!("HTTP connection closed with result: {r:?}");
                        r?;
                        exchange.await
                    }
                    future::Either::Right((result, _)) => result,
                }
                };
                tokio::try_join!(server_task, transfer)?;
                Ok::<(), common::TestError>(())
            };

            tokio::select! {
                result = endpoint::run_endpoint(&endpoint_address) => { result?; Err("task completed unexpectedly".into()) },
                result = client_task => result,
                () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
            }
        }
    )*
    }
}

macro_rules! tcp_upload_tests {
    ($($name:ident: $make_tunnel_fn:expr,)*) => {
    $(
        #[tokio::test]
        async fn $name() -> TestResult {
            common::set_up_logger()?;
            let endpoint_address = common::make_endpoint_address();

            let client_task = async {
                let (server_address, server_task) = run_tcp_server(false).await?;
                let transfer = async {
                tokio::time::sleep(Duration::from_secs(1)).await;

                let (conn_driver, io) = $make_tunnel_fn(endpoint_address, server_address.to_string()).await?;

                let exchange = async {
                    let mut io = io.await?;
                    let mut content = chunks::make_stream_of_chunks(TCP_CONTENT_SIZE, None)?;
                    while let Some(chunk) = content.next().await {
                        io.write_all(chunk).await?;
                    }
                    io.flush().await?;

                    let mut ack = [0; 1];
                    common::check(io.read(&mut ack).await? == 1, "assertion failed: acknowledgment length")
                };

                futures::pin_mut!(exchange);
                match future::select(conn_driver, exchange).await {
                    future::Either::Left((r, exchange)) => {
                        info!("HTTP connection closed with result: {r:?}");
                        r?;
                        exchange.await
                    }
                    future::Either::Right((result, _)) => result,
                }
                };
                tokio::try_join!(server_task, transfer)?;
                Ok::<(), common::TestError>(())
            };

            tokio::select! {
                result = endpoint::run_endpoint(&endpoint_address) => { result?; Err("task completed unexpectedly".into()) },
                result = client_task => result,
                () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
            }
        }
    )*
    }
}

tcp_download_tests! {
    h1_tcp_download: make_h1_tunnel,
    h2_tcp_download: make_h2_tunnel,
}

tcp_upload_tests! {
    h1_tcp_upload: make_h1_tunnel,
    h2_tcp_upload: make_h2_tunnel,
}

#[tokio::test]
async fn h2_udp_download() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let (server_address, server_task) = run_udp_server(true).await?;
        let transfer = async {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let (conn_driver, io) = make_h2_tunnel(endpoint_address, "_udp2".to_string()).await?;

            let exchange = async {
                let mut io = io.await?;
                let hole_puncher = encode_udp_chunk(server_address, &[1]);
                io.write_all(&hole_puncher).await?;

                let mut total = 0;
                let mut buf = vec![0; 64 * 1024];
                while total < EXPECTED_MANGLED_UDP_LENGTH {
                    match io.read(&mut buf).await? {
                        0 => break,
                        n => total += n,
                    }
                }
                common::check(
                    total == EXPECTED_MANGLED_UDP_LENGTH,
                    "assertion failed: total == EXPECTED_MANGLED_UDP_LENGTH",
                )
            };

            futures::pin_mut!(exchange);
            match future::select(conn_driver, exchange).await {
                future::Either::Left((r, exchange)) => {
                    info!("HTTP connection closed with result: {r:?}");
                    r?;
                    exchange.await
                }
                future::Either::Right((result, _)) => result,
            }
        };
        tokio::try_join!(server_task, transfer)?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = endpoint::run_endpoint(&endpoint_address) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn h2_udp_upload() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let (server_address, server_task) = run_udp_server(false).await?;
        let transfer = async {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let (conn_driver, io) = make_h2_tunnel(endpoint_address, "_udp2".to_string()).await?;

            let exchange = async {
                let mut io = io.await?;

                let mut content =
                    chunks::make_stream_of_chunks(UDP_CONTENT_SIZE, Some(UDP_CHUNK_SIZE))?
                        .map(|x| encode_udp_chunk(server_address, x));
                while let Some(chunk) = content.next().await {
                    io.write_all(&chunk).await?;
                }

                let mut ack = [0; UDP_CHUNK_SIZE];
                common::check(
                    io.read(&mut ack).await? == MANGLED_UDP_HEADER_LENGTH + 1,
                    "assertion failed: io.read(&mut ack).await? == MANGLED_UDP_HEADER_LENGTH + 1",
                )
            };

            futures::pin_mut!(exchange);
            match future::select(conn_driver, exchange).await {
                future::Either::Left((r, exchange)) => {
                    info!("HTTP connection closed with result: {r:?}");
                    r?;
                    exchange.await
                }
                future::Either::Right((result, _)) => result,
            }
        };
        tokio::try_join!(server_task, transfer)?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = endpoint::run_endpoint(&endpoint_address) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn h3_tcp_download() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let (server_address, server_task) = run_tcp_server(true).await?;
        let transfer = async {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let mut conn =
                quic::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None)
                    .await?;

            let (response, _) = conn
                .exchange(Request::connect(server_address.to_string()).body(hyper::Body::empty())?)
                .await?;
            common::check(
                response.status == http::StatusCode::OK,
                "assertion failed: response.status == http::StatusCode::OK",
            )?;

            let mut total = 0;
            let mut buf = vec![0; 64 * 1024];
            while total < TCP_CONTENT_SIZE {
                match conn.recv(&mut buf).await? {
                    0 => break,
                    n => total += n,
                }
            }
            common::check(
                total == TCP_CONTENT_SIZE,
                "assertion failed: total == TCP_CONTENT_SIZE",
            )?;
            Ok::<(), common::TestError>(())
        };
        tokio::try_join!(server_task, transfer)?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = endpoint::run_endpoint(&endpoint_address) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn h3_tcp_upload() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let (server_address, server_task) = run_tcp_server(false).await?;
        let transfer = async {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let mut conn =
                quic::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None)
                    .await?;

            let (response, _) = conn
                .exchange(Request::connect(server_address.to_string()).body(hyper::Body::empty())?)
                .await?;
            common::check(
                response.status == http::StatusCode::OK,
                "assertion failed: response.status == http::StatusCode::OK",
            )?;

            conn.send(chunks::make_stream_of_chunks(TCP_CONTENT_SIZE, None)?)
                .await?;
            let mut ack = [0; 1];
            common::check(
                conn.recv(&mut ack).await? == 1,
                "assertion failed: conn.recv(&mut ack).await? == 1",
            )?;
            Ok::<(), common::TestError>(())
        };
        tokio::try_join!(server_task, transfer)?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = endpoint::run_endpoint(&endpoint_address) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn h3_udp_download() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let (server_address, server_task) = run_udp_server(true).await?;
        let transfer = async {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let mut conn =
                quic::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None)
                    .await?;

            let (response, _) = conn
                .exchange(Request::connect("_udp2").body(hyper::Body::empty())?)
                .await?;
            common::check(
                response.status == http::StatusCode::OK,
                "assertion failed: response.status == http::StatusCode::OK",
            )?;

            let hole_puncher = encode_udp_chunk(server_address, &[1]);
            conn.send(futures::stream::iter(std::iter::once(hole_puncher)))
                .await?;

            let mut total = 0;
            let mut buf = vec![0; 64 * 1024];
            while total < EXPECTED_MANGLED_UDP_LENGTH {
                match conn.recv(&mut buf).await? {
                    0 => break,
                    n => total += n,
                }
            }
            common::check(
                total == EXPECTED_MANGLED_UDP_LENGTH,
                "assertion failed: total == EXPECTED_MANGLED_UDP_LENGTH",
            )?;
            Ok::<(), common::TestError>(())
        };
        tokio::try_join!(server_task, transfer)?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = endpoint::run_endpoint(&endpoint_address) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

#[tokio::test]
async fn h3_udp_upload() -> TestResult {
    common::set_up_logger()?;
    let endpoint_address = common::make_endpoint_address();

    let client_task = async {
        let (server_address, server_task) = run_udp_server(false).await?;
        let transfer = async {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let mut conn =
                quic::Http3Session::connect(&endpoint_address, common::MAIN_DOMAIN_NAME, None)
                    .await?;

            let (response, _) = conn
                .exchange(Request::connect("_udp2").body(hyper::Body::empty())?)
                .await?;
            common::check(
                response.status == http::StatusCode::OK,
                "assertion failed: response.status == http::StatusCode::OK",
            )?;

            conn.send(
                chunks::make_stream_of_chunks(UDP_CONTENT_SIZE, Some(UDP_CHUNK_SIZE))?
                    .map(|x| encode_udp_chunk(server_address, x)),
            )
            .await?;

            let mut ack = [0; UDP_CHUNK_SIZE];
            common::check(
                conn.recv(&mut ack).await? == MANGLED_UDP_HEADER_LENGTH + 1,
                "assertion failed: conn.recv(&mut ack).await? == MANGLED_UDP_HEADER_LENGTH + 1",
            )?;
            Ok::<(), common::TestError>(())
        };
        tokio::try_join!(server_task, transfer)?;
        Ok::<(), common::TestError>(())
    };

    tokio::select! {
        result = endpoint::run_endpoint(&endpoint_address) => { result?; Err("task completed unexpectedly".into()) },
        result = client_task => result,
        () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::other("Timed out").into()),
    }
}

async fn make_h1_tunnel(
    endpoint_address: SocketAddr,
    server_address: String,
) -> TestResult<(TunnelDriver, TunnelIo)> {
    let stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, &endpoint_address, None).await?;

    let (mut request, conn) = hyper::client::conn::Builder::new()
        .handshake(stream)
        .await?;

    let conn_driver: TunnelDriver = async move {
        conn.await?;
        Ok(())
    }
    .boxed();

    let exchange = async move {
        let rr = Request::builder()
            .version(http::Version::HTTP_11)
            .method(http::Method::CONNECT)
            .uri(server_address)
            .body(hyper::Body::empty())?;
        let response = request.send_request(rr).await?;
        info!("CONNECT response: {response:?}");
        common::check(
            response.status() == http::StatusCode::OK,
            "assertion failed: response.status() == http::StatusCode::OK",
        )?;

        Ok::<_, common::TestError>(hyper::upgrade::on(response).await?)
    }
    .boxed();

    Ok((conn_driver, exchange))
}

async fn make_h2_tunnel(
    endpoint_address: SocketAddr,
    server_address: String,
) -> TestResult<(TunnelDriver, TunnelIo)> {
    let stream = common::establish_tls_connection(
        common::MAIN_DOMAIN_NAME,
        &endpoint_address,
        Some(net_utils::HTTP2_ALPN.as_bytes()),
    )
    .await?;

    let (mut request, conn) = hyper::client::conn::Builder::new()
        .http2_only(true)
        .handshake(stream)
        .await?;

    let conn_driver: TunnelDriver = async move {
        conn.await?;
        Ok(())
    }
    .boxed();

    let exchange = async move {
        let rr = Request::builder()
            .version(http::Version::HTTP_2)
            .method(http::Method::CONNECT)
            .uri(server_address)
            .body(hyper::Body::empty())?;
        let response = request.send_request(rr).await?;
        info!("CONNECT response: {response:?}");
        common::check(
            response.status() == http::StatusCode::OK,
            "assertion failed: response.status() == http::StatusCode::OK",
        )?;

        Ok::<_, common::TestError>(hyper::upgrade::on(response).await?)
    }
    .boxed();

    Ok((conn_driver, exchange))
}

async fn run_tcp_server(
    is_download: bool,
) -> TestResult<(SocketAddr, impl Future<Output = TestResult>)> {
    let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = server.local_addr()?;
    Ok((address, async move {
        let (mut socket, peer) = server.accept().await?;
        info!("New connection from {peer}");
        if is_download {
            let mut content = chunks::make_stream_of_chunks(TCP_CONTENT_SIZE, None)?;
            while let Some(chunk) = content.next().await {
                socket.write_all(chunk).await?;
            }
        } else {
            let mut total = 0;
            let mut buffer = vec![0; 64 * 1024];
            while total < TCP_CONTENT_SIZE {
                match socket.read(&mut buffer).await? {
                    0 => break,
                    size => total += size,
                }
            }
            common::check(total == TCP_CONTENT_SIZE, "TCP upload size mismatch")?;
            socket.write_all(&[1]).await?;
        }
        socket.flush().await?;
        Ok(())
    }))
}

async fn run_udp_server(
    is_download: bool,
) -> TestResult<(SocketAddrV4, impl Future<Output = TestResult>)> {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, server.local_addr()?.port());
    Ok((address, async move {
        if is_download {
            let mut buffer = [0; UDP_CHUNK_SIZE];
            let (size, peer) = server.recv_from(&mut buffer).await?;
            common::check(size == 1, "UDP hole-punch size mismatch")?;
            let mut content =
                chunks::make_stream_of_chunks(UDP_CONTENT_SIZE, Some(UDP_CHUNK_SIZE))?;
            while let Some(chunk) = content.next().await {
                server.send_to(chunk, peer).await?;
            }
        } else {
            let mut peer = None;
            let mut total = 0;
            let mut buffer = [0; UDP_CHUNK_SIZE];
            while total < UDP_CONTENT_SIZE {
                let (size, source) = server.recv_from(&mut buffer).await?;
                common::check(
                    *peer.get_or_insert(source) == source,
                    "UDP upload peer changed",
                )?;
                total += size;
            }
            common::check(total == UDP_CONTENT_SIZE, "UDP upload size mismatch")?;
            server
                .send_to(&[1], peer.ok_or("UDP upload has no peer")?)
                .await?;
        }
        Ok(())
    }))
}

fn encode_udp_chunk(destination: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    const APP_NAME: &str = "test";
    const SOURCE_IP: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const SOURCE_PORT: u16 = 1234;

    let mut buffer = vec![];
    buffer.put_u32((2 * (16 + 2) + 1 + APP_NAME.len() + payload.len()) as u32);
    buffer.put_slice(&[0; 12]);
    buffer.put_slice(&SOURCE_IP.octets());
    buffer.put_u16(SOURCE_PORT);
    buffer.put_slice(&[0; 12]);
    buffer.put_slice(&destination.ip().octets());
    buffer.put_u16(destination.port());
    buffer.put_u8(APP_NAME.len() as u8);
    buffer.put_slice(APP_NAME.as_bytes());
    buffer.put_slice(payload);

    buffer
}

#[test]
fn chunk_fixture_validates_bounds_and_total() -> TestResult {
    for (total_size, chunk_size) in [(1024, 0), (16_385, 16_385), (1023, 1024), (1025, 1024)] {
        common::check(
            chunks::make_stream_of_chunks(total_size, Some(chunk_size)).is_err(),
            format_args!("invalid payload accepted: total={total_size}, chunk={chunk_size}"),
        )?;
    }
    Ok(())
}

#[test]
fn certificate_fixture_matches_key_and_cleans_up() -> TestResult {
    let file = common::make_cert_key_file()?;
    let path = file.path().to_owned();
    let pem = std::fs::read(&path)?;
    let certificate = boring::x509::X509::from_pem(&pem)?;
    let key = boring::pkey::PKey::private_key_from_pem(&pem)?;
    common::check(
        certificate.public_key()?.public_eq(&key),
        "fixture certificate and key differ",
    )?;
    file.close()?;
    common::check(!path.exists(), "fixture certificate file was not removed")
}
