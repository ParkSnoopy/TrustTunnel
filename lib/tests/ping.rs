//! Ping routing over SNI and path across HTTP transports.

use http::Request;
use std::net::SocketAddr;
use std::time::Duration;
use trusttunnel::net_utils;

mod common;
use common::TestResult;
#[path = "common/endpoint.rs"]
mod endpoint;
#[path = "common/http_get.rs"]
mod http_get;
#[path = "common/quic.rs"]
pub mod quic;

macro_rules! ping_tests {
    ($($name:ident: $client_fn:expr,)*) => {
    $(
        #[tokio::test]
        async fn $name() -> TestResult {
            common::set_up_logger()?;
            let endpoint_address = common::make_endpoint_address();

            let client_task = async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let status = $client_fn(&endpoint_address).await?;
                common::check(status == http::StatusCode::OK, "assertion failed: status == http::StatusCode::OK")?;
                Ok::<(), common::TestError>(())
            };

            tokio::select! {
                result = endpoint::run_endpoint(&endpoint_address) => result,
                result = client_task => result,
                () = tokio::time::sleep(Duration::from_secs(10)) => Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into()),
            }
        }
    )*
    }
}

ping_tests! {
    sni_h1: sni_h1_client,
    sni_h2: sni_h2_client,
    sni_h3: sni_h3_client,
    path_h1: path_h1_client,
    path_h2: path_h2_client,
    path_h3: path_h3_client,
}

async fn sni_h1_client(endpoint_address: &SocketAddr) -> TestResult<http::StatusCode> {
    let stream = common::establish_tls_connection(
        &format!("ping.{}", common::MAIN_DOMAIN_NAME),
        endpoint_address,
        None,
    )
    .await?;

    Ok(http_get::do_get_request(
        stream,
        http::Version::HTTP_11,
        &format!(
            "https://ping.{}:{}",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ),
        &[],
    )
    .await?
    .0
    .status)
}

async fn sni_h2_client(endpoint_address: &SocketAddr) -> TestResult<http::StatusCode> {
    let stream = common::establish_tls_connection(
        &format!("ping.{}", common::MAIN_DOMAIN_NAME),
        endpoint_address,
        Some(net_utils::HTTP2_ALPN.as_bytes()),
    )
    .await?;

    Ok(http_get::do_get_request(
        stream,
        http::Version::HTTP_2,
        &format!(
            "https://ping.{}:{}",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ),
        &[],
    )
    .await?
    .0
    .status)
}

async fn sni_h3_client(endpoint_address: &SocketAddr) -> TestResult<http::StatusCode> {
    let mut conn = quic::Http3Session::connect(
        endpoint_address,
        &format!("ping.{}", common::MAIN_DOMAIN_NAME),
        None,
    )
    .await?;

    conn.send_request(
        Request::get(format!(
            "https://ping.{}:{}",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ))
        .body(hyper::Body::empty())?,
    )
    .await?;

    Ok(conn.recv_response().await?.status)
}

async fn path_h1_client(endpoint_address: &SocketAddr) -> TestResult<http::StatusCode> {
    let stream =
        common::establish_tls_connection(common::MAIN_DOMAIN_NAME, endpoint_address, None).await?;

    Ok(http_get::do_get_request(
        stream,
        http::Version::HTTP_11,
        &format!(
            "https://{}:{}/ping",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ),
        &[],
    )
    .await?
    .0
    .status)
}

async fn path_h2_client(endpoint_address: &SocketAddr) -> TestResult<http::StatusCode> {
    let stream = common::establish_tls_connection(
        common::MAIN_DOMAIN_NAME,
        endpoint_address,
        Some(net_utils::HTTP2_ALPN.as_bytes()),
    )
    .await?;

    Ok(http_get::do_get_request(
        stream,
        http::Version::HTTP_2,
        &format!(
            "https://{}:{}/ping",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ),
        &[],
    )
    .await?
    .0
    .status)
}

async fn path_h3_client(endpoint_address: &SocketAddr) -> TestResult<http::StatusCode> {
    let mut conn =
        quic::Http3Session::connect(endpoint_address, common::MAIN_DOMAIN_NAME, None).await?;
    conn.send_request(
        Request::get(format!(
            "https://{}:{}/ping",
            common::MAIN_DOMAIN_NAME,
            endpoint_address.port()
        ))
        .body(hyper::Body::empty())?,
    )
    .await?;

    Ok(conn.recv_response().await?.status)
}
