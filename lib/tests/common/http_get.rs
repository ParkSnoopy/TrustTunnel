//! Fallible HTTP request fixture.

use crate::common::TestResult;
use bytes::Bytes;
use futures::future;
use log::info;
use tokio::io::{AsyncRead, AsyncWrite};

/// Exchange an HTTP request while driving its connection.
///
/// # Errors
/// Returns HTTP construction, connection-driver, request, or body-read errors.
pub async fn do_get_request<IO>(
    io: IO,
    version: http::Version,
    url: &str,
    extra_headers: &[(&str, &str)],
) -> TestResult<(http::response::Parts, Bytes)>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut request, conn) = hyper::client::conn::Builder::new()
        .http2_only(version == http::Version::HTTP_2)
        .handshake(io)
        .await?;

    let mut request_builder = hyper::Request::get(url).version(version);
    for (n, v) in extra_headers {
        request_builder = request_builder.header(*n, *v);
    }

    let exchange = async {
        let response = request
            .send_request(request_builder.body(hyper::Body::empty())?)
            .await?;
        info!("Received response: {response:?}");

        let (parts, body) = response.into_parts();
        Ok::<_, crate::common::TestError>((parts, hyper::body::to_bytes(body).await?))
    };

    futures::pin_mut!(exchange);
    match future::select(conn, exchange).await {
        future::Either::Left((r, exchange)) => {
            info!("HTTP connection closed with result: {r:?}");
            r?;
            exchange.await
        }
        future::Either::Right((response, _)) => response,
    }
}
