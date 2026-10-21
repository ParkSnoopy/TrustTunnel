//! Fallible HTTP request fixture.

use crate::common::TestResult;
use futures::future;
use http::Response;
use log::info;
use tokio::io::{AsyncRead, AsyncWrite};

/// Exchange an HTTP request while driving its connection.
///
/// # Errors
/// Returns HTTP construction, connection-driver, request, or body-read errors.
pub async fn do_post_request<IO>(
    io: IO,
    version: http::Version,
    url: &str,
    content_length: usize,
) -> TestResult<Response<hyper::Body>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut request, conn) = hyper::client::conn::Builder::new()
        .http2_only(version == http::Version::HTTP_2)
        .handshake(io)
        .await?;

    let exchange = async {
        let req = hyper::Request::post(url)
            .version(version)
            .body(hyper::Body::from(vec![0; content_length]))?;

        let response = request.send_request(req).await?;

        info!("Received response: {response:?}");
        Ok::<_, crate::common::TestError>(response)
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
