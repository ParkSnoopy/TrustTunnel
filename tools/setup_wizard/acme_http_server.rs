use crate::acme::AcmeError;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

const ACME_CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge/";
const HTTP_PORT: u16 = 80;

struct ChallengeData {
    token: String,
    key_authorization: String,
}

fn handle_request<B>(
    req: &Request<B>,
    challenge_data: &ChallengeData,
) -> io::Result<Response<Full<Bytes>>> {
    let path = req.uri().path();

    if let Some(request_token) = path.strip_prefix(ACME_CHALLENGE_PATH_PREFIX) {
        if request_token == challenge_data.token {
            writeln!(
                io::stdout().lock(),
                "  ✓ Serving ACME challenge response for token: {request_token}"
            )?;
            let mut response = Response::new(Full::new(Bytes::from(
                challenge_data.key_authorization.clone(),
            )));
            response.headers_mut().insert(
                "Content-Type",
                hyper::header::HeaderValue::from_static("text/plain"),
            );
            return Ok(response);
        }
        writeln!(
            io::stdout().lock(),
            "  ✗ Token mismatch: expected {}, got {request_token}",
            challenge_data.token
        )?;
    }

    let mut response = Response::new(Full::new(Bytes::from("Not Found")));
    *response.status_mut() = StatusCode::NOT_FOUND;
    Ok(response)
}

pub async fn run_http01_challenge_server(
    token: String,
    key_authorization: String,
) -> Result<(oneshot::Sender<()>, JoinHandle<io::Result<()>>), AcmeError> {
    let addr = SocketAddr::from(([0, 0, 0, 0], HTTP_PORT));

    // Check if port is available
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            AcmeError::PermissionDenied(HTTP_PORT)
        } else {
            AcmeError::PortInUse(HTTP_PORT)
        }
    })?;

    writeln!(
        io::stdout().lock(),
        "  HTTP server listening on port {HTTP_PORT} for ACME challenge"
    )?;

    let challenge_data = Arc::new(ChallengeData {
        token,
        key_authorization,
    });

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    let handle = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let io = TokioIo::new(stream);
                            let challenge_data = Arc::clone(&challenge_data);

                            connections.spawn(async move {
                                let service = service_fn(move |req| {
                                    let challenge_data = Arc::clone(&challenge_data);
                                    async move { handle_request(&req, &challenge_data) }
                                });

                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    writeln!(io::stderr().lock(), "  HTTP server error: {e}")?;
                                }
                                Ok::<(), io::Error>(())
                            });
                        }
                        Err(e) => {
                            writeln!(io::stderr().lock(), "  Failed to accept connection: {e}")?;
                        }
                    }
                }
                Some(result) = connections.join_next() => {
                    result.map_err(io::Error::other)??;
                }
                _ = &mut shutdown_rx => {
                    writeln!(io::stdout().lock(), "  HTTP server shutting down")?;
                    break;
                }
            }
        }
        Ok(())
    });

    Ok((shutdown_tx, handle))
}

#[cfg(test)]
mod tests {
    use super::{handle_request, ChallengeData};
    use crate::WizardResult;
    use http_body_util::BodyExt;
    use hyper::{Request, StatusCode};

    #[tokio::test]
    async fn challenge_response_requires_matching_token_and_path() -> WizardResult<()> {
        let challenge_data = ChallengeData {
            token: "sample-token".to_owned(),
            key_authorization: "sample-token.sample-authorization".to_owned(),
        };
        for (path, status, body) in [
            (
                "/.well-known/acme-challenge/sample-token",
                StatusCode::OK,
                "sample-token.sample-authorization",
            ),
            (
                "/.well-known/acme-challenge/wrong-token",
                StatusCode::NOT_FOUND,
                "Not Found",
            ),
            ("/sample-token", StatusCode::NOT_FOUND, "Not Found"),
        ] {
            let request = Request::builder().uri(path).body(())?;
            let response = handle_request(&request, &challenge_data)?;
            check_eq!(response.status(), status);
            if status == StatusCode::OK {
                check_eq!(
                    response
                        .headers()
                        .get("Content-Type")
                        .map(hyper::header::HeaderValue::as_bytes),
                    Some(b"text/plain".as_slice())
                );
            }
            let collected = response.into_body().collect().await?.to_bytes();
            check_eq!(collected.as_ref(), body.as_bytes());
        }
        Ok(())
    }
}
