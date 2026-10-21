use crate::http_codec::{RequestHeaders, ResponseHeaders};
use crate::pipe::Sink;
use crate::settings::Settings;
use crate::tls_demultiplexer::Protocol;
use crate::{datagram_pipe, http_codec, log_id, log_utils, net_utils, pipe, utils};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};

pub const MAX_RAW_HEADERS_SIZE: usize = 1024;
pub const MAX_HEADERS_NUM: usize = 32;

pub struct Http1Codec<IO> {
    state: State,
    transport_stream: IO,
    /// Receives messages from [`StreamSink::download_tx`]
    download_rx: mpsc::Receiver<Bytes>,
    /// See [`StreamSink::download_tx`]
    download_tx: Option<mpsc::Sender<Bytes>>,
    /// Waits notify from [`StreamSink::download_eof`]
    download_eof: Arc<Notify>,
    /// See [`StreamSource::upload_rx`]
    upload_rx: Option<mpsc::Receiver<Bytes>>,
    /// Sends messages to [`StreamSource::upload_rx`]
    upload_tx: mpsc::Sender<Bytes>,
    upload_buffer_size: usize,
    parent_id_chain: log_utils::IdChain<u64>,
    next_request_id: std::ops::RangeFrom<u64>,
}

pub enum DecodeStatus<Headers> {
    Partial(BytesMut),
    Complete(Headers, BytesMut),
}

enum State {
    WaitingRequest(WaitingRequest),
    RequestInProgress(RequestInProgress),
}

struct WaitingRequest {
    buffer: BytesMut,
}

struct RequestInProgress {
    buffer: BytesMut,
}

struct Stream {
    source: StreamSource,
    sink: StreamSink,
}

struct StreamSource {
    request: RequestHeaders,
    client_address: IpAddr,
    /// Receives messages from [`Http1Codec::upload_tx`]
    upload_rx: mpsc::Receiver<Bytes>,
    id: log_utils::IdChain<u64>,
}

struct StreamSink {
    /// Sends messages to [`Http1Codec::download_rx`]
    download_tx: Option<mpsc::Sender<Bytes>>,
    /// Notifies [`Http1Codec::download_eof`]
    download_eof: Arc<Notify>,
    insert_connection_close: bool,
    id: log_utils::IdChain<u64>,
}

enum RequestStatus {
    Partial,
    Complete(Box<dyn http_codec::Stream>),
    NeedRespond(ResponseHeaders),
}

impl<IO> Http1Codec<IO>
where
    IO: net_utils::PeerAddr,
{
    pub fn new(
        core_settings: &Settings,
        transport_stream: IO,
        parent_id_chain: log_utils::IdChain<u64>,
    ) -> io::Result<Self> {
        let upload_buffer_size = core_settings
            .listen_protocols
            .http1
            .as_ref()
            .ok_or_else(|| io::Error::other("HTTP1 listening is not configured"))?
            .upload_buffer_size;
        let (download_tx, download_rx) = mpsc::channel(1);
        let (upload_tx, upload_rx) = mpsc::channel(1);

        Ok(Self {
            state: State::WaitingRequest(WaitingRequest {
                buffer: BytesMut::with_capacity(MAX_RAW_HEADERS_SIZE),
            }),
            transport_stream,
            download_rx,
            download_tx: Some(download_tx),
            download_eof: Arc::new(Notify::new()),
            upload_rx: Some(upload_rx),
            upload_tx,
            upload_buffer_size,
            parent_id_chain,
            next_request_id: 0..,
        })
    }

    fn on_request_headers_chunk(&mut self, buffer: BytesMut) -> io::Result<RequestStatus> {
        match decode_request(buffer, MAX_HEADERS_NUM, MAX_RAW_HEADERS_SIZE)? {
            DecodeStatus::Partial(bytes) => {
                match &mut self.state {
                    State::WaitingRequest(x) => x.buffer = bytes,
                    State::RequestInProgress(_) => {
                        return Err(io::Error::other("HTTP1 request already in progress"))
                    }
                }
                Ok(RequestStatus::Partial)
            }
            DecodeStatus::Complete(request, tail) => {
                if request.method == http::Method::CONNECT && request.headers.contains_key("expect")
                {
                    return Ok(RequestStatus::NeedRespond(
                        http::response::Builder::new()
                            .version(request.version)
                            .status(http::StatusCode::EXPECTATION_FAILED)
                            .header("Connection", "close")
                            .body(())
                            .map_err(|e| {
                                io::Error::other(format!(
                                    "Failed to build \"Expectation Failed\" response: {e}"
                                ))
                            })?
                            .into_parts()
                            .0,
                    ));
                }

                let _ = std::mem::replace(
                    &mut self.state,
                    State::RequestInProgress(RequestInProgress { buffer: tail }),
                );

                let id = self.parent_id_chain.extended(log_utils::IdItem::new(
                    log_utils::CONNECTION_ID_FMT,
                    self.next_request_id
                        .next()
                        .ok_or_else(|| io::Error::other("HTTP1 request IDs exhausted"))?,
                ));
                let insert_connection_close = request.method == http::Method::CONNECT;
                Ok(RequestStatus::Complete(Box::new(Stream {
                    source: StreamSource {
                        request,
                        client_address: self.transport_stream.peer_addr()?.ip(),
                        upload_rx: self.upload_rx.take().ok_or_else(|| {
                            io::Error::other("HTTP1 upload receiver already taken")
                        })?,
                        id: id.clone(),
                    },
                    sink: StreamSink {
                        download_tx: self.download_tx.take(),
                        download_eof: self.download_eof.clone(),
                        insert_connection_close,
                        id,
                    },
                })))
            }
        }
    }
}

#[async_trait]
impl<IO> http_codec::HttpCodec for Http1Codec<IO>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + net_utils::PeerAddr,
{
    async fn listen(&mut self) -> io::Result<Option<Box<dyn http_codec::Stream>>> {
        loop {
            let wait_read = async {
                let mut buffer = self.state.take_buffer();
                if buffer.is_empty() {
                    if matches!(self.state, State::RequestInProgress(_)) {
                        if let Err(e) = self.upload_tx.reserve().await {
                            log_id!(
                                debug,
                                self.parent_id_chain,
                                "Upload channel closed while waiting for capacity: {}",
                                e
                            );
                        }
                    }
                    self.transport_stream.read_buf(&mut buffer).await?;
                } else if matches!(self.state, State::WaitingRequest(_)) {
                    let bytes_read = self.transport_stream.read_buf(&mut buffer).await?;
                    if bytes_read == 0 {
                        buffer.clear();
                    }
                }
                Ok(buffer)
            };

            tokio::select! {
                r = wait_read => match r {
                    Ok(bytes) if bytes.is_empty() =>
                        return self.graceful_shutdown().await.map(|()| None),
                    Ok(bytes) => match &mut self.state {
                        State::WaitingRequest(_) => {
                            match self.on_request_headers_chunk(bytes)? {
                                RequestStatus::Partial => (),
                                RequestStatus::Complete(stream) => return Ok(Some(stream)),
                                RequestStatus::NeedRespond(response) => {
                                    log_id!(debug, self.parent_id_chain, "Tunnel rejected, responding with: {:?}", response);
                                    let mut response = encode_response(&response)?;
                                    self.transport_stream.write_all_buf(&mut response).await?;
                                    return Ok(None);
                                }
                            }
                        }
                        State::RequestInProgress(x) => {
                            x.buffer = BytesMut::with_capacity(self.upload_buffer_size);
                            match self.upload_tx.send(bytes.freeze()).await {
                                Ok(()) => (),
                                Err(_) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
                            }
                        }
                    },
                    Err(e) => return Err(e),
                },
                r = self.download_rx.recv() => match r {
                    None => {
                        // Arbitrate the race between EOF notification and the pipe dropping
                        let eof_fired = {
                            let eof = self.download_eof.notified();
                            tokio::pin!(eof);
                            eof.enable()
                        };
                        if eof_fired {
                            self.graceful_shutdown().await?;
                            return Ok(None);
                        }
                        return Err(io::Error::from(ErrorKind::UnexpectedEof));
                    },
                    Some(mut bytes) => self.transport_stream.write_all_buf(&mut bytes).await?,
                },
                () = self.download_eof.notified() => {
                    self.graceful_shutdown().await?;
                    return Ok(None);
                }
            }
        }
    }

    async fn graceful_shutdown(&mut self) -> io::Result<()> {
        if let Ok(mut chunk) = self.download_rx.try_recv() {
            self.transport_stream.write_all_buf(&mut chunk).await?;
        }
        self.transport_stream.flush().await?;
        if let Err(e) = self.upload_tx.reserve().await {
            log_id!(
                debug,
                self.parent_id_chain,
                "Upload channel closed during shutdown: {}",
                e
            );
        }
        self.transport_stream.shutdown().await
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http1
    }
}

impl http_codec::Stream for Stream {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.source.id.clone()
    }

    fn request(&self) -> &dyn http_codec::PendingRequest {
        &self.source
    }

    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn http_codec::PendingRequest>,
        Box<dyn http_codec::PendingRespond>,
    ) {
        (Box::new(self.source), Box::new(self.sink))
    }
}

impl http_codec::PendingRequest for StreamSource {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn request(&self) -> &RequestHeaders {
        &self.request
    }

    fn client_address(&self) -> io::Result<IpAddr> {
        Ok(self.client_address)
    }

    fn finalize(self: Box<Self>) -> Box<dyn pipe::Source> {
        self
    }
}

impl http_codec::PendingRespond for StreamSink {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn send_intermediate_response(&self, response: ResponseHeaders) -> io::Result<()> {
        log_id!(
            debug,
            self.id,
            "Sending intermediate response: {:?}",
            response
        );

        self.download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .try_send(encode_response(&response)?)
            .map_err(|e| io::Error::other(format!("Failed to put response in queue: {e}")))
    }

    fn send_response(
        mut self: Box<Self>,
        mut response: ResponseHeaders,
        eof: bool,
    ) -> io::Result<Box<dyn http_codec::RespondedStreamSink>> {
        if self.insert_connection_close && !response.headers.contains_key("Connection") {
            response
                .headers
                .insert("Connection", http::HeaderValue::from_static("close"));
        }
        log_id!(
            debug,
            self.id,
            "Sending response: {:?} (eof={})",
            response,
            eof
        );

        self.download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .try_send(encode_response(&response)?)
            .map_err(|e| io::Error::other(format!("Failed to put response in queue: {e}")))?;

        if eof {
            self.eof()?;
        }

        Ok(self)
    }
}

impl State {
    fn take_buffer(&mut self) -> BytesMut {
        match self {
            Self::WaitingRequest(x) => std::mem::take(&mut x.buffer),
            Self::RequestInProgress(x) => std::mem::take(&mut x.buffer),
        }
    }
}

#[async_trait]
impl pipe::Source for StreamSource {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    async fn read(&mut self) -> io::Result<pipe::Data> {
        Ok(self
            .upload_rx
            .recv()
            .await
            .map_or(pipe::Data::Eof, pipe::Data::Chunk))
    }

    fn consume(&mut self, _size: usize) -> io::Result<()> {
        // do nothing
        Ok(())
    }
}

impl http_codec::RespondedStreamSink for StreamSink {
    fn into_pipe_sink(self: Box<Self>) -> Box<dyn Sink> {
        self
    }

    fn into_datagram_sink(self: Box<Self>) -> Box<dyn http_codec::DroppingSink> {
        self
    }
}

#[async_trait]
impl Sink for StreamSink {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn write(&mut self, data: Bytes) -> io::Result<Bytes> {
        match self
            .download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .try_send(data)
        {
            Ok(()) => Ok(Bytes::new()),
            Err(mpsc::error::TrySendError::Full(unsent)) => Ok(unsent),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::from(ErrorKind::UnexpectedEof))
            }
        }
    }

    fn eof(&mut self) -> io::Result<()> {
        self.download_eof.notify_one();
        Ok(())
    }

    async fn wait_writable(&mut self) -> io::Result<()> {
        match self
            .download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .reserve()
            .await
        {
            Ok(_) => Ok(()),
            Err(_) => Err(io::Error::from(ErrorKind::UnexpectedEof)),
        }
    }
}

impl http_codec::DroppingSink for StreamSink {
    fn write(&mut self, data: Bytes) -> io::Result<datagram_pipe::SendStatus> {
        match self
            .download_tx
            .as_ref()
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
            .try_send(data)
        {
            Ok(()) => Ok(datagram_pipe::SendStatus::Sent),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(datagram_pipe::SendStatus::Dropped),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::from(ErrorKind::UnexpectedEof))
            }
        }
    }
}

fn version_minor_digit(v: http::Version) -> io::Result<u8> {
    match v {
        http::Version::HTTP_10 => Ok(b'0'),
        http::Version::HTTP_11 => Ok(b'1'),
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Not an HTTP/1 version",
        )),
    }
}

fn httparse_to_http_version(v: u8) -> io::Result<http::Version> {
    match v {
        0 => Ok(http::Version::HTTP_10),
        1 => Ok(http::Version::HTTP_11),
        _ => Err(io::Error::new(
            ErrorKind::InvalidData,
            "Not an HTTP/1 version",
        )),
    }
}

fn encode_headers(mut buffer: BytesMut, headers: &http::HeaderMap<http::HeaderValue>) -> BytesMut {
    for (name, value) in headers {
        buffer.put(name.as_ref());
        buffer.put(b": ".as_slice());
        buffer.put(value.as_bytes());
        buffer.put(b"\r\n".as_slice());
    }
    buffer.put(b"\r\n".as_slice());

    buffer
}

pub fn encode_request(request: &RequestHeaders) -> io::Result<Bytes> {
    let mut encoded = BytesMut::new();

    encoded.put(request.method.as_str().as_bytes());
    encoded.put(b" ".as_slice());
    encoded.put(
        request
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str)
            .as_bytes(),
    );
    encoded.put(b" HTTP/1.".as_slice());
    encoded.put([version_minor_digit(request.version)?].as_slice());
    encoded.put(b"\r\n".as_slice());

    if let Some(host) = request.uri.authority() {
        encoded.put(b"Host: ".as_slice());
        encoded.put(host.as_str().as_bytes());
        encoded.put(b"\r\n".as_slice());
    }

    encoded = encode_headers(encoded, &request.headers);

    Ok(encoded.freeze())
}

pub fn encode_response(response: &ResponseHeaders) -> io::Result<Bytes> {
    let mut encoded = BytesMut::new();

    encoded.put(b"HTTP/1.".as_slice());
    encoded.put([version_minor_digit(response.version)?].as_slice());
    encoded.put(b" ".as_slice());
    encoded.put(response.status.as_str().as_bytes());
    encoded.put(b" ".as_slice());
    encoded.put(
        response
            .status
            .canonical_reason()
            .unwrap_or_default()
            .as_bytes(),
    );
    encoded.put(b"\r\n".as_slice());

    encoded = encode_headers(encoded, &response.headers);

    Ok(encoded.freeze())
}

pub fn decode_request(
    mut buffer: BytesMut,
    headers_num_cap: usize,
    raw_buffer_cap: usize,
) -> io::Result<DecodeStatus<RequestHeaders>> {
    let mut headers = vec![httparse::EMPTY_HEADER; headers_num_cap];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(&buffer) {
        Ok(httparse::Status::Complete(idx)) => {
            let mut request_builder = http::request::Request::builder()
                .version(httparse_to_http_version(
                    request
                        .version
                        .ok_or_else(|| io::Error::other("Version not found"))?,
                )?)
                .method(
                    request
                        .method
                        .ok_or_else(|| io::Error::other("Method not found"))?,
                );

            let path = request
                .path
                .ok_or_else(|| io::Error::other(format!("Invalid path: {:?}", request.path)))?;
            let mut uri = http::uri::Uri::from_str(path).map_err(|e| {
                io::Error::other(format!("Invalid path: path={:?}, error={e}", request.path))
            })?;

            for h in request.headers {
                match h.name.to_lowercase().as_str() {
                    "host" if uri.authority().is_none() => {
                        uri = http::uri::Uri::builder()
                            .scheme("https")
                            .authority(h.value)
                            .path_and_query(path)
                            .build()
                            .map_err(|e| {
                                io::Error::other(format!(
                                    "Unexpected URI: error={}, authority={}, path={:?}",
                                    e,
                                    utils::hex_dump(h.value),
                                    request.path,
                                ))
                            })?;
                    }
                    _ => request_builder = request_builder.header(h.name, h.value),
                }
            }

            request_builder = request_builder.uri(uri);

            Ok(DecodeStatus::Complete(
                request_builder
                    .body(())
                    .map_err(|e| io::Error::other(format!("Invalid request: {e}")))?
                    .into_parts()
                    .0,
                buffer.split_off(idx),
            ))
        }
        Ok(httparse::Status::Partial) if buffer.len() < raw_buffer_cap => {
            Ok(DecodeStatus::Partial(buffer))
        }
        Ok(httparse::Status::Partial) => Err(io::Error::other("Too long HTTP request headers")),
        Err(e) => Err(io::Error::other(e.to_string())),
    }
}

pub fn decode_response(
    mut buffer: BytesMut,
    headers_num_cap: usize,
    raw_buffer_cap: usize,
) -> io::Result<DecodeStatus<ResponseHeaders>> {
    let mut headers = vec![httparse::EMPTY_HEADER; headers_num_cap];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(&buffer) {
        Ok(httparse::Status::Complete(idx)) => {
            let mut response_builder = http::response::Response::builder()
                .version(httparse_to_http_version(
                    response
                        .version
                        .ok_or_else(|| io::Error::other("Version not found"))?,
                )?)
                .status(
                    response
                        .code
                        .ok_or_else(|| io::Error::other("Status not found"))?,
                );

            for h in response.headers {
                response_builder = response_builder.header(h.name, h.value);
            }

            Ok(DecodeStatus::Complete(
                response_builder
                    .body(())
                    .map_err(|e| io::Error::other(format!("Invalid response: {e}")))?
                    .into_parts()
                    .0,
                buffer.split_off(idx),
            ))
        }
        Ok(httparse::Status::Partial) if buffer.len() < raw_buffer_cap => {
            Ok(DecodeStatus::Partial(buffer))
        }
        Ok(httparse::Status::Partial) => Err(io::Error::other("Too long HTTP response headers")),
        Err(e) => Err(io::Error::other(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check;

    #[test]
    fn request_wire_format_preserves_version_host_query_and_headers() -> io::Result<()> {
        let request = http::Request::builder()
            .version(http::Version::HTTP_10)
            .method(http::Method::GET)
            .uri("https://example.org:8443/a?b=c")
            .header("x-test", "value")
            .body(())
            .map_err(io::Error::other)?
            .into_parts()
            .0;
        check(
            encode_request(&request)?
                == b"GET /a?b=c HTTP/1.0\r\nHost: example.org:8443\r\nx-test: value\r\n\r\n"
                    .as_slice(),
            "Unexpected request bytes",
        )?;
        Ok(())
    }

    #[test]
    fn response_wire_format_preserves_reason_and_headers() -> io::Result<()> {
        let mut response = http::Response::<()>::default().into_parts().0;
        response.status = http::StatusCode::BAD_GATEWAY;
        response
            .headers
            .insert("connection", http::HeaderValue::from_static("close"));
        check(
            encode_response(&response)?
                == b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n".as_slice(),
            "Unexpected response bytes",
        )?;
        Ok(())
    }

    #[test]
    fn encoding_rejects_other_http_versions() {
        let mut request = http::Request::<()>::default().into_parts().0;
        let mut response = http::Response::<()>::default().into_parts().0;
        for version in [
            http::Version::HTTP_09,
            http::Version::HTTP_2,
            http::Version::HTTP_3,
        ] {
            request.version = version;
            response.version = version;
            assert!(encode_request(&request).is_err());
            assert!(encode_response(&response).is_err());
        }
    }

    #[test]
    fn fragmented_request_preserves_body_tail() -> io::Result<()> {
        let prefix = BytesMut::from(
            b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n".as_slice(),
        );
        let DecodeStatus::Partial(mut buffer) =
            decode_request(prefix, MAX_HEADERS_NUM, MAX_RAW_HEADERS_SIZE)?
        else {
            return Err(io::Error::other("Expected partial request"));
        };
        buffer.extend_from_slice(b"\r\nbody");
        let DecodeStatus::Complete(request, tail) =
            decode_request(buffer, MAX_HEADERS_NUM, MAX_RAW_HEADERS_SIZE)?
        else {
            return Err(io::Error::other("Expected complete request"));
        };
        check(request.method == http::Method::CONNECT, "Unexpected method")?;
        check(
            request.uri.authority().map(http::uri::Authority::as_str) == Some("example.org:443"),
            "Unexpected authority",
        )?;
        check(tail.as_ref() == b"body", "Unexpected body tail")?;
        Ok(())
    }

    #[test]
    fn partial_headers_at_limit_are_rejected() {
        let buffer = BytesMut::from(b"GET / HTTP/1.1\r\nx: ".as_slice());
        let limit = buffer.len();
        assert!(decode_request(buffer, MAX_HEADERS_NUM, limit).is_err());
    }

    #[test]
    fn fragmented_response_preserves_headers_and_body_tail() -> io::Result<()> {
        let headers = b"HTTP/1.0 201 Created\r\nx-test: value\r\n\r\n";
        for split in 0..headers.len() {
            let DecodeStatus::Partial(mut buffer) = decode_response(
                BytesMut::from(&headers[..split]),
                MAX_HEADERS_NUM,
                MAX_RAW_HEADERS_SIZE,
            )?
            else {
                return Err(io::Error::other("Expected partial response"));
            };
            buffer.extend_from_slice(&headers[split..]);
            buffer.extend_from_slice(b"body");
            let DecodeStatus::Complete(response, tail) =
                decode_response(buffer, MAX_HEADERS_NUM, MAX_RAW_HEADERS_SIZE)?
            else {
                return Err(io::Error::other("Expected complete response"));
            };
            check(
                response.version == http::Version::HTTP_10,
                "Unexpected HTTP version",
            )?;
            check(
                response.status == http::StatusCode::CREATED,
                "Unexpected status",
            )?;
            check(
                response.headers.get("x-test") == Some(&http::HeaderValue::from_static("value")),
                "Unexpected response header",
            )?;
            check(tail.as_ref() == b"body", "Unexpected body tail")?;
        }
        Ok(())
    }

    #[test]
    fn pending_request_auth_handles_absent_basic_and_invalid_headers() -> io::Result<()> {
        use crate::http_codec::PendingRequest as _;

        let mut source = StreamSource {
            request: http::Request::<()>::default().into_parts().0,
            client_address: std::net::Ipv4Addr::LOCALHOST.into(),
            upload_rx: mpsc::channel(1).1,
            id: log_utils::IdChain::empty(),
        };
        check(source.auth_info()?.is_none(), "Unexpected authorization")?;
        source.request.headers.insert(
            http::header::PROXY_AUTHORIZATION,
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        check(
            source.auth_info()?
                == Some(crate::authentication::Source::ProxyBasic(
                    "dXNlcjpwYXNz".into(),
                )),
            "Unexpected basic authorization",
        )?;
        for value in [
            http::HeaderValue::from_static("Bearer token"),
            http::HeaderValue::from_bytes(b"\xff").map_err(io::Error::other)?,
        ] {
            source
                .request
                .headers
                .insert(http::header::PROXY_AUTHORIZATION, value);
            check(
                source.auth_info().is_err(),
                "Expected invalid authorization",
            )?;
        }
        Ok(())
    }
}
