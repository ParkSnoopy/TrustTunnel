use crate::forwarder::TcpConnector;
use crate::http_codec::HttpCodec;
use crate::net_utils::TcpDestination;
use crate::pipe::DuplexPipe;
use crate::tcp_forwarder::TcpForwarder;
use crate::tls_demultiplexer::Protocol;
use crate::{core, forwarder, http1_codec, http_codec, log_id, log_utils, pipe, tunnel};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static ORIGINAL_PROTOCOL_HEADER: http::HeaderName =
    http::HeaderName::from_static("x-original-protocol");
const H3_BUFFERED_BODY_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Default)]
struct SessionManager {
    active_streams_num: AtomicUsize,
}

pub async fn listen(
    context: Arc<core::Context>,
    mut codec: Box<dyn HttpCodec>,
    sni: String,
    log_id: log_utils::IdChain<u64>,
) {
    let (mut shutdown_notification, _shutdown_completion) = {
        let shutdown = context.shutdown.lock().unwrap_or_else(|e| {
            log_id!(error, log_id, "Recovering poisoned shutdown lock: {}", e);
            e.into_inner()
        });
        (shutdown.notification_handler(), shutdown.completion_guard())
    };

    tokio::select! {
        x = shutdown_notification.wait() => {
            match x {
                Ok(()) => (),
                Err(e) => log_id!(debug, log_id, "Shutdown notification failure: {}", e),
            }
        },
        () = listen_inner(context, codec.as_mut(), sni, &log_id) => (),
    }

    if let Err(e) = codec.graceful_shutdown().await {
        log_id!(debug, log_id, "Failed to shutdown HTTP session: {}", e);
    }
}

async fn listen_inner(
    context: Arc<core::Context>,
    codec: &mut dyn HttpCodec,
    sni: String,
    log_id: &log_utils::IdChain<u64>,
) {
    let manager = Arc::new(SessionManager::default());
    let timeout = context.settings.connection_establishment_timeout;
    loop {
        match tokio::time::timeout(timeout, codec.listen()).await {
            Ok(Ok(Some(x))) => {
                tokio::spawn({
                    let context = context.clone();
                    let manager = manager.clone();
                    let protocol = codec.protocol();
                    let sni = sni.clone();
                    let log_id = log_id.clone();
                    async move {
                        manager.active_streams_num.fetch_add(1, Ordering::AcqRel);
                        if let Err(e) = handle_stream(context, x, protocol, sni, &log_id).await {
                            log_id!(debug, log_id, "Request failed: {}", e);
                        }
                        manager.active_streams_num.fetch_sub(1, Ordering::AcqRel);
                    }
                });
            }
            Ok(Ok(None)) => {
                log_id!(trace, log_id, "Connection closed");
                break;
            }
            Ok(Err(ref e)) if e.kind() == ErrorKind::UnexpectedEof => {
                log_id!(trace, log_id, "Connection closed");
                break;
            }
            Ok(Err(e)) => {
                log_id!(debug, log_id, "Session error: {}", e);
                break;
            }
            Err(_elapsed) if manager.active_streams_num.load(Ordering::Acquire) > 0 => log_id!(
                trace,
                log_id,
                "Ignoring timeout due to there are some active streams"
            ),
            Err(_elapsed) => {
                log_id!(debug, log_id, "Closing due to timeout");
                if let Err(e) = codec.graceful_shutdown().await {
                    log_id!(debug, log_id, "Failed to shut down session: {}", e);
                }
                break;
            }
        }
    }
}

async fn handle_stream(
    context: Arc<core::Context>,
    stream: Box<dyn http_codec::Stream>,
    protocol: Protocol,
    sni: String,
    log_id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    let (request, respond) = stream.split();
    log_id!(trace, log_id, "Received request: {:?}", request.request());

    let forwarder = Box::new(TcpForwarder::new_for_configured_destination(
        context.clone(),
    ));
    let settings = context
        .settings
        .reverse_proxy
        .as_ref()
        .ok_or_else(|| io::Error::other("Reverse proxy is not configured"))?;
    let (mut server_source, mut server_sink) = forwarder
        .connect(
            log_id.clone(),
            forwarder::TcpConnectionMeta {
                client_address: Ipv4Addr::UNSPECIFIED.into(),
                destination: TcpDestination::Address(settings.server_address),
                auth: None,
                tls_domain: sni,
                user_agent: None,
            },
        )
        .await
        .map_err(|e| match e {
            tunnel::ConnectionError::Io(e) => e,
            _ => io::Error::other(format!("{e}")),
        })?;

    let (request_headers, original_version) =
        translate_request_headers(request.clone_request(), protocol, settings);

    let encoded = http1_codec::encode_request(&request_headers)?;
    log_id!(
        trace,
        log_id,
        "Sending translated request: {:?}",
        request_headers
    );
    server_sink.write_all(encoded).await?;

    let Some((response, chunk, is_chunked)) =
        read_upstream_response(server_source.as_mut(), original_version, protocol).await?
    else {
        return send_bad_gateway(respond, original_version);
    };

    let content_length = response
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|x| x.to_str().ok())
        .and_then(|x| x.parse::<usize>().ok());
    // H3 streaming is fragile in practice; buffer reasonably small bodies to avoid truncation.
    if let (Protocol::Http3, Some(total)) = (
        protocol,
        content_length.filter(|x| *x <= H3_BUFFERED_BODY_LIMIT),
    ) {
        let body = buffer_http3_body(server_source.as_mut(), chunk, total).await?;
        let mut client_sink = respond.send_response(response, false)?.into_pipe_sink();
        client_sink.write_all(body).await?;
        client_sink.eof()?;
        return Ok(());
    }

    let chunk_len = chunk.len();

    if is_chunked && !matches!(protocol, Protocol::Http1) {
        return forward_chunked_body(
            server_source.as_mut(),
            respond,
            response,
            chunk,
            protocol,
            log_id,
        )
        .await;
    }

    let mut client_sink = respond.send_response(response, false)?.into_pipe_sink();
    client_sink.write_all(chunk).await?;
    server_source.consume(chunk_len)?;

    if let Some(remaining) = content_length.and_then(|x| x.checked_sub(chunk_len)) {
        return forward_known_length_body(
            server_source.as_mut(),
            client_sink.as_mut(),
            remaining,
            log_id,
        )
        .await;
    }

    let mut pipe = DuplexPipe::new(
        (
            pipe::SimplexDirection::Outgoing,
            request.finalize(),
            server_sink,
        ),
        (pipe::SimplexDirection::Incoming, server_source, client_sink),
        |_, _| (),
    );

    match pipe
        .exchange(context.settings.tcp_connections_timeout)
        .await
    {
        Ok(()) => Ok(()),
        // HTTP/2 (and sometimes HTTP/3) can surface graceful stream closure
        // as UnexpectedEof once the response has already been delivered.
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Ok(()),
        Err(e) => Err(e),
    }
}

async fn forward_known_length_body(
    server_source: &mut dyn pipe::Source,
    client_sink: &mut dyn pipe::Sink,
    mut remaining: usize,
    log_id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    log_id!(
        debug,
        log_id,
        "Reverse proxy fixed-size body: remaining={} bytes after initial send",
        remaining
    );
    while remaining > 0 {
        match server_source.read().await? {
            pipe::Data::Chunk(chunk) => {
                server_source.consume(chunk.len())?;
                let to_send = std::cmp::min(chunk.len(), remaining);
                client_sink.write_all(chunk.slice(..to_send)).await?;
                remaining -= to_send;
            }
            pipe::Data::Eof => break,
        }
    }
    if let Err(e) = client_sink.eof() {
        log_id!(debug, log_id, "Failed to close client stream: {}", e);
    } else {
        log_id!(debug, log_id, "Reverse proxy client stream closed");
    }
    Ok(())
}

fn translate_request_headers(
    mut request_headers: http_codec::RequestHeaders,
    protocol: Protocol,
    settings: &crate::settings::ReverseProxySettings,
) -> (http_codec::RequestHeaders, http::Version) {
    let original_version = request_headers.version;
    match protocol {
        Protocol::Http1 => (),
        Protocol::Http2 => {
            request_headers.version = http::Version::HTTP_11;
        }
        Protocol::Http3 => {
            request_headers.version = http::Version::HTTP_11;
            if settings.h3_backward_compatibility
                && request_headers.method == http::Method::GET
                && request_headers.uri.path() == "/"
            {
                request_headers.method = http::Method::CONNECT;
            }
        }
    }
    request_headers.headers.insert(
        &ORIGINAL_PROTOCOL_HEADER,
        http::HeaderValue::from_static(protocol.as_str()),
    );

    (request_headers, original_version)
}

async fn read_upstream_response(
    server_source: &mut dyn pipe::Source,
    original_version: http::Version,
    protocol: Protocol,
) -> io::Result<Option<(http_codec::ResponseHeaders, Bytes, bool)>> {
    let mut buffer = BytesMut::new();
    loop {
        match server_source.read().await? {
            pipe::Data::Chunk(chunk) => {
                server_source.consume(chunk.len())?;
                buffer.put(chunk);
            }
            pipe::Data::Eof => {
                // Upstream closed before sending a valid HTTP response. Reply with 502
                // to avoid surfacing this as an H2 stream cancel to the client.
                return Ok(None);
            }
        }

        match http1_codec::decode_response(
            buffer,
            http1_codec::MAX_HEADERS_NUM,
            http1_codec::MAX_RAW_HEADERS_SIZE,
        )? {
            http1_codec::DecodeStatus::Partial(b) => buffer = b,
            http1_codec::DecodeStatus::Complete(mut h, tail) => {
                h.version = original_version; // restore the version in case it was not the same
                let transfer_encoding_raw = h
                    .headers
                    .get(http::header::TRANSFER_ENCODING)
                    .and_then(|x| x.to_str().ok())
                    .map(str::to_owned);
                let is_chunked = transfer_encoding_raw
                    .as_deref()
                    .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
                if !matches!(protocol, Protocol::Http1) {
                    // Strip hop-by-hop headers that are invalid in HTTP/2 and HTTP/3.
                    h.headers.remove(http::header::CONNECTION);
                    h.headers.remove(http::header::TRANSFER_ENCODING);
                    h.headers.remove(http::header::UPGRADE);
                    h.headers.remove(http::header::TE);
                    h.headers.remove(http::header::TRAILER);
                    h.headers
                        .remove(http::HeaderName::from_static("keep-alive"));
                    h.headers
                        .remove(http::HeaderName::from_static("proxy-connection"));
                }
                return Ok(Some((h, tail.freeze(), is_chunked)));
            }
        }
    }
}

async fn buffer_http3_body(
    server_source: &mut dyn pipe::Source,
    chunk: Bytes,
    total: usize,
) -> io::Result<Bytes> {
    let mut body = BytesMut::with_capacity(total);
    let chunk_len = chunk.len();
    body.put(chunk);
    server_source.consume(chunk_len)?;

    let mut remaining = total.saturating_sub(chunk_len);
    while remaining > 0 {
        match server_source.read().await? {
            pipe::Data::Chunk(chunk) => {
                server_source.consume(chunk.len())?;
                let to_take = std::cmp::min(chunk.len(), remaining);
                body.put(chunk.slice(..to_take));
                remaining -= to_take;
            }
            pipe::Data::Eof => {
                return Err(ErrorKind::UnexpectedEof.into());
            }
        }
    }

    Ok(body.freeze())
}

async fn need_more(
    buffer: &mut BytesMut,
    server_source: &mut dyn pipe::Source,
    _log_id: &log_utils::IdChain<u64>,
) -> io::Result<bool> {
    match server_source.read().await? {
        pipe::Data::Chunk(chunk) => {
            server_source.consume(chunk.len())?;
            buffer.put(chunk);
            Ok(false)
        }
        pipe::Data::Eof => Ok(true),
    }
}

async fn read_chunked_chunk(
    buffer: &mut BytesMut,
    server_source: &mut dyn pipe::Source,
    log_id: &log_utils::IdChain<u64>,
) -> io::Result<Option<Bytes>> {
    // Ensure we have a full chunk size line.
    let line_end = loop {
        if let Some(pos) = buffer.windows(2).position(|w| w == b"\r\n").map(|p| p + 2) {
            break pos;
        }
        let eof = need_more(buffer, server_source, log_id).await?;
        if eof {
            return Err(ErrorKind::UnexpectedEof.into());
        }
    };

    let mut line = buffer.split_to(line_end);
    line.truncate(line.len().saturating_sub(2));
    let line = std::str::from_utf8(&line).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let size_hex = line.split(';').next().unwrap_or_default().trim();
    let chunk_size = usize::from_str_radix(size_hex, 16)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if chunk_size == 0 {
        // If there are no trailers, the stream ends with a single CRLF.
        if buffer.len() >= 2 && &buffer[..2] == b"\r\n" {
            buffer.advance(2);
        } else {
            // Consume trailers until CRLFCRLF or upstream EOF.
            loop {
                if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                let eof = need_more(buffer, server_source, log_id).await?;
                if eof {
                    break;
                }
            }
        }
        return Ok(None);
    }
    // Ensure we have the full chunk plus its trailing CRLF.
    while buffer.len() < chunk_size + 2 {
        let eof = need_more(buffer, server_source, log_id).await?;
        if eof {
            return Err(ErrorKind::UnexpectedEof.into());
        }
    }

    let data = buffer.split_to(chunk_size).freeze();
    let _ = buffer.split_to(2);

    Ok(Some(data))
}

async fn forward_chunked_body(
    server_source: &mut dyn pipe::Source,
    respond: Box<dyn http_codec::PendingRespond>,
    response: http_codec::ResponseHeaders,
    chunk: Bytes,
    protocol: Protocol,
    log_id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    // Decode chunked HTTP/1 body and stream raw bytes to the client.
    // For HTTP/2 and HTTP/3, buffer reasonably small responses so we can
    // set Content-Length and avoid relying on connection teardown signals.
    let buffer_for_length = !matches!(protocol, Protocol::Http1);
    let mut buffered_body = BytesMut::new();
    let mut respond_opt = Some(respond);
    let mut response_opt = Some(response);
    let mut client_sink: Option<Box<dyn pipe::Sink>> = None;
    let ensure_client_sink = |response_opt: &mut Option<http_codec::ResponseHeaders>,
                              respond_opt: &mut Option<Box<dyn http_codec::PendingRespond>>,
                              client_sink: &mut Option<Box<dyn pipe::Sink>>|
     -> io::Result<()> {
        if client_sink.is_some() {
            return Ok(());
        }
        let response = response_opt
            .take()
            .ok_or_else(|| io::Error::other("missing response"))?;
        let respond = respond_opt
            .take()
            .ok_or_else(|| io::Error::other("missing respond"))?;
        *client_sink = Some(respond.send_response(response, false)?.into_pipe_sink());
        Ok(())
    };

    let chunk_len = chunk.len();
    let mut buffer = BytesMut::new();
    buffer.put(chunk);
    server_source.consume(chunk_len)?;
    loop {
        let Some(data) = read_chunked_chunk(&mut buffer, server_source, log_id).await? else {
            if buffer_for_length && client_sink.is_none() {
                if let Some(resp) = response_opt.as_mut() {
                    resp.headers
                        .insert(http::header::CONTENT_LENGTH, buffered_body.len().into());
                }
                ensure_client_sink(&mut response_opt, &mut respond_opt, &mut client_sink)?;
                if let Some(sink) = client_sink.as_mut() {
                    sink.write_all(buffered_body.split().freeze()).await?;
                }
            }
            ensure_client_sink(&mut response_opt, &mut respond_opt, &mut client_sink)?;
            if let Some(sink) = client_sink.as_mut() {
                sink.eof()?;
            }
            return Ok(());
        };

        if buffer_for_length && client_sink.is_none() {
            buffered_body.put(data.clone());
            if buffered_body.len() > H3_BUFFERED_BODY_LIMIT {
                // Fall back to streaming without a known length.
                ensure_client_sink(&mut response_opt, &mut respond_opt, &mut client_sink)?;
                if let Some(sink) = client_sink.as_mut() {
                    sink.write_all(buffered_body.split().freeze()).await?;
                }
            }
            continue;
        }

        ensure_client_sink(&mut response_opt, &mut respond_opt, &mut client_sink)?;
        if let Some(sink) = client_sink.as_mut() {
            sink.write_all(data).await?;
        }
    }
}

fn send_bad_gateway(
    respond: Box<dyn http_codec::PendingRespond>,
    version: http::Version,
) -> io::Result<()> {
    let response = http::Response::builder()
        .status(http::StatusCode::BAD_GATEWAY)
        .version(version)
        .body(())
        .map_err(|e| io::Error::other(format!("bad gateway: {e}")))?;
    let (parts, ()) = response.into_parts();
    respond.send_response(parts, true).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct PacketSource {
        chunks: VecDeque<Bytes>,
        consumed: usize,
    }

    #[async_trait::async_trait]
    impl pipe::Source for PacketSource {
        fn id(&self) -> log_utils::IdChain<u64> {
            log_utils::IdChain::empty()
        }

        async fn read(&mut self) -> io::Result<pipe::Data> {
            Ok(self
                .chunks
                .pop_front()
                .map_or(pipe::Data::Eof, pipe::Data::Chunk))
        }

        fn consume(&mut self, size: usize) -> io::Result<()> {
            self.consumed += size;
            Ok(())
        }
    }

    #[tokio::test]
    async fn chunk_extensions_and_fragment_boundaries_preserve_body() -> io::Result<()> {
        let wire = Bytes::from_static(b"4;ext=1\r\nbody\r\n0\r\n\r\n");
        for split in 1..wire.len() {
            let mut source = PacketSource {
                chunks: [wire.slice(..split), wire.slice(split..)].into(),
                consumed: 0,
            };
            let mut buffer = BytesMut::new();
            let id = log_utils::IdChain::empty();
            let body = read_chunked_chunk(&mut buffer, &mut source, &id).await?;
            if body != Some(Bytes::from_static(b"body")) {
                return Err(io::Error::other(format!(
                    "Incorrect body at split {split}: {body:?}"
                )));
            }
            if read_chunked_chunk(&mut buffer, &mut source, &id)
                .await?
                .is_some()
            {
                return Err(io::Error::other(format!(
                    "Missing body terminator at split {split}"
                )));
            }
            if source.consumed != wire.len() {
                return Err(io::Error::other(format!(
                    "Consumed {} of {} bytes at split {split}",
                    source.consumed,
                    wire.len()
                )));
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn truncated_chunk_reports_unexpected_eof() {
        let mut source = PacketSource {
            chunks: [Bytes::from_static(b"5\r\nno")].into(),
            consumed: 0,
        };
        let result = read_chunked_chunk(
            &mut BytesMut::new(),
            &mut source,
            &log_utils::IdChain::empty(),
        )
        .await;
        assert!(result
            .as_ref()
            .is_err_and(|e| e.kind() == ErrorKind::UnexpectedEof));
    }

    #[tokio::test]
    async fn response_translation_restores_version_and_strips_hop_headers() -> io::Result<()> {
        let wire = Bytes::from_static(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nX-Test: retained\r\n\r\nbody");
        let mut source = PacketSource {
            chunks: [wire.clone()].into(),
            consumed: 0,
        };
        let (response, tail, chunked) =
            read_upstream_response(&mut source, http::Version::HTTP_2, Protocol::Http2)
                .await?
                .ok_or_else(|| io::Error::other("Missing response"))?;
        if response.version != http::Version::HTTP_2 {
            return Err(io::Error::other(format!(
                "Incorrect response version: {:?}",
                response.version
            )));
        }
        if !chunked {
            return Err(io::Error::other("Chunked transfer encoding not detected"));
        }
        if response.headers.contains_key(http::header::CONNECTION) {
            return Err(io::Error::other("Connection header was not stripped"));
        }
        if response
            .headers
            .contains_key(http::header::TRANSFER_ENCODING)
        {
            return Err(io::Error::other(
                "Transfer-Encoding header was not stripped",
            ));
        }
        if response.headers.get("x-test") != Some(&http::HeaderValue::from_static("retained")) {
            return Err(io::Error::other("X-Test header was not retained"));
        }
        if tail != b"body".as_slice() {
            return Err(io::Error::other(format!(
                "Incorrect response tail: {tail:?}"
            )));
        }
        if source.consumed != wire.len() {
            return Err(io::Error::other(format!(
                "Consumed {} of {} bytes",
                source.consumed,
                wire.len()
            )));
        }
        Ok(())
    }
}
