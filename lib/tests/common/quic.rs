//! Fallible HTTP/3 client fixture for integration-test requests and tunnels.

use crate::common::{check, TestResult};
use bytes::{Buf, Bytes, BytesMut};
use http::{Request, Response};
use hyper::body::HttpBody;
use log::info;
use quiche::h3::{self, NameValue};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::pin::Pin;
use std::time::Duration;
use tokio::net::UdpSocket;

const MAX_QUIC_UDP_PAYLOAD_SIZE: usize = 1350;

/// One HTTP/3 connection and its active request or bidirectional tunnel stream.
pub struct Http3Session {
    socket: UdpSocket,
    quic_conn: Box<quiche::Connection>,
    h3_conn: h3::Connection,
    stream_id: Option<u64>,
    is_tunnel: bool,
}

impl std::fmt::Debug for Http3Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Http3Session")
            .field("socket", &self.socket)
            .field("stream_id", &self.stream_id)
            .field("is_tunnel", &self.is_tunnel)
            .finish_non_exhaustive()
    }
}

impl Http3Session {
    /// Connect to a loopback endpoint using its disposable certificate.
    ///
    /// # Errors
    /// Returns socket, random-number generation, QUIC configuration, and handshake errors.
    pub async fn connect(
        peer: &SocketAddr,
        server_name: &str,
        alpn: Option<&[u8]>,
    ) -> TestResult<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new()
            .fill(&mut scid)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.verify_peer(false);
        config.set_max_idle_timeout(60_000);
        config.set_max_recv_udp_payload_size(MAX_QUIC_UDP_PAYLOAD_SIZE);
        config.set_max_send_udp_payload_size(MAX_QUIC_UDP_PAYLOAD_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_application_protos(
            alpn.as_ref()
                .map_or(h3::APPLICATION_PROTOCOL, std::slice::from_ref),
        )?;
        let mut quic_conn = Box::new(quiche::connect(
            Some(server_name),
            &quiche::ConnectionId::from_ref(&scid),
            socket.local_addr()?,
            *peer,
            &mut config,
        )?);
        tokio::time::sleep(Duration::from_millis(100)).await;
        Self::flush_quic_data(&socket, &mut quic_conn)?;
        while !quic_conn.is_established() {
            Self::wait_readable(&socket, &mut quic_conn).await?;
            Self::read_out_socket(&socket, &mut quic_conn)?;
            Self::flush_quic_data(&socket, &mut quic_conn)?;
            check(
                !quic_conn.is_closed(),
                "QUIC connection closed during handshake",
            )?;
        }
        let h3_conn = h3::Connection::with_transport(&mut quic_conn, &h3::Config::new()?)?;
        Self::flush_quic_data(&socket, &mut quic_conn)?;
        Ok(Self {
            socket,
            quic_conn,
            h3_conn,
            stream_id: None,
            is_tunnel: false,
        })
    }

    /// Send a request and collect its complete response body, except CONNECT tunnel data.
    ///
    /// # Errors
    /// Returns request, response-header, body, and transport errors.
    pub async fn exchange(
        &mut self,
        request: Request<hyper::Body>,
    ) -> TestResult<(http::response::Parts, Bytes)> {
        let method = request.method().clone();
        self.send_request(request).await?;
        let response = self.recv_response_with_method(&method).await?;
        let content_length = if method == http::Method::CONNECT {
            Some(0)
        } else {
            response
                .headers
                .get(http::header::CONTENT_LENGTH)
                .map(|value| Ok::<_, crate::common::TestError>(value.to_str()?.parse::<usize>()?))
                .transpose()?
        };
        let mut content = BytesMut::with_capacity(content_length.unwrap_or_default());
        while content_length.is_none_or(|size| content.len() < size) {
            let mut buffer = vec![0; 64 * 1024];
            match self.recv(&mut buffer).await? {
                0 => break,
                size => content.extend_from_slice(&buffer[..size]),
            }
        }
        Ok((response, content.freeze()))
    }

    /// Send request headers and body, deferring FIN until the response is available.
    ///
    /// # Errors
    /// Returns malformed request, body-read, and transport errors.
    pub async fn send_request(&mut self, mut request: Request<hyper::Body>) -> TestResult {
        let uri = request.uri();
        let authority = uri.authority().ok_or("HTTP/3 request has no authority")?;
        let mut headers = vec![h3::Header::new(
            b":method",
            request.method().as_str().as_bytes(),
        )];
        if let Some(scheme) = uri.scheme_str() {
            headers.push(h3::Header::new(b":scheme", scheme.as_bytes()));
        }
        headers.push(h3::Header::new(
            b":authority",
            authority.as_str().as_bytes(),
        ));
        if let Some(path) = uri.path_and_query() {
            headers.push(h3::Header::new(b":path", path.as_str().as_bytes()));
        }
        headers.extend(
            request
                .headers()
                .iter()
                .map(|(name, value)| h3::Header::new(name.as_str().as_bytes(), value.as_bytes())),
        );
        self.stream_id = Some(
            self.h3_conn
                .send_request(&mut self.quic_conn, &headers, false)?,
        );
        Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
        while let Some(chunk) = request.body_mut().data().await {
            let mut chunk = chunk?;
            while !chunk.is_empty() {
                let stream_id = self.stream_id()?;
                match self
                    .h3_conn
                    .send_body(&mut self.quic_conn, stream_id, &chunk, false)
                {
                    Ok(size) => chunk.advance(size),
                    Err(h3::Error::Done) => {
                        Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
                        Self::wait_readable(&self.socket, &mut self.quic_conn).await?;
                    }
                    Err(error) => return Err(error.into()),
                }
                Self::read_out_socket(&self.socket, &mut self.quic_conn)?;
                Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
            }
        }
        Self::flush_quic_data(&self.socket, &mut self.quic_conn)
    }

    /// Receive response headers for a non-CONNECT request.
    ///
    /// # Errors
    /// Returns invalid response-header, unexpected HTTP/3 event, and transport errors.
    pub async fn recv_response(&mut self) -> TestResult<http::response::Parts> {
        self.recv_response_with_method(&http::Method::GET).await
    }

    async fn recv_response_with_method(
        &mut self,
        method: &http::Method,
    ) -> TestResult<http::response::Parts> {
        Self::read_out_socket(&self.socket, &mut self.quic_conn)?;
        Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
        loop {
            match self.poll().await? {
                h3::Event::Headers { list, .. } => {
                    let mut response = Response::builder().version(http::Version::HTTP_3);
                    for header in list {
                        response = match header.name() {
                            b":status" => response.status(header.value()),
                            _ => response.header(header.name(), header.value()),
                        };
                    }
                    let response = response.body(())?.into_parts().0;
                    info!("Received response: {response:?}");
                    if method == http::Method::CONNECT {
                        self.is_tunnel = true;
                    }
                    if !self.is_tunnel {
                        self.finish_stream().await?;
                    }
                    return Ok(response);
                }
                h3::Event::Finished => (),
                event => {
                    return Err(std::io::Error::other(format!(
                        "unexpected response event: {event:?}"
                    ))
                    .into())
                }
            }
        }
    }

    fn read_out_socket(socket: &UdpSocket, quic_conn: &mut quiche::Connection) -> TestResult {
        let mut buffer = [0; MAX_QUIC_UDP_PAYLOAD_SIZE];
        loop {
            match socket.try_recv_from(&mut buffer) {
                Ok((size, peer)) => {
                    let recv_info = quiche::RecvInfo {
                        from: peer,
                        to: socket.local_addr()?,
                    };
                    let consumed = quic_conn.recv(&mut buffer[..size], recv_info)?;
                    check(
                        size == consumed,
                        "QUIC did not consume the complete UDP datagram",
                    )?;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// Send chunks on the active stream, keeping CONNECT tunnels bidirectional.
    ///
    /// # Errors
    /// Returns missing-stream, socket, and HTTP/3 transport errors.
    pub async fn send(
        &mut self,
        mut stream: impl futures::stream::Stream<Item = impl Deref<Target = [u8]>> + Unpin,
    ) -> TestResult {
        while let Some(chunk) =
            futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await
        {
            let mut chunk: &[u8] = &chunk;
            while !chunk.is_empty() {
                let stream_id = self.stream_id()?;
                match self
                    .h3_conn
                    .send_body(&mut self.quic_conn, stream_id, chunk, false)
                {
                    Ok(size) => chunk = &chunk[size..],
                    Err(h3::Error::Done) => {
                        Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
                        Self::wait_readable(&self.socket, &mut self.quic_conn).await?;
                    }
                    Err(error) => return Err(error.into()),
                }
                Self::read_out_socket(&self.socket, &mut self.quic_conn)?;
                Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
            }
        }
        if !self.is_tunnel {
            self.finish_stream().await?;
        }
        Self::flush_quic_data(&self.socket, &mut self.quic_conn)
    }

    async fn finish_stream(&mut self) -> TestResult {
        loop {
            let stream_id = self.stream_id()?;
            match self
                .h3_conn
                .send_body(&mut self.quic_conn, stream_id, &[], true)
            {
                Err(h3::Error::Done) => {
                    Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
                    if self.quic_conn.timeout().is_none() {
                        break;
                    }
                    Self::wait_readable(&self.socket, &mut self.quic_conn).await?;
                    Self::read_out_socket(&self.socket, &mut self.quic_conn)?;
                }
                Ok(_)
                | Err(
                    h3::Error::TransportError(_) | h3::Error::StreamBlocked | h3::Error::IdError,
                ) => break,
                Err(error) => return Err(error.into()),
            }
        }
        Self::flush_quic_data(&self.socket, &mut self.quic_conn)
    }

    /// Receive body or tunnel data, returning zero for end of stream.
    ///
    /// # Errors
    /// Returns socket, stream-identity, unexpected HTTP/3 event, and transport errors.
    pub async fn recv(&mut self, buffer: &mut [u8]) -> TestResult<usize> {
        let received = loop {
            Self::read_out_socket(&self.socket, &mut self.quic_conn)?;
            let stream_id = self.stream_id()?;
            match self
                .h3_conn
                .recv_body(&mut self.quic_conn, stream_id, buffer)
            {
                Ok(size) => break size,
                Err(h3::Error::Done) => (),
                Err(error) => return Err(error.into()),
            }
            Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
            // Poll pending DATA and FIN before waiting for another datagram.
            match self.h3_conn.poll(&mut self.quic_conn) {
                Ok((stream_id, event)) => {
                    check(
                        stream_id == self.stream_id()?,
                        "HTTP/3 body arrived on an unexpected stream",
                    )?;
                    match event {
                        h3::Event::Data => continue,
                        h3::Event::Finished | h3::Event::Reset(_) => break 0,
                        event => {
                            return Err(std::io::Error::other(format!(
                                "unexpected body event: {event:?}"
                            ))
                            .into())
                        }
                    }
                }
                Err(h3::Error::Done) => (),
                Err(error) => return Err(error.into()),
            }
            if self.quic_conn.timeout().is_none() {
                break 0;
            }
            Self::wait_readable(&self.socket, &mut self.quic_conn).await?;
            Self::read_out_socket(&self.socket, &mut self.quic_conn)?;
        };
        Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
        Ok(received)
    }

    fn flush_quic_data(socket: &UdpSocket, quic_conn: &mut quiche::Connection) -> TestResult {
        let mut buffer = [0; MAX_QUIC_UDP_PAYLOAD_SIZE];
        loop {
            match quic_conn.send(&mut buffer) {
                Ok((size, send_info)) => match socket.try_send_to(&buffer[..size], send_info.to) {
                    Ok(_) => (),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                },
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    async fn wait_readable(socket: &UdpSocket, quic_conn: &mut quiche::Connection) -> TestResult {
        let wait = quic_conn
            .timeout()
            .ok_or("QUIC connection has no active timer")?;
        match tokio::time::timeout(wait, socket.readable()).await {
            Ok(result) => result?,
            Err(_) => quic_conn.on_timeout(),
        }
        Ok(())
    }

    async fn poll(&mut self) -> TestResult<h3::Event> {
        Self::read_out_socket(&self.socket, &mut self.quic_conn)?;
        let event = loop {
            match self.h3_conn.poll(&mut self.quic_conn) {
                Ok((stream_id, event)) => {
                    check(
                        stream_id == self.stream_id()?,
                        "HTTP/3 event arrived on an unexpected stream",
                    )?;
                    break event;
                }
                Err(h3::Error::Done) => (),
                Err(error) => return Err(error.into()),
            }
            Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
            if self.quic_conn.timeout().is_none() {
                break h3::Event::Finished;
            }
            Self::wait_readable(&self.socket, &mut self.quic_conn).await?;
            Self::read_out_socket(&self.socket, &mut self.quic_conn)?;
            check(
                !self.quic_conn.is_closed(),
                "QUIC connection closed while waiting for an HTTP/3 event",
            )?;
        };
        Self::flush_quic_data(&self.socket, &mut self.quic_conn)?;
        Ok(event)
    }

    fn stream_id(&self) -> TestResult<u64> {
        self.stream_id
            .ok_or_else(|| std::io::Error::other("HTTP/3 request stream is not initialized").into())
    }
}
