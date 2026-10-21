use crate::{log_utils, net_utils, tls_demultiplexer};
use rustls::crypto::aws_lc_rs;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tls_parser::{parse_tls_plaintext, TlsMessage};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, StartHandshake};

#[derive(Clone, Copy, Debug, Default)]
pub struct TlsListener {}

pub struct TlsAcceptor {
    inner: StartHandshake<PrebufferedTcpStream>,
    client_random: Option<Vec<u8>>,
}

impl TlsListener {
    pub const fn new() -> Self {
        Self {}
    }

    pub async fn listen(&self, stream: TcpStream) -> io::Result<TlsAcceptor> {
        let (stream, client_random) = Self::read_client_random_and_wrap_stream(stream).await?;

        // Now let rustls handle the stream normally
        LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
            .await
            .map(|hs| TlsAcceptor {
                inner: hs,
                client_random,
            })
    }

    async fn read_client_random_and_wrap_stream(
        mut stream: TcpStream,
    ) -> io::Result<(PrebufferedTcpStream, Option<Vec<u8>>)> {
        const MAX_PREBUFFER_LEN: usize = 16 * 1024;
        const READ_CHUNK_LEN: usize = 1024;

        let mut client_random = None;
        let mut prebuffer: Vec<u8> = Vec::new();
        while prebuffer.len() < MAX_PREBUFFER_LEN {
            match Self::extract_client_random(&prebuffer) {
                ClientRandomExtraction::Found(cr) => {
                    client_random = Some(cr);
                    break;
                }
                ClientRandomExtraction::NotFound => break,
                ClientRandomExtraction::NeedMoreData => {}
            }

            let remaining = MAX_PREBUFFER_LEN - prebuffer.len();
            let read_len = READ_CHUNK_LEN.min(remaining);
            let mut tmp = vec![0u8; read_len];
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            prebuffer.extend_from_slice(&tmp[..n]);
        }

        Ok((PrebufferedTcpStream::new(prebuffer, stream), client_random))
    }

    fn extract_client_random(data: &[u8]) -> ClientRandomExtraction {
        // Parse TLS plaintext record
        match parse_tls_plaintext(data) {
            Ok((_, plaintext)) => {
                // Look for handshake messages
                for message in &plaintext.msg {
                    if let TlsMessage::Handshake(handshake) = message {
                        // Check if this is a ClientHello handshake
                        if matches!(handshake, tls_parser::TlsMessageHandshake::ClientHello(..)) {
                            // Extract the ClientHello data
                            if let tls_parser::TlsMessageHandshake::ClientHello(client_hello) =
                                handshake
                            {
                                if client_hello.random.len() >= 32 {
                                    let client_random = client_hello.random[..32].to_vec();

                                    return ClientRandomExtraction::Found(client_random);
                                }
                            }
                        }
                    }
                }
                ClientRandomExtraction::NotFound
            }
            Err(tls_parser::Err::Incomplete(_)) => ClientRandomExtraction::NeedMoreData,
            Err(e) => {
                log::debug!("Failed to parse TLS plaintext: {e:?}");
                ClientRandomExtraction::NotFound
            }
        }
    }
}

enum ClientRandomExtraction {
    Found(Vec<u8>),
    NeedMoreData,
    NotFound,
}

pub struct PrebufferedTcpStream {
    prebuffer: Vec<u8>,
    prebuffer_pos: usize,
    stream: TcpStream,
}

impl std::fmt::Debug for PrebufferedTcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrebufferedTcpStream")
            .field("prebuffer_len", &self.prebuffer.len())
            .field("prebuffer_pos", &self.prebuffer_pos)
            .finish_non_exhaustive()
    }
}

impl PrebufferedTcpStream {
    const fn new(prebuffer: Vec<u8>, stream: TcpStream) -> Self {
        Self {
            prebuffer,
            prebuffer_pos: 0,
            stream,
        }
    }
}

impl net_utils::PeerAddr for PrebufferedTcpStream {
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}

impl AsyncRead for PrebufferedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prebuffer_pos < self.prebuffer.len() {
            let available = self.prebuffer.len() - self.prebuffer_pos;
            let to_copy = available.min(buf.remaining());
            let start = self.prebuffer_pos;
            let end = start + to_copy;
            buf.put_slice(&self.prebuffer[start..end]);
            self.prebuffer_pos = end;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrebufferedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl TlsAcceptor {
    pub fn sni(&self) -> Option<String> {
        self.inner.client_hello().server_name().map(String::from)
    }

    pub fn alpn(&self) -> Vec<Vec<u8>> {
        self.inner
            .client_hello()
            .alpn()
            .map_or_else(Vec::new, |x| x.map(Vec::from).collect())
    }

    pub fn client_random(&self) -> Option<Vec<u8>> {
        self.client_random.clone()
    }

    pub async fn accept(
        self,
        protocol: tls_demultiplexer::Protocol,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        _log_id: &log_utils::IdChain<u64>,
    ) -> io::Result<TlsStream<PrebufferedTcpStream>> {
        let tls_config = {
            let mut provider = aws_lc_rs::default_provider();
            provider.kx_groups = vec![
                aws_lc_rs::kx_group::X25519MLKEM768,
                aws_lc_rs::kx_group::X25519,
                aws_lc_rs::kx_group::SECP256R1,
                aws_lc_rs::kx_group::SECP384R1,
            ];
            let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .map_err(|e| io::Error::other(format!("TLS config error: {e}")))?
                .with_no_client_auth()
                .with_single_cert(cert_chain, key)
                .map_err(|e| {
                    io::Error::other(format!("Failed to create TLS configuration: {e}"))
                })?;

            cfg.alpn_protocols = vec![protocol.as_alpn().as_bytes().to_vec()];
            Arc::new(cfg)
        };

        self.inner.into_stream(tls_config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn client_hello_record(random: &[u8; 32]) -> io::Result<Vec<u8>> {
        let mut hello = vec![3, 3];
        hello.extend_from_slice(random);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
        let length = u16::try_from(hello.len()).map_err(io::Error::other)?;
        let mut handshake = vec![1, 0];
        handshake.extend_from_slice(&length.to_be_bytes());
        handshake.extend_from_slice(&hello);
        let length = u16::try_from(handshake.len()).map_err(io::Error::other)?;
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(&handshake);
        Ok(record)
    }

    #[test]
    fn client_random_waits_for_a_complete_record() -> io::Result<()> {
        let random = [0x42; 32];
        let record = client_hello_record(&random)?;
        for end in 0..record.len() {
            if !matches!(
                TlsListener::extract_client_random(&record[..end]),
                ClientRandomExtraction::NeedMoreData
            ) {
                return Err(io::Error::other(format!(
                    "Incomplete record accepted at byte {end}"
                )));
            }
        }
        let ClientRandomExtraction::Found(actual) = TlsListener::extract_client_random(&record)
        else {
            return Err(io::Error::other("Client random not found"));
        };
        if actual != random {
            return Err(io::Error::other(format!(
                "Client random changed: {actual:?} != {random:?}"
            )));
        }
        Ok(())
    }

    #[tokio::test]
    async fn prebuffer_is_drained_before_transport_bytes() -> io::Result<()> {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let mut client = client?;
        let (stream, _) = accepted?;
        client.write_all(b"def").await?;
        client.shutdown().await?;
        let mut stream = PrebufferedTcpStream::new(b"abc".to_vec(), stream);
        let mut first = [0; 2];
        stream.read_exact(&mut first).await?;
        if &first != b"ab" {
            return Err(io::Error::other(format!(
                "Incorrect prebuffer prefix: {first:?}"
            )));
        }
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await?;
        if &rest != b"cdef" {
            return Err(io::Error::other(format!(
                "Incorrect remaining bytes: {rest:?}"
            )));
        }
        Ok(())
    }
}
