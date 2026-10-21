use crate::forwarder::TcpConnector;
use crate::metrics::OutboundTcpSocketCounter;
use crate::net_utils::TcpDestination;
use crate::{core, forwarder, log_id, log_utils, net_utils, pipe, tunnel};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

pub struct TcpForwarder {
    context: Arc<core::Context>,
    /// Whether the destination may belong to the endpoint's private network regardless
    /// of [`crate::settings::Settings::allow_private_network_connections`]
    allow_private_network: bool,
}

struct StreamRx {
    rx: OwnedReadHalf,
    id: log_utils::IdChain<u64>,
    _metrics_guard: OutboundTcpSocketCounter,
}

struct StreamTx {
    tx: OwnedWriteHalf,
    /// This is a workaround for the fact that half-closed connections are often not
    /// supported in the wild. For example,
    /// nginx <https://mailman.nginx.org/pipermail/nginx/2008-September/007388.html>, or
    /// golang <https://github.com/golang/go/issues/18527>.
    eof_pending: bool,
    id: log_utils::IdChain<u64>,
}

impl TcpForwarder {
    pub const fn new(context: Arc<core::Context>) -> Self {
        Self {
            context,
            allow_private_network: false,
        }
    }

    /// Creates a forwarder which is allowed to reach the endpoint's private network
    /// regardless of [`crate::settings::Settings::allow_private_network_connections`].
    /// Intended for destinations taken from the endpoint configuration (and thus trusted),
    /// not from a client request.
    pub(crate) const fn new_for_configured_destination(context: Arc<core::Context>) -> Self {
        Self {
            context,
            allow_private_network: true,
        }
    }

    pub(crate) fn pipe_from_stream(
        stream: TcpStream,
        id: log_utils::IdChain<u64>,
        metrics_guard: OutboundTcpSocketCounter,
    ) -> (Box<dyn pipe::Source>, Box<dyn pipe::Sink>) {
        let (rx, tx) = stream.into_split();
        (
            Box::new(StreamRx {
                rx,
                id: id.clone(),
                _metrics_guard: metrics_guard,
            }),
            Box::new(StreamTx {
                tx,
                eof_pending: false,
                id,
            }),
        )
    }
}

#[async_trait]
impl TcpConnector for TcpForwarder {
    async fn connect(
        self: Box<Self>,
        id: log_utils::IdChain<u64>,
        meta: forwarder::TcpConnectionMeta,
    ) -> Result<(Box<dyn pipe::Source>, Box<dyn pipe::Sink>), tunnel::ConnectionError> {
        let allow_private_network =
            self.allow_private_network || self.context.settings.allow_private_network_connections;
        let peer = match meta.destination {
            TcpDestination::Address(peer) => {
                let peer_ip = peer.ip();
                if !allow_private_network && !net_utils::is_global_ip(&peer_ip) {
                    if peer_ip.is_loopback() {
                        return Err(tunnel::ConnectionError::DnsLoopback);
                    }
                    return Err(tunnel::ConnectionError::DnsNonroutable);
                }

                peer
            }
            TcpDestination::HostName(peer) => {
                enum SelectionStatus {
                    Loopback,
                    NonRoutable,
                    Suitable(SocketAddr),
                }

                log_id!(trace, id, "Resolving peer: {:?}", peer);

                let resolved = tokio::net::lookup_host(format!("{}:{}", peer.0, peer.1))
                    .await
                    .map_err(io_to_connection_error)?;

                let mut status = None;
                for a in resolved {
                    let ip = a.ip();
                    if ip.is_ipv6() && !self.context.settings.ipv6_available {
                        continue;
                    }

                    if net_utils::is_global_ip(&ip) || allow_private_network {
                        status = Some(SelectionStatus::Suitable(a));
                        break;
                    }

                    if status.is_none() && ip.is_loopback() {
                        status = Some(SelectionStatus::Loopback);
                        continue;
                    }

                    status = Some(SelectionStatus::NonRoutable);
                }

                match status {
                    None => {
                        return Err(io_to_connection_error(io::Error::other(
                            "Resolved to empty list",
                        )))
                    }
                    Some(SelectionStatus::Loopback) => {
                        return Err(tunnel::ConnectionError::DnsLoopback)
                    }
                    Some(SelectionStatus::NonRoutable) => {
                        return Err(tunnel::ConnectionError::DnsNonroutable)
                    }
                    Some(SelectionStatus::Suitable(x)) => {
                        log_id!(trace, id, "Selected address: {}", x);
                        x
                    }
                }
            }
        };

        log_id!(trace, id, "Connecting to peer: {}", peer);
        let metrics_guard = self.context.metrics.clone().outbound_tcp_socket_counter();
        TcpStream::connect(peer)
            .await
            .and_then(|s| {
                s.set_nodelay(true)?;
                Ok(s)
            })
            .map(|s| {
                if let Ok(local_addr) = s.local_addr() {
                    log_id!(
                        trace,
                        id,
                        "Connection established, local port: {}",
                        local_addr.port()
                    );
                }
                Self::pipe_from_stream(s, id, metrics_guard)
            })
            .map_err(io_to_connection_error)
    }
}

#[async_trait]
impl pipe::Source for StreamRx {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    async fn read(&mut self) -> io::Result<pipe::Data> {
        const READ_CHUNK_SIZE: usize = 64 * 1024;
        let mut buffer = Vec::with_capacity(READ_CHUNK_SIZE);

        loop {
            match self.rx.read_buf(&mut buffer).await {
                Ok(0) => break Ok(pipe::Data::Eof),
                Ok(_) => break Ok(pipe::Data::Chunk(Bytes::from(buffer))),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => break Err(e),
            }
        }
    }

    fn consume(&mut self, _size: usize) -> io::Result<()> {
        // do nothing
        Ok(())
    }
}

#[async_trait]
impl pipe::Sink for StreamTx {
    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    fn write(&mut self, mut data: Bytes) -> io::Result<Bytes> {
        if self.eof_pending {
            return Err(io::Error::other("Already shut down".to_string()));
        }

        while !data.is_empty() {
            match self.tx.try_write(data.as_ref()) {
                Ok(n) => data.advance(n),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        Ok(data)
    }

    fn eof(&mut self) -> io::Result<()> {
        // Mark eof as pending but do not close the connection yet, it will
        // be done in flush.
        self.eof_pending = true;
        Ok(())
    }

    async fn wait_writable(&mut self) -> io::Result<()> {
        if self.eof_pending {
            return Err(io::Error::other("Already shut down".to_string()));
        }

        self.tx.writable().await
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.tx.flush().await?;
        if self.eof_pending {
            self.tx.shutdown().await?;
        }
        Ok(())
    }
}

fn io_to_connection_error(error: io::Error) -> tunnel::ConnectionError {
    // for now, corresponding ErrorKind's are not stable
    if error.raw_os_error() == Some(libc::ENETUNREACH)
        || error.raw_os_error() == Some(libc::EHOSTUNREACH)
    {
        return tunnel::ConnectionError::HostUnreachable;
    }

    if error.kind() == ErrorKind::TimedOut {
        return tunnel::ConnectionError::Timeout;
    }

    tunnel::ConnectionError::Io(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    fn make_test_context_disallow_private_network() -> io::Result<Arc<core::Context>> {
        let mut ctx = core::Context::test()?;
        Arc::get_mut(&mut ctx.settings)
            .ok_or_else(|| io::Error::other("Test settings are unexpectedly shared"))?
            .allow_private_network_connections = false;
        Ok(Arc::new(ctx))
    }

    #[tokio::test]
    async fn test_connect_denies_loopback_address_when_private_network_disallowed() {
        let result = async {
            let context = make_test_context_disallow_private_network()?;
            let connector: Box<dyn TcpConnector> = Box::new(TcpForwarder::new(context));

            let meta = forwarder::TcpConnectionMeta {
                client_address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                destination: TcpDestination::Address(SocketAddr::from((Ipv4Addr::LOCALHOST, 22))),
                auth: None,
                tls_domain: String::new(),
                user_agent: None,
            };

            Ok::<_, io::Error>(connector.connect(log_utils::IdChain::empty(), meta).await)
        }
        .await;

        assert!(matches!(
            result,
            Ok(Err(tunnel::ConnectionError::DnsLoopback))
        ));
    }

    #[tokio::test]
    async fn test_connect_denies_private_address_when_private_network_disallowed() {
        let result = async {
            let context = make_test_context_disallow_private_network()?;
            let connector: Box<dyn TcpConnector> = Box::new(TcpForwarder::new(context));

            let meta = forwarder::TcpConnectionMeta {
                client_address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                destination: TcpDestination::Address(SocketAddr::from((
                    Ipv4Addr::new(192, 168, 0, 1),
                    80,
                ))),
                auth: None,
                tls_domain: String::new(),
                user_agent: None,
            };

            Ok::<_, io::Error>(connector.connect(log_utils::IdChain::empty(), meta).await)
        }
        .await;

        assert!(matches!(
            result,
            Ok(Err(tunnel::ConnectionError::DnsNonroutable))
        ));
    }

    #[tokio::test]
    async fn test_connect_denies_ipv4_mapped_private_address() {
        let result = async {
            let context = make_test_context_disallow_private_network()?;
            let connector: Box<dyn TcpConnector> = Box::new(TcpForwarder::new(context));

            // ::ffff:192.168.0.1 — IPv4-mapped private address
            let mapped_private = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0001);
            let meta = forwarder::TcpConnectionMeta {
                client_address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                destination: TcpDestination::Address(SocketAddr::V6(SocketAddrV6::new(
                    mapped_private,
                    80,
                    0,
                    0,
                ))),
                auth: None,
                tls_domain: String::new(),
                user_agent: None,
            };

            Ok::<_, io::Error>(connector.connect(log_utils::IdChain::empty(), meta).await)
        }
        .await;

        assert!(matches!(
            result,
            Ok(Err(tunnel::ConnectionError::DnsNonroutable))
        ));
    }

    #[tokio::test]
    async fn test_connect_allows_loopback_for_configured_destination() {
        let result = async {
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let listen_address = listener.local_addr()?;

            let context = make_test_context_disallow_private_network()?;
            let connector: Box<dyn TcpConnector> =
                Box::new(TcpForwarder::new_for_configured_destination(context));

            let meta = forwarder::TcpConnectionMeta {
                client_address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                destination: TcpDestination::Address(listen_address),
                auth: None,
                tls_domain: String::new(),
                user_agent: None,
            };

            connector
                .connect(log_utils::IdChain::empty(), meta)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok::<_, io::Error>(())
        }
        .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[tokio::test]
    async fn test_connect_denies_ipv4_mapped_loopback() {
        let result = async {
            let context = make_test_context_disallow_private_network()?;
            let connector: Box<dyn TcpConnector> = Box::new(TcpForwarder::new(context));

            // ::ffff:127.0.0.1 — IPv4-mapped loopback
            let mapped_loopback = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001);
            let meta = forwarder::TcpConnectionMeta {
                client_address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                destination: TcpDestination::Address(SocketAddr::V6(SocketAddrV6::new(
                    mapped_loopback,
                    22,
                    0,
                    0,
                ))),
                auth: None,
                tls_domain: String::new(),
                user_agent: None,
            };

            Ok::<_, io::Error>(connector.connect(log_utils::IdChain::empty(), meta).await)
        }
        .await;

        // IPv4-mapped loopback is blocked as non-routable (the V6 wrapper means
        // IpAddr::is_loopback() returns false, so it hits DnsNonroutable rather
        // than DnsLoopback — but the connection is denied either way)
        assert!(matches!(
            result,
            Ok(Err(tunnel::ConnectionError::DnsNonroutable))
        ));
    }
}
