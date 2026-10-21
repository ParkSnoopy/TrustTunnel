use crate::forwarder::{Forwarder, IcmpMultiplexer, UdpMultiplexer};
use crate::settings::{ForwardProtocolSettings, Settings, Socks5ForwarderSettings};
use crate::tcp_forwarder::TcpForwarder;
use crate::{
    authentication, core, datagram_pipe, downstream, forwarder, log_id, log_utils, net_utils, pipe,
    socks5_client, tunnel,
};
use async_trait::async_trait;
use base64::Engine;
use bytes::BytesMut;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub struct Socks5Forwarder {
    context: Arc<core::Context>,
}

struct TcpConnector {
    context: Arc<core::Context>,
}

struct DatagramSource {
    shared: Arc<DatagramTransceiverShared>,
    new_socket_rx: mpsc::Receiver<()>,
    pending_read: Option<SocketAddr>,
    pending_closures: VecDeque<(forwarder::UdpDatagramMeta, io::Error)>,
}

struct DatagramSink {
    shared: Arc<DatagramTransceiverShared>,
}

struct DatagramTransceiverShared {
    context: Arc<core::Context>,
    /// Key is the source address received in packet from client
    associations: Mutex<HashMap<SocketAddr, UdpAssociation>>,
    new_socket_tx: mpsc::Sender<()>,
    auth: Option<socks5_client::Authentication<'static>>,
    id: log_utils::IdChain<u64>,
}

type UdpAssociationSocket = socks5_client::UdpAssociation<TcpStream>;

impl DatagramTransceiverShared {
    fn associations(&self) -> MutexGuard<'_, HashMap<SocketAddr, UdpAssociation>> {
        self.associations.lock().unwrap_or_else(|error| {
            error!("Recovering poisoned SOCKS5 associations lock: {error}");
            error.into_inner()
        })
    }
}

struct UdpAssociation {
    socket: Arc<UdpAssociationSocket>,
    peers: HashSet<SocketAddr>,
    _metrics_guard: crate::metrics::OutboundUdpSocketCounter,
}

struct SocketError {
    source: SocketAddr,
    io: io::Error,
}

struct DatagramMuxAuthenticator {
    context: Arc<core::Context>,
}

impl Socks5Forwarder {
    pub const fn new(context: Arc<core::Context>) -> Self {
        Self { context }
    }
}

#[async_trait]
impl forwarder::UdpDatagramPipeShared for DatagramTransceiverShared {
    async fn on_new_udp_connection(&self, meta: &downstream::UdpDatagramMeta) -> io::Result<()> {
        let dest_ip = meta.destination.ip();
        if !self.context.settings.allow_private_network_connections
            && !net_utils::is_global_ip(&dest_ip)
        {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "UDP destination is in a non-routable network",
            ));
        }

        if let Some(x) = self.associations().get_mut(&meta.source) {
            if !x.peers.insert(meta.destination) {
                return Err(io::Error::other(format!(
                    "UDP association peer already present: {meta:?}"
                )));
            }
            return Ok(());
        }

        let settings = socks_settings(&self.context.settings)?;
        let socket = match socks5_client::connect(
            TcpStream::connect(settings.address).await?,
            self.auth.clone(),
            socks5_client::Request::UdpAssociate,
        )
        .await
        {
            Ok(socks5_client::ConnectResult::TcpConnection(_)) => {
                return Err(io::Error::other(
                    "SOCKS server returned a TCP connection instead of a UDP association",
                ));
            }
            Ok(socks5_client::ConnectResult::UdpAssociation(x)) => Arc::new(x),
            Ok(socks5_client::ConnectResult::Failure(x)) => {
                return Err(io::Error::other(format!(
                    "SOCKS server replied with error code: {x:?}"
                )))
            }
            Err(socks5_client::Error::Io(x)) => return Err(x),
            Err(socks5_client::Error::Protocol(x)) => {
                return Err(io::Error::other(format!("SOCKS protocol error: {x}")))
            }
            Err(socks5_client::Error::Authentication(x)) => {
                self.associations().clear();
                return Err(io::Error::other(format!("Authentication error: {x}")));
            }
        };

        let metrics_guard = self.context.metrics.clone().outbound_udp_socket_counter();
        self.associations().insert(
            meta.source,
            UdpAssociation {
                socket,
                peers: HashSet::from([meta.destination]),
                _metrics_guard: metrics_guard,
            },
        );

        match self.new_socket_tx.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => {
                self.associations().remove(&meta.source);
                Err(io::Error::other("Source waker is unexpectedly closed"))
            }
        }
    }

    fn on_connection_closed(&self, meta: &forwarder::UdpDatagramMeta) {
        let mut associations = self.associations();
        if let Some(mut x) = associations.remove(&meta.destination) {
            x.peers.remove(&meta.source);
            if !x.peers.is_empty() {
                associations.insert(meta.destination, x);
            }
        }
    }
}

impl Forwarder for Socks5Forwarder {
    fn tcp_connector(&self) -> Box<dyn forwarder::TcpConnector> {
        Box::new(TcpConnector {
            context: self.context.clone(),
        })
    }

    fn datagram_mux_authenticator(&self) -> Box<dyn forwarder::DatagramMultiplexerAuthenticator> {
        Box::new(DatagramMuxAuthenticator {
            context: self.context.clone(),
        })
    }

    fn make_udp_datagram_multiplexer(
        &self,
        id: log_utils::IdChain<u64>,
        meta: forwarder::UdpMultiplexerMeta,
    ) -> io::Result<UdpMultiplexer> {
        let settings = socks_settings(&self.context.settings)?;
        let (tx, rx) = mpsc::channel(1);
        let shared = Arc::new(DatagramTransceiverShared {
            context: self.context.clone(),
            associations: Mutex::default(),
            new_socket_tx: tx,
            auth: meta
                .auth
                .map(|x| {
                    if settings.extended_auth {
                        Ok(make_extended_auth(
                            x,
                            &meta.tls_domain,
                            &meta.client_address,
                            meta.user_agent.as_ref().map(std::convert::AsRef::as_ref),
                        )
                        .into_owned())
                    } else {
                        make_auth(x)
                    }
                })
                .transpose()
                .map_err(io::Error::other)?,
            id,
        });

        Ok((
            shared.clone(),
            Box::new(DatagramSource {
                shared: shared.clone(),
                new_socket_rx: rx,
                pending_read: None,
                pending_closures: VecDeque::default(),
            }),
            Box::new(DatagramSink { shared }),
        ))
    }

    fn make_icmp_datagram_multiplexer(
        &self,
        id: log_utils::IdChain<u64>,
    ) -> io::Result<Option<IcmpMultiplexer>> {
        self.context
            .icmp_forwarder
            .as_ref()
            .map(|x| x.make_multiplexer(id))
            .transpose()
    }
}

#[async_trait]
impl forwarder::TcpConnector for TcpConnector {
    async fn connect(
        self: Box<Self>,
        id: log_utils::IdChain<u64>,
        meta: forwarder::TcpConnectionMeta,
    ) -> Result<(Box<dyn pipe::Source>, Box<dyn pipe::Sink>), tunnel::ConnectionError> {
        // Enforce private network restrictions before forwarding to SOCKS5
        if !self.context.settings.allow_private_network_connections {
            if let net_utils::TcpDestination::Address(addr) = &meta.destination {
                let ip = addr.ip();
                if !net_utils::is_global_ip(&ip) {
                    if ip.is_loopback() {
                        return Err(tunnel::ConnectionError::DnsLoopback);
                    }
                    return Err(tunnel::ConnectionError::DnsNonroutable);
                }
            }
        }

        let (destination, port) = match &meta.destination {
            net_utils::TcpDestination::Address(x) => {
                (socks5_client::Address::IpAddress(x.ip()), x.port())
            }
            net_utils::TcpDestination::HostName(x) => {
                (socks5_client::Address::DomainName(Cow::Borrowed(&x.0)), x.1)
            }
        };

        let settings =
            socks_settings(&self.context.settings).map_err(tunnel::ConnectionError::Io)?;
        let stream = match TcpStream::connect(settings.address).await {
            Ok(s) => s,
            Err(e) => return Err(tunnel::ConnectionError::Io(e)),
        };

        match socks5_client::connect(
            stream,
            meta.auth
                .map(|x| {
                    if settings.extended_auth {
                        Ok(make_extended_auth(
                            x,
                            &meta.tls_domain,
                            &meta.client_address,
                            meta.user_agent.as_ref().map(std::convert::AsRef::as_ref),
                        ))
                    } else {
                        make_auth(x)
                    }
                })
                .transpose()
                .map_err(tunnel::ConnectionError::Other)?,
            socks5_client::Request::Connect(destination, port),
        )
        .await
        {
            Ok(socks5_client::ConnectResult::TcpConnection(stream)) => {
                let metrics_guard = self.context.metrics.clone().outbound_tcp_socket_counter();
                Ok(TcpForwarder::pipe_from_stream(stream, id, metrics_guard))
            }
            Ok(socks5_client::ConnectResult::UdpAssociation(_)) => {
                Err(tunnel::ConnectionError::Other(
                    "SOCKS server returned a UDP association instead of a TCP connection"
                        .to_string(),
                ))
            }
            Ok(socks5_client::ConnectResult::Failure(
                socks5_client::ReplyCode::HostUnreachable
                | socks5_client::ReplyCode::NetworkUnreachable,
            )) => Err(tunnel::ConnectionError::HostUnreachable),
            Ok(socks5_client::ConnectResult::Failure(
                socks5_client::ReplyCode::ConnectionRefused,
            )) => Err(tunnel::ConnectionError::Io(
                ErrorKind::ConnectionRefused.into(),
            )),
            Ok(socks5_client::ConnectResult::Failure(socks5_client::ReplyCode::TtlExpired)) => {
                Err(tunnel::ConnectionError::Timeout)
            }
            Ok(socks5_client::ConnectResult::Failure(x)) => Err(tunnel::ConnectionError::Other(
                format!("SOCKS server replied with error code: {x:?}"),
            )),
            Err(socks5_client::Error::Io(x)) => Err(tunnel::ConnectionError::Io(x)),
            Err(socks5_client::Error::Protocol(x)) => Err(tunnel::ConnectionError::Other(format!(
                "SOCKS protocol error: {x}"
            ))),
            Err(socks5_client::Error::Authentication(x)) => {
                Err(tunnel::ConnectionError::Authentication(x))
            }
        }
    }
}

#[async_trait]
impl forwarder::DatagramMultiplexerAuthenticator for DatagramMuxAuthenticator {
    async fn check_auth(
        self: Box<Self>,
        client_address: IpAddr,
        tls_domain: &'_ str,
        auth: authentication::Source<'_>,
        user_agent: Option<&'_ str>,
    ) -> Result<(), tunnel::ConnectionError> {
        let settings =
            socks_settings(&self.context.settings).map_err(tunnel::ConnectionError::Io)?;
        match socks5_client::connect(
            TcpStream::connect(settings.address)
                .await
                .map_err(tunnel::ConnectionError::Io)?,
            Some(
                if settings.extended_auth {
                    Ok(make_extended_auth(
                        auth,
                        tls_domain,
                        &client_address,
                        user_agent,
                    ))
                } else {
                    make_auth(auth)
                }
                .map_err(|x| tunnel::ConnectionError::Io(io::Error::other(x)))?,
            ),
            socks5_client::Request::UdpAssociate,
        )
        .await
        {
            Ok(socks5_client::ConnectResult::TcpConnection(_)) => {
                Err(tunnel::ConnectionError::Other(
                    "SOCKS server returned a TCP connection instead of a UDP association"
                        .to_string(),
                ))
            }
            Ok(socks5_client::ConnectResult::UdpAssociation(_)) => Ok(()),
            Ok(socks5_client::ConnectResult::Failure(x)) => Err(tunnel::ConnectionError::Other(
                format!("SOCKS server replied with error code: {x:?}"),
            )),
            Err(socks5_client::Error::Io(x)) => Err(tunnel::ConnectionError::Io(x)),
            Err(socks5_client::Error::Protocol(x)) => Err(tunnel::ConnectionError::Other(format!(
                "SOCKS protocol error: {x}"
            ))),
            Err(socks5_client::Error::Authentication(x)) => {
                Err(tunnel::ConnectionError::Authentication(x))
            }
        }
    }
}

impl DatagramSource {
    async fn read_pending_socket(
        &self,
        source: &SocketAddr,
    ) -> io::Result<Option<forwarder::UdpDatagramReadStatus>> {
        let socket = match self.shared.associations().get(source) {
            None => {
                log_id!(
                    debug,
                    self.shared.id,
                    "UDP association not found: source={}",
                    source
                );
                return Ok(None);
            }
            Some(x) => x.socket.clone(),
        };

        let mut buffer = BytesMut::zeroed(net_utils::MAX_UDP_PAYLOAD_SIZE);
        let (n, peer) = socket
            .recv_from(buffer.as_mut())
            .await
            .map_err(socks_to_io_error)?;
        buffer.truncate(n);

        Ok(Some(forwarder::UdpDatagramReadStatus::Read(
            forwarder::UdpDatagram {
                meta: forwarder::UdpDatagramMeta {
                    source: peer,
                    destination: *source,
                },
                payload: buffer.freeze(),
            },
        )))
    }

    fn on_socket_error(&mut self, source: &SocketAddr, error: &io::Error) {
        let mut associations = self.shared.associations();
        if let Some(a) = associations.remove(source) {
            self.pending_closures
                .extend(a.peers.into_iter().map(|peer| {
                    (
                        forwarder::UdpDatagramMeta {
                            source: peer,
                            destination: *source,
                        },
                        io::Error::new(error.kind(), error.to_string()),
                    )
                }));
        }
        drop(associations);
    }

    async fn poll_events(&mut self) -> io::Result<Option<SocketError>> {
        let futures = {
            type Future = Box<dyn futures::Future<Output = Result<SocketAddr, SocketError>> + Send>;

            let associations = self.shared.associations();
            let mut futures: Vec<Pin<Future>> = Vec::with_capacity(1 + associations.len());
            // add always pending future to avoid a busy loop in case of connection absence
            futures.push(Box::pin(futures::future::pending()));
            for (meta, assoc) in &*associations {
                futures.push(Box::pin(listen_socket_read(*meta, assoc.socket.clone())));
            }
            drop(associations);
            futures
        };

        let wait_reads = futures::future::select_all(futures);
        tokio::pin!(wait_reads);

        let wait_new_socket = self.new_socket_rx.recv();
        tokio::pin!(wait_new_socket);

        tokio::select! {
            event = wait_reads => match event.0 {
                Ok(ready) => {
                    self.pending_read = Some(ready);
                    Ok(None)
                }
                Err(e) => {
                    log_id!(debug, self.shared.id, "Error waiting for UDP read: source={} error={}",
                        e.source, e.io);
                    Ok(Some(e))
                }
            },
            r = wait_new_socket => if r == Some(()) { Ok(None) } else {
                log_id!(debug, self.shared.id, "Wake sender dropped");
                Err(io::Error::from(ErrorKind::UnexpectedEof))
            }
        }
    }
}

async fn listen_socket_read(
    source: SocketAddr,
    socket: Arc<UdpAssociationSocket>,
) -> Result<SocketAddr, SocketError> {
    socket
        .get_ref()
        .readable()
        .await
        .map(|()| source)
        .map_err(|io| SocketError { source, io })
}

#[async_trait]
impl datagram_pipe::Source for DatagramSource {
    type Output = forwarder::UdpDatagramReadStatus;

    fn id(&self) -> log_utils::IdChain<u64> {
        self.shared.id.clone()
    }

    async fn read(&mut self) -> io::Result<forwarder::UdpDatagramReadStatus> {
        loop {
            if let Some(source) = self.pending_read.take() {
                match self.read_pending_socket(&source).await {
                    Ok(None) => (),
                    Ok(Some(x)) => return Ok(x),
                    Err(e) => {
                        log_id!(
                            debug,
                            self.shared.id,
                            "Error reading UDP socket: source={} error={}",
                            source,
                            e
                        );
                        self.on_socket_error(&source, &e);
                    }
                }
            }

            if let Some((meta, error)) = self.pending_closures.pop_front() {
                return Ok(forwarder::UdpDatagramReadStatus::UdpClose(meta, error));
            }

            if let Some(err) = self.poll_events().await? {
                self.on_socket_error(&err.source, &err.io);
            }
        }
    }
}

#[async_trait]
impl datagram_pipe::Sink for DatagramSink {
    type Input = downstream::UdpDatagram;

    async fn write(
        &mut self,
        datagram: downstream::UdpDatagram,
    ) -> io::Result<datagram_pipe::SendStatus> {
        let meta = forwarder::UdpDatagramMeta::from(&datagram.meta);
        let socket = self
            .shared
            .associations()
            .get(&meta.source)
            .map(|x| x.socket.clone())
            .ok_or_else(|| io::Error::from(ErrorKind::NotFound))?;

        socket
            .send_to(datagram.payload.as_ref(), meta.destination)
            .await
            .map(|()| datagram_pipe::SendStatus::Sent)
            .map_err(socks_to_io_error)
    }
}

fn make_auth(
    auth: authentication::Source<'_>,
) -> Result<socks5_client::Authentication<'_>, String> {
    Ok(match auth {
        authentication::Source::Sni(x) => {
            socks5_client::Authentication::UsernamePassword(x.clone(), x)
        }
        authentication::Source::ProxyBasic(x) => {
            let credentials = base64::engine::general_purpose::STANDARD
                .decode(x.as_ref())
                .map_err(|e| e.to_string())
                .and_then(|x| String::from_utf8(x).map_err(|e| e.to_string()))?;
            let (username, password) = credentials
                .split_once(':')
                .ok_or_else(|| "Expected colon-separated credentials".to_string())?;

            socks5_client::Authentication::UsernamePassword(
                Cow::Owned(String::from(username)),
                Cow::Owned(String::from(password)),
            )
        }
    })
}

fn make_extended_auth<'a>(
    auth: authentication::Source<'a>,
    tls_domain: &'a str,
    client_address: &IpAddr,
    user_agent: Option<&'a str>,
) -> socks5_client::Authentication<'a> {
    let mut values = vec![
        socks5_client::ExtendedAuthenticationValue::Domain(Cow::Borrowed(tls_domain)),
        socks5_client::ExtendedAuthenticationValue::ClientAddress(*client_address),
    ];

    if let Some(user_agent) = user_agent {
        values.push(socks5_client::ExtendedAuthenticationValue::UserAgent(
            Cow::Borrowed(user_agent),
        ));
    }

    match auth {
        authentication::Source::Sni(_) => {
            values.push(socks5_client::ExtendedAuthenticationValue::SniAuth);
        }
        authentication::Source::ProxyBasic(x) => values.push(
            socks5_client::ExtendedAuthenticationValue::BasicProxyAuth(x),
        ),
    }

    socks5_client::Authentication::Extended(values)
}

fn socks_settings(settings: &Settings) -> io::Result<&Socks5ForwarderSettings> {
    match &settings.forward_protocol {
        ForwardProtocolSettings::Socks5(x) => Ok(x),
        ForwardProtocolSettings::Direct(_) => Err(io::Error::other(
            "SOCKS5 forwarder requires SOCKS5 settings",
        )),
    }
}

fn socks_to_io_error(err: socks5_client::Error) -> io::Error {
    match err {
        socks5_client::Error::Io(e) => e,
        socks5_client::Error::Protocol(e) => io::Error::other(format!("SOCKS protocol error: {e}")),
        socks5_client::Error::Authentication(e) => {
            io::Error::other(format!("Authentication error: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarder_requires_socks_settings() {
        let mut settings = Settings::default();
        assert!(socks_settings(&settings).is_err());
        let address = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 1080));
        settings.forward_protocol = ForwardProtocolSettings::Socks5(Socks5ForwarderSettings {
            address,
            extended_auth: true,
        });
        assert!(
            matches!(socks_settings(&settings), Ok(settings) if settings.address == address && settings.extended_auth)
        );
    }

    #[test]
    fn proxy_credentials_keep_empty_fields_and_password_colons() {
        for credentials in [":", "user:", ":password", "user:pass:word"] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
            let auth = make_auth(authentication::Source::ProxyBasic(Cow::Owned(encoded)));
            assert!(
                matches!(auth, Ok(socks5_client::Authentication::UsernamePassword(username, password)) if format!("{username}:{password}") == credentials)
            );
        }
        let missing_colon = base64::engine::general_purpose::STANDARD.encode("user");
        assert!(make_auth(authentication::Source::ProxyBasic(Cow::Owned(
            missing_colon
        )))
        .is_err());
        assert!(make_auth(authentication::Source::ProxyBasic(Cow::Borrowed("!"))).is_err());
    }
}
