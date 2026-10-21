use crate::http_codec::{RequestHeaders, ResponseHeaders};
use crate::settings::Settings;
use crate::tls_demultiplexer::TlsDemux;
use crate::utils::Either;
use crate::{log_id, log_utils, net_utils, tls_demultiplexer, utils};
use boring::ssl::{NameType, SelectCertError, SslContextBuilder, SslMethod, SslRef};
use bytes::{Buf, Bytes, BytesMut};
use http::header::InvalidHeaderName;
use quiche::h3;
use quiche::h3::NameValue;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

const TOKEN_PREFIX_SIZE: usize = 16;
const MUX_ID_FMT: &str = "QMUX={}";
const SOCKET_ID_FMT: &str = "QSOCK={}";

const QUIC_CONNECTION_CLOSE_CODE: u64 = 0x42;

static CONN_ID_SEED: LazyLock<Result<ring::hmac::Key, ring::error::Unspecified>> =
    LazyLock::new(|| {
        let rng = ring::rand::SystemRandom::new();
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng)
    });

type QuicConnection = quiche::Connection;
type SharedQuicConnection = Arc<std::sync::Mutex<QuicConnection>>;
type NewConnectionResult =
    Result<Either<QuicSocket, SharedQuicConnection>, (io::Error, Option<SharedQuicConnection>)>;

fn recover_poison<T>(error: std::sync::PoisonError<T>) -> T {
    log::error!("Recovering poisoned QUIC state lock: {error}");
    error.into_inner()
}

pub struct QuicMultiplexer {
    core_settings: Arc<Settings>,
    socket: Arc<UdpSocket>,
    /// Receives messages from [`QuicSocket::mux_tx`]
    socket_rx: mpsc::Receiver<SocketMessage>,
    /// See [`QuicSocket::mux_tx`]
    mux_tx: Arc<std::sync::Mutex<mpsc::Sender<SocketMessage>>>,
    connections: HashMap<quiche::ConnectionId<'static>, Connection>,
    deadlines: HashMap<quiche::ConnectionId<'static>, Instant>,
    closest_deadline: Option<Instant>,
    tls_demux: Arc<std::sync::RwLock<TlsDemux>>,
    token_prefix: [u8; TOKEN_PREFIX_SIZE],
    id: log_utils::IdChain<u64>,
    next_socket_id: Arc<AtomicU64>,
}

pub struct QuicSocket {
    /// Receives messages from [`EstablishedConnection::socket_tx`]
    conn_rx: tokio::sync::Mutex<mpsc::Receiver<MultiplexerMessage>>,
    /// Sends messages to [`QuicMultiplexer::socket_rx`]
    mux_tx: Arc<std::sync::Mutex<mpsc::Sender<SocketMessage>>>,
    peer: SocketAddr,
    udp_socket: Arc<UdpSocket>,
    quic_conn: Arc<std::sync::Mutex<QuicConnection>>,
    h3_conn: Arc<std::sync::Mutex<h3::Connection>>,
    waiting_writable_streams: std::sync::Mutex<HashSet<u64>>,
    id: log_utils::IdChain<u64>,
    tls_connection_meta: tls_demultiplexer::ConnectionMeta,
    /// TLS `client_random` extracted from QUIC handshake
    client_random: Vec<u8>,
}

pub enum QuicSocketEvent {
    Request(/* stream id */ u64, Box<RequestHeaders>),
    Readable(/* stream id */ u64),
    Writable(Vec</* stream id */ u64>),
    Close(/* stream id */ u64),
}

/// Messages sent by [`QuicMultiplexer`] to [`QuicSocket`]s
#[derive(Ord, PartialOrd, Eq, PartialEq)]
enum MultiplexerMessage {
    PollH3,
    Close,
}

/// Messages sent by [`QuicSocket`]s to [`QuicMultiplexer`]
enum SocketMessage {
    Close(quiche::ConnectionId<'static>),
    /// Tell the multiplexer to re-read [`quiche::Connection::timeout`] for this connection.
    RefreshDeadline(quiche::ConnectionId<'static>),
}

struct HandshakingConnection {
    quic_conn: Arc<std::sync::Mutex<QuicConnection>>,
    local_address: SocketAddr,
    tls_connection_meta: tls_demultiplexer::ConnectionMeta,
}

struct EstablishedConnection {
    /// Sends messages to [`QuicSocket::conn_rx`]
    socket_tx: mpsc::Sender<MultiplexerMessage>,
    quic_conn: Arc<std::sync::Mutex<QuicConnection>>,
}

enum Connection {
    Handshake(HandshakingConnection),
    Established(EstablishedConnection),
}

enum UnknownPacketStatus {
    Process,
    Skip,
}

enum HandshakeStatus {
    InProgress,
    Complete,
}

/// Background means that a connection is not yet established or already being tunneled
struct BackgroundConnection {
    quic: Arc<std::sync::Mutex<QuicConnection>>,
    message: Option<(mpsc::Sender<MultiplexerMessage>, MultiplexerMessage)>,
}

impl BackgroundConnection {
    const fn with_conn(conn: Arc<std::sync::Mutex<QuicConnection>>) -> Self {
        Self {
            quic: conn,
            message: None,
        }
    }
}

impl QuicMultiplexer {
    pub fn new(
        core_settings: Arc<Settings>,
        socket: UdpSocket,
        tls_demux: Arc<std::sync::RwLock<TlsDemux>>,
        next_socket_id: Arc<AtomicU64>,
    ) -> io::Result<Self> {
        let queue_cap = core_settings
            .listen_protocols
            .quic
            .as_ref()
            .ok_or_else(|| io::Error::other("QUIC listening is not configured"))?
            .message_queue_capacity;
        let (tx, rx) = mpsc::channel(queue_cap);

        Ok(Self {
            core_settings,
            socket: Arc::new(socket),
            socket_rx: rx,
            mux_tx: Arc::new(std::sync::Mutex::new(tx)),
            connections: HashMap::new(),
            deadlines: HashMap::new(),
            closest_deadline: None,
            tls_demux,
            token_prefix: ring::rand::generate(&ring::rand::SystemRandom::new())
                .map_err(|e| {
                    io::Error::other(format!("Failed to generate QUIC token prefix: {e}"))
                })?
                .expose(),
            id: log_utils::IdChain::from(log_utils::IdItem::new(MUX_ID_FMT, 0)),
            next_socket_id,
        })
    }

    pub async fn listen(&mut self) -> io::Result<QuicSocket> {
        enum Event {
            UdpRead,
            UdpSend(SocketMessage),
        }

        loop {
            let event = {
                let wait_timeout =
                    tokio::time::sleep_until(self.closest_deadline.unwrap_or_else(Instant::now));
                tokio::pin!(wait_timeout);

                let wait_udp_send = self.socket_rx.recv();
                tokio::pin!(wait_udp_send);

                let wait_udp_read = self.socket.readable();
                tokio::pin!(wait_udp_read);

                tokio::select! {
                    r = wait_udp_read => match r {
                        Ok(()) => Some(Event::UdpRead),
                        Err(e) => return Err(e),
                    },
                    r = wait_udp_send => match r {
                        Some(m) => Some(Event::UdpSend(m)),
                        None => return Err(io::Error::other("Message receiving channel closed unexpectedly")),
                    },
                    // Arm this even for an expired deadline: tokio timers fire slightly
                    // after the deadline, so a `> now` guard disables the branch exactly
                    // when the timer fires and timeouts would only run on incoming packets.
                    () = &mut wait_timeout, if self.closest_deadline.is_some() => None,
                }
            };

            self.process_timeouts();

            match event {
                None => (),
                Some(Event::UdpSend(m)) => self.on_socket_message(m),
                Some(Event::UdpRead) => {
                    if let Some(s) = self.read_udp_socket()? {
                        return Ok(s);
                    }
                }
            }

            self.process_pending_socket_messages()?;
            self.remove_closed_connections();
        }
    }

    fn read_udp_socket(&mut self) -> io::Result<Option<QuicSocket>> {
        struct Entry {
            conn: Arc<std::sync::Mutex<QuicConnection>>,
            socket_tx: Option<mpsc::Sender<MultiplexerMessage>>,
            messages: BTreeSet<MultiplexerMessage>,
        }

        const READ_BUDGET: usize = 1024;

        let mut socket = None;
        let mut pending = HashMap::with_capacity(READ_BUDGET / 2);
        let mut buffer = vec![0; net_utils::MAX_UDP_PAYLOAD_SIZE];
        for _ in 0..READ_BUDGET {
            match self.socket.try_recv_from(&mut buffer) {
                Ok((n, peer)) => {
                    let header =
                        match quiche::Header::from_slice(&mut buffer[..n], quiche::MAX_CONN_ID_LEN)
                        {
                            Ok(h) => {
                                log_id!(trace, self.id, "Received QUIC packet: {:?}", h);
                                h
                            }
                            Err(e) => {
                                log_id!(debug, self.id, "Parsing UDP packet header failed: {}", e);
                                continue;
                            }
                        };

                    match self.on_quic_packet(&peer, &header, &mut buffer[..n]) {
                        Some(Either::Left(s)) => {
                            pending.entry(header.dcid).or_insert_with(|| Entry {
                                conn: s.quic_conn.clone(),
                                socket_tx: None,
                                messages: BTreeSet::new(),
                            });
                            socket = Some(s);
                            break;
                        }
                        Some(Either::Right(x)) => {
                            let entry = pending.entry(header.dcid).or_insert_with(|| Entry {
                                conn: x.quic,
                                socket_tx: None,
                                messages: BTreeSet::new(),
                            });
                            if let Some((tx, msg)) = x.message {
                                entry.socket_tx = Some(tx);
                                entry.messages.insert(msg);
                            }
                        }
                        None => (),
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        for (conn_id, entry) in pending {
            let result = entry
                .socket_tx
                .iter()
                .cycle()
                .zip(entry.messages)
                .try_for_each(|(sender, msg)| match sender.try_send(msg) {
                    // `Full` is not considered as an error in this case, as the connection does not need
                    // multiple `poll` messages in the queue
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        Err(io::Error::other("Channel closed"))
                    }
                });

            let mut quic_conn = entry.conn.lock().unwrap_or_else(recover_poison);
            if let Err(e) = result {
                if let Err(e) =
                    quic_conn.close(false, QUIC_CONNECTION_CLOSE_CODE, e.to_string().as_bytes())
                {
                    log_id!(debug, self.id, "Failed to close QUIC connection: {}", e);
                }
            }

            if let Some(timeout) = quic_conn.timeout() {
                self.update_connection_deadline(conn_id, timeout);
            }

            if let Err(e) = flush_pending_data(&mut quic_conn, &self.socket, &self.id) {
                log_id!(debug, self.id, "Failed to flush QUIC connection: {}", e);
            }
            drop(quic_conn);
        }

        Ok(socket)
    }

    fn on_quic_packet(
        &mut self,
        peer: &SocketAddr,
        header: &quiche::Header<'static>,
        packet: &mut [u8],
    ) -> Option<Either<QuicSocket, BackgroundConnection>> {
        let (quic_conn, err) = match self.connections.get(&header.dcid) {
            None => match self.on_unknown_quic_packet(peer, header) {
                Ok(UnknownPacketStatus::Process) => {
                    match self.on_new_connection(peer, header, packet) {
                        Ok(x) => return Some(x.map_right(BackgroundConnection::with_conn)),
                        Err((e, Some(quic))) => (quic, e),
                        Err((e, None)) => {
                            log_id!(
                                debug,
                                self.id,
                                "Failed to process QUIC packet: header={:?}, error={}",
                                header,
                                e
                            );
                            return None;
                        }
                    }
                }
                Ok(UnknownPacketStatus::Skip) => return None,
                Err(e) => {
                    log_id!(
                        debug,
                        self.id,
                        "Failed to process QUIC packet: header={:?}, error={}",
                        header,
                        e
                    );
                    return None;
                }
            },
            Some(Connection::Handshake(conn)) => {
                match conn.proceed_handshake(peer, packet, &self.id) {
                    Ok(HandshakeStatus::InProgress) => {
                        return Some(Either::with_right(BackgroundConnection::with_conn(
                            conn.quic_conn.clone(),
                        )))
                    }
                    Ok(HandshakeStatus::Complete) => {
                        self.deadlines.remove(&header.dcid);
                        let conn = self.connections.remove(&header.dcid).and_then(|x| match x {
                            Connection::Handshake(x) => Some(x),
                            Connection::Established(_) => None,
                        });
                        let Some(conn) = conn else {
                            log_id!(error, self.id, "QUIC handshake connection disappeared");
                            return None;
                        };
                        match self.finalize_established_connection(&header.dcid, conn, peer) {
                            Ok(sock) => return Some(Either::with_left(sock)),
                            Err((e, q)) => (q, e),
                        }
                    }
                    Err(e) => (conn.quic_conn.clone(), e),
                }
            }
            Some(Connection::Established(conn)) => {
                match self.proceed_established_connection(conn, peer, packet) {
                    Ok(()) => {
                        return Some(Either::with_right(BackgroundConnection {
                            quic: conn.quic_conn.clone(),
                            message: Some((conn.socket_tx.clone(), MultiplexerMessage::PollH3)),
                        }))
                    }
                    Err(e) => (conn.quic_conn.clone(), e),
                }
            }
        };

        {
            let mut quic_conn = quic_conn.lock().unwrap_or_else(recover_poison);
            log_id!(
                debug,
                self.id,
                "Failed to process QUIC packet: header={:?}, error={}",
                header,
                err
            );
            if let Err(e) = quic_conn.close(
                false,
                QUIC_CONNECTION_CLOSE_CODE,
                err.to_string().as_bytes(),
            ) {
                log_id!(debug, self.id, "Failed to close QUIC connection: {}", e);
            }
        }

        Some(Either::with_right(BackgroundConnection::with_conn(
            quic_conn,
        )))
    }

    fn on_unknown_quic_packet(
        &self,
        peer: &SocketAddr,
        header: &quiche::Header<'_>,
    ) -> io::Result<UnknownPacketStatus> {
        if !matches!(header.ty, quiche::Type::Initial) {
            return Err(io::Error::other(format!(
                "Unexpected packet type: {header:?}"
            )));
        }

        if !quiche::version_is_supported(header.version) {
            log_id!(trace, self.id, "Doing version negotiation: {:?}", header);
            let mut out = vec![0; net_utils::MAX_UDP_PAYLOAD_SIZE];
            let n = quiche::negotiate_version(&header.scid, &header.dcid, &mut out)
                .map_err(|e| io::Error::other(format!("Version negotiation failed: {e}")))?;
            return self
                .socket
                .try_send_to(&out[..n], *peer)
                .map(|_| UnknownPacketStatus::Skip);
        }

        let quic_token = header
            .token
            .as_ref()
            .ok_or_else(|| io::Error::other("Invalid packet: initial packet must contain token"))?;

        let seed = CONN_ID_SEED.as_ref().map_err(|e| {
            io::Error::other(format!("Failed to generate QUIC connection ID seed: {e}"))
        })?;
        let conn_id = ring::hmac::sign(seed, &header.dcid);
        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];

        let scid = quiche::ConnectionId::from_ref(conn_id);

        if quic_token.is_empty() {
            log_id!(trace, self.id, "Doing stateless retry: {:?}", header);
            let mut out = vec![0; net_utils::MAX_UDP_PAYLOAD_SIZE];
            let n = quiche::retry(
                &header.scid,
                &header.dcid,
                &scid,
                &mint_token(header, &self.token_prefix, peer),
                header.version,
                &mut out,
            )
            .map_err(|e| io::Error::other(format!("Retry failed: {e}")))?;
            return self
                .socket
                .try_send_to(&out[..n], *peer)
                .map(|_| UnknownPacketStatus::Skip);
        }

        if scid.len() != header.dcid.len() {
            return Err(io::Error::other(
                "Invalid packet: unexpected destination connection ID",
            ));
        }

        Ok(UnknownPacketStatus::Process)
    }

    fn accept_quic_connection<'a>(
        &self,
        scid: &quiche::ConnectionId<'a>,
        odcid: Option<&quiche::ConnectionId<'a>>,
        peer: &SocketAddr,
        packet: &mut [u8],
    ) -> io::Result<QuicConnection> {
        let local_address = self.core_settings.listen_address;
        let mut quic_config =
            make_quic_config_with_domain_contexts(&self.core_settings, &self.tls_demux)?;
        let mut quic_conn = quiche::accept(scid, odcid, local_address, *peer, &mut quic_config)
            .map_err(|e| io::Error::other(format!("Failed to accept QUIC connection: {e}")))?;

        quic_recv(
            &mut quic_conn,
            packet,
            &quiche::RecvInfo {
                from: *peer,
                to: local_address,
            },
            &self.id,
        )?;

        Ok(quic_conn)
    }

    fn finalize_established_connection(
        &mut self,
        conn_id: &quiche::ConnectionId<'_>,
        mut conn: HandshakingConnection,
        peer: &SocketAddr,
    ) -> Result<QuicSocket, (io::Error, Arc<std::sync::Mutex<QuicConnection>>)> {
        let quic_conn = conn.quic_conn;

        let sni = quic_conn
            .lock()
            .unwrap_or_else(recover_poison)
            .server_name()
            .unwrap_or("")
            .to_string();

        if sni.is_empty() {
            log_id!(
                debug,
                self.id,
                "SNI is empty in finalize_established_connection, using bootstrap meta"
            );
        } else {
            let tls_demux = self.tls_demux.read().unwrap_or_else(recover_poison);
            if let Ok(meta) = tls_demux.select(
                std::iter::once(tls_demultiplexer::Protocol::Http3.as_alpn().as_bytes()),
                sni,
            ) {
                conn.tls_connection_meta = meta;
            }
            drop(tls_demux);
        }

        let h3_conn = {
            let mut quic = quic_conn.lock().unwrap_or_else(recover_poison);
            let h3_config = h3::Config::new()
                .map_err(|e| (io::Error::other(e.to_string()), quic_conn.clone()))?;
            let h3_conn = match h3::Connection::with_transport(&mut quic, &h3_config) {
                Ok(x) => x,
                Err(e) => {
                    drop(quic);
                    return Err((
                        io::Error::other(format!("Failed to open HTTP3 session: {e}")),
                        quic_conn,
                    ));
                }
            };

            drop(quic);
            Arc::new(std::sync::Mutex::new(h3_conn))
        };

        // Extract client_random from QUIC after handshake is complete
        let extracted_client_random = {
            let mut quic = quic_conn.lock().unwrap_or_else(recover_poison);
            let ssl: &mut SslRef = quic.as_mut();
            let mut client_random = [0u8; 32];
            ssl.client_random(&mut client_random);
            let client_random = client_random.to_vec();
            drop(quic);
            client_random
        };

        let (tx, rx) = mpsc::channel(1);
        self.connections.insert(
            conn_id.clone().into_owned(),
            Connection::Established(EstablishedConnection {
                socket_tx: tx,
                quic_conn: quic_conn.clone(),
            }),
        );

        Ok(QuicSocket {
            conn_rx: tokio::sync::Mutex::new(rx),
            mux_tx: self.mux_tx.clone(),
            peer: *peer,
            udp_socket: self.socket.clone(),
            quic_conn,
            h3_conn,
            waiting_writable_streams: std::sync::Mutex::default(),
            id: self.id.extended(log_utils::IdItem::new(
                SOCKET_ID_FMT,
                self.next_socket_id.fetch_add(1, Ordering::Relaxed),
            )),
            tls_connection_meta: conn.tls_connection_meta,
            client_random: extracted_client_random,
        })
    }

    fn on_new_connection(
        &mut self,
        peer: &SocketAddr,
        header: &quiche::Header<'_>,
        packet: &mut [u8],
    ) -> NewConnectionResult {
        let token = header
            .token
            .as_ref()
            .ok_or_else(|| (io::Error::other("Invalid packet: token missing"), None))?;
        let odcid = validate_token(&self.token_prefix, peer, token)
            .ok_or_else(|| (io::Error::other("Invalid packet: unexpected token"), None))?;

        log_id!(
            debug,
            self.id,
            "New connection: dcid={} scid={}",
            utils::hex_dump(&header.dcid),
            utils::hex_dump(&header.scid)
        );

        // Create QUIC connection - TLS callback will handle certificate selection automatically
        let quic_conn = self
            .accept_quic_connection(&header.dcid, Some(&odcid), peer, packet)
            .map_err(|e| (e, None))?;

        // Get connection metadata after handshake (SNI will be available)
        let tls_connection_meta = self
            .tls_demux
            .read()
            .unwrap_or_else(recover_poison)
            .get_quic_connection_bootstrap_meta()
            .map_err(|e| (e, None))?;

        log_id!(debug, self.id, "Bootstrap meta: {:?}", tls_connection_meta);

        let is_established = quic_conn.is_established() || quic_conn.is_in_early_data();
        let quic_conn = Arc::new(std::sync::Mutex::new(quic_conn));
        let conn = HandshakingConnection {
            quic_conn: quic_conn.clone(),
            local_address: self.core_settings.listen_address,
            tls_connection_meta,
        };

        if is_established {
            return self
                .finalize_established_connection(&header.dcid, conn, peer)
                .map(Either::with_left)
                .map_err(|(e, q)| (e, Some(q)));
        }

        self.connections.insert(
            header.dcid.clone().into_owned(),
            Connection::Handshake(conn),
        );
        Ok(Either::with_right(quic_conn))
    }

    fn proceed_established_connection(
        &self,
        conn: &EstablishedConnection,
        peer: &SocketAddr,
        packet: &mut [u8],
    ) -> io::Result<()> {
        quic_recv(
            &mut conn.quic_conn.lock().unwrap_or_else(recover_poison),
            packet,
            &quiche::RecvInfo {
                from: *peer,
                to: self.core_settings.listen_address,
            },
            &self.id,
        )
    }

    fn update_connection_deadline(
        &mut self,
        conn_id: quiche::ConnectionId<'static>,
        duration: Duration,
    ) {
        let deadline = Instant::now() + duration;
        self.deadlines.insert(conn_id, deadline);
        self.closest_deadline = self.deadlines.values().min().copied();
    }

    fn process_timeouts(&mut self) {
        let now = Instant::now();

        let timedout: Vec<_> = self
            .deadlines
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(conn_id, _)| conn_id.clone())
            .collect();

        for conn_id in timedout {
            self.deadlines.remove(&conn_id);

            let quic_conn_arc = match self.connections.get(&conn_id) {
                None => {
                    log_id!(
                        debug,
                        self.id,
                        "Expired connection not found: {:?}",
                        conn_id
                    );
                    continue;
                }
                Some(Connection::Handshake(conn)) => conn.quic_conn.clone(),
                Some(Connection::Established(conn)) => conn.quic_conn.clone(),
            };

            let new_timeout = {
                let mut quic_conn = quic_conn_arc.lock().unwrap_or_else(recover_poison);
                quic_conn.on_timeout();
                if let Err(e) = flush_pending_data(&mut quic_conn, &self.socket, &self.id) {
                    log_id!(debug, self.id, "Failed to flush after on_timeout: {}", e);
                }
                quic_conn.timeout()
            };

            if let Some(timeout) = new_timeout {
                self.update_connection_deadline(conn_id, timeout);
            }
        }

        self.closest_deadline = self.deadlines.values().min().copied();
    }

    fn on_socket_message(&mut self, message: SocketMessage) {
        match message {
            SocketMessage::Close(conn_id) => {
                self.connections.remove(&conn_id);
            }
            SocketMessage::RefreshDeadline(conn_id) => {
                let quic_conn = match self.connections.get(&conn_id) {
                    Some(Connection::Handshake(c)) => c.quic_conn.clone(),
                    Some(Connection::Established(c)) => c.quic_conn.clone(),
                    None => return,
                };
                let timeout = quic_conn.lock().unwrap_or_else(recover_poison).timeout();
                match timeout {
                    Some(d) => self.update_connection_deadline(conn_id, d),
                    None => {
                        if self.deadlines.remove(&conn_id).is_some() {
                            self.closest_deadline = self.deadlines.values().min().copied();
                        }
                    }
                }
            }
        }
    }

    fn process_pending_socket_messages(&mut self) -> io::Result<()> {
        loop {
            match self.socket_rx.try_recv() {
                Ok(m) => self.on_socket_message(m),
                Err(mpsc::error::TryRecvError::Empty) => return Ok(()),
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err(io::Error::other(
                        "Message receive channel closed unexpectedly",
                    ))
                }
            }
        }
    }

    fn remove_closed_connections(&mut self) {
        let closed: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, conn)| match conn {
                Connection::Handshake(c) => c
                    .quic_conn
                    .lock()
                    .unwrap_or_else(recover_poison)
                    .is_closed(),
                Connection::Established(c) => c
                    .quic_conn
                    .lock()
                    .unwrap_or_else(recover_poison)
                    .is_closed(),
            })
            .map(|(id, _)| id.clone())
            .collect();

        for conn_id in closed {
            self.deadlines.remove(&conn_id);
            if let Some(Connection::Established(c)) = self.connections.remove(&conn_id) {
                if let Err(e) = c.socket_tx.try_send(MultiplexerMessage::Close) {
                    log_id!(debug, self.id, "Failed to notify closed QUIC socket: {}", e);
                }
            }
        }
    }
}

impl net_utils::PeerAddr for QuicSocket {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
}

impl QuicSocket {
    pub fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    pub const fn tls_connection_meta(&self) -> &tls_demultiplexer::ConnectionMeta {
        &self.tls_connection_meta
    }

    pub fn client_random(&self) -> Vec<u8> {
        self.client_random.clone()
    }

    pub fn send_response(
        &self,
        stream_id: u64,
        response: &ResponseHeaders,
        fin: bool,
    ) -> io::Result<()> {
        let response: Vec<_> = std::iter::once(h3::HeaderRef::new(
            b":status",
            response.status.as_str().as_bytes(),
        ))
        .chain(
            response
                .headers
                .iter()
                .map(|(n, v)| h3::HeaderRef::new(n.as_ref(), v.as_ref())),
        )
        .collect();

        self.h3_conn
            .lock()
            .unwrap_or_else(recover_poison)
            .send_response(
                &mut self.quic_conn.lock().unwrap_or_else(recover_poison),
                stream_id,
                response.as_slice(),
                fin,
            )
            .map_err(|e| {
                let kind = if matches!(e, h3::Error::StreamBlocked) {
                    ErrorKind::WouldBlock
                } else {
                    ErrorKind::Other
                };
                io::Error::new(kind, e.to_string())
            })?;

        self.flush_pending_data()
    }

    pub fn read(&self, stream_id: u64) -> io::Result<Option<Bytes>> {
        let chunk = {
            const READ_CHUNK_SIZE: usize = 64 * 1024;
            let mut bytes = BytesMut::zeroed(READ_CHUNK_SIZE);

            let mut read_offset = 0;
            loop {
                let buf = bytes.split_at_mut(read_offset).1;
                let mut h3_conn = self.h3_conn.lock().unwrap_or_else(recover_poison);
                let mut quic_conn = self.quic_conn.lock().unwrap_or_else(recover_poison);
                match h3_conn.recv_body(&mut quic_conn, stream_id, buf) {
                    Ok(n) => {
                        read_offset += n;
                        if read_offset == bytes.capacity() {
                            break Some(bytes.freeze());
                        }
                    }
                    Err(h3::Error::Done) if read_offset > 0 => {
                        bytes.truncate(read_offset);
                        break Some(bytes.freeze());
                    }
                    Err(h3::Error::Done) => break None,
                    Err(e) => return Err(io::Error::other(e.to_string())),
                }
                drop(quic_conn);
                drop(h3_conn);
            }
        };

        self.flush_pending_data()?;
        Ok(chunk)
    }

    pub fn write(&self, stream_id: u64, mut data: Bytes) -> io::Result<Bytes> {
        {
            let mut h3_conn = self.h3_conn.lock().unwrap_or_else(recover_poison);
            let mut quic_conn = self.quic_conn.lock().unwrap_or_else(recover_poison);
            match h3_conn.send_body(&mut quic_conn, stream_id, data.as_ref(), false) {
                Ok(n) => data.advance(n),
                Err(h3::Error::Done | h3::Error::StreamBlocked) => (),
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
            drop(quic_conn);
            drop(h3_conn);
        }

        self.flush_pending_data().map(|()| data)
    }

    pub fn stream_capacity(&self, stream_id: u64) -> io::Result<usize> {
        self.quic_conn
            .lock()
            .unwrap_or_else(recover_poison)
            .stream_capacity(stream_id)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    pub fn stream_finished(&self, stream_id: u64) -> bool {
        self.quic_conn
            .lock()
            .unwrap_or_else(recover_poison)
            .stream_finished(stream_id)
    }

    pub fn notify_stream_waiting_writable(&self, stream_id: u64) {
        self.waiting_writable_streams
            .lock()
            .unwrap_or_else(recover_poison)
            .insert(stream_id);
    }

    pub fn shutdown_stream(&self, stream_id: u64, direction: quiche::Shutdown) {
        match direction {
            quiche::Shutdown::Write => {
                // `stream_shutdown(Write)` is dropping still unsent data
                let mut quic_conn = self.quic_conn.lock().unwrap_or_else(recover_poison);
                if let Err(e) = quic_conn.stream_send(stream_id, &[], true) {
                    log_id!(debug, self.id, "Failed to finish QUIC stream: {}", e);
                }
                drop(quic_conn);
            }
            quiche::Shutdown::Read => {
                let mut quic_conn = self.quic_conn.lock().unwrap_or_else(recover_poison);
                if let Err(e) = quic_conn.stream_shutdown(stream_id, direction, 0) {
                    log_id!(debug, self.id, "Failed to shut down QUIC stream: {}", e);
                }
                drop(quic_conn);
            }
        }
        if let Err(e) = self.flush_pending_data() {
            log_id!(debug, self.id, "Failed to flush QUIC shutdown data: {}", e);
        }
    }

    pub fn graceful_shutdown(&self) -> io::Result<()> {
        {
            let mut quic_conn = self.quic_conn.lock().unwrap_or_else(recover_poison);
            let mut h3_conn = self.h3_conn.lock().unwrap_or_else(recover_poison);
            for stream_id in quic_conn.writable() {
                if let Err(e) = h3_conn.send_body(&mut quic_conn, stream_id, &[], true) {
                    log_id!(
                        debug,
                        self.id,
                        "Failed to finish HTTP3 stream during shutdown: {}",
                        e
                    );
                }
            }
        }
        if let Err(e) = self.flush_pending_data() {
            log_id!(debug, self.id, "Failed to flush QUIC shutdown data: {}", e);
        }

        self.quic_conn
            .lock()
            .unwrap_or_else(recover_poison)
            .close(true, 0, b"bye")
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.flush_pending_data()
    }

    pub async fn listen(&self) -> io::Result<QuicSocketEvent> {
        loop {
            let event = loop {
                match self.process_pending_h3_events()? {
                    None => {
                        let writable_streams: Vec<_> = {
                            let mut quic_conn =
                                self.quic_conn.lock().unwrap_or_else(recover_poison);
                            let mut waiting_streams = self
                                .waiting_writable_streams
                                .lock()
                                .unwrap_or_else(recover_poison);
                            // Avoid emitting Writable events for streams with negligible capacity.
                            let writable_streams: Vec<_> = waiting_streams
                                .iter()
                                .filter(|id| {
                                    quic_conn.stream_capacity(**id).map_or(true, |x| {
                                        x >= net_utils::MIN_USABLE_QUIC_STREAM_CAPACITY
                                    })
                                })
                                .copied()
                                .collect();
                            waiting_streams.retain(|id| !writable_streams.contains(id));
                            writable_streams
                        };

                        if !writable_streams.is_empty() {
                            break Some(QuicSocketEvent::Writable(writable_streams));
                        }
                    }
                    Some(event) => break Some(event),
                }

                match self
                    .conn_rx
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?
                {
                    MultiplexerMessage::PollH3 => (),
                    MultiplexerMessage::Close => break None,
                }
            };

            let quic_conn = self.quic_conn.lock().unwrap_or_else(recover_poison);
            if quic_conn.is_closed() {
                let mux_tx = self.mux_tx.lock().unwrap_or_else(recover_poison);
                if let Err(e) =
                    mux_tx.try_send(SocketMessage::Close(quic_conn.source_id().into_owned()))
                {
                    log_id!(
                        debug,
                        self.id,
                        "Failed to notify closed QUIC connection: {}",
                        e
                    );
                }
                drop(mux_tx);
                return Err(io::Error::from(ErrorKind::UnexpectedEof));
            }

            match event {
                None => (),
                Some(ev) => return Ok(ev),
            }
            drop(quic_conn);
        }
    }

    fn flush_pending_data(&self) -> io::Result<()> {
        let (result, conn_id) = {
            let mut quic_conn = self.quic_conn.lock().unwrap_or_else(recover_poison);
            let r = flush_pending_data(&mut quic_conn, &self.udp_socket, &self.id);
            (r, quic_conn.source_id().into_owned())
        };
        // Notify the multiplexer that the loss-detection timer may have changed
        let mux_tx = self.mux_tx.lock().unwrap_or_else(recover_poison);
        if let Err(e) = mux_tx.try_send(SocketMessage::RefreshDeadline(conn_id)) {
            log_id!(debug, self.id, "Failed to refresh QUIC deadline: {}", e);
        }
        drop(mux_tx);
        result
    }

    fn poll_h3_connection(&self) -> h3::Result<(u64, h3::Event)> {
        self.h3_conn
            .lock()
            .unwrap_or_else(recover_poison)
            .poll(&mut self.quic_conn.lock().unwrap_or_else(recover_poison))
    }

    fn process_pending_h3_events(&self) -> io::Result<Option<QuicSocketEvent>> {
        match self.poll_h3_connection() {
            Ok((stream_id, h3::Event::Headers { list, .. })) => {
                match Self::on_request(stream_id, list) {
                    Ok(x) => Ok(Some(x)),
                    Err(e) => {
                        let mut response = http::Response::<()>::default().into_parts().0;
                        response.status = http::StatusCode::BAD_REQUEST;
                        if let Err(e) = self.send_response(stream_id, &response, true) {
                            log_id!(debug, self.id, "Failed to send bad HTTP3 response: {}", e);
                        }
                        Err(e)
                    }
                }
            }
            Ok((stream_id, h3::Event::Data)) => Ok(Some(QuicSocketEvent::Readable(stream_id))),
            Ok((stream_id, h3::Event::Finished)) => Ok(Some(QuicSocketEvent::Close(stream_id))),
            Ok((stream_id, h3::Event::Reset(err))) => {
                log_id!(
                    trace,
                    self.id,
                    "Stream reset by client: id={}, err={}",
                    stream_id,
                    err
                );
                Ok(Some(QuicSocketEvent::Close(stream_id)))
            }
            Ok((_, h3::Event::PriorityUpdate)) | Err(h3::Error::Done) => Ok(None),
            Ok((_, h3::Event::GoAway)) => {
                Err(io::Error::new(ErrorKind::UnexpectedEof, "Received GOAWAY"))
            }
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn on_request(stream_id: u64, headers: Vec<h3::Header>) -> io::Result<QuicSocketEvent> {
        let mut request_builder = http::request::Request::builder().version(http::Version::HTTP_3);

        let mut uri_builder = http::uri::Uri::builder();
        for h in headers {
            match h.name() {
                b":method" => request_builder = request_builder.method(h.value()),
                b":scheme" => uri_builder = uri_builder.scheme(h.value()),
                b":authority" => uri_builder = uri_builder.authority(h.value()),
                b":path" => uri_builder = uri_builder.path_and_query(h.value()),
                x => {
                    request_builder = match http::header::HeaderName::from_lowercase(x) {
                        Ok(name) => request_builder.header(name, h.value()),
                        Err(InvalidHeaderName { .. }) => {
                            return Err(io::Error::new(
                                ErrorKind::InvalidData,
                                format!("Unexpected header name: 0x{}", utils::hex_dump(h.name())),
                            ))
                        }
                    }
                }
            }
        }

        request_builder
            .uri(
                uri_builder.build().map_err(|e| {
                    io::Error::new(ErrorKind::InvalidData, format!("Invalid URI: {e}"))
                })?,
            )
            .body(())
            .map(|r| QuicSocketEvent::Request(stream_id, Box::new(r.into_parts().0)))
            .map_err(|e| io::Error::other(format!("Invalid request: {e}")))
    }
}

impl HandshakingConnection {
    fn proceed_handshake(
        &self,
        peer: &SocketAddr,
        packet: &mut [u8],
        log_id: &log_utils::IdChain<u64>,
    ) -> io::Result<HandshakeStatus> {
        let mut quic_conn = self.quic_conn.lock().unwrap_or_else(recover_poison);
        quic_recv(
            &mut quic_conn,
            packet,
            &quiche::RecvInfo {
                from: *peer,
                to: self.local_address,
            },
            log_id,
        )?;

        if quic_conn.is_closed() {
            return Err(io::Error::other(format!(
                "[{}] Connection closed",
                quic_conn.trace_id()
            )));
        }

        if quic_conn.is_draining() || (!quic_conn.is_established() && !quic_conn.is_in_early_data())
        {
            Ok(HandshakeStatus::InProgress)
        } else {
            Ok(HandshakeStatus::Complete)
        }
    }
}

fn flush_pending_data(
    quic_conn: &mut quiche::Connection,
    udp_socket: &UdpSocket,
    id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    let mut out = vec![0; net_utils::MAX_UDP_PAYLOAD_SIZE];
    loop {
        match quic_conn.send(&mut out) {
            Ok((n, info)) => udp_socket_send_to(udp_socket, &out[..n], &info.to, id)?,
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(io::Error::other(e.to_string())),
        }
    }

    Ok(())
}

fn udp_socket_send_to(
    socket: &UdpSocket,
    data: &[u8],
    peer: &SocketAddr,
    id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    match socket.try_send_to(data, *peer) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS) => {
            log_id!(
                debug,
                id,
                "Dropping {} bytes due to socket would block: peer={}",
                data.len(),
                peer
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn quic_recv(
    conn: &mut quiche::Connection,
    packet: &mut [u8],
    info: &quiche::RecvInfo,
    id: &log_utils::IdChain<u64>,
) -> io::Result<()> {
    match conn.recv(packet, *info) {
        Ok(n) => {
            if n != packet.len() {
                log_id!(
                    debug,
                    id,
                    "Dropping {} bytes unaccepted during handshake: {}",
                    packet.len() - n,
                    conn.trace_id()
                );
            }
            Ok(())
        }
        Err(e) => Err(io::Error::other(format!("QUIC receive failure: {e}"))),
    }
}

fn make_quic_config_with_domain_contexts(
    core_settings: &Settings,
    tls_demux: &Arc<std::sync::RwLock<TlsDemux>>,
) -> io::Result<quiche::Config> {
    let quic_settings = core_settings
        .listen_protocols
        .quic
        .as_ref()
        .ok_or_else(|| io::Error::other("QUIC listening is not configured"))?;

    // Create main SSL context with SNI callback that dynamically creates and switches contexts
    let mut main_ctx = SslContextBuilder::new(SslMethod::tls())?;

    // Clone tls_demux for use in callback
    let tls_demux_clone = tls_demux.clone();
    main_ctx.set_select_certificate_callback(move |mut client_hello| {
        let Some(sni) = client_hello.servername(NameType::HOST_NAME) else {
            return Ok(());
        };

        let tls_demux = tls_demux_clone.read().unwrap_or_else(recover_poison);
        let Ok(meta) = tls_demux.select(
            std::iter::once(tls_demultiplexer::Protocol::Http3.as_alpn().as_bytes()),
            sni.to_string(),
        ) else {
            return Ok(()); // unknown SNI -> bootstrap cert
        };
        drop(tls_demux);

        if meta.boring.chain.is_empty() {
            return Err(SelectCertError::ERROR);
        }

        let ssl = client_hello.ssl_mut();

        ssl.set_certificate(&meta.boring.chain[0])
            .map_err(|_| SelectCertError::ERROR)?;

        for cert in meta.boring.chain.iter().skip(1) {
            ssl.add_chain_cert(cert)
                .map_err(|_| SelectCertError::ERROR)?;
        }

        ssl.set_private_key(&meta.boring.key)
            .map_err(|_| SelectCertError::ERROR)?;

        Ok(())
    });

    // Load bootstrap certificate as default
    let bootstrap_meta = tls_demux
        .read()
        .unwrap_or_else(recover_poison)
        .get_quic_connection_bootstrap_meta()?;
    main_ctx.set_certificate_chain_file(&bootstrap_meta.cert_chain_path)?;
    main_ctx.set_private_key_file(&bootstrap_meta.key_path, boring::ssl::SslFiletype::PEM)?;

    let mut cfg = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, main_ctx)
        .map_err(|e| io::Error::other(format!("Failed to create QUIC config: {e}")))?;
    cfg.set_application_protos(h3::APPLICATION_PROTOCOL)
        .map_err(|e| io::Error::other(format!("Failed to set QUIC application protocols: {e}")))?;
    cfg.set_max_idle_timeout(core_settings.client_listener_timeout.as_millis() as u64);
    cfg.set_max_recv_udp_payload_size(quic_settings.recv_udp_payload_size);
    cfg.set_max_send_udp_payload_size(quic_settings.send_udp_payload_size);
    cfg.set_initial_max_data(quic_settings.initial_max_data);
    cfg.set_initial_max_stream_data_bidi_local(quic_settings.initial_max_stream_data_bidi_local);
    cfg.set_initial_max_stream_data_bidi_remote(quic_settings.initial_max_stream_data_bidi_remote);
    cfg.set_initial_max_stream_data_uni(quic_settings.initial_max_stream_data_uni);
    cfg.set_initial_max_streams_bidi(quic_settings.initial_max_streams_bidi);
    cfg.set_initial_max_streams_uni(quic_settings.initial_max_streams_uni);
    cfg.set_max_connection_window(quic_settings.max_connection_window);
    cfg.set_max_stream_window(quic_settings.max_stream_window);
    cfg.set_disable_active_migration(quic_settings.disable_active_migration);
    if quic_settings.enable_early_data {
        cfg.enable_early_data();
    }
    Ok(cfg)
}

fn socket_addr_to_vec(addr: &SocketAddr) -> Vec<u8> {
    match addr.ip() {
        std::net::IpAddr::V4(a) => a
            .octets()
            .iter()
            .copied()
            .chain(addr.port().to_be_bytes().iter().copied())
            .collect(),
        std::net::IpAddr::V6(a) => a
            .octets()
            .iter()
            .copied()
            .chain(addr.port().to_be_bytes().iter().copied())
            .collect(),
    }
}

fn mint_token(
    header: &quiche::Header<'_>,
    prefix: &[u8; TOKEN_PREFIX_SIZE],
    peer: &SocketAddr,
) -> Vec<u8> {
    prefix
        .iter()
        .copied()
        .chain(socket_addr_to_vec(peer).iter().copied())
        .chain(header.dcid.iter().copied())
        .collect()
}

fn validate_token<'a>(
    prefix: &[u8; TOKEN_PREFIX_SIZE],
    peer: &SocketAddr,
    token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    token
        .strip_prefix(prefix)
        .and_then(|token| token.strip_prefix(socket_addr_to_vec(peer).as_slice()))
        .map(quiche::ConnectionId::from_ref)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn negotiation_and_retry_preserve_datagram_identity() -> io::Result<()> {
        let mut settings = Settings::default();
        settings.listen_protocols.quic = Some(crate::settings::QuicSettings::builder().build());
        let demux = TlsDemux::new(&settings, &crate::settings::TlsHostsSettings::default())?;
        let mut mux = QuicMultiplexer::new(
            Arc::new(settings),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?,
            Arc::new(std::sync::RwLock::new(demux)),
            Arc::new(AtomicU64::new(0)),
        )?;
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let peer_addr = peer.local_addr()?;
        let mux_addr = mux.socket.local_addr()?;
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(io::Error::other)?;
        config
            .set_application_protos(h3::APPLICATION_PROTOCOL)
            .map_err(io::Error::other)?;
        let mut conn = quiche::connect(
            Some("example.org"),
            &quiche::ConnectionId::from_ref(&[0x42; quiche::MAX_CONN_ID_LEN]),
            peer_addr,
            mux_addr,
            &mut config,
        )
        .map_err(io::Error::other)?;
        peer.writable().await?;
        flush_pending_data(&mut conn, &peer, &log_utils::IdChain::empty())?;
        let mut packet = vec![0; net_utils::MAX_UDP_PAYLOAD_SIZE];
        let (n, source) =
            tokio::time::timeout(Duration::from_secs(5), mux.socket.recv_from(&mut packet))
                .await??;
        if source != peer_addr {
            return Err(io::Error::other("Initial datagram source changed"));
        }
        packet.truncate(n);
        let initial = quiche::Header::from_slice(&mut packet, quiche::MAX_CONN_ID_LEN)
            .map_err(io::Error::other)?;
        mux.socket.writable().await?;
        let mut response = vec![0; net_utils::MAX_UDP_PAYLOAD_SIZE];

        packet[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        peer.send_to(&packet, mux_addr).await?;
        mux.socket.readable().await?;
        if mux.read_udp_socket()?.is_some() {
            return Err(io::Error::other(
                "Unsupported version established a connection",
            ));
        }
        let (n, source) =
            tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut response)).await??;
        let negotiated = quiche::Header::from_slice(&mut response[..n], quiche::MAX_CONN_ID_LEN)
            .map_err(io::Error::other)?;
        if source != mux_addr
            || negotiated.ty != quiche::Type::VersionNegotiation
            || negotiated.scid != initial.dcid
            || negotiated.dcid != initial.scid
            || !negotiated
                .versions
                .as_ref()
                .is_some_and(|versions| versions.contains(&quiche::PROTOCOL_VERSION))
        {
            return Err(io::Error::other(format!(
                "Invalid version negotiation: {negotiated:?}"
            )));
        }

        packet[1..5].copy_from_slice(&quiche::PROTOCOL_VERSION.to_be_bytes());
        peer.send_to(&packet, mux_addr).await?;
        mux.socket.readable().await?;
        if mux.read_udp_socket()?.is_some() {
            return Err(io::Error::other(
                "Tokenless Initial established a connection",
            ));
        }
        let (n, source) =
            tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut response)).await??;
        let retry = quiche::Header::from_slice(&mut response[..n], quiche::MAX_CONN_ID_LEN)
            .map_err(io::Error::other)?;
        if source != mux_addr
            || retry.ty != quiche::Type::Retry
            || retry.dcid != initial.scid
            || retry.scid.len() != quiche::MAX_CONN_ID_LEN
            || retry.token.as_deref()
                != Some(mint_token(&initial, &mux.token_prefix, &peer_addr).as_slice())
        {
            return Err(io::Error::other(format!(
                "Invalid stateless retry: {retry:?}"
            )));
        }
        if !mux.connections.is_empty() || !mux.deadlines.is_empty() {
            return Err(io::Error::other(
                "Stateless packets retained connection state",
            ));
        }
        Ok(())
    }

    #[test]
    fn request_headers_preserve_stream_and_reject_invalid_names() {
        let request = QuicSocket::on_request(
            7,
            vec![
                h3::Header::new(b":method", b"GET"),
                h3::Header::new(b":scheme", b"https"),
                h3::Header::new(b":authority", b"example.org"),
                h3::Header::new(b":path", b"/path?q=1"),
                h3::Header::new(b"x-test", b"retained"),
            ],
        );
        assert!(matches!(request, Ok(QuicSocketEvent::Request(7, headers))
            if headers.version == http::Version::HTTP_3
                && headers.method == http::Method::GET
                && headers.uri == "https://example.org/path?q=1"
                && headers.headers.get("x-test") == Some(&http::HeaderValue::from_static("retained"))));
        let invalid = QuicSocket::on_request(7, vec![h3::Header::new(b"X-Test", b"value")]);
        assert!(invalid.is_err_and(|error| error.kind() == ErrorKind::InvalidData));
    }

    #[test]
    fn retry_token_preserves_connection_id_and_binds_peer() {
        let prefix = [0x42; TOKEN_PREFIX_SIZE];
        let dcid = [1, 2, 3, 4];
        for peer in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
        ] {
            let mut token = prefix.to_vec();
            token.extend(socket_addr_to_vec(&peer));
            token.extend_from_slice(&dcid);
            let id = validate_token(&prefix, &peer, &token);
            assert_eq!(id.as_ref().map(AsRef::as_ref), Some(dcid.as_slice()));
            let other_peer = SocketAddr::new(peer.ip(), 444);
            assert!(validate_token(&prefix, &other_peer, &token).is_none());
            assert!(validate_token(&[0; TOKEN_PREFIX_SIZE], &peer, &token).is_none());
            for end in 0..TOKEN_PREFIX_SIZE + socket_addr_to_vec(&peer).len() {
                assert!(validate_token(&prefix, &peer, &token[..end]).is_none());
            }
        }
    }
}
