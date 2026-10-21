use crate::forwarder::IcmpMultiplexer;
use crate::settings::{IcmpSettings, Settings};
use crate::{datagram_pipe, downstream, forwarder, icmp_utils, log_utils, net_utils, utils};
use async_trait::async_trait;
use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::ops::Bound;
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, RwLock};
use tokio::time::Instant;

pub struct IcmpForwarder {
    shared: Arc<ForwarderShared>,
    /// Waiting for notification from [`ForwarderShared::deadline_waker_tx`]
    deadline_waker_rx: Arc<tokio::sync::Notify>,
}

#[derive(Clone)]
struct ReplyWaiter {
    original_peer: IpAddr,
    waker_tx: mpsc::Sender<(IpAddr, icmp_utils::Message)>,
}

#[derive(Default)]
struct Listeners {
    reply_waiters: HashMap<icmp_utils::Echo, ReplyWaiter>,
    deadlines: BTreeMap<Instant, Vec<icmp_utils::Echo>>,
}

#[derive(Default)]
struct Sockets {
    v4: Option<RawPacketStream>,
    v6: Option<RawPacketStream>,
}

struct ForwarderShared {
    core_settings: Arc<Settings>,
    sockets: RwLock<Sockets>,
    listeners: Mutex<Listeners>,
    /// Wakes [`IcmpForwarder::deadline_waker_rx`]
    deadline_waker_tx: Arc<tokio::sync::Notify>,
}

struct PipeShared {
    forwarder_shared: Arc<ForwarderShared>,
}

struct IcmpSource {
    rx: mpsc::Receiver<(IpAddr, icmp_utils::Message)>,
    id: log_utils::IdChain<u64>,
}

struct IcmpSink {
    shared: Arc<PipeShared>,
    tx: mpsc::Sender<(IpAddr, icmp_utils::Message)>,
}

impl IcmpForwarder {
    pub fn new(core_settings: Arc<Settings>) -> Self {
        let deadline_waker = Arc::new(tokio::sync::Notify::new());
        Self {
            shared: Arc::new(ForwarderShared {
                core_settings,
                sockets: RwLock::default(),
                listeners: Mutex::default(),
                deadline_waker_tx: deadline_waker.clone(),
            }),
            deadline_waker_rx: deadline_waker,
        }
    }

    pub fn make_multiplexer(&self, id: log_utils::IdChain<u64>) -> io::Result<IcmpMultiplexer> {
        let capacity = self.shared.icmp_settings()?.recv_message_queue_capacity;
        if capacity == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "empty ICMP receive queue",
            ));
        }
        let (tx, rx) = mpsc::channel(capacity);
        let shared = Arc::new(PipeShared {
            forwarder_shared: self.shared.clone(),
        });
        Ok((
            Box::new(IcmpSource { rx, id }),
            Box::new(IcmpSink { shared, tx }),
        ))
    }

    pub async fn listen(&self) -> io::Result<()> {
        self.init_sockets().await?;

        loop {
            let maintenance = self.maintain_listeners();
            tokio::pin!(maintenance);

            let wait_v4 = self.listen_v4();
            tokio::pin!(wait_v4);

            let wait_v6 = self.listen_v6();
            tokio::pin!(wait_v6);

            let (peer, reply) = tokio::select! {
                r = maintenance => match r {
                    Ok(never) => match never {},
                    Err(e) => return Err(e),
                },
                r = wait_v4 => r?,
                r = wait_v6 => r?,
            };

            trace!("Received message: peer={peer} message={reply:?}");
            let Some(request) = reply.responded_echo_request() else {
                debug!(
                    "Failed to extract echo request, dropping message: peer={peer}, message={reply:?}"
                );
                continue;
            };

            let mut listeners = self
                .shared
                .listeners
                .lock()
                .map_err(|e| io::Error::other(e.to_string()))?;
            match listeners.reply_waiters.get(&request) {
                None => {
                    debug!("Reply waiter not found: peer={peer}, reply={reply:?}");
                }
                Some(ReplyWaiter { waker_tx, .. }) => match waker_tx.try_send((peer, reply)) {
                    Ok(()) => (),
                    Err(mpsc::error::TrySendError::Closed((peer, message))) => {
                        debug!(
                            "Listener closed: peer={peer} request={request:?} reply={message:?}"
                        );
                        listeners.reply_waiters.remove(&request);
                    }
                    Err(mpsc::error::TrySendError::Full((peer, message))) => {
                        debug!("Dropping message due to queue overflow: peer={peer} request={request:?} reply={message:?}");
                        listeners.reply_waiters.remove(&request);
                    }
                },
            }
        }
    }

    async fn init_sockets(&self) -> io::Result<()> {
        let settings = self.shared.icmp_settings()?;
        let mut sockets = self.shared.sockets.write().await;
        sockets.v4 = Some(RawPacketStream::new(
            libc::IPPROTO_ICMP,
            &settings.interface_name,
        )?);

        sockets.v6 = if self.shared.core_settings.ipv6_available {
            Some(RawPacketStream::new(
                libc::IPPROTO_ICMPV6,
                &settings.interface_name,
            )?)
        } else {
            None
        };

        Ok(())
    }

    async fn maintain_listeners(&self) -> io::Result<std::convert::Infallible> {
        loop {
            let closest_deadline = self
                .shared
                .listeners
                .lock()
                .map_err(|e| io::Error::other(e.to_string()))?
                .deadlines
                .keys()
                .next()
                .copied();
            match closest_deadline {
                None => self.deadline_waker_rx.notified().await,
                Some(x) => tokio::time::sleep_until(x).await,
            }

            let mut listeners = self
                .shared
                .listeners
                .lock()
                .map_err(|e| io::Error::other(e.to_string()))?;
            let now = Instant::now();
            let expired: Vec<_> = listeners
                .deadlines
                .range((Bound::Unbounded, Bound::Included(now)))
                .map(|(k, _)| *k)
                .collect();
            for deadline in expired {
                if let Some(requests) = listeners.deadlines.remove(&deadline) {
                    for request in requests {
                        if let Some(waiter) = listeners.reply_waiters.remove(&request) {
                            debug!(
                                "Request expired: peer={} request={:?}",
                                waiter.original_peer, request
                            );
                        }
                    }
                }
            }
        }
    }

    async fn listen_v4(&self) -> io::Result<(IpAddr, icmp_utils::Message)> {
        if let Some(socket) = self.shared.sockets.read().await.v4.as_ref() {
            loop {
                let (peer, packet) = Self::listen_socket(socket).await?;

                match icmp_utils::v4::Message::deserialize(packet.clone()) {
                    Ok(x) => break Ok((peer, icmp_utils::Message::from(x))),
                    Err(e) => {
                        debug!(
                            "Dropping malformed ICMPv4 message: {:?}, {}",
                            e,
                            utils::hex_dump(&packet)
                        );
                    }
                }
            }
        } else {
            Err(io::Error::new(
                ErrorKind::NotConnected,
                "ICMPv4 socket is not initialized",
            ))
        }
    }

    async fn listen_v6(&self) -> io::Result<(IpAddr, icmp_utils::Message)> {
        if let Some(socket) = self.shared.sockets.read().await.v6.as_ref() {
            loop {
                let (peer, packet) = Self::listen_socket(socket).await?;
                match icmp_utils::v6::Message::deserialize(packet) {
                    Ok(x) => break Ok((peer, icmp_utils::Message::from(x))),
                    Err(e) => {
                        debug!("Dropping malformed ICMPv6 message: {e:?}");
                    }
                }
            }
        } else {
            futures::future::pending().await
        }
    }

    async fn listen_socket(sock: &RawPacketStream) -> io::Result<(IpAddr, Bytes)> {
        loop {
            let mut guard = sock.inner.readable().await?;
            let (peer, packet) = match guard.try_io(|x| net_utils::recv_from(x.get_ref(), None)) {
                Ok(x) => x?,
                Err(_would_block) => continue,
            };
            if peer.is_ipv4() {
                match net_utils::skip_ipv4_header(packet) {
                    None => debug!("Dropping ICMPv4 packet with invalid IP header"),
                    Some((proto, payload)) if proto == libc::IPPROTO_ICMP => {
                        if accepts_icmp_type(true, payload.first().copied()) {
                            trace!(
                                "Received ICMP: peer={} bytes={:?}",
                                peer,
                                utils::hex_dump(&payload)
                            );
                            return Ok((peer, payload));
                        }
                    }
                    Some((proto, payload)) => debug!(
                        "Dropping non-ICMP packet: proto={}, payload={}",
                        proto,
                        utils::hex_dump(&payload)
                    ),
                }
            } else if accepts_icmp_type(false, packet.first().copied()) {
                trace!(
                    "Received ICMP: peer={} bytes={:?}",
                    peer,
                    utils::hex_dump(&packet)
                );
                return Ok((peer, packet));
            }
            tokio::task::consume_budget().await;
        }
    }
}

impl ForwarderShared {
    fn icmp_settings(&self) -> io::Result<&IcmpSettings> {
        self.core_settings.icmp.as_ref().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "ICMP forwarding is not configured")
        })
    }
}

fn accepts_icmp_type(is_ipv4: bool, message_type: Option<u8>) -> bool {
    if is_ipv4 {
        if cfg!(target_os = "linux") {
            use icmp_utils::v4::TypeId;
            matches!(
                message_type.map(TypeId),
                Some(
                    TypeId(32..=u8::MAX)
                        | TypeId::ECHO_REPLY
                        | TypeId::DESTINATION_UNREACHABLE
                        | TypeId::TIME_EXCEEDED
                        | TypeId::PARAMETER_PROBLEM
                )
            )
        } else {
            message_type.is_some()
        }
    } else {
        use icmp_utils::v6::TypeId;
        matches!(
            message_type.map(TypeId),
            Some(
                TypeId::DESTINATION_UNREACHABLE
                    | TypeId::PACKET_TOO_BIG
                    | TypeId::TIME_EXCEEDED
                    | TypeId::PARAMETER_PROBLEM
                    | TypeId::ECHO_REPLY
            )
        )
    }
}

#[cfg(target_os = "linux")]
fn attach_icmp_filter(socket: &Socket, is_ipv4: bool) -> io::Result<()> {
    use libc::{
        BPF_ABS, BPF_B, BPF_IND, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JMP, BPF_K, BPF_LD, BPF_LDX,
        BPF_MSH, BPF_RET,
    };

    let instruction = |code, jt, jf, k| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    if is_ipv4 {
        // IPv4 raw packets include the variable-length IP header; types >=32 bypass ICMP_FILTER.
        socket.attach_filter(&[
            instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, 0),
            instruction(BPF_LD | BPF_B | BPF_IND, 0, 0, 0),
            instruction(BPF_JMP | BPF_JGE | BPF_K, 5, 0, 32),
            instruction(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 0),
            instruction(BPF_JMP | BPF_JEQ | BPF_K, 3, 0, 3),
            instruction(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 11),
            instruction(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 12),
            instruction(BPF_RET | BPF_K, 0, 0, 0),
            instruction(BPF_RET | BPF_K, 0, 0, u32::MAX),
        ])
    } else {
        // IPv6 raw packets start with the ICMPv6 header, not an IP header.
        socket.attach_filter(&[
            instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0),
            instruction(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 129),
            instruction(BPF_JMP | BPF_JGE | BPF_K, 0, 2, 1),
            instruction(BPF_JMP | BPF_JGT | BPF_K, 1, 0, 4),
            instruction(BPF_RET | BPF_K, 0, 0, u32::MAX),
            instruction(BPF_RET | BPF_K, 0, 0, 0),
        ])
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd", test))]
mod native_icmpv6 {
    use super::{accepts_icmp_type, Socket};
    use nix::{setsockopt_impl, sockopt_impl};
    use std::io;

    const ICMP6_FILTER: libc::c_int = 18;

    sockopt_impl!(
        /// Native BSD/macOS `ICMPv6` receive filter.
        Icmpv6Filter,
        SetOnly,
        libc::IPPROTO_ICMPV6,
        ICMP6_FILTER,
        [u32; 8]
    );

    fn filter() -> [u32; 8] {
        let mut words = [0; 8];
        for message_type in 0..=u8::MAX {
            if accepts_icmp_type(false, Some(message_type)) {
                let bit = usize::from(message_type);
                words[bit / 32] |= 1 << (bit % 32);
            }
        }
        words
    }

    pub(super) fn attach(socket: &Socket) -> io::Result<()> {
        nix::sys::socket::setsockopt(socket, Icmpv6Filter, &filter())?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::net::UnixDatagram;

        #[test]
        fn native_filter_pass_bits_cover_exactly_the_allowed_types() {
            let words = filter();
            assert_eq!(std::mem::size_of_val(&words), 32);
            for message_type in 0..=u8::MAX {
                let bit = usize::from(message_type);
                assert_eq!(
                    words[bit / 32] & (1 << (bit % 32)) != 0,
                    matches!(message_type, 1..=4 | 129),
                    "native ICMPv6 filter type {message_type}"
                );
            }
        }

        #[test]
        fn native_filter_reports_socket_option_failures() -> io::Result<()> {
            let socket = Socket::from(UnixDatagram::unbound()?);
            crate::utils::check(
                attach(&socket).is_err(),
                "native ICMPv6 filter accepted a Unix socket",
            )
        }
    }
}

#[async_trait]
impl datagram_pipe::Source for IcmpSource {
    type Output = forwarder::IcmpDatagram;

    fn id(&self) -> log_utils::IdChain<u64> {
        self.id.clone()
    }

    async fn read(&mut self) -> io::Result<forwarder::IcmpDatagram> {
        let (peer, message) = self
            .rx
            .recv()
            .await
            .ok_or_else(|| io::Error::from(ErrorKind::UnexpectedEof))?;

        Ok(forwarder::IcmpDatagram {
            meta: forwarder::IcmpDatagramMeta { peer },
            message,
        })
    }
}

#[async_trait]
impl datagram_pipe::Sink for IcmpSink {
    type Input = downstream::IcmpDatagram;

    async fn write(
        &mut self,
        datagram: downstream::IcmpDatagram,
    ) -> io::Result<datagram_pipe::SendStatus> {
        let peer_ip = datagram.meta.peer;
        if !self
            .shared
            .forwarder_shared
            .core_settings
            .allow_private_network_connections
            && !net_utils::is_global_ip(&peer_ip)
        {
            debug!("Dropping ICMP to non-routable destination: {peer_ip}");
            return Ok(datagram_pipe::SendStatus::Dropped);
        }

        let Some(echo) = datagram.message.to_echo() else {
            debug!("Only echo request messages can be sent to peer");
            return Ok(datagram_pipe::SendStatus::Dropped);
        };

        let forwarder_shared = self.shared.forwarder_shared.clone();
        let sockets = forwarder_shared.sockets.read().await;
        let socket = {
            let socket = if datagram.meta.peer.is_ipv4() {
                sockets.v4.as_ref()
            } else {
                sockets.v6.as_ref()
            };

            let Some(socket) = socket else {
                return Ok(datagram_pipe::SendStatus::Dropped);
            };
            socket
        };

        let serialized = datagram.message.serialize();
        socket
            .send_to(datagram.meta.peer, datagram.ttl, &serialized)
            .await?;

        let deadline = Instant::now() + forwarder_shared.icmp_settings()?.request_timeout;
        let mut listeners = forwarder_shared
            .listeners
            .lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        listeners.reply_waiters.insert(
            echo.clone(),
            ReplyWaiter {
                original_peer: datagram.meta.peer,
                waker_tx: self.tx.clone(),
            },
        );

        match listeners.deadlines.entry(deadline) {
            Entry::Vacant(e) => {
                e.insert(vec![echo.clone()]);
                if listeners.deadlines.len() == 1 {
                    forwarder_shared.deadline_waker_tx.notify_one();
                }
            }
            Entry::Occupied(mut e) => {
                e.get_mut().push(echo.clone());
            }
        }

        Ok(datagram_pipe::SendStatus::Sent)
    }
}

struct RawPacketStream {
    inner: AsyncFd<Socket>,
}

impl RawPacketStream {
    pub fn new(protocol: libc::c_int, if_name: &str) -> io::Result<Self> {
        let domain = match protocol {
            libc::IPPROTO_ICMP => Domain::IPV4,
            libc::IPPROTO_ICMPV6 => Domain::IPV6,
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "unsupported ICMP protocol",
                ))
            }
        };
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        let socket_type = Type::RAW;
        #[cfg(target_os = "macos")]
        let socket_type = Type::DGRAM;
        let socket = Socket::new(domain, socket_type, Some(Protocol::from(protocol)))?;
        net_utils::bind_to_interface(&socket, domain == Domain::IPV4, if_name)?;
        #[cfg(target_os = "linux")]
        attach_icmp_filter(&socket, domain == Domain::IPV4)?;
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        if domain == Domain::IPV6 {
            native_icmpv6::attach(&socket)?;
        }
        Self::from_socket(socket)
    }

    fn from_socket(socket: Socket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(socket)?,
        })
    }

    pub async fn send_to(&self, dst: IpAddr, ttl: u8, packet: &[u8]) -> io::Result<()> {
        let address = SocketAddr::from((dst, 0)).into();
        loop {
            let mut guard = self.inner.writable().await?;
            if let Ok(result) = guard.try_io(|socket| {
                let socket = socket.get_ref();
                net_utils::set_socket_ttl(socket, dst.is_ipv4(), ttl)?;
                socket.send_to(packet, &address)
            }) {
                if result? != packet.len() {
                    return Err(io::Error::new(
                        ErrorKind::WriteZero,
                        "incomplete ICMP datagram",
                    ));
                }
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
    use std::time::Duration;

    #[test]
    fn icmp_filters_keep_the_native_message_sets() {
        for message_type in 0..=u8::MAX {
            let v4_allowed = !cfg!(target_os = "linux")
                || matches!(message_type, 0 | 3 | 11 | 12 | 32..=u8::MAX);
            assert_eq!(accepts_icmp_type(true, Some(message_type)), v4_allowed);
            assert_eq!(
                accepts_icmp_type(false, Some(message_type)),
                matches!(message_type, 1..=4 | 129)
            );
        }
        assert!(!accepts_icmp_type(true, None));
        assert!(!accepts_icmp_type(false, None));
    }

    #[test]
    fn rejects_non_icmp_protocol_without_opening_a_socket() {
        assert!(
            matches!(RawPacketStream::new(libc::IPPROTO_UDP, ""), Err(e) if e.kind() == ErrorKind::InvalidInput)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_kernel_ipv4_filter_keeps_native_types_with_ip_options() -> io::Result<()> {
        for header_words in [5, 6, 15] {
            check_kernel_icmp_filter(true, header_words)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_kernel_ipv6_filter_keeps_native_types_without_ip_header() -> io::Result<()> {
        check_kernel_icmp_filter(false, 0)
    }

    #[cfg(target_os = "linux")]
    fn check_kernel_icmp_filter(is_ipv4: bool, header_words: u8) -> io::Result<()> {
        use std::os::unix::net::UnixDatagram;

        // Unix datagrams exercise the exact BPF packet offsets without raw-socket privileges.
        let (sender, receiver) = UnixDatagram::pair()?;
        let socket = Socket::from(receiver);
        attach_icmp_filter(&socket, is_ipv4)?;
        let receiver = UnixDatagram::from(socket);
        receiver.set_nonblocking(true)?;
        let header_size = usize::from(header_words) * 4;
        let mut packet = vec![8; header_size];
        if let Some(first) = packet.first_mut() {
            *first = 0x40 | header_words;
        }
        for message_type in 0..=u8::MAX {
            packet.truncate(header_size);
            packet.extend_from_slice(&[message_type, 0, 0, 0, 0, 0, 0, 0]);
            sender.send(&packet)?;
            let mut buffer = [0; 128];
            let actual = receiver.recv(&mut buffer);
            let allowed = if is_ipv4 {
                matches!(message_type, 0 | 3 | 11 | 12 | 32..=u8::MAX)
            } else {
                matches!(message_type, 1..=4 | 129)
            };
            match (allowed, actual) {
                (true, Ok(size)) if buffer.get(..size) == Some(packet.as_slice()) => (),
                (false, Err(error)) if error.kind() == ErrorKind::WouldBlock => (),
                (expected, actual) => {
                    return Err(io::Error::other(format!(
                        "ICMPv{} type {message_type}, IHL {header_words}: allowed={expected}, receive={actual:?}",
                        if is_ipv4 { 4 } else { 6 }
                    )));
                }
            }
        }
        packet.truncate(header_size);
        sender.send(&packet)?;
        if !matches!(receiver.recv(&mut [0; 128]), Err(error) if error.kind() == ErrorKind::WouldBlock)
        {
            return Err(io::Error::other(
                "kernel filter accepted a missing ICMP type",
            ));
        }
        Ok(())
    }

    fn check(condition: bool, message: &str) -> io::Result<()> {
        condition
            .then_some(())
            .ok_or_else(|| io::Error::other(message.to_owned()))
    }

    #[tokio::test]
    async fn local_ipv4_receive_filters_and_decodes_icmp_and_closes_socket() -> io::Result<()> {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = receiver.local_addr()?;
        let stream = RawPacketStream::from_socket(receiver.into())?;
        check(stream.inner.get_ref().nonblocking()?, "socket is blocking")?;
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let echo = icmp_utils::Echo {
            code: 0,
            identifier: 0x1234,
            sequence_number: 42,
            data: Bytes::from_static(b"payload"),
        };
        let mut message = icmp_utils::v4::Message::Echo(echo.clone())
            .serialize()
            .to_vec();
        message[0] = icmp_utils::v4::TypeId::ECHO_REPLY.0;
        message[2..4].fill(0);
        let checksum = net_utils::rfc1071_checksum(&message).to_be_bytes();
        message[2..4].copy_from_slice(&checksum);
        let message = Bytes::from(message);
        let mut packet = vec![0; net_utils::MIN_IPV4_HEADER_SIZE];
        packet[0] = 0x45;
        packet[9] = libc::IPPROTO_ICMP as u8;
        packet.extend_from_slice(&message);
        sender.send_to(&[0], address)?;
        if cfg!(target_os = "linux") {
            let mut filtered = packet.clone();
            filtered[net_utils::MIN_IPV4_HEADER_SIZE] = icmp_utils::v4::TypeId::ECHO.0;
            sender.send_to(&filtered, address)?;
        }
        sender.send_to(&packet, address)?;
        let (peer, actual) = tokio::time::timeout(
            Duration::from_secs(1),
            IcmpForwarder::listen_socket(&stream),
        )
        .await??;
        check(peer == sender.local_addr()?.ip(), "unexpected IPv4 peer")?;
        check(actual == message, "IPv4 packet differs from sent message")?;
        check(
            net_utils::rfc1071_checksum(&actual) == 0,
            "invalid checksum",
        )?;
        check(
            matches!(icmp_utils::v4::Message::deserialize(actual), Ok(icmp_utils::v4::Message::EchoReply(reply)) if reply == echo),
            "unexpected IPv4 echo reply",
        )?;
        drop(stream);
        let rebound = UdpSocket::bind(address)?;
        check(rebound.local_addr()? == address, "socket was not released")?;
        Ok(())
    }

    #[tokio::test]
    async fn local_ipv6_receive_filters_without_skipping_an_ip_header() -> io::Result<()> {
        let receiver = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))?;
        let address = receiver.local_addr()?;
        let stream = RawPacketStream::from_socket(receiver.into())?;
        let sender = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0))?;
        let echo = icmp_utils::Echo {
            code: 0,
            identifier: 7,
            sequence_number: 42,
            data: Bytes::from_static(b"payload"),
        };
        let mut message = icmp_utils::v6::Message::EchoRequest(echo.clone())
            .serialize()
            .to_vec();
        message[0] = icmp_utils::v6::TypeId::ECHO_REPLY.0;
        message[2..4].fill(0);
        let checksum = net_utils::rfc1071_checksum(&message).to_be_bytes();
        message[2..4].copy_from_slice(&checksum);
        let message = Bytes::from(message);
        let mut filtered = message.to_vec();
        filtered[0] = icmp_utils::v6::TypeId::ECHO_REQUEST.0;
        sender.send_to(&filtered, address)?;
        sender.send_to(&message, address)?;
        let (peer, actual) = tokio::time::timeout(
            Duration::from_secs(1),
            IcmpForwarder::listen_socket(&stream),
        )
        .await??;
        check(peer == sender.local_addr()?.ip(), "unexpected IPv6 peer")?;
        check(actual == message, "IPv6 packet differs from sent message")?;
        check(
            matches!(icmp_utils::v6::Message::deserialize(actual), Ok(icmp_utils::v6::Message::EchoReply(reply)) if reply == echo),
            "unexpected IPv6 echo reply",
        )?;
        Ok(())
    }
}
