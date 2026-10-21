//! Networking constants, wire codecs, and socket helpers.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use nix::sys::socket::{recvmsg, MsgFlags, SockaddrStorage};
use socket2::Socket;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

pub(crate) const MIN_LINK_MTU: usize = 1280;
pub(crate) const MIN_IPV4_HEADER_SIZE: usize = 20;
pub(crate) const MIN_IPV6_HEADER_SIZE: usize = 40;
pub(crate) const MAX_IP_PACKET_SIZE: usize = 2_usize.pow(16);
pub(crate) const UDP_HEADER_SIZE: usize = 8;
/// `IPv6` allows sending slightly bigger datagrams, but assume it does not matter
pub(crate) const MAX_UDP_PAYLOAD_SIZE: usize =
    MAX_IP_PACKET_SIZE - MIN_IPV4_HEADER_SIZE - UDP_HEADER_SIZE;
pub(crate) const PLAIN_DNS_PORT_NUMBER: u16 = 53;
pub(crate) const PLAIN_HTTP_PORT_NUMBER: u16 = 80;

pub(crate) const IPV4_WIRE_LENGTH: usize = 4;
pub(crate) const IPV6_WIRE_LENGTH: usize = 16;
const FIXED_LENGTH_IP_WIRE_LENGTH: usize = IPV6_WIRE_LENGTH;
const IPV4_PADDING_WIRE_LENGTH: usize = FIXED_LENGTH_IP_WIRE_LENGTH - IPV4_WIRE_LENGTH;

/// ALPN identifier for HTTP/1.1.
pub const HTTP1_ALPN: &str = "http/1.1";
/// ALPN identifier for HTTP/2.
pub const HTTP2_ALPN: &str = "h2";
/// ALPN identifier for HTTP/3.
pub const HTTP3_ALPN: &str = "h3";

pub(crate) const HTTP3_DATA_FRAME_TYPE_WIRE_LENGTH: usize = varint_len(0);
/// The minimum value of a stream capacity which allows to send a data chunk.
/// Consists of 1 byte for frame ID, 1 byte for the shortest frame length, and
/// 1 byte for the chunk itself.
pub(crate) const MIN_USABLE_QUIC_STREAM_CAPACITY: usize = http3_data_frame_overhead(1) + 1;

const SCRUBBED_PLACEHOLDER: &str = "__stripped__";

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Channel {
    /// The connection is used for tunneling client's connections (see [`crate::tunnel`])
    Tunnel,
    /// The connection is used just for measuring a ping
    Ping,
    /// The connection is used for a speedtest (see [`crate::http_speedtest_handler`])
    Speedtest,
    /// The connection is used for proxying requests further (see [`crate::reverse_proxy`])
    ReverseProxy,
    /// The connection is used to serve the subscription JSON
    /// (see [`crate::http_subscription_handler`])
    Subscription,
}

pub(crate) type HostnamePort = (String, u16);

#[derive(Debug, Clone)]
pub(crate) enum TcpDestination {
    Address(SocketAddr),
    HostName(HostnamePort),
}

pub(crate) trait PeerAddr {
    fn peer_addr(&self) -> io::Result<SocketAddr>;
}

impl PeerAddr for tokio::net::TcpStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr()
    }
}

impl<IO> PeerAddr for tokio_rustls::server::TlsStream<IO>
where
    IO: PeerAddr,
{
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.peer_addr()
    }
}

pub(crate) fn make_udp_socket(is_v4: bool) -> io::Result<UdpSocket> {
    if is_v4 {
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    } else {
        UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
    }
}

/// Returns the encoded length, capped at QUIC's largest integer width.
/// See <https://www.rfc-editor.org/rfc/rfc9000.html#section-16>.
pub(crate) const fn varint_len(x: usize) -> usize {
    if x <= 63 {
        1
    } else if x <= 16_383 {
        2
    } else if x <= 1_073_741_823 {
        4
    } else {
        8
    }
}

pub(crate) const fn http3_data_frame_overhead(payload_size: usize) -> usize {
    HTTP3_DATA_FRAME_TYPE_WIRE_LENGTH + varint_len(payload_size)
}

pub(crate) fn get_fixed_size_ip(bytes: &mut Bytes) -> Option<IpAddr> {
    let address: [u8; FIXED_LENGTH_IP_WIRE_LENGTH] =
        bytes.get(..FIXED_LENGTH_IP_WIRE_LENGTH)?.try_into().ok()?;
    bytes.advance(FIXED_LENGTH_IP_WIRE_LENGTH);
    if address[..IPV4_PADDING_WIRE_LENGTH].iter().all(|x| *x == 0) {
        Some(IpAddr::from([
            address[12],
            address[13],
            address[14],
            address[15],
        ]))
    } else {
        Some(IpAddr::from(address))
    }
}

pub(crate) fn put_fixed_size_ip(bytes: &mut BytesMut, ip: &IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            bytes.put_slice(&[0; IPV4_PADDING_WIRE_LENGTH]);
            bytes.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => bytes.put_slice(&ip.octets()),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn bind_to_interface(socket: &Socket, _is_ipv4: bool, name: &str) -> io::Result<()> {
    socket.bind_device(Some(name.as_bytes()))
}

#[cfg(target_os = "macos")]
pub(crate) fn bind_to_interface(socket: &Socket, is_ipv4: bool, name: &str) -> io::Result<()> {
    let index = nix::net::if_::if_nametoindex(name)?;
    let index = std::num::NonZeroU32::new(index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface has no index"))?;
    if is_ipv4 {
        socket.bind_device_by_index_v4(Some(index))
    } else {
        socket.bind_device_by_index_v6(Some(index))
    }
}

#[cfg(target_os = "freebsd")]
pub(crate) fn bind_to_interface(socket: &Socket, is_ipv4: bool, name: &str) -> io::Result<()> {
    if name.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    let mut candidates = nix::ifaddrs::getifaddrs()?
        .filter(|interface| interface.interface_name == name)
        .filter_map(|interface| {
            let address = socket_addr_from_storage(&interface.address?).ok()?;
            (address.is_ipv4() == is_ipv4).then_some((address, interface.flags.bits()))
        });
    let address = if is_ipv4 {
        candidates.next()
    } else {
        candidates.max_by_key(|(address, flags)| match address {
            SocketAddr::V6(address) => ipv6_interface_priority(address.ip(), *flags),
            SocketAddr::V4(_) => 0,
        })
    }
    .map(|(address, _)| address)
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no {} address found for interface {name}",
                if is_ipv4 { "IPv4" } else { "IPv6" }
            ),
        )
    })?;
    socket.bind(&address.into())
}

#[cfg(any(target_os = "freebsd", test))]
const fn ipv6_interface_priority(ip: &Ipv6Addr, flags: libc::c_int) -> u8 {
    const IN6_IFF_TEMPORARY: libc::c_int = 0x0080;
    let temporary = flags & IN6_IFF_TEMPORARY != 0;
    if is_unicast_global_ipv6(ip) {
        if temporary {
            10
        } else {
            9
        }
    } else if ip.segments()[0] & 0xfe00 == 0xfc00 {
        if temporary {
            6
        } else {
            5
        }
    } else if ip.segments()[0] & 0xffc0 == 0xfe80 {
        1
    } else {
        0
    }
}

pub(crate) fn set_socket_ttl(socket: &Socket, is_ipv4: bool, ttl: u8) -> io::Result<()> {
    if is_ipv4 {
        socket.set_ttl(u32::from(ttl))
    } else {
        socket.set_unicast_hops_v6(u32::from(ttl))
    }
}

fn socket_addr_from_storage(address: &SockaddrStorage) -> io::Result<SocketAddr> {
    address
        .as_sockaddr_in()
        .map(|address| (*address).into())
        .or_else(|| address.as_sockaddr_in6().map(|address| (*address).into()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-IP socket address"))
}

/// Receives without blocking; defaults to a buffer of [`MIN_LINK_MTU`] bytes.
pub(crate) fn recv_from(
    socket: &Socket,
    buffer_size: Option<usize>,
) -> io::Result<(IpAddr, Bytes)> {
    let mut buffer = BytesMut::zeroed(buffer_size.unwrap_or(MIN_LINK_MTU));
    let (length, peer) = {
        let mut buffers = [io::IoSliceMut::new(&mut buffer)];
        let message = recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut buffers,
            None,
            MsgFlags::MSG_DONTWAIT,
        )?;
        (message.bytes, message.address)
    };
    let peer =
        peer.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing peer address"))?;
    buffer.truncate(length);
    Ok((socket_addr_from_storage(&peer)?.ip(), buffer.freeze()))
}

/// # Return
///
/// [`None`] in case of packet is invalid, or
/// the next header protocol ID (`libc::IPPROTO_*`) and IP packet payload otherwise.
pub(crate) fn skip_ipv4_header(mut packet: Bytes) -> Option<(libc::c_int, Bytes)> {
    if packet.len() < MIN_IPV4_HEADER_SIZE {
        return None;
    }

    let x = packet.get_u8(); // Version + Header length
    let header_length = usize::from((x & 0x0f) * 4);
    if x >> 4 != 4 || header_length < MIN_IPV4_HEADER_SIZE || header_length > packet.len() + 1 {
        return None;
    }

    packet.advance(1 + 2 + 2 + 2 + 1); // DSCP + ECN + Total length + ID + Flags + Frag. Offset + TTL
    let next_protocol = libc::c_int::from(packet.get_u8());
    packet.advance(2 + 4 + 4 + (header_length - MIN_IPV4_HEADER_SIZE)); // Checksum + Source + Destination + Options

    Some((next_protocol, packet))
}

/// # Return
///
/// [`None`] in case of packet is invalid, or
/// the next header protocol ID (`libc::IPPROTO_*`) and IP packet payload otherwise.
pub(crate) fn skip_ipv6_header(mut packet: Bytes) -> Option<(libc::c_int, Bytes)> {
    if packet.len() < MIN_IPV6_HEADER_SIZE || packet[0] >> 4 != 6 {
        return None;
    }

    packet.advance(4 + 2); // Version + Traffic class + Flow label + Payload length
    let mut next_protocol = libc::c_int::from(packet.get_u8());
    packet.advance(1 + 16 + 16); // Hop limit + Source + Destination

    loop {
        match next_protocol {
            libc::IPPROTO_HOPOPTS | libc::IPPROTO_ROUTING | libc::IPPROTO_DSTOPTS => {
                if packet.len() < 2 {
                    return None;
                }
                next_protocol = libc::c_int::from(packet.get_u8());
                let header_ext_length = (usize::from(packet.get_u8()) + 1) * 8 - 2;
                if packet.len() < header_ext_length {
                    return None;
                }
                packet.advance(header_ext_length);
            }
            libc::IPPROTO_FRAGMENT => {
                const IPV6_FRAGMENT_EXT_LENGTH: usize = 8;
                if packet.len() < IPV6_FRAGMENT_EXT_LENGTH {
                    return None;
                }

                next_protocol = libc::c_int::from(packet.get_u8());
                packet.advance(IPV6_FRAGMENT_EXT_LENGTH - 1);
            }
            _ => break,
        }
    }

    Some((next_protocol, packet))
}

/// Calculates the checksum for the provided byte array
/// in accordance with <https://datatracker.ietf.org/doc/html/rfc1071>.
pub(crate) fn rfc1071_checksum(bytes: &[u8]) -> u16 {
    let sum = bytes.chunks(2).fold(0_u32, |sum, word| {
        let word = u16::from_be_bytes([word[0], word.get(1).copied().unwrap_or(0)]);
        let sum = sum + u32::from(word);
        (sum & 0xffff) + (sum >> 16)
    });
    !(sum as u16)
}

/// Returns [`true`] if the address appears to be globally routable.
/// See [iana-ipv4-special-registry][ipv4-sr].
///
/// The following return [`false`]:
///
/// - private addresses (see [`Ipv4Addr::is_private()`])
/// - the loopback address (see [`Ipv4Addr::is_loopback()`])
/// - the link-local address (see [`Ipv4Addr::is_link_local()`])
/// - the broadcast address (see [`Ipv4Addr::is_broadcast()`])
/// - addresses used for documentation (see [`Ipv4Addr::is_documentation()`])
/// - the unspecified address (see [`Ipv4Addr::is_unspecified()`]), and the whole
///   `0.0.0.0/8` block
/// - addresses reserved for future protocols, except
///   `192.0.0.9/32` and `192.0.0.10/32` which are globally routable
/// - addresses reserved for future use (see [IETF RFC 1112])
/// - addresses reserved for networking devices benchmarking (see [IETF RFC 2544])
///
/// [ipv4-sr]: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
///
/// @todo: replace with [`Ipv4Addr::is_global`] when it becomes stable
pub(crate) const fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // check if this address is 192.0.0.9 or 192.0.0.10. These addresses are the only two
    // globally routable addresses in the 192.0.0.0/24 range.
    {
        let ip = u32::from_be_bytes(octets);
        if ip == 0xc000_0009 || ip == 0xc000_000a {
            return true;
        }
    }
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation())
        // address is part of the Shared Address Space defined in [IETF RFC 6598] (`100.64.0.0/10`)
        && !(octets[0] == 100 && (octets[1] & 0b1100_0000 == 0b0100_0000))
        // addresses reserved for future protocols (`192.0.0.0/24`)
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        // address is reserved by IANA for future use [IETF RFC 1112]
        && octets[0] & 0xf0 != 0xf0
        // reserved for network devices benchmarking [IETF RFC 2544]
        && !(octets[0] == 198 && (octets[1] & 0xfe) == 18)
        // Make sure the address is not in 0.0.0.0/8
        && octets[0] != 0
}

/// Returns [`true`] if the address is a globally routable unicast address.
///
/// The following return false:
///
/// - the loopback address
/// - the link-local addresses
/// - unique local addresses
/// - the unspecified address
/// - the address range reserved for documentation
///
/// This method returns [`true`] for site-local addresses as per [RFC 4291 section 2.5.7]
///
/// [RFC 4291 section 2.5.7]: https://tools.ietf.org/html/rfc4291#section-2.5.7
///
/// @todo: replace with [`Ipv6Addr::is_unicast_global`] when it becomes stable
#[must_use]
#[inline]
pub(crate) const fn is_unicast_global_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();

    !(ip.is_multicast()
        || ip.is_loopback()
        // unicast address with link-local scope [RFC 4291]
        || (segments[0] & 0xffc0) == 0xfe80
        // unique local address (`fc00::/7`) [IETF RFC 4193]
        || (segments[0] & 0xfe00) == 0xfc00
        || ip.is_unspecified()
        // address reserved for documentation (`2001:db8::/32`) [IETF RFC 3849]
        || (segments[0] == 0x2001) && (segments[1] == 0xdb8))
}

/// Returns [`true`] if the address appears to be globally routable.
///
/// The following return [`false`]:
///
/// - the loopback address
/// - link-local and unique local unicast addresses
/// - interface-, link-, realm-, admin- and site-local multicast addresses
///
/// @todo: replace with [`Ipv6Addr::is_global`] when it becomes stable
#[must_use]
#[inline]
pub(crate) const fn is_global_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_multicast() {
        return ip.segments()[0] & 0x000f == 0x0e;
    }
    is_unicast_global_ipv6(ip)
}

/// Converts an IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`)
/// `IPv6` address to a plain `IpAddr::V4`.
///
/// When the endpoint listens on `[::]` with `IPV6_V6ONLY=false`, the OS presents
/// incoming `IPv4` connections as `IPv6`-mapped addresses. This function unmaps them so
/// that IP-based filtering (rules engine, `allow_private_network_connections`) works
/// correctly with `IPv4` CIDR ranges.
#[must_use]
#[inline]
pub(crate) fn unmap_ipv6(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => extract_ipv4_from_ipv6(&v6).map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Extracts the `IPv4` address from an `IPv4`-mapped (`::ffff:x.x.x.x`) or
/// `IPv4`-compatible (`::x.x.x.x`) `IPv6` address. Returns [`None`] for native `IPv6`.
const fn extract_ipv4_from_ipv6(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = ip.segments();
    // IPv4-mapped: ::ffff:x.x.x.x  →  [0,0,0,0,0,0xffff,hi,lo]
    let is_mapped =
        seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0xffff;
    // IPv4-compatible (deprecated): ::x.x.x.x  →  [0,0,0,0,0,0,hi,lo]
    // Exclude :: (unspecified) and ::1 (loopback) which are native IPv6.
    let is_compat = seg[0] == 0
        && seg[1] == 0
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0
        && (seg[6] != 0 || seg[7] > 1);

    if is_mapped || is_compat {
        let octets = ip.octets();
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

/// Returns [`true`] if the address appears to be globally routable.
///
/// Handles `IPv4`-mapped `IPv6` addresses (`::ffff:x.x.x.x`) by unmapping them
/// to `IPv4` and checking against [`is_global_ipv4`].
#[must_use]
#[inline]
pub(crate) const fn is_global_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(x) => is_global_ipv4(*x),
        IpAddr::V6(x) => match extract_ipv4_from_ipv6(x) {
            Some(v4) => is_global_ipv4(v4),
            None => is_global_ipv6(x),
        },
    }
}

/// Returns HTTP request with sensitive fields removed.
#[inline]
pub(crate) fn scrub_request(request: &http::request::Parts) -> http::request::Parts {
    let mut r = http::request::Request::new(()).into_parts().0;
    r.method.clone_from(&request.method);
    r.uri.clone_from(&request.uri);
    r.version = request.version;
    r.headers.clone_from(&request.headers);
    for header in &[
        http::header::AUTHORIZATION,
        http::header::PROXY_AUTHORIZATION,
        http::header::COOKIE,
    ] {
        if r.headers.contains_key(header) {
            r.headers
                .insert(header, http::HeaderValue::from_static(SCRUBBED_PLACEHOLDER));
        }
    }
    r
}

/// Returns SNI with sensitive data removed.
#[inline]
pub(crate) fn scrub_sni(mut sni: String) -> String {
    if let Some(to) = sni.find('.') {
        sni.replace_range(..to, SCRUBBED_PLACEHOLDER);
    }
    sni
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check;
    use http::uri;
    use std::net::{SocketAddrV4, SocketAddrV6};

    #[test]
    fn varint_length_boundaries() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(63), 1);
        assert_eq!(varint_len(64), 2);
        assert_eq!(varint_len(16_383), 2);
        assert_eq!(varint_len(16_384), 4);
        assert_eq!(varint_len(1_073_741_823), 4);
        assert_eq!(varint_len(1_073_741_824), 8);
        assert_eq!(varint_len(usize::MAX), 8);
    }

    #[test]
    fn sockaddr_conversion_v4() -> io::Result<()> {
        let address = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 1234);
        check(
            socket_addr_from_storage(&address.into())? == address.into(),
            "IPv4 socket address changed",
        )?;
        Ok(())
    }

    #[test]
    fn sockaddr_conversion_v6() -> io::Result<()> {
        let address = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1234, 0x1234, 42);
        check(
            socket_addr_from_storage(&address.into())? == address.into(),
            "IPv6 socket address changed",
        )?;
        Ok(())
    }

    #[test]
    fn sockaddr_rejects_non_ip() -> io::Result<()> {
        let socket = std::os::unix::net::UnixDatagram::unbound()?;
        let address = nix::sys::socket::getsockname::<SockaddrStorage>(socket.as_raw_fd())?;
        check(
            matches!(socket_addr_from_storage(&address), Err(e) if e.kind() == io::ErrorKind::InvalidData),
            "non-IP socket address was accepted",
        )?;
        Ok(())
    }

    #[test]
    fn fixed_size_ip_roundtrip_and_short_input() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
        ] {
            let mut encoded = BytesMut::new();
            put_fixed_size_ip(&mut encoded, &ip);
            encoded.put_u8(42);
            let mut encoded = encoded.freeze();
            let expected = if ip == IpAddr::V6(Ipv6Addr::LOCALHOST) {
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1))
            } else {
                ip
            };
            assert_eq!(get_fixed_size_ip(&mut encoded), Some(expected));
            assert_eq!(&encoded[..], &[42]);
        }
        for length in 0..FIXED_LENGTH_IP_WIRE_LENGTH {
            let mut bytes = Bytes::from(vec![1; length]);
            let original = bytes.clone();
            assert_eq!(get_fixed_size_ip(&mut bytes), None);
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn udp_receive_is_nonblocking_and_preserves_buffer_boundaries() -> io::Result<()> {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = receiver.local_addr()?;
        let socket = Socket::from(receiver);
        check(
            matches!(recv_from(&socket, None), Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "empty receive did not return WouldBlock",
        )?;
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        for (payload, size, expected) in [
            (&b"payload"[..], Some(3), &b"pay"[..]),
            (&b""[..], None, &b""[..]),
            (&b"discard"[..], Some(0), &b""[..]),
        ] {
            sender.send_to(payload, address)?;
            let (peer, actual) = recv_from(&socket, size)?;
            check(peer == sender.local_addr()?.ip(), "datagram peer changed")?;
            check(&actual[..] == expected, "datagram payload boundary changed")?;
        }
        sender.send_to(&vec![42; MIN_LINK_MTU + 1], address)?;
        check(
            recv_from(&socket, None)?.1.len() == MIN_LINK_MTU,
            "default receive size changed",
        )?;
        check(
            matches!(recv_from(&socket, None), Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "drained receive did not return WouldBlock",
        )?;
        Ok(())
    }

    #[test]
    fn socket_ttl_uses_the_requested_address_family() -> io::Result<()> {
        use socket2::{Domain, Protocol, Type};
        let v4 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let v6 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        for ttl in [1, 64, u8::MAX] {
            set_socket_ttl(&v4, true, ttl)?;
            set_socket_ttl(&v6, false, ttl)?;
            check(v4.ttl()? == u32::from(ttl), "IPv4 TTL changed")?;
            check(
                v6.unicast_hops_v6()? == u32::from(ttl),
                "IPv6 hop limit changed",
            )?;
        }
        set_socket_ttl(&v6, false, 0)?;
        check(v6.unicast_hops_v6()? == 0, "IPv6 zero hop limit changed")?;
        if cfg!(target_os = "linux") {
            check(
                set_socket_ttl(&v4, true, 0).is_err(),
                "IPv4 zero TTL was accepted",
            )?;
        }
        Ok(())
    }

    #[test]
    fn ipv6_interface_addresses_keep_their_priority() {
        let global = Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 1);
        let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        for (ip, flags, priority) in [
            (global, 0x80, 10),
            (global, 0, 9),
            (ula, 0x80, 6),
            (ula, 0, 5),
            (link_local, 0, 1),
            (Ipv6Addr::LOCALHOST, 0, 0),
        ] {
            assert_eq!(ipv6_interface_priority(&ip, flags), priority);
        }
    }

    #[test]
    fn ip_headers_reject_truncation_and_skip_ipv4_options() {
        let mut v4 = vec![0; MIN_IPV4_HEADER_SIZE + 4];
        v4[0] = 0x46;
        v4[9] = libc::IPPROTO_ICMP as u8;
        for length in 0..v4.len() {
            assert!(skip_ipv4_header(Bytes::copy_from_slice(&v4[..length])).is_none());
        }
        v4.extend_from_slice(b"icmp");
        assert_eq!(
            skip_ipv4_header(Bytes::from(v4)),
            Some((libc::IPPROTO_ICMP, Bytes::from_static(b"icmp")))
        );
        for first_byte in [0x44, 0x65] {
            let mut invalid = vec![0; MIN_IPV4_HEADER_SIZE];
            invalid[0] = first_byte;
            assert!(skip_ipv4_header(Bytes::from(invalid)).is_none());
        }
        for length in 0..MIN_IPV6_HEADER_SIZE {
            assert!(skip_ipv6_header(Bytes::from(vec![0x60; length])).is_none());
        }
        let mut invalid = vec![0; MIN_IPV6_HEADER_SIZE];
        invalid[0] = 0x40;
        assert!(skip_ipv6_header(Bytes::from(invalid)).is_none());
    }

    #[test]
    fn ipv6_extensions_use_eight_byte_units_and_reject_truncation() {
        for protocol in [
            libc::IPPROTO_HOPOPTS,
            libc::IPPROTO_ROUTING,
            libc::IPPROTO_DSTOPTS,
        ] {
            for ext_length in [0_u8, 1, u8::MAX] {
                let mut packet = vec![0; MIN_IPV6_HEADER_SIZE];
                packet[0] = 0x60;
                packet[6] = protocol as u8;
                packet.extend_from_slice(&[libc::IPPROTO_ICMPV6 as u8, ext_length]);
                packet.resize(MIN_IPV6_HEADER_SIZE + (usize::from(ext_length) + 1) * 8, 0);
                for length in MIN_IPV6_HEADER_SIZE..packet.len() {
                    assert!(skip_ipv6_header(Bytes::copy_from_slice(&packet[..length])).is_none());
                }
                packet.extend_from_slice(b"icmp");
                assert_eq!(
                    skip_ipv6_header(Bytes::from(packet)),
                    Some((libc::IPPROTO_ICMPV6, Bytes::from_static(b"icmp")))
                );
            }
        }
        let mut packet = vec![0; MIN_IPV6_HEADER_SIZE];
        packet[0] = 0x60;
        packet[6] = libc::IPPROTO_FRAGMENT as u8;
        packet.extend_from_slice(&[libc::IPPROTO_ICMPV6 as u8, 0, 0, 0, 0, 0, 0, 0]);
        for length in MIN_IPV6_HEADER_SIZE..packet.len() {
            assert!(skip_ipv6_header(Bytes::copy_from_slice(&packet[..length])).is_none());
        }
        assert_eq!(
            skip_ipv6_header(Bytes::from(packet)),
            Some((libc::IPPROTO_ICMPV6, Bytes::new()))
        );
    }

    #[test]
    fn checksum_folds_repeated_carries_and_pads_odd_payloads() {
        assert_eq!(rfc1071_checksum(&[]), 0xffff);
        assert_eq!(
            rfc1071_checksum(&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        assert_eq!(rfc1071_checksum(&[0xff, 0xff, 0, 1, 0xff, 0xff]), 0xfffe);
        assert_eq!(rfc1071_checksum(&[1, 2, 3]), 0xfbfd);
        assert_eq!(
            rfc1071_checksum(&vec![0xff; MAX_IP_PACKET_SIZE + 1]),
            0x00ff
        );
    }

    #[test]
    fn scrubbing_of_sni() {
        assert_eq!("one", scrub_sni("one".to_string()));
        assert_eq!(
            format!("{SCRUBBED_PLACEHOLDER}."),
            crate::net_utils::scrub_sni("one.".to_string())
        );
        assert_eq!(
            format!("{SCRUBBED_PLACEHOLDER}.one"),
            crate::net_utils::scrub_sni(".one".to_string())
        );
        assert_eq!(
            format!("{SCRUBBED_PLACEHOLDER}.two"),
            crate::net_utils::scrub_sni("one.two".to_string())
        );
        assert_eq!(
            format!("{SCRUBBED_PLACEHOLDER}.two.three"),
            crate::net_utils::scrub_sni("one.two.three".to_string())
        );
    }

    #[test]
    fn scrubbing_of_headers() {
        let mut original = http::request::Request::new(()).into_parts().0;
        original.method.clone_from(&http::Method::GET);
        original
            .uri
            .clone_from(&uri::Uri::from_static("https://httpbin.agrd.dev/abcd"));
        original.version = http::Version::HTTP_11;
        original.headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("secret1"),
        );
        original.headers.insert(
            http::header::PROXY_AUTHORIZATION,
            http::HeaderValue::from_static("secret2"),
        );
        original.headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("cookie1"),
        );
        original.headers.append(
            http::header::COOKIE,
            http::HeaderValue::from_static("cookie2"),
        );
        original.headers.append(
            http::header::COOKIE,
            http::HeaderValue::from_static("cookie3"),
        );
        original.headers.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("text/html"),
        );
        let mut scrubbed = scrub_request(&original);
        assert_eq!(original.method, scrubbed.method);
        assert_eq!(original.uri, scrubbed.uri);
        assert_eq!(original.version, scrubbed.version);
        assert_eq!(
            vec![SCRUBBED_PLACEHOLDER.as_bytes()],
            scrubbed
                .headers
                .get_all(http::header::AUTHORIZATION)
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![SCRUBBED_PLACEHOLDER.as_bytes()],
            scrubbed
                .headers
                .get_all(http::header::PROXY_AUTHORIZATION)
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![SCRUBBED_PLACEHOLDER.as_bytes()],
            scrubbed
                .headers
                .get_all(http::header::COOKIE)
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect::<Vec<_>>()
        );
        original.headers.remove(http::header::AUTHORIZATION);
        scrubbed.headers.remove(http::header::AUTHORIZATION);
        original.headers.remove(http::header::PROXY_AUTHORIZATION);
        scrubbed.headers.remove(http::header::PROXY_AUTHORIZATION);
        original.headers.remove(http::header::COOKIE);
        scrubbed.headers.remove(http::header::COOKIE);
        assert_eq!(original.headers, scrubbed.headers);
    }

    #[test]
    fn is_global_ip_blocks_ipv4_mapped_private() {
        // ::ffff:192.168.1.1 — IPv4-mapped private address must be rejected
        let mapped_private: IpAddr =
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101));
        assert!(!is_global_ip(&mapped_private));

        // ::ffff:10.0.0.1 — IPv4-mapped 10.x private
        let mapped_10: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001));
        assert!(!is_global_ip(&mapped_10));

        // ::ffff:127.0.0.1 — IPv4-mapped loopback
        let mapped_loopback: IpAddr =
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        assert!(!is_global_ip(&mapped_loopback));

        // ::ffff:172.17.0.1 — IPv4-mapped Docker bridge
        let mapped_docker: IpAddr =
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xac11, 0x0001));
        assert!(!is_global_ip(&mapped_docker));

        // ::ffff:169.254.1.1 — IPv4-mapped link-local
        let mapped_link_local: IpAddr =
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0x0101));
        assert!(!is_global_ip(&mapped_link_local));
    }

    #[test]
    fn is_global_ip_blocks_ipv4_compatible_private() {
        // ::192.168.1.1 — IPv4-compatible (deprecated) private address
        let compat_private: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc0a8, 0x0101));
        assert!(!is_global_ip(&compat_private));

        // ::10.0.0.1 — IPv4-compatible 10.x
        let compat_10: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0a00, 0x0001));
        assert!(!is_global_ip(&compat_10));
    }

    #[test]
    fn is_global_ip_allows_ipv4_mapped_public() {
        // ::ffff:8.8.8.8 — IPv4-mapped public address must be allowed
        let mapped_public: IpAddr =
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808));
        assert!(is_global_ip(&mapped_public));
    }

    #[test]
    fn is_global_ip_handles_native_ipv6() {
        // Native IPv6 loopback ::1 must be rejected
        assert!(!is_global_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // Native IPv6 unspecified :: must be rejected
        assert!(!is_global_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        // Plain IPv4 private must be rejected
        assert!(!is_global_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        // Plain IPv4 public must be allowed
        assert!(is_global_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn scrubbing_of_headers_do_not_add() {
        let mut original = http::request::Request::new(()).into_parts().0;
        original.headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("secret1"),
        );
        original.headers.insert(
            http::header::PROXY_AUTHORIZATION,
            http::HeaderValue::from_static("secret2"),
        );
        let scrubbed = scrub_request(&original);
        assert_eq!(
            vec![SCRUBBED_PLACEHOLDER.as_bytes()],
            scrubbed
                .headers
                .get_all(http::header::AUTHORIZATION)
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vec![SCRUBBED_PLACEHOLDER.as_bytes()],
            scrubbed
                .headers
                .get_all(http::header::PROXY_AUTHORIZATION)
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            0,
            scrubbed
                .headers
                .get_all(http::header::COOKIE)
                .iter()
                .count()
        );
    }

    #[test]
    fn test_unmap_ipv6_mapped_ipv4() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304));
        assert_eq!(super::unmap_ipv6(mapped), IpAddr::from([1, 2, 3, 4]));
    }

    #[test]
    fn test_unmap_ipv6_pure_ipv6_unchanged() {
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(super::unmap_ipv6(v6), v6);
    }

    #[test]
    fn test_unmap_ipv6_plain_ipv4_unchanged() {
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(super::unmap_ipv6(v4), v4);
    }

    #[test]
    fn test_unmap_ipv6_ipv4_compatible() {
        // IPv4-compatible address ::192.168.1.1
        let compat: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc0a8, 0x0101));
        assert_eq!(super::unmap_ipv6(compat), IpAddr::from([192, 168, 1, 1]));
    }
}
