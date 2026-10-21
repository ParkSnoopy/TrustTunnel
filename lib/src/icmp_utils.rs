use crate::net_utils;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};

const TYPE_SIZE: usize = 1;
const CODE_SIZE: usize = 1;
const CHECKSUM_SIZE: usize = 2;
const ICMP_ID_SIZE: usize = 2;
const ICMP_SEQNO_SIZE: usize = 2;
/// The meaning of the last 4 bytes depends on the type, but they are always present
/// in a message
const ICMP_MIN_COMMON_HEADER_SIZE: usize = TYPE_SIZE + CODE_SIZE + CHECKSUM_SIZE + 4;
const ICMP_V4_MIN_MATCHING_DATA_SIZE: usize =
    net_utils::MIN_IPV4_HEADER_SIZE + ICMP_MIN_COMMON_HEADER_SIZE;
const ECHO_HEADER_SIZE: usize =
    TYPE_SIZE + CODE_SIZE + CHECKSUM_SIZE + ICMP_ID_SIZE + ICMP_SEQNO_SIZE;

#[derive(Debug, Clone)]
pub enum Message {
    V4(v4::Message),
    V6(v6::Message),
}

#[derive(Debug, Clone)]
pub struct Echo {
    pub code: u8,
    /// If code = 0, an identifier to aid in matching echos and replies, may be zero.
    pub identifier: u16,
    /// If code = 0, a sequence number to aid in matching echos and replies, may be zero.
    pub sequence_number: u16,
    /// The data received in the echo message must be returned in the echo reply message.
    pub data: Bytes,
}

#[derive(Debug)]
pub enum DeserializeError {
    InvalidLength(String),
    MessageType(u8),
    DestinationUnreachableCode(u8),
    TimeExceededCode(u8),
}

impl Display for DeserializeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(message) => f.write_str(message),
            Self::MessageType(value) => write!(f, "Unsupported message type: {value}"),
            Self::DestinationUnreachableCode(value) => {
                write!(f, "Invalid destination unreachable code: {value}")
            }
            Self::TimeExceededCode(value) => write!(f, "Invalid time exceeded code: {value}"),
        }
    }
}

impl std::error::Error for DeserializeError {}

pub type DeserializeResult<M> = Result<M, DeserializeError>;

impl Message {
    /// Serialize the message into the wire format
    pub fn serialize(&self) -> Bytes {
        match self {
            Self::V4(x) => x.serialize(),
            Self::V6(x) => x.serialize(),
        }
    }

    /// Unwrap an [`Echo`] message in case the message contains it
    pub const fn to_echo(&self) -> Option<&Echo> {
        match self {
            Self::V4(v4::Message::Echo(x) | v4::Message::EchoReply(x))
            | Self::V6(v6::Message::EchoRequest(x) | v6::Message::EchoReply(x)) => Some(x),
            _ => None,
        }
    }

    /// Get the echo request that is responded responded by this message
    pub fn responded_echo_request(&self) -> Option<Echo> {
        match self {
            Self::V4(x) => x.responded_echo_request(),
            Self::V6(x) => x.responded_echo_request(),
        }
    }

    /// Get the message type identifier
    pub const fn type_id(&self) -> u8 {
        match self {
            Self::V4(x) => x.type_id().0,
            Self::V6(x) => x.type_id().0,
        }
    }

    /// Get the message code identifier
    pub const fn code(&self) -> u8 {
        match self {
            Self::V4(x) => x.code(),
            Self::V6(x) => x.code(),
        }
    }

    /// Get the message on-the-wire length
    pub const fn len(&self) -> usize {
        match self {
            Self::V4(x) => x.len(),
            Self::V6(x) => x.len(),
        }
    }
}

impl Hash for Echo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identifier.hash(state);
        self.sequence_number.hash(state);
    }
}

impl Eq for Echo {}

impl PartialEq for Echo {
    fn eq(&self, other: &Self) -> bool {
        if self.identifier != other.identifier || self.sequence_number != other.sequence_number {
            return false;
        }

        if self.data.len() >= other.data.len() {
            self.data.starts_with(&other.data)
        } else {
            other.data.starts_with(&self.data)
        }
    }
}

impl Echo {
    fn serialize(&self, type_id: u8) -> Bytes {
        let mut packet = BytesMut::new();
        packet.reserve(ECHO_HEADER_SIZE + self.data.len());

        packet.put_u8(type_id);
        packet.put_u8(0);
        packet.put_u16(0);
        packet.put_u16(self.identifier);
        packet.put_u16(self.sequence_number);
        packet.put_slice(&self.data);

        let checksum = net_utils::rfc1071_checksum(&packet).to_be_bytes();
        packet[2..4].copy_from_slice(&checksum);

        packet.freeze()
    }
}

impl From<v4::Message> for Message {
    fn from(x: v4::Message) -> Self {
        Self::V4(x)
    }
}

impl From<v6::Message> for Message {
    fn from(x: v6::Message) -> Self {
        Self::V6(x)
    }
}

enum LengthCheck {
    Exact(usize),
    LowerBound(usize),
}

macro_rules! deserialize_packet {
    ($func:ident, $packet:ident, $length_check:expr, $out_type:ident $(, $wrap:ident)?) => {
        match ($length_check, 1 + $packet.len()) {
            // 1 is for message type extracted earlier
            (LengthCheck::Exact(n), m) if n != m => Err(super::DeserializeError::InvalidLength(
                format!("Expected length: {}, packet length: {}", n, m),
            )),
            (LengthCheck::LowerBound(n), m) if m < n => {
                Err(super::DeserializeError::InvalidLength(format!(
                    "Expected length at least: {}, packet length: {}",
                    n, m
                )))
            }
            _ => {
                let code = $packet.get_u8();
                // todo: verify checksum
                $($wrap)?(Self::$func(code, $packet.split_off(super::CHECKSUM_SIZE))).map(Message::$out_type)
            }
        }
    };
}

pub mod v4 {
    use super::LengthCheck;
    use crate::net_utils;
    use bytes::{Buf, Bytes};

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct TypeId(pub u8);

    impl TypeId {
        pub const ECHO_REPLY: Self = Self(0);
        pub const DESTINATION_UNREACHABLE: Self = Self(3);
        pub const SOURCE_QUENCH: Self = Self(4);
        pub const REDIRECT: Self = Self(5);
        pub const ECHO: Self = Self(8);
        pub const TIME_EXCEEDED: Self = Self(11);
        pub const PARAMETER_PROBLEM: Self = Self(12);
        pub const TIMESTAMP: Self = Self(13);
        pub const TIMESTAMP_REPLY: Self = Self(14);
        pub const INFORMATION_REQUEST: Self = Self(15);
        pub const INFORMATION_REPLY: Self = Self(16);
    }

    #[derive(Debug, Clone)]
    pub enum Message {
        DestinationUnreachable(DestinationUnreachable),
        TimeExceeded(TimeExceeded),
        ParameterProblem(ParameterProblem),
        SourceQuench(SourceQuench),
        Redirect(Redirect),
        Echo(super::Echo),
        EchoReply(super::Echo),
        Timestamp(Timestamp),
        TimestampReply(Timestamp),
        InformationRequest(Information),
        InformationReply(Information),
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct DestinationUnreachableCode(u8);

    impl DestinationUnreachableCode {
        pub const NET_UNREACHABLE: Self = Self(0);
        pub const HOST_UNREACHABLE: Self = Self(1);
        pub const PROTOCOL_UNREACHABLE: Self = Self(2);
        pub const PORT_UNREACHABLE: Self = Self(3);
        pub const FRAGMENTATION_NEEDED: Self = Self(4);
        pub const ROUTE_FAILED: Self = Self(5);
    }

    #[derive(Debug, Clone)]
    pub struct DestinationUnreachable {
        pub code: DestinationUnreachableCode,
        /// The internet header plus the first 64 bits of the original
        /// datagram's data.  This data is used by the host to match the
        /// message to the appropriate process.  If a higher level protocol
        /// uses port numbers, they are assumed to be in the first 64 data
        /// bits of the original datagram's data.
        pub data: Bytes,
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct TimeExceededCode(u8);

    impl TimeExceededCode {
        /// Time to live exceeded in transit
        pub const TTL_EXCEEDED: Self = Self(0);
        /// Fragment reassembly time exceeded
        pub const FRAGMENT_REASSEMBLY: Self = Self(1);
    }

    #[derive(Debug, Clone)]
    pub struct TimeExceeded {
        pub code: TimeExceededCode,
        /// The internet header plus the first 64 bits of the original
        /// datagram's data.  This data is used by the host to match the
        /// message to the appropriate process.  If a higher level protocol
        /// uses port numbers, they are assumed to be in the first 64 data
        /// bits of the original datagram's data.
        pub data: Bytes,
    }

    #[derive(Clone)]
    pub struct ParameterProblem {
        pub code: u8,
        /// If code = 0, identifies the octet where an error was detected.
        pub pointer: u8,
        /// The internet header plus the first 64 bits of the original
        /// datagram's data.  This data is used by the host to match the
        /// message to the appropriate process.  If a higher level protocol
        /// uses port numbers, they are assumed to be in the first 64 data
        /// bits of the original datagram's data.
        pub data: Bytes,
    }

    impl std::fmt::Debug for ParameterProblem {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ParameterProblem")
                .field("code", &self.code)
                .field("pointer", &self.pointer)
                .field("data", &self.data)
                .finish()
        }
    }

    #[derive(Debug, Clone)]
    pub struct SourceQuench {
        pub code: u8,
        /// The internet header plus the first 64 bits of the original
        /// datagram's data.  This data is used by the host to match the
        /// message to the appropriate process.  If a higher level protocol
        /// uses port numbers, they are assumed to be in the first 64 data
        /// bits of the original datagram's data.
        pub data: Bytes,
    }

    #[derive(Clone)]
    pub struct Redirect {
        /// 0 = Redirect datagrams for the Network.
        /// 1 = Redirect datagrams for the Host.
        /// 2 = Redirect datagrams for the Type of Service and Network.
        /// 3 = Redirect datagrams for the Type of Service and Host.
        pub code: u8,
        /// Address of the gateway to which traffic for the network specified
        /// in the internet destination network field of the original
        /// datagram's data should be sent.
        pub gateway_redirect_address: u32,
        /// The internet header plus the first 64 bits of the original
        /// datagram's data.  This data is used by the host to match the
        /// message to the appropriate process.  If a higher level protocol
        /// uses port numbers, they are assumed to be in the first 64 data
        /// bits of the original datagram's data.
        pub data: Bytes,
    }

    impl std::fmt::Debug for Redirect {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Redirect")
                .field("code", &self.code)
                .field("gateway_redirect_address", &self.gateway_redirect_address)
                .field("data", &self.data)
                .finish()
        }
    }

    #[derive(Copy, Clone)]
    pub struct TimestampMessage {
        pub code: u8,
        /// If code = 0, an identifier to aid in matching timestamp and replies, may be zero.
        pub identifier: u16,
        /// If code = 0, a sequence number to aid in matching timestamp and replies, may be zero.
        pub sequence_number: u16,
        /// The time the sender last touched the message before sending it.
        pub originate_timestamp: u32,
        /// The time the echoer first touched it on receipt.
        pub receive_timestamp: u32,
        /// The time the echoer last touched the message on sending it.
        pub transmit_timestamp: u32,
    }

    pub type Timestamp = TimestampMessage;

    impl std::fmt::Debug for Timestamp {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Timestamp")
                .field("code", &self.code)
                .field("identifier", &self.identifier)
                .field("sequence_number", &self.sequence_number)
                .field("originate_timestamp", &self.originate_timestamp)
                .field("receive_timestamp", &self.receive_timestamp)
                .field("transmit_timestamp", &self.transmit_timestamp)
                .finish()
        }
    }

    #[derive(Copy, Clone)]
    pub struct Information {
        pub code: u8,
        /// If code = 0, an identifier to aid in matching request and replies, may be zero.
        pub identifier: u16,
        /// If code = 0, a sequence number to aid in matching request and replies, may be zero.
        pub sequence_number: u16,
    }

    impl std::fmt::Debug for Information {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Information")
                .field("code", &self.code)
                .field("identifier", &self.identifier)
                .field("sequence_number", &self.sequence_number)
                .finish()
        }
    }

    impl Message {
        pub const fn type_id(&self) -> TypeId {
            match self {
                Self::DestinationUnreachable(_) => TypeId::DESTINATION_UNREACHABLE,
                Self::TimeExceeded(_) => TypeId::TIME_EXCEEDED,
                Self::ParameterProblem(_) => TypeId::PARAMETER_PROBLEM,
                Self::SourceQuench(_) => TypeId::SOURCE_QUENCH,
                Self::Redirect(_) => TypeId::REDIRECT,
                Self::Echo(_) => TypeId::ECHO,
                Self::EchoReply(_) => TypeId::ECHO_REPLY,
                Self::Timestamp(_) => TypeId::TIMESTAMP,
                Self::TimestampReply(_) => TypeId::TIMESTAMP_REPLY,
                Self::InformationRequest(_) => TypeId::INFORMATION_REQUEST,
                Self::InformationReply(_) => TypeId::INFORMATION_REPLY,
            }
        }

        pub const fn code(&self) -> u8 {
            match self {
                Self::DestinationUnreachable(x) => x.code.0,
                Self::TimeExceeded(x) => x.code.0,
                Self::ParameterProblem(x) => x.code,
                Self::SourceQuench(x) => x.code,
                Self::Redirect(x) => x.code,
                Self::Echo(x) | Self::EchoReply(x) => x.code,
                Self::Timestamp(x) | Self::TimestampReply(x) => x.code,
                Self::InformationRequest(x) | Self::InformationReply(x) => x.code,
            }
        }

        pub const fn len(&self) -> usize {
            super::ICMP_MIN_COMMON_HEADER_SIZE
                + match self {
                    Self::DestinationUnreachable(x) => x.data.len(),
                    Self::TimeExceeded(x) => x.data.len(),
                    Self::ParameterProblem(x) => x.data.len(),
                    Self::SourceQuench(x) => x.data.len(),
                    Self::Redirect(x) => x.data.len(),
                    Self::Echo(x) | Self::EchoReply(x) => x.data.len(),
                    Self::Timestamp(x) | Self::TimestampReply(x) => {
                        std::mem::size_of_val(&x.originate_timestamp)
                            + std::mem::size_of_val(&x.receive_timestamp)
                            + std::mem::size_of_val(&x.transmit_timestamp)
                    }
                    Self::InformationRequest(_) | Self::InformationReply(_) => 0,
                }
        }

        pub fn responded_echo_request(&self) -> Option<super::Echo> {
            let icmp_data = match self {
                Self::DestinationUnreachable(x) => Some(&x.data),
                Self::TimeExceeded(x) => Some(&x.data),
                Self::ParameterProblem(x) => Some(&x.data),
                Self::SourceQuench(x) => Some(&x.data),
                Self::Redirect(x) => Some(&x.data),
                Self::EchoReply(x) => return Some(x.clone()),
                _ => None,
            }?;

            let (proto, mut payload) = net_utils::skip_ipv4_header(icmp_data.clone())?;
            if proto != libc::IPPROTO_ICMP
                || payload.is_empty()
                || TypeId(payload.get_u8()) != TypeId::ECHO
            {
                return None;
            }
            match deserialize_packet!(
                parse_echo,
                payload,
                LengthCheck::LowerBound(super::ECHO_HEADER_SIZE),
                Echo,
                Ok
            ) {
                Ok(Self::Echo(x)) => Some(x),
                _ => None,
            }
        }

        pub fn serialize(&self) -> Bytes {
            match self {
                Self::Echo(x) => x.serialize(self.type_id().0),
                x => unreachable!("{:?}", x),
            }
        }

        pub fn deserialize(mut packet: Bytes) -> super::DeserializeResult<Self> {
            if packet.is_empty() {
                return Err(super::DeserializeError::InvalidLength(
                    "Empty packet".to_string(),
                ));
            }

            match TypeId(packet.get_u8()) {
                TypeId::ECHO_REPLY => deserialize_packet!(
                    parse_echo,
                    packet,
                    LengthCheck::LowerBound(super::ECHO_HEADER_SIZE),
                    EchoReply,
                    Ok
                ),
                TypeId::DESTINATION_UNREACHABLE => deserialize_packet!(
                    parse_destination_unreachable,
                    packet,
                    LengthCheck::LowerBound(
                        super::ICMP_MIN_COMMON_HEADER_SIZE + super::ICMP_V4_MIN_MATCHING_DATA_SIZE
                    ),
                    DestinationUnreachable
                ),
                TypeId::SOURCE_QUENCH => deserialize_packet!(
                    parse_source_quench,
                    packet,
                    LengthCheck::LowerBound(
                        super::ICMP_MIN_COMMON_HEADER_SIZE + super::ICMP_V4_MIN_MATCHING_DATA_SIZE
                    ),
                    SourceQuench,
                    Ok
                ),
                TypeId::REDIRECT => deserialize_packet!(
                    parse_redirect,
                    packet,
                    LengthCheck::LowerBound(
                        super::ICMP_MIN_COMMON_HEADER_SIZE + super::ICMP_V4_MIN_MATCHING_DATA_SIZE
                    ),
                    Redirect,
                    Ok
                ),
                TypeId::ECHO => deserialize_packet!(
                    parse_echo,
                    packet,
                    LengthCheck::LowerBound(super::ECHO_HEADER_SIZE),
                    Echo,
                    Ok
                ),
                TypeId::TIME_EXCEEDED => deserialize_packet!(
                    parse_time_exceeded,
                    packet,
                    LengthCheck::LowerBound(
                        super::ICMP_MIN_COMMON_HEADER_SIZE + super::ICMP_V4_MIN_MATCHING_DATA_SIZE
                    ),
                    TimeExceeded
                ),
                TypeId::PARAMETER_PROBLEM => deserialize_packet!(
                    parse_parameter_problem,
                    packet,
                    LengthCheck::LowerBound(
                        super::ICMP_MIN_COMMON_HEADER_SIZE + super::ICMP_V4_MIN_MATCHING_DATA_SIZE
                    ),
                    ParameterProblem,
                    Ok
                ),
                TypeId::TIMESTAMP => {
                    deserialize_packet!(
                        parse_timestamp,
                        packet,
                        LengthCheck::Exact(20),
                        Timestamp,
                        Ok
                    )
                }
                TypeId::TIMESTAMP_REPLY => deserialize_packet!(
                    parse_timestamp,
                    packet,
                    LengthCheck::Exact(20),
                    TimestampReply,
                    Ok
                ),
                TypeId::INFORMATION_REQUEST => deserialize_packet!(
                    parse_information,
                    packet,
                    LengthCheck::Exact(20),
                    InformationRequest,
                    Ok
                ),
                TypeId::INFORMATION_REPLY => deserialize_packet!(
                    parse_information,
                    packet,
                    LengthCheck::Exact(20),
                    InformationReply,
                    Ok
                ),
                x => Err(super::DeserializeError::MessageType(x.0)),
            }
        }

        fn parse_echo(code: u8, packet: Bytes) -> super::Echo {
            super::parse_echo(code, packet)
        }

        fn parse_destination_unreachable(
            code: u8,
            mut packet: Bytes,
        ) -> super::DeserializeResult<DestinationUnreachable> {
            Ok(DestinationUnreachable {
                code: match DestinationUnreachableCode(code) {
                    DestinationUnreachableCode::NET_UNREACHABLE
                    | DestinationUnreachableCode::HOST_UNREACHABLE
                    | DestinationUnreachableCode::PROTOCOL_UNREACHABLE
                    | DestinationUnreachableCode::PORT_UNREACHABLE
                    | DestinationUnreachableCode::FRAGMENTATION_NEEDED
                    | DestinationUnreachableCode::ROUTE_FAILED => DestinationUnreachableCode(code),
                    _ => return Err(super::DeserializeError::DestinationUnreachableCode(code)),
                },
                data: packet.split_off(4),
            })
        }

        fn parse_source_quench(code: u8, mut packet: Bytes) -> SourceQuench {
            SourceQuench {
                code,
                data: packet.split_off(4),
            }
        }

        fn parse_redirect(code: u8, mut packet: Bytes) -> Redirect {
            Redirect {
                code,
                gateway_redirect_address: packet.get_u32(),
                data: packet,
            }
        }

        fn parse_time_exceeded(
            code: u8,
            mut packet: Bytes,
        ) -> super::DeserializeResult<TimeExceeded> {
            Ok(TimeExceeded {
                code: match TimeExceededCode(code) {
                    TimeExceededCode::TTL_EXCEEDED | TimeExceededCode::FRAGMENT_REASSEMBLY => {
                        TimeExceededCode(code)
                    }
                    _ => return Err(super::DeserializeError::TimeExceededCode(code)),
                },
                data: packet.split_off(4),
            })
        }

        fn parse_parameter_problem(code: u8, mut packet: Bytes) -> ParameterProblem {
            ParameterProblem {
                code,
                pointer: packet.get_u8(),
                data: packet.split_off(3),
            }
        }

        fn parse_timestamp(code: u8, mut packet: Bytes) -> Timestamp {
            Timestamp {
                code,
                identifier: packet.get_u16(),
                sequence_number: packet.get_u16(),
                originate_timestamp: packet.get_u32(),
                receive_timestamp: packet.get_u32(),
                transmit_timestamp: packet.get_u32(),
            }
        }

        fn parse_information(code: u8, mut packet: Bytes) -> Information {
            Information {
                code,
                identifier: packet.get_u16(),
                sequence_number: packet.get_u16(),
            }
        }
    }
}

pub mod v6 {
    use super::LengthCheck;
    use crate::net_utils;
    use bytes::{Buf, Bytes};

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct TypeId(pub u8);

    impl TypeId {
        pub const DESTINATION_UNREACHABLE: Self = Self(1);
        pub const PACKET_TOO_BIG: Self = Self(2);
        pub const TIME_EXCEEDED: Self = Self(3);
        pub const PARAMETER_PROBLEM: Self = Self(4);
        pub const ECHO_REQUEST: Self = Self(128);
        pub const ECHO_REPLY: Self = Self(129);
    }

    #[derive(Debug, Clone)]
    pub enum Message {
        DestinationUnreachable(DestinationUnreachable),
        PacketTooBig(PacketTooBig),
        TimeExceeded(TimeExceeded),
        ParameterProblem(ParameterProblem),
        EchoRequest(super::Echo),
        EchoReply(super::Echo),
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct DestinationUnreachableCode(u8);

    impl DestinationUnreachableCode {
        /// No route to destination
        pub const NO_ROUTE: Self = Self(0);
        /// Communication with destination administratively prohibited
        pub const ADMINISTRATIVELY_PROHIBITED: Self = Self(1);
        /// Beyond scope of source address
        pub const BEYOND_SCOPE: Self = Self(2);
        /// Address unreachable
        pub const ADDRESS_UNREACHABLE: Self = Self(3);
        /// Port unreachable
        pub const PORT_UNREACHABLE: Self = Self(4);
        /// Source address failed ingress/egress policy
        pub const SOURCE_FAILED_POLICY: Self = Self(5);
        /// Reject route to destination
        pub const REJECT_ROUTE: Self = Self(6);
    }

    #[derive(Debug, Clone)]
    pub struct DestinationUnreachable {
        pub code: DestinationUnreachableCode,
        /// As much of invoking packet as possible without the `ICMPv6` packet
        /// exceeding the minimum `IPv6` MTU.
        pub data: Bytes,
    }

    #[derive(Clone)]
    pub struct PacketTooBig {
        pub code: u8,
        /// The Maximum Transmission Unit of the next-hop link.
        pub mtu: u32,
        /// As much of invoking packet as possible without the `ICMPv6` packet
        /// exceeding the minimum `IPv6` MTU.
        pub data: Bytes,
    }

    impl std::fmt::Debug for PacketTooBig {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PacketTooBig")
                .field("code", &self.code)
                .field("mtu", &self.mtu)
                .field("data", &self.data)
                .finish()
        }
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct TimeExceededCode(u8);

    impl TimeExceededCode {
        /// Hop limit exceeded in transit
        pub const HOP_LIMIT: Self = Self(0);
        /// Fragment reassembly time exceeded
        pub const FRAGMENT_REASSEMBLY: Self = Self(1);
    }

    #[derive(Debug, Clone)]
    pub struct TimeExceeded {
        pub code: TimeExceededCode,
        /// As much of invoking packet as possible without the `ICMPv6` packet
        /// exceeding the minimum `IPv6` MTU.
        pub data: Bytes,
    }

    #[derive(Clone)]
    pub struct ParameterProblem {
        /// 0 - Erroneous header field encountered
        /// 1 - Unrecognized Next Header type encountered
        /// 2 - Unrecognized `IPv6` option encountered
        pub code: u8,
        /// Identifies the octet offset within the
        /// invoking packet where the error was detected.
        ///
        /// The pointer will point beyond the end of the `ICMPv6`
        /// packet if the field in error is beyond what can fit
        /// in the maximum size of an `ICMPv6` error message.
        pub pointer: u32,
        /// As much of invoking packet as possible without the `ICMPv6` packet
        /// exceeding the minimum `IPv6` MTU.
        pub data: Bytes,
    }

    impl std::fmt::Debug for ParameterProblem {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ParameterProblem")
                .field("code", &self.code)
                .field("pointer", &self.pointer)
                .field("data", &self.data)
                .finish()
        }
    }

    impl Message {
        pub const fn type_id(&self) -> TypeId {
            match self {
                Self::DestinationUnreachable(_) => TypeId::DESTINATION_UNREACHABLE,
                Self::PacketTooBig(_) => TypeId::PACKET_TOO_BIG,
                Self::TimeExceeded(_) => TypeId::TIME_EXCEEDED,
                Self::ParameterProblem(_) => TypeId::PARAMETER_PROBLEM,
                Self::EchoRequest(_) => TypeId::ECHO_REQUEST,
                Self::EchoReply(_) => TypeId::ECHO_REPLY,
            }
        }

        pub const fn code(&self) -> u8 {
            match self {
                Self::DestinationUnreachable(x) => x.code.0,
                Self::PacketTooBig(x) => x.code,
                Self::TimeExceeded(x) => x.code.0,
                Self::ParameterProblem(x) => x.code,
                Self::EchoRequest(x) | Self::EchoReply(x) => x.code,
            }
        }

        pub const fn len(&self) -> usize {
            super::ICMP_MIN_COMMON_HEADER_SIZE
                + match self {
                    Self::DestinationUnreachable(x) => x.data.len(),
                    Self::PacketTooBig(x) => x.data.len(),
                    Self::TimeExceeded(x) => x.data.len(),
                    Self::ParameterProblem(x) => x.data.len(),
                    Self::EchoRequest(x) | Self::EchoReply(x) => x.data.len(),
                }
        }

        pub fn responded_echo_request(&self) -> Option<super::Echo> {
            let icmp_data = match self {
                Self::DestinationUnreachable(x) => Some(&x.data),
                Self::PacketTooBig(x) => Some(&x.data),
                Self::TimeExceeded(x) => Some(&x.data),
                Self::ParameterProblem(x) => Some(&x.data),
                Self::EchoRequest(_) => None,
                Self::EchoReply(x) => return Some(x.clone()),
            }?;

            let (proto, mut payload) = net_utils::skip_ipv6_header(icmp_data.clone())?;
            if proto != libc::IPPROTO_ICMPV6
                || payload.is_empty()
                || TypeId(payload.get_u8()) != TypeId::ECHO_REQUEST
            {
                return None;
            }
            match deserialize_packet!(
                parse_echo,
                payload,
                LengthCheck::LowerBound(super::ICMP_MIN_COMMON_HEADER_SIZE),
                EchoRequest,
                Ok
            ) {
                Ok(Self::EchoRequest(x)) => Some(x),
                _ => None,
            }
        }

        pub fn serialize(&self) -> Bytes {
            match self {
                Self::EchoRequest(x) => x.serialize(self.type_id().0),
                x => unreachable!("{:?}", x),
            }
        }

        pub fn deserialize(mut packet: Bytes) -> super::DeserializeResult<Self> {
            if packet.is_empty() {
                return Err(super::DeserializeError::InvalidLength(
                    "Empty packet".to_string(),
                ));
            }

            match TypeId(packet.get_u8()) {
                TypeId::DESTINATION_UNREACHABLE => deserialize_packet!(
                    parse_destination_unreachable,
                    packet,
                    LengthCheck::LowerBound(
                        super::ICMP_MIN_COMMON_HEADER_SIZE + net_utils::MIN_IPV6_HEADER_SIZE
                    ),
                    DestinationUnreachable
                ),
                TypeId::PACKET_TOO_BIG => deserialize_packet!(
                    parse_packet_too_big,
                    packet,
                    LengthCheck::LowerBound(
                        super::ICMP_MIN_COMMON_HEADER_SIZE + net_utils::MIN_IPV6_HEADER_SIZE
                    ),
                    PacketTooBig,
                    Ok
                ),
                TypeId::TIME_EXCEEDED => deserialize_packet!(
                    parse_time_exceeded,
                    packet,
                    LengthCheck::LowerBound(
                        super::ICMP_MIN_COMMON_HEADER_SIZE + net_utils::MIN_IPV6_HEADER_SIZE
                    ),
                    TimeExceeded
                ),
                TypeId::PARAMETER_PROBLEM => deserialize_packet!(
                    parse_parameter_problem,
                    packet,
                    LengthCheck::LowerBound(
                        super::ICMP_MIN_COMMON_HEADER_SIZE + net_utils::MIN_IPV6_HEADER_SIZE
                    ),
                    ParameterProblem,
                    Ok
                ),
                TypeId::ECHO_REQUEST => deserialize_packet!(
                    parse_echo,
                    packet,
                    LengthCheck::LowerBound(super::ICMP_MIN_COMMON_HEADER_SIZE),
                    EchoRequest,
                    Ok
                ),
                TypeId::ECHO_REPLY => deserialize_packet!(
                    parse_echo,
                    packet,
                    LengthCheck::LowerBound(super::ICMP_MIN_COMMON_HEADER_SIZE),
                    EchoReply,
                    Ok
                ),
                x => Err(super::DeserializeError::MessageType(x.0)),
            }
        }

        fn parse_echo(code: u8, packet: Bytes) -> super::Echo {
            super::parse_echo(code, packet)
        }

        fn parse_destination_unreachable(
            code: u8,
            mut packet: Bytes,
        ) -> super::DeserializeResult<DestinationUnreachable> {
            Ok(DestinationUnreachable {
                code: match DestinationUnreachableCode(code) {
                    DestinationUnreachableCode::NO_ROUTE
                    | DestinationUnreachableCode::ADMINISTRATIVELY_PROHIBITED
                    | DestinationUnreachableCode::BEYOND_SCOPE
                    | DestinationUnreachableCode::ADDRESS_UNREACHABLE
                    | DestinationUnreachableCode::PORT_UNREACHABLE
                    | DestinationUnreachableCode::SOURCE_FAILED_POLICY
                    | DestinationUnreachableCode::REJECT_ROUTE => DestinationUnreachableCode(code),
                    _ => return Err(super::DeserializeError::DestinationUnreachableCode(code)),
                },
                data: packet.split_off(4),
            })
        }

        fn parse_packet_too_big(code: u8, mut packet: Bytes) -> PacketTooBig {
            PacketTooBig {
                code,
                mtu: packet.get_u32(),
                data: packet,
            }
        }

        fn parse_time_exceeded(
            code: u8,
            mut packet: Bytes,
        ) -> super::DeserializeResult<TimeExceeded> {
            Ok(TimeExceeded {
                code: match TimeExceededCode(code) {
                    TimeExceededCode::HOP_LIMIT | TimeExceededCode::FRAGMENT_REASSEMBLY => {
                        TimeExceededCode(code)
                    }
                    _ => return Err(super::DeserializeError::TimeExceededCode(code)),
                },
                data: packet.split_off(4),
            })
        }

        fn parse_parameter_problem(code: u8, mut packet: Bytes) -> ParameterProblem {
            ParameterProblem {
                code,
                pointer: packet.get_u32(),
                data: packet,
            }
        }
    }
}

fn parse_echo(code: u8, mut packet: Bytes) -> Echo {
    Echo {
        code,
        identifier: packet.get_u16(),
        sequence_number: packet.get_u16(),
        data: packet,
    }
}

#[cfg(test)]
mod tests {
    use super::{v4, v6, Bytes, DeserializeError, Echo, Message};

    #[test]
    fn echo_wire_bytes_are_unchanged() {
        let echo = Echo {
            code: 0,
            identifier: 0x1234,
            sequence_number: 0x5678,
            data: Bytes::from_static(b"ping"),
        };
        for (message, expected) in [
            (
                Message::V4(v4::Message::Echo(echo.clone())),
                Bytes::from_static(b"\x08\x00\xb0\x82\x12\x34\x56\x78ping"),
            ),
            (
                Message::V6(v6::Message::EchoRequest(echo)),
                Bytes::from_static(b"\x80\x00\x38\x82\x12\x34\x56\x78ping"),
            ),
        ] {
            let packet = message.serialize();
            assert_eq!(packet, expected);
            assert_eq!(message.len(), packet.len());
            let decoded = match message {
                Message::V4(_) => v4::Message::deserialize(packet).map(Message::V4),
                Message::V6(_) => v6::Message::deserialize(packet).map(Message::V6),
            };
            assert!(matches!(decoded, Ok(ref decoded) if decoded.to_echo() == message.to_echo()));
        }
    }

    #[test]
    fn message_lengths_and_truncated_headers_are_unchanged() {
        for (kind, length, reported) in [
            (0, 8, 8),
            (3, 36, 36),
            (4, 36, 36),
            (5, 36, 36),
            (8, 8, 8),
            (11, 36, 36),
            (12, 36, 36),
            (13, 20, 20),
            (14, 20, 20),
            (15, 20, 8),
            (16, 20, 8),
        ] {
            let mut packet = vec![0; length];
            packet[0] = kind;
            for short_length in 0..length {
                assert!(matches!(
                    v4::Message::deserialize(Bytes::copy_from_slice(&packet[..short_length])),
                    Err(DeserializeError::InvalidLength(_))
                ));
            }
            assert!(
                matches!(v4::Message::deserialize(Bytes::from(packet)), Ok(message) if message.len() == reported)
            );
        }
        for (kind, length) in [(1, 48), (2, 48), (3, 48), (4, 48), (128, 8), (129, 8)] {
            let mut packet = vec![0; length];
            packet[0] = kind;
            for short_length in 0..length {
                assert!(matches!(
                    v6::Message::deserialize(Bytes::copy_from_slice(&packet[..short_length])),
                    Err(DeserializeError::InvalidLength(_))
                ));
            }
            assert!(
                matches!(v6::Message::deserialize(Bytes::from(packet)), Ok(message) if message.len() == length)
            );
        }
    }
}
