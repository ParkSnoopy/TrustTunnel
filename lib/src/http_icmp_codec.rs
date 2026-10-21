//! Outgoing ICMP packet format (sent from us to client)
//!
//! +----------+----------------+--------+--------+-----------------+
//! |  ID      | Source address | Type   | Code   | Sequence number |
//! | 2 bytes  |  16 bytes      | 1 byte | 1 byte | 2 bytes         |
//! +----------+----------------+--------+--------+-----------------+
//!
//! Incoming ICMP packet format (sent from client to us)
//!
//! +----------+---------------------+-----------------+---------------+-----------+
//! |  ID      | Destination address | Sequence number | TTL/Hop limit | Data size |
//! | 2 bytes  |  16 bytes           | 2 bytes         | 1 byte        | 2 bytes   |
//! +----------+---------------------+-----------------+---------------+-----------+

use crate::{downstream, forwarder, http_datagram_codec, icmp_utils, net_utils};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::rand::SecureRandom;

const ICMPPKT_ID_SIZE: usize = 2;
const ICMPPKT_ADDR_SIZE: usize = 16;
const ICMPPKT_SEQNO_SIZE: usize = 2;
const ICMPPKT_TTL_SIZE: usize = 1;
const ICMPPKT_DATA_SIZE: usize = 2;
const ICMPPKT_TYPE_SIZE: usize = 1;
const ICMPPKT_CODE_SIZE: usize = 1;
const ICMPPKT_REQ_SIZE: usize =
    ICMPPKT_ID_SIZE + ICMPPKT_ADDR_SIZE + ICMPPKT_SEQNO_SIZE + ICMPPKT_TTL_SIZE + ICMPPKT_DATA_SIZE;
const ICMPPKT_REPLY_SIZE: usize = ICMPPKT_ID_SIZE
    + ICMPPKT_ADDR_SIZE
    + ICMPPKT_TYPE_SIZE
    + ICMPPKT_CODE_SIZE
    + ICMPPKT_SEQNO_SIZE;

pub struct Decoder {
    buffer: BytesMut,
}

#[derive(Default)]
pub struct Encoder {}

impl http_datagram_codec::Decoder for Decoder {
    type Datagram = downstream::IcmpDatagram;

    fn decode_chunk(&mut self, data: Bytes) -> http_datagram_codec::DecodeResult<Self::Datagram> {
        match self.on_message_chunk(data) {
            None => http_datagram_codec::DecodeResult::WantMore,
            Some((mut raw, tail)) => {
                let identifier = raw.get_u16();
                let Some(destination) = net_utils::get_fixed_size_ip(&mut raw) else {
                    return http_datagram_codec::DecodeResult::Error(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Incomplete ICMP destination",
                    ));
                };
                let sequence_number = raw.get_u16();

                let ttl = raw.get_u8();

                let data_size = raw.get_u16() as usize;
                let mut data = vec![0_u8; data_size];
                if let Err(e) = ring::rand::SystemRandom::new().fill(&mut data) {
                    return http_datagram_codec::DecodeResult::Error(std::io::Error::other(
                        format!("Failed to generate ICMP payload: {e}"),
                    ));
                }

                let echo = icmp_utils::Echo {
                    code: 0,
                    identifier,
                    sequence_number,
                    data: Bytes::from(data),
                };

                http_datagram_codec::DecodeResult::Complete(
                    downstream::IcmpDatagram {
                        meta: downstream::IcmpDatagramMeta { peer: destination },
                        message: if destination.is_ipv4() {
                            icmp_utils::Message::V4(icmp_utils::v4::Message::Echo(echo))
                        } else {
                            icmp_utils::Message::V6(icmp_utils::v6::Message::EchoRequest(echo))
                        },
                        ttl,
                    },
                    tail,
                )
            }
        }
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(ICMPPKT_REQ_SIZE),
        }
    }

    fn on_message_chunk(&mut self, mut chunk: Bytes) -> Option<(Bytes, Bytes)> {
        if !self.buffer.is_empty() || self.buffer.len() + chunk.len() < ICMPPKT_REQ_SIZE {
            self.buffer.extend(chunk.split_to(std::cmp::min(
                chunk.len(),
                ICMPPKT_REQ_SIZE - self.buffer.len(),
            )));
            assert!(self.buffer.len() <= ICMPPKT_REQ_SIZE);
            if self.buffer.len() < ICMPPKT_REQ_SIZE {
                assert!(chunk.is_empty());
                None
            } else {
                Some((
                    std::mem::replace(&mut self.buffer, BytesMut::with_capacity(ICMPPKT_REQ_SIZE))
                        .freeze(),
                    chunk,
                ))
            }
        } else {
            Some((chunk.split_to(ICMPPKT_REQ_SIZE), chunk))
        }
    }
}

impl http_datagram_codec::Encoder for Encoder {
    type Datagram = forwarder::IcmpDatagram;

    fn encode_packet(&self, datagram: &forwarder::IcmpDatagram) -> Option<Bytes> {
        let echo = datagram.message.responded_echo_request()?;

        let mut encoded = BytesMut::with_capacity(ICMPPKT_REPLY_SIZE);

        encoded.put_u16(echo.identifier);
        net_utils::put_fixed_size_ip(&mut encoded, &datagram.meta.peer);
        encoded.put_u8(datagram.message.type_id());
        encoded.put_u8(datagram.message.code());
        encoded.put_u16(echo.sequence_number);

        Some(encoded.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_datagram_codec::{DecodeResult, Decoder as _, Encoder as _};
    use crate::utils::check;
    use std::io;
    use std::net::Ipv4Addr;

    #[test]
    fn fragmented_request_preserves_fields_and_next_packet() -> io::Result<()> {
        let mut request = BytesMut::new();
        request.put_u16(0x1234);
        net_utils::put_fixed_size_ip(&mut request, &Ipv4Addr::LOCALHOST.into());
        request.put_u16(0x5678);
        request.put_u8(42);
        request.put_u16(16);
        let request = request.freeze();
        for split in 1..request.len() {
            let mut decoder = Decoder::new();
            check(
                matches!(
                    decoder.decode_chunk(request.slice(..split)),
                    DecodeResult::WantMore
                ),
                "Expected partial ICMP packet",
            )?;
            let mut rest = BytesMut::from(request.slice(split..).as_ref());
            rest.extend_from_slice(&request);
            let DecodeResult::Complete(datagram, tail) = decoder.decode_chunk(rest.freeze()) else {
                return Err(io::Error::other("Expected complete ICMP packet"));
            };
            check(datagram.meta.peer == Ipv4Addr::LOCALHOST, "Unexpected peer")?;
            check(datagram.ttl == 42, "Unexpected TTL")?;
            let icmp_utils::Message::V4(icmp_utils::v4::Message::Echo(echo)) = datagram.message
            else {
                return Err(io::Error::other("Expected IPv4 echo request"));
            };
            check(echo.identifier == 0x1234, "Unexpected identifier")?;
            check(echo.sequence_number == 0x5678, "Unexpected sequence")?;
            check(echo.data.len() == 16, "Unexpected payload length")?;
            check(tail == request, "Unexpected packet tail")?;
        }
        Ok(())
    }

    #[test]
    fn reply_wire_format_preserves_identifier_address_type_code_and_sequence() -> io::Result<()> {
        let datagram = forwarder::IcmpDatagram {
            meta: forwarder::IcmpDatagramMeta {
                peer: Ipv4Addr::LOCALHOST.into(),
            },
            message: icmp_utils::Message::V4(icmp_utils::v4::Message::EchoReply(
                icmp_utils::Echo {
                    code: 0,
                    identifier: 0x1234,
                    sequence_number: 0x5678,
                    data: Bytes::from_static(b"not included in the reply"),
                },
            )),
        };
        let encoded = Encoder::default()
            .encode_packet(&datagram)
            .ok_or_else(|| io::Error::other("Expected encoded ICMP reply"))?;
        check(
            encoded.as_ref()
                == b"\x12\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x00\x00\x01\x00\x00\x56\x78",
            "Unexpected ICMP reply bytes",
        )?;
        Ok(())
    }
}
