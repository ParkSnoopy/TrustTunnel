//! Outgoing UDP packet format (sent from us to client)
//!
//! +----------+----------------+-------------+---------------------+------------------+---------+
//! |  Length  | Source address | Source port | Destination address | Destination port | Payload |
//! | 4 bytes  |  16 bytes      | 2 bytes     |  16 bytes           | 2 bytes          | N bytes |
//! +----------+----------------+-------------+---------------------+------------------+---------+
//!
//! Incoming UDP packet format (sent from client to us)
//!
//! +----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+
//! |  Length  | Source address | Source port | Destination address | Destination port | App name len (L) | App name | Payload |
//! | 4 bytes  |  16 bytes      | 2 bytes     |  16 bytes           | 2 bytes          | 1 byte           | L bytes  | N bytes |
//! +----------+----------------+-------------+---------------------+------------------+------------------+----------+---------+

use crate::{downstream, forwarder, http_datagram_codec, log_id, log_utils, net_utils};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::SocketAddr;

const UDPPKT_LENGTH_SIZE: usize = 4;
const UDPPKT_ADDR_SIZE: usize = 16;
const UDPPKT_PORT_SIZE: usize = 2;
const UDPPKT_APPLEN_SIZE: usize = 1;

const UDPPKT_IN_FIXED_HEADER_SIZE: usize =
    UDPPKT_LENGTH_SIZE + 2 * (UDPPKT_ADDR_SIZE + UDPPKT_PORT_SIZE) + UDPPKT_APPLEN_SIZE;
const UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE: usize =
    UDPPKT_IN_FIXED_HEADER_SIZE - UDPPKT_LENGTH_SIZE;
const UDPPKT_OUT_FIXED_HEADER_SIZE: usize =
    UDPPKT_LENGTH_SIZE + 2 * (UDPPKT_ADDR_SIZE + UDPPKT_PORT_SIZE);
const UDPPKT_OUT_FIXED_HEADER_NO_LENGTH_SIZE: usize =
    UDPPKT_OUT_FIXED_HEADER_SIZE - UDPPKT_LENGTH_SIZE;

const MAX_UDP_IN_PAYLOAD_SIZE: usize =
    net_utils::MAX_UDP_PAYLOAD_SIZE - UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE;

pub struct Decoder {
    state: RecvState,
    total_length: usize,
    buffer: BytesMut,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    app_name: Option<String>,
    id: log_utils::IdChain<u64>,
}

#[derive(Default)]
pub struct Encoder {}

impl Decoder {
    pub fn new(id: log_utils::IdChain<u64>) -> Self {
        Self {
            state: RecvState::default(),
            total_length: 0,
            buffer: BytesMut::default(),
            source: None,
            destination: None,
            app_name: None,
            id,
        }
    }

    fn decode_chunk_once(
        &mut self,
        mut data: Bytes,
    ) -> std::io::Result<(Option<downstream::UdpDatagram>, Bytes)> {
        Ok(match self.state {
            RecvState::Length => (None, self.process_client_length(data)),
            RecvState::FixedHeader => (None, self.process_client_fixed_header(data)?),
            RecvState::AppName(length) => (None, self.process_client_app_name(length, data)),
            RecvState::Payload(length) => return self.process_client_payload(length, data),
            RecvState::Dropping(remaining_length) => {
                let to_drop = remaining_length.min(data.len());

                if remaining_length <= to_drop {
                    self.state = RecvState::Length;
                } else {
                    self.state = RecvState::Dropping(remaining_length - to_drop);
                }

                (None, data.split_to(to_drop))
            }
        })
    }

    fn process_client_length(&mut self, data: Bytes) -> Bytes {
        let Some((mut raw_length, tail)) = self.buffered_read(data, UDPPKT_LENGTH_SIZE) else {
            return Bytes::new();
        };

        self.total_length = raw_length.get_u32() as usize;
        if self.total_length >= UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE {
            self.state = RecvState::FixedHeader;
        } else {
            log_id!(
                debug,
                self.id,
                "UDP packet length ({}) is less than fixed header size - dropping it",
                self.total_length
            );
            self.state = RecvState::Dropping(self.total_length);
        }

        tail
    }

    fn process_client_fixed_header(&mut self, data: Bytes) -> std::io::Result<Bytes> {
        let Some((mut header, tail)) =
            self.buffered_read(data, UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE)
        else {
            return Ok(Bytes::new());
        };

        self.source = Some(SocketAddr::new(
            net_utils::get_fixed_size_ip(&mut header).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Incomplete UDP source")
            })?,
            header.get_u16(),
        ));
        self.destination = Some(SocketAddr::new(
            net_utils::get_fixed_size_ip(&mut header).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Incomplete UDP destination",
                )
            })?,
            header.get_u16(),
        ));
        let app_name_length = header.get_u8() as usize;
        if self.total_length > MAX_UDP_IN_PAYLOAD_SIZE - app_name_length {
            log_id!(
                debug,
                self.id,
                "Too large UDP packet length ({}) - dropping it",
                self.total_length
            );
            self.state =
                RecvState::Dropping(self.total_length - UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE);
        } else if self.total_length >= UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE + app_name_length {
            self.state = RecvState::AppName(app_name_length);
        } else {
            log_id!(
                debug,
                self.id,
                "UDP packet length ({}) is less than header size - dropping it",
                self.total_length
            );
            self.state =
                RecvState::Dropping(self.total_length - UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE);
        }

        Ok(tail)
    }

    fn process_client_app_name(&mut self, length: usize, data: Bytes) -> Bytes {
        let Some((name, tail)) = self.buffered_read(data, length) else {
            return Bytes::new();
        };

        let payload_length = self.total_length - UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE - length;
        match std::str::from_utf8(name.as_ref()) {
            Ok(name) => {
                self.app_name = Some(name.to_string());
                self.state = RecvState::Payload(payload_length);
            }
            Err(e) => {
                log_id!(
                    debug,
                    self.id,
                    "Failed to convert app name: {}, dropping the rest of the packet",
                    e.to_string()
                );
                self.state = RecvState::Dropping(payload_length);
            }
        }

        tail
    }

    fn process_client_payload(
        &mut self,
        length: usize,
        mut data: Bytes,
    ) -> std::io::Result<(Option<downstream::UdpDatagram>, Bytes)> {
        let (to_send, tail) = if self.buffer.is_empty() && data.len() >= length {
            (data.split_to(length), data)
        } else {
            let to_drain = data.len().min(length - self.buffer.len());
            self.buffer
                .extend_from_slice(data.split_to(to_drain).as_ref());
            if self.buffer.len() < length {
                return Ok((None, data));
            }

            (std::mem::take(&mut self.buffer).freeze(), data)
        };

        self.state = RecvState::Length;
        Ok((
            Some(downstream::UdpDatagram {
                meta: downstream::UdpDatagramMeta {
                    source: self
                        .source
                        .ok_or_else(|| std::io::Error::other("Missing UDP source"))?,
                    destination: self
                        .destination
                        .ok_or_else(|| std::io::Error::other("Missing UDP destination"))?,
                    app_name: self.app_name.take(),
                },
                payload: to_send,
            }),
            tail,
        ))
    }

    fn buffered_read(&mut self, mut input: Bytes, cap: usize) -> Option<(Bytes, Bytes)> {
        assert!(
            self.buffer.len() < cap || cap == 0,
            "buffer={} cap={}",
            self.buffer.len(),
            cap
        );

        let to_drain = input.len().min(cap - self.buffer.len());
        self.buffer
            .extend_from_slice(input.split_to(to_drain).as_ref());

        if self.buffer.len() < cap {
            assert!(input.is_empty());
            return None;
        }

        Some((std::mem::take(&mut self.buffer).freeze(), input))
    }
}

impl http_datagram_codec::Decoder for Decoder {
    type Datagram = downstream::UdpDatagram;

    fn decode_chunk(
        &mut self,
        mut data: Bytes,
    ) -> http_datagram_codec::DecodeResult<Self::Datagram> {
        while !data.is_empty() {
            match self.decode_chunk_once(data) {
                Ok((Some(d), tail)) => return http_datagram_codec::DecodeResult::Complete(d, tail),
                Ok((None, tail)) => data = tail,
                Err(e) => return http_datagram_codec::DecodeResult::Error(e),
            }
        }

        assert!(
            data.is_empty(),
            "Expected to be fully processed, but {} bytes left unprocessed",
            data.len()
        );
        http_datagram_codec::DecodeResult::WantMore
    }
}

impl http_datagram_codec::Encoder for Encoder {
    type Datagram = forwarder::UdpDatagram;

    fn encode_packet(&self, datagram: &Self::Datagram) -> Option<Bytes> {
        let total_length = UDPPKT_OUT_FIXED_HEADER_NO_LENGTH_SIZE + datagram.payload.len();
        let mut encoded = BytesMut::with_capacity(total_length);

        encoded.put_u32(total_length as u32);
        net_utils::put_fixed_size_ip(&mut encoded, &datagram.meta.source.ip());
        encoded.put_u16(datagram.meta.source.port());
        net_utils::put_fixed_size_ip(&mut encoded, &datagram.meta.destination.ip());
        encoded.put_u16(datagram.meta.destination.port());

        encoded.extend_from_slice(&datagram.payload);

        Some(encoded.freeze())
    }
}

#[derive(Debug, Default)]
enum RecvState {
    /// Waiting for the `Length` field
    #[default]
    Length,
    /// Waiting for the header (without app name) completion
    FixedHeader,
    /// Waiting for the `App name` field
    AppName(usize),
    /// Waiting for the payload completion
    Payload(usize),
    /// Dropping the packet for some reason
    Dropping(usize),
}

#[cfg(test)]
mod tests {
    use crate::http_datagram_codec::{DecodeResult, Decoder};
    use crate::http_udp_codec;
    use crate::http_udp_codec::UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE;
    use crate::log_utils::IdChain;
    use crate::utils::check;
    use bytes::{BufMut, Bytes};
    use std::net::Ipv4Addr;

    #[test]
    fn decode() -> std::io::Result<()> {
        const APP_NAME: &str = "test";
        const PAYLOAD: &str = "hello world!";
        const SOURCE_IP: Ipv4Addr = Ipv4Addr::LOCALHOST;
        const SOURCE_PORT: u16 = 1234;
        const DESTINATION_IP: Ipv4Addr = Ipv4Addr::BROADCAST;
        const DESTINATION_PORT: u16 = 9876;

        let mut buffer = vec![];
        buffer.put_u32(
            (UDPPKT_IN_FIXED_HEADER_NO_LENGTH_SIZE + APP_NAME.len() + PAYLOAD.len()) as u32,
        );
        buffer.put_slice(&[0; 12]);
        buffer.put_slice(&SOURCE_IP.octets());
        buffer.put_u16(SOURCE_PORT);
        buffer.put_slice(&[0; 12]);
        buffer.put_slice(&DESTINATION_IP.octets());
        buffer.put_u16(DESTINATION_PORT);
        buffer.put_u8(APP_NAME.len() as u8);
        buffer.put_slice(APP_NAME.as_bytes());
        buffer.put_slice(PAYLOAD.as_bytes());

        let buffer = Bytes::from(buffer);
        for split in 0..buffer.len() {
            let mut decoder = http_udp_codec::Decoder::new(IdChain::empty());
            if split > 0 {
                check(
                    matches!(
                        decoder.decode_chunk(buffer.slice(..split)),
                        DecodeResult::WantMore
                    ),
                    "Expected partial UDP packet",
                )?;
            }
            match decoder.decode_chunk(buffer.slice(split..)) {
                DecodeResult::WantMore => {
                    return Err(std::io::Error::other("Expected complete UDP packet"))
                }
                DecodeResult::Error(e) => return Err(e),
                DecodeResult::Complete(datagram, tail) => {
                    check(
                        datagram.meta.source == (SOURCE_IP, SOURCE_PORT).into(),
                        "Unexpected source",
                    )?;
                    check(
                        datagram.meta.destination == (DESTINATION_IP, DESTINATION_PORT).into(),
                        "Unexpected destination",
                    )?;
                    check(
                        datagram.meta.app_name.as_deref() == Some(APP_NAME),
                        "Unexpected app name",
                    )?;
                    check(datagram.payload == PAYLOAD.as_bytes(), "Unexpected payload")?;
                    check(tail.is_empty(), "Unexpected packet tail")?;
                }
            }
        }
        Ok(())
    }
}
