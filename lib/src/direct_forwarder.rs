use crate::forwarder::{Forwarder, IcmpMultiplexer, UdpMultiplexer};
use crate::tcp_forwarder::TcpForwarder;
use crate::{authentication, core, forwarder, log_utils, tunnel, udp_forwarder};
use async_trait::async_trait;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

pub struct DirectForwarder {
    context: Arc<core::Context>,
}

impl DirectForwarder {
    pub const fn new(context: Arc<core::Context>) -> Self {
        Self { context }
    }
}

impl Forwarder for DirectForwarder {
    fn tcp_connector(&self) -> Box<dyn forwarder::TcpConnector> {
        Box::new(TcpForwarder::new(self.context.clone()))
    }

    fn datagram_mux_authenticator(&self) -> Box<dyn forwarder::DatagramMultiplexerAuthenticator> {
        struct Dummy;

        #[async_trait]
        impl forwarder::DatagramMultiplexerAuthenticator for Dummy {
            async fn check_auth(
                self: Box<Self>,
                _: IpAddr,
                _: &'_ str,
                _: authentication::Source<'_>,
                _: Option<&'_ str>,
            ) -> Result<(), tunnel::ConnectionError> {
                Ok(())
            }
        }

        Box::new(Dummy)
    }

    fn make_udp_datagram_multiplexer(
        &self,
        id: log_utils::IdChain<u64>,
        _: forwarder::UdpMultiplexerMeta,
    ) -> io::Result<UdpMultiplexer> {
        Ok(udp_forwarder::make_multiplexer(self.context.clone(), id))
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
