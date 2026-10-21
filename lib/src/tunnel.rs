use crate::authentication::Status;
use crate::connection_limiter::ConnectionGuard;
use crate::downstream::{
    Downstream, PendingDatagramMultiplexerRequest, PendingDemultiplexedRequest,
    PendingTcpConnectRequest,
};
use crate::forwarder::Forwarder;
use crate::pipe::DuplexPipe;
use crate::{
    authentication, core, datagram_pipe, downstream, forwarder, log_id, log_utils, pipe, udp_pipe,
};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};

/// Extract the username from base64-encoded `username:password` credentials.
fn decode_username(creds: &str) -> Option<String> {
    BASE64_ENGINE
        .decode(creds)
        .ok()
        .and_then(|v| String::from_utf8(v).ok())
        .and_then(|s| s.split(':').next().map(ToString::to_string))
}

#[derive(Clone)]
pub enum AuthenticationPolicy<'this> {
    /// Perform the regular authentication procedure through the configured authenticator
    Default,
    /// The whole connection is authenticated.
    /// Contains the authenticated info.
    Authenticated(authentication::Source<'this>),
}

pub struct Tunnel {
    context: Arc<core::Context>,
    downstream: Box<dyn Downstream>,
    forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
    authentication_policy: AuthenticationPolicy<'static>,
    /// Holds the connection slot acquired for this tunnel.
    /// Set at construction time for SNI-authenticated connections,
    /// or lazily on the first authenticated request for proxy-basic connections.
    connection_guard: Option<ConnectionGuard>,
    id: log_utils::IdChain<u64>,
}

#[derive(Debug)]
pub enum ConnectionError {
    Io(io::Error),
    Authentication(String),
    Timeout,
    HostUnreachable,
    DnsNonroutable,
    DnsLoopback,
    Other(String),
}

type RequestFailure<R> = (Option<Box<R>>, &'static str, ConnectionError);

impl Display for ConnectionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(x) => write!(f, "IO error: {x}"),
            Self::Authentication(x) => write!(f, "Authentication error: {x}"),
            Self::Timeout => write!(f, "Connection timed out"),
            Self::HostUnreachable => write!(f, "Remote host is unreachable"),
            Self::DnsNonroutable => write!(f, "DNS: resolved address in non-routable network"),
            Self::DnsLoopback => write!(f, "DNS: resolved address in loopback"),
            Self::Other(x) => write!(f, "{x}"),
        }
    }
}

impl Tunnel {
    pub fn new(
        context: Arc<core::Context>,
        downstream: Box<dyn Downstream>,
        forwarder: Box<dyn Forwarder>,
        authentication_policy: AuthenticationPolicy<'static>,
        connection_guard: Option<ConnectionGuard>,
        id: log_utils::IdChain<u64>,
    ) -> Self {
        Self {
            context,
            downstream,
            forwarder: Arc::new(Mutex::new(forwarder)),
            authentication_policy,
            connection_guard,
            id,
        }
    }

    pub async fn listen(&mut self) -> io::Result<()> {
        let (mut shutdown_notification, _shutdown_completion) = {
            let shutdown = self.context.shutdown.lock().unwrap_or_else(|e| {
                log_id!(error, self.id, "Recovering poisoned shutdown lock: {}", e);
                e.into_inner()
            });
            (shutdown.notification_handler(), shutdown.completion_guard())
        };
        tokio::select! {
            x = shutdown_notification.wait() => {
                match x {
                    Ok(()) => self.downstream.graceful_shutdown().await,
                    Err(e) => Err(io::Error::other(format!("{e}"))),
                }
            }
            x = self.listen_inner() => x,
        }
    }

    fn resolve_username(
        &self,
        request: &dyn downstream::PendingMultiplexedRequest,
    ) -> Option<String> {
        match &self.authentication_policy {
            AuthenticationPolicy::Authenticated(source) => {
                self.context.authenticator.as_ref()?.username(source)
            }
            AuthenticationPolicy::Default => match request.auth_info() {
                Ok(Some(source)) => match &source {
                    authentication::Source::ProxyBasic(s) | authentication::Source::Sni(s) => {
                        decode_username(s.as_ref())
                    }
                },
                _ => None,
            },
        }
    }

    async fn listen_inner(&mut self) -> io::Result<()> {
        loop {
            log_id!(trace, self.id, "Tunnel waiting for request");
            let request = match tokio::time::timeout(
                self.context.settings.client_listener_timeout,
                self.downstream.listen(),
            )
            .await
            {
                Ok(Ok(None)) => {
                    log_id!(debug, self.id, "Tunnel closed gracefully");
                    return Ok(());
                }
                Ok(Ok(Some(r))) => {
                    log_id!(trace, self.id, "Tunnel received request");
                    r
                }
                Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                    log_id!(debug, self.id, "Tunnel closed gracefully");
                    return Ok(());
                }
                Ok(Err(e)) => {
                    log_id!(trace, self.id, "Tunnel listen error: {}", e);
                    return Err(e);
                }
                Err(_) => {
                    log_id!(trace, self.id, "Tunnel listen timeout");
                    return Err(io::Error::from(ErrorKind::TimedOut));
                }
            };

            self.spawn_request(request)?;
        }
    }

    fn spawn_request(
        &mut self,
        request: Box<dyn downstream::PendingMultiplexedRequest>,
    ) -> io::Result<()> {
        let context = self.context.clone();
        let forwarder = self.forwarder.clone();
        let tls_domain = self.downstream.tls_domain().to_string();
        let authentication_policy = self.authentication_policy.clone();
        let log_id = self.id.clone();
        let protocol = self.downstream.protocol();
        let username = if context.metrics.per_client() {
            self.resolve_username(request.as_ref())
        } else {
            None
        };
        let update_metrics = {
            let metrics = context.metrics.clone();
            move |direction, n| match direction {
                pipe::SimplexDirection::Incoming => {
                    metrics.add_inbound_bytes(protocol, username.as_deref(), n);
                }
                pipe::SimplexDirection::Outgoing => {
                    metrics.add_outbound_bytes(protocol, username.as_deref(), n);
                }
            }
        };

        if let Err(e) = self.acquire_connection_guard(request.as_ref()) {
            request.fail_request(ConnectionError::Authentication(
                "Connection limit exceeded".to_string(),
            ));
            return Err(e);
        }

        tokio::spawn(async move {
            let request_id = request.id();
            log_id!(trace, request_id, "Processing tunnel request");
            let auth_info_result = request
                .auth_info()
                .map(|x| x.map(authentication::Source::into_owned));
            let forwarder_auth = match Self::authenticate_request(
                auth_info_result.as_ref().cloned(),
                authentication_policy,
                &context,
                &log_id,
                &request_id,
            ) {
                Ok(auth) => auth,
                Err(err) => {
                    request.fail_request(err);
                    return;
                }
            };

            log_id!(
                trace,
                request_id,
                "Authentication complete, promoting request"
            );

            // If this request carried credentials, relabel the session
            // with the authenticated username (no-op if it's already labelled).
            if let Ok(Some(source)) = auth_info_result {
                let username_opt = match &source {
                    authentication::Source::ProxyBasic(s) | authentication::Source::Sni(s) => {
                        decode_username(s.as_ref())
                    }
                };
                if let Some(u) = username_opt {
                    context.metrics.transfer_session_username(
                        protocol,
                        &log_id.to_string(),
                        Some(u),
                    );
                }
            }
            Self::forward_request(
                context,
                forwarder,
                request,
                forwarder_auth,
                tls_domain,
                update_metrics,
                request_id,
            )
            .await;
        });
        Ok(())
    }

    async fn forward_request<F: Fn(pipe::SimplexDirection, usize) + Send + Clone + Sync>(
        context: Arc<core::Context>,
        forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
        request: Box<dyn downstream::PendingMultiplexedRequest>,
        forwarder_auth: Option<authentication::Source<'static>>,
        tls_domain: String,
        update_metrics: F,
        request_id: log_utils::IdChain<u64>,
    ) {
        match request.promote_to_next_state() {
            Ok(None) => {
                log_id!(trace, request_id, "Health check request completed");
            }
            Ok(Some(PendingDemultiplexedRequest::TcpConnect(request))) => {
                log_id!(trace, request_id, "Handling TCP connect request");
                if let Err((request, message, e)) = Self::on_tcp_connect_request(
                    context.clone(),
                    forwarder,
                    request,
                    forwarder_auth,
                    tls_domain,
                    update_metrics,
                )
                .await
                {
                    Self::report_fatal_if_too_many_open_files(&context, &e);
                    log_id!(debug, request_id, "{}: {}", message, e);
                    if let Some(request) = request {
                        request.fail_request(e);
                    }
                }
            }
            Ok(Some(PendingDemultiplexedRequest::DatagramMultiplexer(request))) => {
                log_id!(trace, request_id, "Handling datagram multiplexer request");
                if let Err((request, message, e)) = Self::on_datagram_mux_request(
                    context.clone(),
                    forwarder,
                    request,
                    forwarder_auth,
                    tls_domain,
                    update_metrics,
                )
                .await
                {
                    Self::report_fatal_if_too_many_open_files(&context, &e);
                    log_id!(debug, request_id, "{}: {}", message, e);
                    if let Some(request) = request {
                        request.fail_request(e);
                    }
                }
            }
            Err(e) => {
                log_id!(debug, request_id, "Failed to complete request: {}", e);
            }
        }
    }

    fn acquire_connection_guard(
        &mut self,
        request: &dyn downstream::PendingMultiplexedRequest,
    ) -> io::Result<()> {
        // For proxy-basic connections, lazily acquire the connection slot on the first
        // authenticated request. This means the limit applies to active tunnels that have
        // sent at least one request, not to idle connections. This is done before spawning
        // so the guard lifetime matches the tunnel, not an individual request task.
        if self.connection_guard.is_none() {
            if let Some(limiter) = self.context.connection_limiter.as_ref() {
                let auth_info = request
                    .auth_info()
                    .map(|x| x.map(authentication::Source::into_owned));
                let protocol = self.downstream.protocol();
                if let Ok(Some(source)) = auth_info {
                    let authenticated = self
                        .context
                        .authenticator
                        .as_ref()
                        .is_some_and(|a| a.authenticate(&source, &self.id) == Status::Pass);
                    if authenticated {
                        let creds = match &source {
                            authentication::Source::ProxyBasic(s)
                            | authentication::Source::Sni(s) => s.as_ref(),
                        };
                        if let Some(guard) = limiter.try_acquire(creds, protocol) {
                            self.connection_guard = Some(guard);
                        } else {
                            log_id!(debug, self.id, "Connection limit exceeded, closing tunnel");
                            return Err(io::Error::new(
                                ErrorKind::PermissionDenied,
                                "Connection limit exceeded",
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn authenticate_request(
        auth_info_result: Result<Option<authentication::Source<'static>>, &io::Error>,
        authentication_policy: AuthenticationPolicy<'static>,
        context: &core::Context,
        log_id: &log_utils::IdChain<u64>,
        request_id: &log_utils::IdChain<u64>,
    ) -> Result<Option<authentication::Source<'static>>, ConnectionError> {
        Ok(
            match (
                auth_info_result,
                authentication_policy,
                context.authenticator.clone(),
            ) {
                (Ok(Some(source)), _, Some(authenticator)) => {
                    match authenticator.authenticate(&source, log_id) {
                        Status::Pass => Some(source),
                        Status::Reject => {
                            let err = ConnectionError::Authentication(
                                "Authentication failed".to_string(),
                            );
                            log_id!(debug, request_id, "{}", err);
                            return Err(err);
                        }
                    }
                }
                (Ok(None), AuthenticationPolicy::Authenticated(x), Some(_)) => Some(x),
                (Ok(x), policy, None) => x.or(match policy {
                    AuthenticationPolicy::Default => None,
                    AuthenticationPolicy::Authenticated(y) => Some(y),
                }),
                (Ok(None), AuthenticationPolicy::Default, Some(_)) => {
                    let err = ConnectionError::Authentication(
                        "Got request without authentication info on non-authenticated connection"
                            .to_string(),
                    );
                    log_id!(debug, request_id, "{}", err);
                    return Err(err);
                }
                (Err(e), ..) => {
                    log_id!(debug, request_id, "Failed to get auth info: {}", e);
                    return Err(ConnectionError::Io(io::Error::new(e.kind(), e.to_string())));
                }
            },
        )
    }

    fn report_fatal_if_too_many_open_files(context: &Arc<core::Context>, e: &ConnectionError) {
        if let ConnectionError::Io(io) = e {
            if core::Core::is_too_many_open_files_error(io) {
                context.report_fatal_io_error(io);
            }
        }
    }

    async fn on_tcp_connect_request<F: Fn(pipe::SimplexDirection, usize) + Send + Clone>(
        context: Arc<core::Context>,
        forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
        request: Box<dyn PendingTcpConnectRequest>,
        forwarder_auth: Option<authentication::Source<'static>>,
        tls_domain: String,
        update_metrics: F,
    ) -> Result<(), RequestFailure<dyn PendingTcpConnectRequest>> {
        let request_id = request.id();
        log_id!(trace, request_id, "TCP connect: extracting destination");
        let destination = match request.destination() {
            Ok(d) => {
                log_id!(trace, request_id, "TCP connect: destination={:?}", d);
                d
            }
            Err(e) => {
                return Err((
                    Some(request),
                    "Failed to get destination",
                    ConnectionError::Io(e),
                ))
            }
        };

        let meta = forwarder::TcpConnectionMeta {
            client_address: match request.client_address() {
                Ok(x) => x,
                Err(e) => {
                    return Err((
                        Some(request),
                        "Failed to get client address",
                        ConnectionError::Io(e),
                    ))
                }
            },
            destination,
            tls_domain,
            auth: forwarder_auth,
            user_agent: request.user_agent(),
        };

        log_id!(trace, request_id, "TCP connect: connecting to peer");
        let connector = forwarder
            .lock()
            .unwrap_or_else(|e| {
                log::error!("Recovering poisoned forwarder lock: {e}");
                e.into_inner()
            })
            .tcp_connector();
        let (fwd_rx, fwd_tx) = match tokio::time::timeout(
            context.settings.connection_establishment_timeout,
            connector.connect(request_id.clone(), meta.clone()),
        )
        .await
        .unwrap_or(Err(ConnectionError::Timeout))
        {
            Ok(x) => {
                log_id!(
                    trace,
                    request_id,
                    "TCP connect: peer connection established"
                );
                x
            }
            Err(e) => return Err((Some(request), "Connection to peer failed", e)),
        };

        log_id!(debug, request_id, "Successfully connected to {:?}", meta);
        log_id!(
            trace,
            request_id,
            "TCP connect: promoting downstream request"
        );
        let (dstr_rx, dstr_tx) = match request.promote_to_next_state() {
            Ok(x) => {
                log_id!(
                    trace,
                    request_id,
                    "TCP connect: downstream ready, starting pipe"
                );
                x
            }
            Err(e) => return Err((None, "Failed to complete request", ConnectionError::Io(e))),
        };

        let mut pipe = DuplexPipe::new(
            (pipe::SimplexDirection::Outgoing, dstr_rx, fwd_tx),
            (pipe::SimplexDirection::Incoming, fwd_rx, dstr_tx),
            update_metrics,
        );

        log_id!(trace, request_id, "TCP connect: pipe exchange started");
        match pipe
            .exchange(context.settings.tcp_connections_timeout)
            .await
        {
            Ok(()) => {
                log_id!(trace, request_id, "TCP connect: pipe closed gracefully");
                Ok(())
            }
            Err(e) => {
                log_id!(trace, request_id, "TCP connect: pipe error: {}", e);
                Err((None, "Error on pipe", ConnectionError::Io(e)))
            }
        }
    }

    async fn prepare_datagram_mux_request(
        forwarder: &Mutex<Box<dyn Forwarder>>,
        request: Box<dyn PendingDatagramMultiplexerRequest>,
        auth: Option<authentication::Source<'static>>,
        tls_domain: String,
    ) -> Result<
        (
            Box<dyn PendingDatagramMultiplexerRequest>,
            forwarder::UdpMultiplexerMeta,
        ),
        RequestFailure<dyn PendingDatagramMultiplexerRequest>,
    > {
        let client_address = match request.client_address() {
            Ok(address) => address,
            Err(e) => {
                return Err((
                    Some(request),
                    "Failed to get client address",
                    ConnectionError::Io(e),
                ))
            }
        };
        let user_agent = request.user_agent();

        if let Some(auth) = &auth {
            let authenticator = forwarder
                .lock()
                .unwrap_or_else(|e| {
                    log::error!("Recovering poisoned forwarder lock: {e}");
                    e.into_inner()
                })
                .datagram_mux_authenticator();
            if let Err(e) = authenticator
                .check_auth(
                    client_address,
                    &tls_domain,
                    auth.clone(),
                    user_agent.as_deref(),
                )
                .await
            {
                return Err((Some(request), "Failed to authenticate", e));
            }
        }

        Ok((
            request,
            forwarder::UdpMultiplexerMeta {
                client_address,
                auth,
                tls_domain,
                user_agent,
            },
        ))
    }

    async fn on_datagram_mux_request<F: Fn(pipe::SimplexDirection, usize) + Send + Clone + Sync>(
        context: Arc<core::Context>,
        forwarder: Arc<Mutex<Box<dyn Forwarder>>>,
        request: Box<dyn PendingDatagramMultiplexerRequest>,
        forwarder_auth: Option<authentication::Source<'static>>,
        tls_domain: String,
        update_metrics: F,
    ) -> Result<(), RequestFailure<dyn PendingDatagramMultiplexerRequest>> {
        let request_id = request.id();
        let (request, meta) =
            Self::prepare_datagram_mux_request(&forwarder, request, forwarder_auth, tls_domain)
                .await?;

        let mut pipe: Box<dyn datagram_pipe::DuplexPipe> = match request.promote_to_next_state() {
            Ok(downstream::DatagramPipeHalves::Udp(dstr_source, dstr_sink)) => {
                let (fwd_shared, fwd_source, fwd_sink) = {
                    let forwarder = forwarder.lock().unwrap_or_else(|e| {
                        log::error!("Recovering poisoned forwarder lock: {e}");
                        e.into_inner()
                    });
                    match forwarder.make_udp_datagram_multiplexer(request_id.clone(), meta) {
                        Ok(x) => x,
                        Err(e) => {
                            return Err((
                                None,
                                "Failed to create datagram multiplexer",
                                ConnectionError::Io(e),
                            ))
                        }
                    }
                };

                Box::new(udp_pipe::DuplexPipe::new(
                    (dstr_source, dstr_sink),
                    (fwd_shared, fwd_source, fwd_sink),
                    update_metrics,
                    context.settings.udp_connections_timeout,
                ))
            }
            Ok(downstream::DatagramPipeHalves::Icmp(dstr_source, dstr_sink)) => {
                let (fwd_source, fwd_sink) = {
                    let forwarder = forwarder.lock().unwrap_or_else(|e| {
                        log::error!("Recovering poisoned forwarder lock: {e}");
                        e.into_inner()
                    });
                    match forwarder.make_icmp_datagram_multiplexer(request_id.clone()) {
                        Ok(Some(x)) => x,
                        Ok(None) => {
                            return Err((
                                None,
                                "ICMP forwarding isn't set up",
                                ConnectionError::Other("Not allowed".to_string()),
                            ))
                        }
                        Err(e) => {
                            return Err((
                                None,
                                "Failed to create datagram multiplexer",
                                ConnectionError::Io(e),
                            ))
                        }
                    }
                };

                Box::new(datagram_pipe::GenericDuplexPipe::new(
                    (pipe::SimplexDirection::Outgoing, dstr_source, fwd_sink),
                    (pipe::SimplexDirection::Incoming, fwd_source, dstr_sink),
                    update_metrics,
                ))
            }
            Err(e) => {
                return Err((
                    None,
                    "Failed to respond for datagram multiplexer request",
                    ConnectionError::Io(e),
                ))
            }
        };

        match pipe.exchange().await {
            Ok(()) => {
                log_id!(trace, request_id, "Datagram multiplexer gracefully closed");
                Ok(())
            }
            Err(e) => Err((
                None,
                "Datagram multiplexer closed with error",
                ConnectionError::Io(e),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::registry_based::Client;
    use crate::connection_limiter::ConnectionLimiter;
    use crate::direct_forwarder::DirectForwarder;
    use crate::tls_demultiplexer::Protocol;
    use crate::utils::check;
    use async_trait::async_trait;

    struct IdleDownstream;

    #[async_trait]
    impl Downstream for IdleDownstream {
        async fn listen(
            &mut self,
        ) -> io::Result<Option<Box<dyn downstream::PendingMultiplexedRequest>>> {
            futures::future::pending().await
        }

        async fn graceful_shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn protocol(&self) -> Protocol {
            Protocol::Http2
        }

        fn tls_domain(&self) -> &'static str {
            "test"
        }
    }

    #[tokio::test]
    async fn cancelling_listener_keeps_connection_slot_until_tunnel_drop() -> io::Result<()> {
        let context = Arc::new(core::Context::test()?);
        let limiter = Arc::new(ConnectionLimiter::new(
            &[Client {
                username: "user".into(),
                password: "password".into(),
                max_http2_conns: None,
                max_http3_conns: None,
            }],
            Some(1),
            None,
        ));
        let credentials = BASE64_ENGINE.encode("user:password");
        let guard = limiter
            .try_acquire(&credentials, Protocol::Http2)
            .ok_or_else(|| io::Error::other("Initial tunnel slot was denied"))?;
        let mut tunnel = Tunnel::new(
            context.clone(),
            Box::new(IdleDownstream),
            Box::new(DirectForwarder::new(context)),
            AuthenticationPolicy::Default,
            Some(guard),
            log_utils::IdChain::empty(),
        );
        {
            let listener = tunnel.listen();
            tokio::pin!(listener);
            check(
                futures::poll!(listener.as_mut()).is_pending(),
                "Idle tunnel listener completed unexpectedly",
            )?;
            check(
                limiter.try_acquire(&credentials, Protocol::Http2).is_none(),
                "Listening tunnel released its connection slot",
            )?;
        }
        check(
            limiter.try_acquire(&credentials, Protocol::Http2).is_none(),
            "Cancelling the listener released the tunnel's connection slot",
        )?;
        drop(tunnel);
        check(
            limiter.try_acquire(&credentials, Protocol::Http2).is_some(),
            "Dropping the tunnel did not release its connection slot",
        )
    }

    #[test]
    fn username_decoding_preserves_empty_fields_colons_and_invalid_input() {
        for (credentials, expected) in [
            ("user:password", "user"),
            ("user:password:with:colons", "user"),
            (":password", ""),
            ("user", "user"),
            ("", ""),
        ] {
            assert_eq!(
                decode_username(&BASE64_ENGINE.encode(credentials)).as_deref(),
                Some(expected)
            );
        }
        assert_eq!(decode_username("not base64"), None);
        assert_eq!(decode_username(&BASE64_ENGINE.encode([0xff])), None);
    }
}
