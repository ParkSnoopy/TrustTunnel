use crate::http1_codec::Http1Codec;
use crate::http_codec::HttpCodec;
use crate::tls_demultiplexer::Protocol;
use crate::{core, http_codec, log_id, log_utils};
use bytes::Bytes;
use prometheus::Encoder;
use serde::Serialize;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};

const LOG_FMT: &str = "METRICS={}";
const HEALTH_CHECK_PATH: &str = "/health-check";
const METRICS_PATH: &str = "/metrics";
const CLIENTS_PATH: &str = "/clients";

pub struct Metrics {
    registry: prometheus::Registry,
    per_client: bool,
    client_sessions: prometheus::IntGaugeVec,
    inbound_traffic: prometheus::IntCounterVec,
    outbound_traffic: prometheus::IntCounterVec,
    client_sessions_per_user: prometheus::IntGaugeVec,
    inbound_traffic_per_user: prometheus::IntCounterVec,
    outbound_traffic_per_user: prometheus::IntCounterVec,
    outbound_tcp_sockets: prometheus::IntGauge,
    outbound_udp_sockets: prometheus::IntGauge,
    clients: Mutex<HashMap<String, ClientInfo>>,
}

#[derive(Debug, Default)]
struct ClientInfo {
    username: Option<String>,
    ip: Option<IpAddr>,
    sessions: u64,
}

#[derive(Serialize)]
struct ClientSummary {
    username: String,
    ip: Option<String>,
    sessions: u64,
    inbound: u64,
    outbound: u64,
}

pub struct ClientSessionsCounter {
    metrics: Arc<Metrics>,
    protocol: Protocol,
    conn_id: String,
}

pub struct OutboundTcpSocketCounter {
    metrics: Arc<Metrics>,
}

pub struct OutboundUdpSocketCounter {
    metrics: Arc<Metrics>,
}

impl Metrics {
    pub fn new(per_client: bool) -> io::Result<Arc<Self>> {
        let registry = prometheus::Registry::new();
        Ok(Arc::new(Self {
            per_client,
            client_sessions: prometheus::register_int_gauge_vec_with_registry!(
                "client_sessions",
                "Number of active client sessions",
                &["protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            inbound_traffic: prometheus::register_int_counter_vec_with_registry!(
                "inbound_traffic_bytes",
                "Total number of bytes uploaded by clients",
                &["protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_traffic: prometheus::register_int_counter_vec_with_registry!(
                "outbound_traffic_bytes",
                "Total number of bytes downloaded by clients",
                &["protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            client_sessions_per_user: prometheus::register_int_gauge_vec_with_registry!(
                "client_sessions_per_user",
                "Number of active client sessions per user",
                &["username", "protocol_type"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            inbound_traffic_per_user: prometheus::register_int_counter_vec_with_registry!(
                "inbound_traffic_bytes_per_user",
                "Total number of bytes uploaded per user",
                &["username"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_traffic_per_user: prometheus::register_int_counter_vec_with_registry!(
                "outbound_traffic_bytes_per_user",
                "Total number of bytes downloaded per user",
                &["username"],
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_tcp_sockets: prometheus::register_int_gauge_with_registry!(
                "outbound_tcp_sockets",
                "Number of active outbound TCP connections",
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            outbound_udp_sockets: prometheus::register_int_gauge_with_registry!(
                "outbound_udp_sockets",
                "Number of active outbound UDP sockets",
                registry,
            )
            .map_err(prometheus_to_io_error)?,
            registry,
            clients: Mutex::new(HashMap::new()),
        }))
    }

    pub const fn per_client(&self) -> bool {
        self.per_client
    }

    pub fn client_sessions_counter(
        self: Arc<Self>,
        protocol: Protocol,
        conn_id: String,
        username: Option<String>,
    ) -> ClientSessionsCounter {
        ClientSessionsCounter::new(self, protocol, conn_id, username)
    }

    pub fn outbound_tcp_socket_counter(self: Arc<Self>) -> OutboundTcpSocketCounter {
        OutboundTcpSocketCounter::new(self)
    }

    pub fn outbound_udp_socket_counter(self: Arc<Self>) -> OutboundUdpSocketCounter {
        OutboundUdpSocketCounter::new(self)
    }

    pub fn add_inbound_bytes(&self, protocol: Protocol, username: Option<&str>, n: usize) {
        self.inbound_traffic
            .with_label_values(&[protocol.as_str()])
            .inc_by(n as u64);
        if self.per_client {
            if let Some(username) = username {
                self.inbound_traffic_per_user
                    .with_label_values(&[username])
                    .inc_by(n as u64);
            }
        }
    }

    pub fn add_outbound_bytes(&self, protocol: Protocol, username: Option<&str>, n: usize) {
        self.outbound_traffic
            .with_label_values(&[protocol.as_str()])
            .inc_by(n as u64);
        if self.per_client {
            if let Some(username) = username {
                self.outbound_traffic_per_user
                    .with_label_values(&[username])
                    .inc_by(n as u64);
            }
        }
    }

    fn collect(&self) -> io::Result<(String, Bytes)> {
        let encoder = prometheus::TextEncoder::new();

        let mut metric_families = self.registry.gather();
        metric_families.extend(prometheus::gather());
        let mut buffer = vec![];
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(prometheus_to_io_error)?;

        Ok((encoder.format_type().to_string(), Bytes::from(buffer)))
    }

    /// Seed the metadata entry for a connection. Only sets the client IP; the
    /// session gauge accounting is owned by the `ClientSessionsCounter` RAII guard.
    pub fn register_connection(&self, conn_id: String, ip: Option<IpAddr>) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.entry(conn_id).or_insert_with(|| ClientInfo {
                username: None,
                ip,
                sessions: 0,
            });
        }
    }

    /// Remove the metadata entry for a connection that never got a session guard
    /// (e.g. codec creation failed before the tunnel started).
    pub fn unregister_connection(&self, conn_id: &str) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.remove(conn_id);
        }
    }

    /// Relabel an active session from its current username to a new one.
    /// Used for proxy-basic tunnels whose username is only known after the first
    /// authenticated request. No-op when the label is unchanged. Gauges are only
    /// adjusted for connections that are actually tracked in the clients map, so
    /// the per-user counter always stays balanced.
    pub fn transfer_session_username(
        &self,
        protocol: Protocol,
        conn_id: &str,
        username: Option<String>,
    ) {
        let Ok(mut clients) = self.clients.lock() else {
            return;
        };
        let Some(entry) = clients.get_mut(conn_id) else {
            return;
        };
        let old = entry.username.clone().unwrap_or_default();
        let new = username.clone().unwrap_or_default();
        if old == new {
            return;
        }
        if self.per_client {
            self.client_sessions_per_user
                .with_label_values(&[old.as_str(), protocol.as_str()])
                .dec();
            self.client_sessions_per_user
                .with_label_values(&[new.as_str(), protocol.as_str()])
                .inc();
        }
        entry.username = username;
    }

    /// Aggregate per-user summaries: configured clients (shown even when idle) merged
    /// with runtime connections and lifetime traffic totals from the per-user counters.
    fn clients_summary(&self, configured_usernames: &[String]) -> Vec<ClientSummary> {
        let mut agg: HashMap<String, ClientSummary> = HashMap::new();

        for uname in configured_usernames {
            agg.entry(uname.clone()).or_insert_with(|| ClientSummary {
                username: uname.clone(),
                ip: None,
                sessions: 0,
                inbound: 0,
                outbound: 0,
            });
        }

        if let Ok(clients_map) = self.clients.lock() {
            for info in clients_map.values() {
                let uname = info.username.clone().unwrap_or_default();
                let entry = agg.entry(uname.clone()).or_insert_with(|| ClientSummary {
                    username: uname,
                    ip: info.ip.map(|x| x.to_string()),
                    sessions: 0,
                    inbound: 0,
                    outbound: 0,
                });
                entry.sessions = entry.sessions.saturating_add(info.sessions);
                if entry.ip.is_none() {
                    entry.ip = info.ip.map(|x| x.to_string());
                }
            }
        }

        let mut summaries: Vec<ClientSummary> = agg.into_values().collect();
        if self.per_client {
            for summary in &mut summaries {
                summary.inbound = self
                    .inbound_traffic_per_user
                    .get_metric_with_label_values(&[&summary.username])
                    .map_or(0, |c| c.get());
                summary.outbound = self
                    .outbound_traffic_per_user
                    .get_metric_with_label_values(&[&summary.username])
                    .map_or(0, |c| c.get());
            }
        }
        summaries
    }
}

impl ClientSessionsCounter {
    fn new(
        metrics: Arc<Metrics>,
        protocol: Protocol,
        conn_id: String,
        username: Option<String>,
    ) -> Self {
        metrics
            .client_sessions
            .with_label_values(&[protocol.as_str()])
            .inc();
        if metrics.per_client {
            let label = username.as_deref().unwrap_or("");
            metrics
                .client_sessions_per_user
                .with_label_values(&[label, protocol.as_str()])
                .inc();
        }

        if let Ok(mut clients) = metrics.clients.lock() {
            let entry = clients.entry(conn_id.clone()).or_default();
            if let Some(u) = username {
                entry.username = Some(u);
            }
            entry.sessions = entry.sessions.saturating_add(1);
        }

        Self {
            metrics,
            protocol,
            conn_id,
        }
    }
}

impl Drop for ClientSessionsCounter {
    fn drop(&mut self) {
        self.metrics
            .client_sessions
            .with_label_values(&[self.protocol.as_str()])
            .dec();
        if let Ok(mut clients) = self.metrics.clients.lock() {
            if let Some(entry) = clients.remove(&self.conn_id) {
                if self.metrics.per_client {
                    let label = entry.username.as_deref().unwrap_or("");
                    self.metrics
                        .client_sessions_per_user
                        .with_label_values(&[label, self.protocol.as_str()])
                        .dec();
                }
            }
        }
    }
}

impl OutboundTcpSocketCounter {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.outbound_tcp_sockets.inc();
        Self { metrics }
    }
}

impl Drop for OutboundTcpSocketCounter {
    fn drop(&mut self) {
        self.metrics.outbound_tcp_sockets.dec();
    }
}

impl OutboundUdpSocketCounter {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.outbound_udp_sockets.inc();
        Self { metrics }
    }
}

impl Drop for OutboundUdpSocketCounter {
    fn drop(&mut self) {
        self.metrics.outbound_udp_sockets.dec();
    }
}

pub async fn listen(
    context: Arc<core::Context>,
    log_chain: log_utils::IdChain<u64>,
) -> io::Result<()> {
    let (mut shutdown_notification, _shutdown_completion) = {
        let shutdown = context
            .shutdown
            .lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        (shutdown.notification_handler(), shutdown.completion_guard())
    };

    tokio::select! {
        x = shutdown_notification.wait() => {
            match x {
                Ok(()) => Ok(()),
                Err(e) => Err(io::Error::other(e.to_string())),
            }
        }
        x = listen_inner(context, log_chain) => x,
    }
}

async fn listen_inner(
    context: Arc<core::Context>,
    log_chain: log_utils::IdChain<u64>,
) -> io::Result<()> {
    let Some(settings) = context.settings.metrics.as_ref() else {
        return Ok(());
    };

    let next_id = AtomicU64::default();
    let listener = TcpListener::bind(settings.address).await?;
    let timeout = settings.request_timeout;

    loop {
        let (stream, peer) = listener.accept().await?;
        let log_id = log_chain.extended(log_utils::IdItem::new(
            LOG_FMT,
            next_id.fetch_add(1, Ordering::Relaxed),
        ));
        log_id!(trace, log_id, "New connection from {}", peer);
        let context = context.clone();
        tokio::spawn(async move { handle_request(context, stream, log_id, timeout).await });
    }
}

async fn handle_request(
    context: Arc<core::Context>,
    io: TcpStream,
    log_id: log_utils::IdChain<u64>,
    timeout: std::time::Duration,
) {
    let mut codec = match Http1Codec::new(&context.settings, io, log_id.clone()) {
        Ok(codec) => codec,
        Err(e) => {
            log_id!(debug, log_id, "Failed to create HTTP codec: {}", e);
            return;
        }
    };
    let stream = match tokio::time::timeout(timeout, codec.listen()).await {
        Ok(Ok(Some(x))) => {
            log_id!(trace, log_id, "Got request: {:?}", x.request().request());
            x
        }
        Ok(Ok(None)) => {
            log_id!(debug, log_id, "Connection closed immediately");
            return;
        }
        Ok(Err(e)) => {
            log_id!(debug, log_id, "Listen failed: {}", e);
            return;
        }
        Err(_elapsed) => {
            log_id!(
                debug,
                log_id,
                "Didn't receive any request during configured period"
            );
            return;
        }
    };

    let dispatch = async {
        match codec.listen().await {
            Ok(Some(x)) => log_id!(
                debug,
                log_id,
                "Got unexpected request while processing previous: {:?}",
                x.request().request(),
            ),
            Ok(None) => (),
            Err(e) => log_id!(debug, log_id, "IO error during processing: {}", e),
        }
    };

    let handle = async {
        let path = stream.request().request().uri.path();
        let result = match path {
            HEALTH_CHECK_PATH => handle_health_check(stream),
            METRICS_PATH => handle_metrics_collect(&context.metrics, stream).await,
            CLIENTS_PATH => handle_clients_collect(context.clone(), &context.metrics, stream).await,
            x => {
                log_id!(debug, log_id, "Unexpected path: {}", x);
                let respond = stream.split().1;
                if let Err(e) =
                    respond.send_bad_response(http::status::StatusCode::BAD_REQUEST, vec![])
                {
                    log_id!(debug, log_id, "Failed to send response: {}", e);
                }
                return;
            }
        };

        if let Err(e) = result {
            log_id!(debug, log_id, "Failed to handle request: {}", e);
        }
    };

    tokio::select! {
        () = dispatch => (),
        () = handle => (),
    }

    if let Err(e) = codec.graceful_shutdown().await {
        log_id!(debug, log_id, "Failed to shutdown HTTP session: {}", e);
    }
}

fn handle_health_check(stream: Box<dyn http_codec::Stream>) -> io::Result<()> {
    stream.split().1.send_ok_response(true).map(|_| ())
}

async fn handle_clients_collect(
    context: Arc<core::Context>,
    metrics: &Metrics,
    stream: Box<dyn http_codec::Stream>,
) -> io::Result<()> {
    if !metrics.per_client() {
        let respond = stream.split().1;
        return respond.send_bad_response(http::status::StatusCode::NOT_FOUND, vec![]);
    }

    let configured_usernames: Vec<String> = context
        .settings
        .clients
        .iter()
        .map(|c| c.username.clone())
        .collect();
    let Ok(content_vec) = serde_json::to_vec(&metrics.clients_summary(&configured_usernames))
    else {
        let respond = stream.split().1;
        return respond.send_bad_response(http::status::StatusCode::INTERNAL_SERVER_ERROR, vec![]);
    };
    let mut body = Bytes::from(content_vec);
    let response = http::Response::builder()
        .version(stream.request().request().version)
        .status(http::status::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(())
        .map_err(io::Error::other)?
        .into_parts()
        .0;

    let mut sink = stream
        .split()
        .1
        .send_response(response, false)?
        .into_pipe_sink();

    while !body.is_empty() {
        body = sink.write(body)?;
        sink.wait_writable().await?;
    }

    sink.eof()
}

async fn handle_metrics_collect(
    metrics: &Metrics,
    stream: Box<dyn http_codec::Stream>,
) -> io::Result<()> {
    let (content_type, mut content) = metrics.collect()?;
    let response = http::Response::builder()
        .version(stream.request().request().version)
        .status(http::status::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, content.len())
        .body(())
        .map_err(io::Error::other)?
        .into_parts()
        .0;

    let mut sink = stream
        .split()
        .1
        .send_response(response, false)?
        .into_pipe_sink();

    while !content.is_empty() {
        content = sink.write(content)?;
        sink.wait_writable().await?;
    }

    sink.eof()
}

fn prometheus_to_io_error(e: prometheus::Error) -> io::Error {
    match e {
        prometheus::Error::Io(e) => e,
        e => io::Error::other(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check;

    fn metrics(per_client: bool) -> io::Result<Arc<Metrics>> {
        Metrics::new(per_client)
    }

    fn output(metrics: &Metrics) -> io::Result<String> {
        let (_, body) = metrics.collect()?;
        String::from_utf8(body.to_vec()).map_err(io::Error::other)
    }

    #[test]
    fn per_user_bytes_recorded_when_enabled() -> io::Result<()> {
        let m = metrics(true)?;
        m.add_inbound_bytes(Protocol::Http2, Some("alice"), 100);
        m.add_outbound_bytes(Protocol::Http2, Some("alice"), 200);

        let out = output(&m)?;
        check(
            out.contains("inbound_traffic_bytes{protocol_type=\"HTTP2\"} 100"),
            "missing inbound total",
        )?;
        check(
            out.contains("outbound_traffic_bytes{protocol_type=\"HTTP2\"} 200"),
            "missing outbound total",
        )?;
        check(
            out.contains("inbound_traffic_bytes_per_user{username=\"alice\"} 100"),
            "missing per-user inbound total",
        )?;
        check(
            out.contains("outbound_traffic_bytes_per_user{username=\"alice\"} 200"),
            "missing per-user outbound total",
        )?;
        Ok(())
    }

    #[test]
    fn per_user_bytes_not_recorded_when_disabled() -> io::Result<()> {
        let m = metrics(false)?;
        m.add_inbound_bytes(Protocol::Http2, Some("alice"), 100);
        m.add_outbound_bytes(Protocol::Http2, Some("alice"), 200);

        let out = output(&m)?;
        check(
            out.contains("inbound_traffic_bytes{protocol_type=\"HTTP2\"} 100"),
            "missing inbound total",
        )?;
        check(
            !out.contains("_per_user"),
            "disabled per-user metrics were recorded",
        )?;
        Ok(())
    }

    #[test]
    fn session_guard_balances_gauges_on_drop() -> io::Result<()> {
        let m = metrics(true)?;
        {
            let _guard = m.clone().client_sessions_counter(
                Protocol::Http2,
                "conn1".into(),
                Some("alice".into()),
            );
            let out = output(&m)?;
            check(
                out.contains("client_sessions{protocol_type=\"HTTP2\"} 1"),
                "session gauge was not incremented",
            )?;
            check(
                out.contains(
                    "client_sessions_per_user{protocol_type=\"HTTP2\",username=\"alice\"} 1",
                ),
                "per-user session gauge was not incremented",
            )?;
            check(
                m.clients
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?
                    .contains_key("conn1"),
                "active connection was not registered",
            )?;
        }

        let out = output(&m)?;
        check(
            out.contains("client_sessions{protocol_type=\"HTTP2\"} 0"),
            "session gauge was not decremented",
        )?;
        check(
            out.contains("client_sessions_per_user{protocol_type=\"HTTP2\",username=\"alice\"} 0"),
            "per-user session gauge was not decremented",
        )?;
        check(
            !m.clients
                .lock()
                .map_err(|e| io::Error::other(e.to_string()))?
                .contains_key("conn1"),
            "dropped connection remains registered",
        )?;
        Ok(())
    }

    #[test]
    fn session_guard_disabled_does_not_touch_per_user() -> io::Result<()> {
        let m = metrics(false)?;
        {
            let _guard = m.clone().client_sessions_counter(
                Protocol::Http2,
                "conn1".into(),
                Some("alice".into()),
            );
            let out = output(&m)?;
            check(
                out.contains("client_sessions{protocol_type=\"HTTP2\"} 1"),
                "session gauge was not incremented",
            )?;
            check(
                !out.contains("_per_user"),
                "disabled per-user session was recorded",
            )?;
        }
        Ok(())
    }

    #[test]
    fn transfer_session_username_relabels_gauge() -> io::Result<()> {
        let m = metrics(true)?;
        let _guard = m
            .clone()
            .client_sessions_counter(Protocol::Http2, "conn1".into(), None);

        m.transfer_session_username(Protocol::Http2, "conn1", Some("bob".into()));
        let out = output(&m)?;
        check(
            out.contains("client_sessions_per_user{protocol_type=\"HTTP2\",username=\"bob\"} 1"),
            "new username session gauge was not incremented",
        )?;
        check(
            out.contains("client_sessions_per_user{protocol_type=\"HTTP2\",username=\"\"} 0"),
            "old username session gauge was not decremented",
        )?;

        // Transferring to the same username is a no-op.
        m.transfer_session_username(Protocol::Http2, "conn1", Some("bob".into()));
        let out = output(&m)?;
        check(
            out.contains("client_sessions_per_user{protocol_type=\"HTTP2\",username=\"bob\"} 1"),
            "unchanged username unbalanced session gauge",
        )?;
        Ok(())
    }

    #[test]
    fn unregister_without_guard_is_safe() -> io::Result<()> {
        let m = metrics(true)?;
        m.register_connection("conn1".into(), Some(std::net::Ipv4Addr::LOCALHOST.into()));
        check(
            m.clients
                .lock()
                .map_err(|e| io::Error::other(e.to_string()))?
                .contains_key("conn1"),
            "connection was not registered",
        )?;

        m.unregister_connection("conn1");
        check(
            !m.clients
                .lock()
                .map_err(|e| io::Error::other(e.to_string()))?
                .contains_key("conn1"),
            "connection was not unregistered",
        )?;
        Ok(())
    }

    #[test]
    fn clients_summary_merges_configured_and_runtime() -> io::Result<()> {
        let m = metrics(true)?;
        m.register_connection("conn1".into(), Some(std::net::Ipv4Addr::LOCALHOST.into()));
        let _guard = m.clone().client_sessions_counter(
            Protocol::Http2,
            "conn1".into(),
            Some("alice".into()),
        );
        m.add_inbound_bytes(Protocol::Http2, Some("alice"), 42);
        m.add_outbound_bytes(Protocol::Http2, Some("alice"), 7);

        let configured = vec!["alice".to_string(), "bob".to_string()];
        let summaries = m.clients_summary(&configured);

        let alice = summaries
            .iter()
            .find(|s| s.username == "alice")
            .ok_or_else(|| io::Error::other("missing alice summary"))?;
        check(alice.sessions == 1, "wrong active session count")?;
        check(alice.inbound == 42, "wrong active inbound bytes")?;
        check(alice.outbound == 7, "wrong active outbound bytes")?;
        check(alice.ip.as_deref() == Some("127.0.0.1"), "wrong active IP")?;

        let bob = summaries
            .iter()
            .find(|s| s.username == "bob")
            .ok_or_else(|| io::Error::other("missing bob summary"))?;
        check(bob.sessions == 0, "idle client has sessions")?;
        check(bob.inbound == 0, "idle client has inbound bytes")?;
        check(bob.outbound == 0, "idle client has outbound bytes")?;
        check(bob.ip.is_none(), "idle client has an IP")?;
        Ok(())
    }

    #[test]
    fn clients_summary_shows_zeroes_when_disabled() -> io::Result<()> {
        let m = metrics(false)?;
        let configured = vec!["alice".to_string()];
        let summaries = m.clients_summary(&configured);

        check(summaries.len() == 1, "wrong configured summary count")?;
        check(
            summaries[0].username == "alice",
            "wrong configured username",
        )?;
        check(summaries[0].sessions == 0, "disabled summary has sessions")?;
        check(
            summaries[0].inbound == 0,
            "disabled summary has inbound bytes",
        )?;
        check(
            summaries[0].outbound == 0,
            "disabled summary has outbound bytes",
        )?;
        Ok(())
    }
}
