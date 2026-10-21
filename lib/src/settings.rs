//! Endpoint settings, builders, deserialization, and validation.

use std::collections::HashSet;
use std::fmt::{Debug, Formatter};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use crate::subscription::SubscriptionSettings;
use crate::{authentication, rules, utils};
use authentication::registry_based::Client;
#[cfg(feature = "rt_doc")]
use macros::{Getter, RuntimeDoc};
use serde::{Deserialize, Serialize};
use toml_edit::{Document, Item};

/// Result of constructing SOCKS5 forwarder settings.
pub type Socks5BuilderResult<T> = Result<T, Socks5Error>;

/// Invalid endpoint or TLS host configuration.
pub enum ValidationError {
    /// `Settings::listen_address` is not set
    ListenAddressNotSet,
    /// Invalid `TlsHostsSettings::main_hosts`
    MainTlsHostInfo(String),
    /// Invalid `TlsHostsSettings::ping_hosts`
    PingTlsHostInfo(String),
    /// Invalid `TlsHostsSettings::speedtest_hosts`
    SpeedTlsHostInfo(String),
    /// Invalid `Settings::reverse_proxy`
    ReverseProxy(String),
    /// Invalid `Settings::subscription`
    Subscription(String),
    /// Invalid `Settings::listen_protocols`
    ListenProtocols(String),
    /// Invalid request path configuration
    InvalidPath(String),
    /// Invalid rules file
    RulesFile(String),
    /// No credentials configured while listening on a public address
    NoCredentialsOnPublicAddress,
    /// Invalid auth failure status code
    InvalidAuthFailureStatusCode(u16),
}

impl Debug for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ListenAddressNotSet => write!(f, "Listen address is not set"),
            Self::MainTlsHostInfo(x) => write!(f, "Invalid main TLS hosts: {x}"),
            Self::PingTlsHostInfo(x) => write!(f, "Invalid ping TLS hosts: {x}"),
            Self::SpeedTlsHostInfo(x) => write!(f, "Invalid speedtest TLS hosts: {x}"),
            Self::ReverseProxy(x) => write!(f, "Invalid reverse proxy settings: {x}"),
            Self::Subscription(x) => write!(f, "Invalid subscription settings: {x}"),
            Self::ListenProtocols(x) => write!(f, "Invalid listen protocols settings: {x}"),
            Self::InvalidPath(x) => write!(f, "Invalid request path: {x}"),
            Self::RulesFile(x) => write!(f, "Invalid rules file: {x}"),
            Self::NoCredentialsOnPublicAddress => write!(
                f,
                "No credentials configured (credentials_file is missing) while listening on a public address. \
                This is a security risk. Either configure credentials or use a loopback address (127.0.0.1 or ::1)"
            ),
            Self::InvalidAuthFailureStatusCode(code) => write!(
                f,
                "Invalid auth_failure_status_code: {code}. Supported values: 407, 405, 404, 403"),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ValidationError {}

/// Invalid SOCKS5 forwarder configuration.
#[derive(Clone, Copy)]
pub enum Socks5Error {
    /// `Socks5ForwarderSettings::address` is not set
    AddressNotSet,
}

impl Debug for Socks5Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressNotSet => write!(f, "Server address is not set"),
        }
    }
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Socks5Error {}

/// Endpoint configuration and validation state.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rt_doc", derive(Getter, RuntimeDoc))]
pub struct Settings {
    /// The address to listen on
    #[serde(default = "Settings::default_listen_address")]
    pub(crate) listen_address: SocketAddr,
    #[serde(default = "Settings::default_ipv6_available")]
    pub(crate) ipv6_available: bool,
    /// Whether connections to private network of the endpoint are allowed.
    /// Applies to the traffic tunneled by clients only: destinations taken from
    /// the endpoint configuration, such as `ReverseProxySettings::server_address`,
    /// are always allowed.
    #[serde(default = "Settings::default_allow_private_network_connections")]
    pub(crate) allow_private_network_connections: bool,
    /// Timeout of an incoming TLS handshake
    #[serde(default = "Settings::default_tls_handshake_timeout")]
    #[serde(rename = "tls_handshake_timeout_secs")]
    #[serde(
        deserialize_with = "deserialize_duration_secs",
        serialize_with = "serialize_duration_secs"
    )]
    pub(crate) tls_handshake_timeout: Duration,
    /// Timeout of a client listener
    #[serde(default = "Settings::default_client_listener_timeout")]
    #[serde(rename = "client_listener_timeout_secs")]
    #[serde(
        deserialize_with = "deserialize_duration_secs",
        serialize_with = "serialize_duration_secs"
    )]
    pub(crate) client_listener_timeout: Duration,
    /// Timeout of outgoing connection establishment.
    /// For example, it is related to client's connection requests.
    #[serde(default = "Settings::default_connection_establishment_timeout")]
    #[serde(rename = "connection_establishment_timeout_secs")]
    #[serde(
        deserialize_with = "deserialize_duration_secs",
        serialize_with = "serialize_duration_secs"
    )]
    pub(crate) connection_establishment_timeout: Duration,
    /// Idle timeout of tunneled TCP connections
    #[serde(default = "Settings::default_tcp_connections_timeout")]
    #[serde(rename = "tcp_connections_timeout_secs")]
    #[serde(
        deserialize_with = "deserialize_duration_secs",
        serialize_with = "serialize_duration_secs"
    )]
    pub(crate) tcp_connections_timeout: Duration,
    /// Timeout of tunneled UDP "connections"
    #[serde(default = "Settings::default_udp_connections_timeout")]
    #[serde(rename = "udp_connections_timeout_secs")]
    #[serde(
        deserialize_with = "deserialize_duration_secs",
        serialize_with = "serialize_duration_secs"
    )]
    pub(crate) udp_connections_timeout: Duration,
    /// The set of connection forwarder settings
    #[serde(default)]
    pub(crate) forward_protocol: ForwardProtocolSettings,
    /// The set of enabled client listener codecs
    pub(crate) listen_protocols: ListenProtocolSettings,
    // TODO (ayakushin): fix docs
    /// The client authenticator.
    ///
    /// If `forward_protocol` is set to
    /// [SOCKS5](ForwardProtocolSettings::Socks5), the endpoint will advertise authentication
    /// to the SOCKS5 server even if the `Settings::authenticator` is [`None`].
    ///
    /// In case the [`Settings`] are deserialized from a file, the authenticator
    /// is specified as the `credentials_file` field, which contains the path to the TOML
    /// file in the form shown below, and the resulting type of the authenticator is
    /// [`authentication::registry_based::RegistryBasedAuthenticator`].
    ///
    /// The credentials file format:
    ///
    /// ```text
    /// [[client]]
    /// username = "a"
    /// password = "b"
    ///
    /// [[client]]
    /// ...
    /// ```
    #[serde(default)]
    #[serde(skip_serializing)]
    #[serde(rename(deserialize = "credentials_file"))]
    #[serde(deserialize_with = "deserialize_clients")]
    pub(crate) clients: Vec<Client>,
    /// The reverse proxy settings.
    /// With this one set up the endpoint does TLS termination on such connections and
    /// translates HTTP/x traffic into HTTP/1.1 protocol towards the server and back
    /// into original HTTP/x towards the client. Like this:
    ///
    /// `(client) TLS(HTTP/x) <--(endpoint)--> (server) HTTP/1.1`
    ///
    /// The translated HTTP/1.1 requests have the custom header `X-Original-Protocol`
    /// appended. For now, its value can be either `HTTP1`, or `HTTP3`.
    /// TLS hosts for the reverse proxy channel are configured through [`TlsHostsSettings`].
    pub(crate) reverse_proxy: Option<ReverseProxySettings>,
    /// The subscription endpoint settings.
    /// When enabled, the endpoint serves a per-user JSON configuration over an
    /// existing main TLS host. Hot-reloaded on `SIGHUP` (see
    /// [`crate::core::Core::reload_subscription_settings`]).
    #[serde(default)]
    pub(crate) subscription: Option<SubscriptionSettings>,
    /// The ICMP forwarding settings.
    /// Setting up this feature requires superuser rights on some systems.
    pub(crate) icmp: Option<IcmpSettings>,
    /// The metrics gathering request handler settings
    pub(crate) metrics: Option<MetricsSettings>,
    /// Path to the rules file for connection filtering.
    /// If not specified or file doesn't exist, all connections are allowed by default.
    #[serde(default)]
    #[serde(skip_serializing)]
    #[serde(rename(deserialize = "rules_file"))]
    #[serde(deserialize_with = "deserialize_rules")]
    pub(crate) rules_engine: Option<rules::RulesEngine>,

    /// Availability of diagnostic services on the main hosts.
    #[serde(flatten)]
    pub(crate) main_host_services: MainHostServices,
    /// Optional path prefix for ping requests on main hosts.
    #[serde(default = "Settings::default_ping_path")]
    pub(crate) ping_path: Option<String>,
    /// Optional path prefix for speedtest requests on main hosts.
    #[serde(default = "Settings::default_speedtest_path")]
    pub(crate) speedtest_path: Option<String>,

    /// HTTP status code returned on authentication failure for CONNECT requests.
    /// Supported values: 407 (Proxy Authentication Required), 405 (Method Not Allowed),
    /// 404 (Not Found), 403 (Forbidden).
    /// Warning: using a value other than 407 breaks proxy authentication in Chrome,
    /// as Chrome relies on 407 to trigger its proxy authentication logic.
    #[serde(default = "Settings::default_auth_failure_status_code")]
    pub(crate) auth_failure_status_code: u16,

    /// HTTP status code returned on authentication failure for non-CONNECT requests.
    /// Supported values: 407 (Proxy Authentication Required), 405 (Method Not Allowed),
    /// 404 (Not Found), 403 (Forbidden).
    /// If absent, falls back to `auth_failure_status_code`.
    #[serde(default)]
    pub(crate) non_connect_auth_failure_status_code: Option<u16>,

    /// Default maximum number of simultaneous HTTP/1 and HTTP/2 connections per client credentials.
    /// `TrustTunnel` clients open 8 HTTP/2 connections by default, so set this to
    /// `8 * <max_devices>` to limit the number of simultaneously connected devices.
    /// Can be overridden per-client with `max_http2_conns` in the credentials file.
    /// If absent, HTTP/2 connections are unlimited.
    #[serde(default)]
    pub(crate) default_max_http2_conns_per_client: Option<u32>,

    /// Default maximum number of simultaneous HTTP/3 (QUIC) connections per client credentials.
    /// `TrustTunnel` clients open 1 HTTP/3 connection by default.
    /// Can be overridden per-client with `max_http3_conns` in the credentials file.
    /// If absent, HTTP/3 connections are unlimited.
    #[serde(default)]
    pub(crate) default_max_http3_conns_per_client: Option<u32>,

    /// Whether an instance was built through a [`SettingsBuilder`].
    /// This flag is a workaround for absence of the ability to validate
    /// the deserialized structure.
    /// <https://github.com/serde-rs/serde/issues/642>
    #[serde(skip)]
    built: bool,
}

/// Availability of diagnostic services on the main TLS hosts.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[cfg_attr(feature = "rt_doc", derive(RuntimeDoc))]
pub struct MainHostServices {
    /// Whether speedtest is available on the main hosts.
    #[serde(default = "Settings::default_speedtest_enable")]
    pub(crate) speedtest_enable: bool,
    /// Whether ping is available on the main hosts.
    #[serde(default = "Settings::default_ping_enable")]
    pub(crate) ping_enable: bool,
}

/// Certificate identity and accepted names for a TLS host.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "rt_doc", derive(RuntimeDoc))]
pub struct TlsHostInfo {
    /// Used as a key for selecting a certificate chain in TLS handshake.
    /// MUST be unique.
    pub hostname: String,
    /// Path to a file containing the certificate chain.
    /// MUST remain valid while [`crate::core::Core::listen()`] is running, or
    /// until the next [`crate::core::Core::reload_tls_hosts_settings()`] call.
    #[serde(deserialize_with = "deserialize_file_path")]
    pub cert_chain_path: String,
    /// Path to a file containing the private key.
    /// May be equal to `cert_chain_path` if it contains both of them.
    /// MUST remain valid while [`crate::core::Core::listen()`] is running, or
    /// until the next [`crate::core::Core::reload_tls_hosts_settings()`] call.
    #[serde(deserialize_with = "deserialize_file_path")]
    pub private_key_path: String,
    /// List of alternative SNIs that should be accepted for this host.
    /// When a client sends one of these SNIs, the connection will use this host's certificate.
    #[serde(default)]
    pub allowed_sni: Vec<String>,
}

/// TLS host groups used for endpoint routing.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(test, derive(Default))]
#[cfg_attr(feature = "rt_doc", derive(RuntimeDoc))]
pub struct TlsHostsSettings {
    /// Еhe main TLS hosts.
    /// Used for traffic tunneling and service requests handling.
    pub(crate) main_hosts: Vec<TlsHostInfo>,
    /// The TLS hosts for HTTPS pinging.
    /// With this one set up the endpoint responds with `200 OK` to HTTPS `GET` requests
    /// to the specified domains.
    #[serde(default)]
    pub(crate) ping_hosts: Vec<TlsHostInfo>,
    /// The TLS hosts for speed testing.
    /// With this one set up the endpoint accepts connections to the specified hosts and
    /// handles HTTP requests in the following way:
    ///     * `GET` requests with `/Nmb.bin` path (where `N` is 1 to 100, e.g. `/100mb.bin`)
    ///       are considered as download speedtest transferring `N` megabytes to a client
    ///     * `POST` requests with `/upload.html` path and `Content-Length: N`
    ///       are considered as upload speedtest receiving `N` bytes from a client,
    ///       where `N` is up to 120 * 1024 * 1024 bytes
    #[serde(default)]
    pub(crate) speedtest_hosts: Vec<TlsHostInfo>,
    /// The TLS hosts for the connections must be forwarded to the reverse proxy
    /// (see `Settings::reverse_proxy`).
    /// Only makes sense if the reverse proxy is set up, otherwise it is ignored.
    #[serde(default)]
    pub(crate) reverse_proxy_hosts: Vec<TlsHostInfo>,

    /// Whether an instance was built through a [`TlsSettingsBuilder`].
    /// This flag is a workaround for absence of the ability to validate
    /// the deserialized structure.
    /// <https://github.com/serde-rs/serde/issues/642>
    #[serde(skip)]
    built: bool,
}

/// Origin and routing settings for the reverse proxy.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rt_doc", derive(RuntimeDoc))]
pub struct ReverseProxySettings {
    /// The origin server address. It is reachable regardless of
    /// `Settings::allow_private_network_connections`.
    pub(crate) server_address: SocketAddr,
    /// Connections to [the main hosts](TlsHostsSettings::get_main_hosts) with
    /// paths starting with this mask are routed to the reverse proxy server.
    /// MUST start with slash.
    pub(crate) path_mask: String,
    /// With this one set to `true` the endpoint overrides the HTTP method while
    /// translating an HTTP3 request to HTTP1 in case the request has the `GET` method
    /// and its path is `/` or matches `ReverseProxySettings::path_mask`
    #[serde(default)]
    pub(crate) h3_backward_compatibility: bool,
}

/// The set of connection forwarder settings
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "rt_doc", derive(RuntimeDoc))]
pub enum ForwardProtocolSettings {
    /// A direct forwarder routes a connection directly to its target host
    Direct(DirectForwarderSettings),
    /// A SOCKS5 forwarder routes a connection though a SOCKS5 proxy
    Socks5(Socks5ForwarderSettings),
}

/// Settings for direct forwarding to destination hosts.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct DirectForwarderSettings {}

/// Address and authentication settings for a SOCKS5 proxy.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[cfg_attr(feature = "rt_doc", derive(Getter, RuntimeDoc))]
pub struct Socks5ForwarderSettings {
    /// The address of a proxy
    pub(crate) address: SocketAddr,
    /// Whether the extended authentication is enabled
    #[serde(default)]
    pub(crate) extended_auth: bool,
}

/// Builder for validated [`Socks5ForwarderSettings`].
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Socks5ForwarderSettingsBuilder {
    settings: Socks5ForwarderSettings,
}

/// The set of enabled client listener codecs
#[derive(Debug, Clone, Default, Serialize, Deserialize, Copy)]
#[cfg_attr(feature = "rt_doc", derive(RuntimeDoc))]
pub struct ListenProtocolSettings {
    /// HTTP/1.1 listener settings
    #[serde(default)]
    pub http1: Option<Http1Settings>,
    /// HTTP/2 listener settings
    #[serde(default)]
    pub http2: Option<Http2Settings>,
    #[serde(default)]
    /// QUIC / HTTP/3 listener settings
    pub quic: Option<QuicSettings>,
}

/// The ICMP forwarding settings.
/// Setting up this feature requires superuser rights on some systems.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rt_doc", derive(Getter, RuntimeDoc))]
pub struct IcmpSettings {
    /// The name of a network interface to bind the outbound ICMP socket to
    #[serde(default = "IcmpSettings::default_interface_name")]
    pub(crate) interface_name: String,
    /// Timeout of tunneled ICMP requests
    #[serde(default = "IcmpSettings::default_request_timeout")]
    #[serde(rename = "request_timeout_secs")]
    #[serde(
        deserialize_with = "deserialize_duration_secs",
        serialize_with = "serialize_duration_secs"
    )]
    pub(crate) request_timeout: Duration,
    /// The capacity of the ICMP multiplexer received messages queue.
    /// Decreasing it may cause packet dropping in case the multiplexer cannot keep up the pace.
    /// Increasing it may lead to high memory consumption.
    /// Each client has its own queue.
    #[serde(default = "IcmpSettings::default_message_queue_capacity")]
    pub(crate) recv_message_queue_capacity: usize,
}

/// The metrics gathering request handler settings
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[cfg_attr(feature = "rt_doc", derive(Getter, RuntimeDoc))]
pub struct MetricsSettings {
    /// The address to listen on for settings export requests
    #[serde(default = "MetricsSettings::default_listen_address")]
    pub(crate) address: SocketAddr,
    /// Timeout of a metrics request
    #[serde(default = "MetricsSettings::default_request_timeout")]
    #[serde(rename = "request_timeout_secs")]
    #[serde(
        deserialize_with = "deserialize_duration_secs",
        serialize_with = "serialize_duration_secs"
    )]
    pub(crate) request_timeout: Duration,
    /// Whether to expose per-client metrics labelled with the client username.
    ///
    /// When disabled (the default), only aggregate metrics are exported. When enabled,
    /// additional `*_per_user` series labelled with the authenticated `username` and the
    /// `/clients` endpoint are exposed. Enabling this exposes usernames and client IPs,
    /// so it should only be turned on when the metrics endpoint is adequately protected.
    #[serde(default = "MetricsSettings::default_per_client_metrics")]
    pub(crate) per_client_metrics: bool,
}

/// The set of HTTP/1.1 listener codec settings
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[cfg_attr(feature = "rt_doc", derive(Getter, RuntimeDoc))]
pub struct Http1Settings {
    /// Buffer size for outgoing traffic
    #[serde(default = "Http1Settings::default_upload_buffer_size")]
    pub(crate) upload_buffer_size: usize,
}

/// The set of HTTP/2 listener codec settings
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[cfg_attr(feature = "rt_doc", derive(Getter, RuntimeDoc))]
pub struct Http2Settings {
    /// The initial window size (in octets) for connection-level flow control for received data
    #[serde(default = "Http2Settings::default_initial_connection_window_size")]
    pub(crate) initial_connection_window_size: u32,
    /// The initial window size (in octets) for stream-level flow control for received data
    #[serde(default = "Http2Settings::default_initial_stream_window_size")]
    pub(crate) initial_stream_window_size: u32,
    /// The number of streams that the sender permits the receiver to create
    #[serde(default = "Http2Settings::default_max_concurrent_streams")]
    pub(crate) max_concurrent_streams: u32,
    /// The size (in octets) of the largest HTTP/2 frame payload that we are able to accept
    #[serde(default = "Http2Settings::default_max_frame_size")]
    pub(crate) max_frame_size: u32,
    /// The max size of received header frames
    #[serde(default = "Http2Settings::default_header_table_size")]
    pub(crate) header_table_size: u32,
}

/// The set of QUIC listener codec settings
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[cfg_attr(feature = "rt_doc", derive(Getter, RuntimeDoc))]
pub struct QuicSettings {
    /// The size of UDP payloads that the endpoint is willing to receive. UDP datagrams with
    /// payloads larger than this limit are not likely to be processed.
    #[serde(default = "QuicSettings::default_recv_udp_payload_size")]
    pub(crate) recv_udp_payload_size: usize,
    /// The size of UDP payloads that the endpoint is willing to send
    #[serde(default = "QuicSettings::default_send_udp_payload_size")]
    pub(crate) send_udp_payload_size: usize,
    /// The initial value for the maximum amount of data that can be sent on the connection
    #[serde(default = "QuicSettings::default_initial_max_data")]
    pub(crate) initial_max_data: u64,
    /// The initial flow control limit for locally initiated bidirectional streams
    #[serde(default = "QuicSettings::default_initial_max_stream_data_bidi_local")]
    #[serde(alias = "max_stream_data_bidi_local")]
    pub(crate) initial_max_stream_data_bidi_local: u64,
    /// The initial flow control limit for peer-initiated bidirectional streams
    #[serde(default = "QuicSettings::default_initial_max_stream_data_bidi_remote")]
    #[serde(alias = "max_stream_data_bidi_remote")]
    pub(crate) initial_max_stream_data_bidi_remote: u64,
    /// The initial flow control limit for unidirectional streams
    #[serde(default = "QuicSettings::default_initial_max_stream_data_uni")]
    #[serde(alias = "max_stream_data_uni")]
    pub(crate) initial_max_stream_data_uni: u64,
    /// The initial maximum number of bidirectional streams the endpoint that receives this
    /// transport parameter is permitted to initiate
    #[serde(default = "QuicSettings::default_initial_max_streams_bidi")]
    #[serde(alias = "max_streams_bidi")]
    pub(crate) initial_max_streams_bidi: u64,
    /// The initial maximum number of unidirectional streams the endpoint that receives this
    /// transport parameter is permitted to initiate
    #[serde(default = "QuicSettings::default_initial_max_streams_uni")]
    #[serde(alias = "max_streams_uni")]
    pub(crate) initial_max_streams_uni: u64,
    /// The maximum size of the connection window
    #[serde(default = "QuicSettings::default_max_connection_window")]
    pub(crate) max_connection_window: u64,
    /// The maximum size of the stream window
    #[serde(default = "QuicSettings::default_max_stream_window")]
    pub(crate) max_stream_window: u64,
    /// Disable active connection migration on the address being used during the handshake
    #[serde(default = "QuicSettings::default_disable_active_migration")]
    pub(crate) disable_active_migration: bool,
    /// Enable sending or receiving early data
    #[serde(default = "QuicSettings::default_enable_early_data")]
    pub(crate) enable_early_data: bool,
    /// The capacity of the QUIC multiplexer message queue.
    /// Decreasing it may cause packet dropping in case the multiplexer cannot keep up the pace.
    /// Increasing it may lead to high memory consumption.
    // @todo: separate values for incoming and outgoing?
    #[serde(default = "QuicSettings::default_message_queue_capacity")]
    pub(crate) message_queue_capacity: usize,
}

/// Builder for validated [`Settings`].
#[derive(Debug)]
#[must_use]
pub struct SettingsBuilder {
    settings: Settings,
}

/// Builder for validated [`TlsHostsSettings`].
#[derive(Debug)]
#[must_use]
pub struct TlsSettingsBuilder {
    settings: TlsHostsSettings,
}

/// Builder for validated [`Http1Settings`].
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Http1SettingsBuilder {
    settings: Http1Settings,
}

/// Builder for validated [`Http2Settings`].
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Http2SettingsBuilder {
    settings: Http2Settings,
}

/// Builder for validated [`QuicSettings`].
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct QuicSettingsBuilder {
    settings: QuicSettings,
}

/// Builder for validated [`ReverseProxySettings`].
#[derive(Debug)]
#[must_use]
pub struct ReverseProxySettingsBuilder {
    settings: ReverseProxySettings,
}

/// Builder for validated [`IcmpSettings`].
#[derive(Debug)]
#[must_use]
pub struct IcmpSettingsBuilder {
    settings: IcmpSettings,
}

/// Builder for validated [`MetricsSettings`].
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct MetricsSettingsBuilder {
    settings: MetricsSettings,
}

impl Settings {
    /// Create a configuration builder.
    pub fn builder() -> SettingsBuilder {
        SettingsBuilder::new()
    }

    /// Borrow the configured client registry.
    #[cfg(not(feature = "rt_doc"))]
    #[must_use]
    pub const fn get_clients(&self) -> &Vec<Client> {
        &self.clients
    }

    /// Borrow the main-host speedtest availability flag.
    #[must_use]
    pub const fn get_speedtest_enable(&self) -> &bool {
        &self.main_host_services.speedtest_enable
    }

    /// Borrow the main-host ping availability flag.
    #[must_use]
    pub const fn get_ping_enable(&self) -> &bool {
        &self.main_host_services.ping_enable
    }

    /// Return the legacy configuration comment for `IPv6` availability.
    #[cfg(feature = "rt_doc")]
    #[must_use]
    pub const fn doc_ipv6_available() -> &'static str {
        "Whether IPv6 connections can be routed or rejected with unreachable status"
    }

    /// Return the speedtest availability documentation.
    #[cfg(feature = "rt_doc")]
    #[must_use]
    pub fn doc_speedtest_enable() -> &'static str {
        MainHostServices::doc_speedtest_enable()
    }

    /// Return the ping availability documentation.
    #[cfg(feature = "rt_doc")]
    #[must_use]
    pub fn doc_ping_enable() -> &'static str {
        MainHostServices::doc_ping_enable()
    }

    pub(crate) const fn is_built(&self) -> bool {
        self.built
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        if self.listen_address.ip().is_unspecified() && self.listen_address.port() == 0 {
            return Err(ValidationError::ListenAddressNotSet);
        }

        self.reverse_proxy
            .as_ref()
            .map(ReverseProxySettings::validate)
            .transpose()?;

        Self::validate_request_path("ping_path", self.ping_path.as_deref())?;
        Self::validate_request_path("speedtest_path", self.speedtest_path.as_deref())?;
        Self::validate_request_path_overlaps(
            self.ping_path.as_deref(),
            self.speedtest_path.as_deref(),
        )?;

        if self.listen_protocols.http1.is_none()
            && self.listen_protocols.http2.is_none()
            && self.listen_protocols.quic.is_none()
        {
            return Err(ValidationError::ListenProtocols("Not set".into()));
        }

        // Do not start the endpoint without credentials on a public address
        if self.clients.is_empty() && !self.listen_address.ip().is_loopback() {
            return Err(ValidationError::NoCredentialsOnPublicAddress);
        }

        if !Self::is_valid_auth_failure_status_code(self.auth_failure_status_code) {
            return Err(ValidationError::InvalidAuthFailureStatusCode(
                self.auth_failure_status_code,
            ));
        }

        if let Some(code) = self.non_connect_auth_failure_status_code {
            if !Self::is_valid_auth_failure_status_code(code) {
                return Err(ValidationError::InvalidAuthFailureStatusCode(code));
            }
        }

        Ok(())
    }

    /// Return the default `listen_address` value.
    #[must_use]
    pub fn default_listen_address() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443))
    }

    /// Return the default `ipv6_available` value.
    #[must_use]
    pub const fn default_ipv6_available() -> bool {
        true
    }

    /// Return the default `allow_private_network_connections` value.
    #[must_use]
    pub const fn default_allow_private_network_connections() -> bool {
        false
    }

    /// Return the default `tls_handshake_timeout` value.
    #[must_use]
    pub const fn default_tls_handshake_timeout() -> Duration {
        Duration::from_secs(10)
    }

    /// Return the default `client_listener_timeout` value.
    #[must_use]
    pub const fn default_client_listener_timeout() -> Duration {
        Duration::from_mins(10)
    }

    /// Return the default `connection_establishment_timeout` value.
    #[must_use]
    pub const fn default_connection_establishment_timeout() -> Duration {
        Duration::from_secs(30)
    }

    /// Return the default `tcp_connections_timeout` value.
    #[must_use]
    pub const fn default_tcp_connections_timeout() -> Duration {
        Duration::new(604_800, 0) // 1 week (match client tcpip module)
    }

    /// Return the default `udp_connections_timeout` value.
    #[must_use]
    pub const fn default_udp_connections_timeout() -> Duration {
        Duration::from_secs(300) // 5 minutes (match client tcpip module)
    }

    /// Return the default `speedtest_enable` value.
    #[must_use]
    pub const fn default_speedtest_enable() -> bool {
        false
    }

    /// Return the default `speedtest_path` value.
    #[must_use]
    pub fn default_speedtest_path() -> Option<String> {
        Some("/speedtest".to_string())
    }

    /// Return the default `ping_enable` value.
    #[must_use]
    pub const fn default_ping_enable() -> bool {
        false
    }

    /// Return the default `ping_path` value.
    #[must_use]
    pub fn default_ping_path() -> Option<String> {
        Some("/ping".to_string())
    }

    /// Return the default `auth_failure_status_code` value.
    #[must_use]
    pub const fn default_auth_failure_status_code() -> u16 {
        407
    }

    const fn is_valid_auth_failure_status_code(code: u16) -> bool {
        matches!(code, 407 | 405 | 404 | 403)
    }

    fn validate_request_path(name: &str, path: Option<&str>) -> Result<(), ValidationError> {
        if let Some(path) = path {
            if path.is_empty() || !path.starts_with('/') {
                return Err(ValidationError::InvalidPath(format!("{name}: {path}")));
            }
        }
        Ok(())
    }

    fn validate_request_path_overlaps(
        left: Option<&str>,
        right: Option<&str>,
    ) -> Result<(), ValidationError> {
        let (Some(left), Some(right)) = (left, right) else {
            return Ok(());
        };
        if left == right || left.starts_with(right) || right.starts_with(left) {
            return Err(ValidationError::InvalidPath(format!(
                "path overlap: {left} vs {right}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
impl Default for Settings {
    fn default() -> Self {
        Self {
            listen_address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            ipv6_available: false,
            allow_private_network_connections: true,
            tls_handshake_timeout: Self::default_tls_handshake_timeout(),
            client_listener_timeout: Self::default_client_listener_timeout(),
            connection_establishment_timeout: Self::default_connection_establishment_timeout(),
            tcp_connections_timeout: Self::default_tcp_connections_timeout(),
            udp_connections_timeout: Self::default_udp_connections_timeout(),
            forward_protocol: ForwardProtocolSettings::default(),
            clients: Vec::default(),
            listen_protocols: ListenProtocolSettings {
                http1: Some(Http1Settings::builder().build()),
                http2: Some(Http2Settings::builder().build()),
                quic: Some(QuicSettings::builder().build()),
            },
            reverse_proxy: None,
            subscription: None,
            icmp: None,
            metrics: None,
            rules_engine: Some(rules::RulesEngine::default_allow()),
            main_host_services: MainHostServices {
                speedtest_enable: false,
                ping_enable: Self::default_ping_enable(),
            },
            ping_path: None,
            speedtest_path: None,
            default_max_http2_conns_per_client: None,
            default_max_http3_conns_per_client: None,
            auth_failure_status_code: Self::default_auth_failure_status_code(),
            non_connect_auth_failure_status_code: None,
            built: false,
        }
    }
}

impl TlsHostsSettings {
    /// Create a configuration builder.
    pub fn builder() -> TlsSettingsBuilder {
        TlsSettingsBuilder::new()
    }

    /// Return the hosts used for tunneling and service requests.
    #[must_use]
    pub fn get_main_hosts(&self) -> &[TlsHostInfo] {
        &self.main_hosts
    }

    pub(crate) const fn is_built(&self) -> bool {
        self.built
    }

    fn validate_tls_hosts<'a, Iter>(
        hosts: Iter,
        mut unique_hosts: HashSet<&'a str>,
    ) -> Result<HashSet<&'a str>, String>
    where
        Iter: Iterator<Item = &'a TlsHostInfo>,
    {
        for h in hosts {
            utils::load_certs(&h.cert_chain_path).map_err(|e| {
                format!(
                    "Invalid cert chain: path='{}', error='{}'",
                    h.cert_chain_path, e
                )
            })?;

            utils::load_private_key(&h.private_key_path).map_err(|e| {
                format!("Invalid key: path='{}', error='{}'", h.private_key_path, e)
            })?;

            if !unique_hosts.insert(&h.hostname) {
                return Err(format!("Hostname must be unique: {}", h.hostname));
            }
        }

        Ok(unique_hosts)
    }

    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        if self.main_hosts.is_empty() {
            return Err(ValidationError::MainTlsHostInfo("Not set".to_string()));
        }

        let hosts = Self::validate_tls_hosts(self.main_hosts.iter(), HashSet::new())
            .map_err(ValidationError::MainTlsHostInfo)?;
        let hosts = Self::validate_tls_hosts(self.ping_hosts.iter(), hosts)
            .map_err(ValidationError::PingTlsHostInfo)?;
        let hosts = Self::validate_tls_hosts(self.speedtest_hosts.iter(), hosts)
            .map_err(ValidationError::SpeedTlsHostInfo)?;
        Self::validate_tls_hosts(self.reverse_proxy_hosts.iter(), hosts)
            .map_err(ValidationError::ReverseProxy)?;

        Ok(())
    }
}

impl Socks5ForwarderSettings {
    /// Create a configuration builder.
    pub fn builder() -> Socks5ForwarderSettingsBuilder {
        Socks5ForwarderSettingsBuilder::new()
    }
}

impl Http1Settings {
    /// Create a configuration builder.
    pub const fn builder() -> Http1SettingsBuilder {
        Http1SettingsBuilder::new()
    }

    /// Return the default `upload_buffer_size` value.
    #[must_use]
    pub const fn default_upload_buffer_size() -> usize {
        32 * 1024
    }
}

impl Http2Settings {
    /// Create a configuration builder.
    pub const fn builder() -> Http2SettingsBuilder {
        Http2SettingsBuilder::new()
    }

    /// Return the default `initial_connection_window_size` value.
    #[must_use]
    pub const fn default_initial_connection_window_size() -> u32 {
        8 * 1024 * 1024
    }

    /// Return the default `initial_stream_window_size` value.
    #[must_use]
    pub const fn default_initial_stream_window_size() -> u32 {
        128 * 1024 // Chrome constant
    }

    /// Return the default `max_concurrent_streams` value.
    #[must_use]
    pub const fn default_max_concurrent_streams() -> u32 {
        1000 // Chrome constant
    }

    /// Return the default `max_frame_size` value.
    #[must_use]
    pub const fn default_max_frame_size() -> u32 {
        1 << 14 // Firefox constant
    }

    /// Return the default `header_table_size` value.
    #[must_use]
    pub const fn default_header_table_size() -> u32 {
        65536
    }
}

impl QuicSettings {
    /// Create a configuration builder.
    pub const fn builder() -> QuicSettingsBuilder {
        QuicSettingsBuilder::new()
    }

    /// Return the default `recv_udp_payload_size` value.
    #[must_use]
    pub const fn default_recv_udp_payload_size() -> usize {
        1350
    }

    /// Return the default `send_udp_payload_size` value.
    #[must_use]
    pub const fn default_send_udp_payload_size() -> usize {
        1350
    }

    /// Return the default `initial_max_data` value.
    #[must_use]
    pub const fn default_initial_max_data() -> u64 {
        100 * 1024 * 1024
    }

    /// Return the default `initial_max_stream_data_bidi_local` value.
    #[must_use]
    pub const fn default_initial_max_stream_data_bidi_local() -> u64 {
        1024 * 1024
    }

    /// Return the default `initial_max_stream_data_bidi_remote` value.
    #[must_use]
    pub const fn default_initial_max_stream_data_bidi_remote() -> u64 {
        1024 * 1024
    }

    /// Return the default `initial_max_stream_data_uni` value.
    #[must_use]
    pub const fn default_initial_max_stream_data_uni() -> u64 {
        1024 * 1024
    }

    /// Return the default `initial_max_streams_bidi` value.
    #[must_use]
    pub const fn default_initial_max_streams_bidi() -> u64 {
        4 * 1024
    }

    /// Return the default `initial_max_streams_uni` value.
    #[must_use]
    pub const fn default_initial_max_streams_uni() -> u64 {
        4 * 1024
    }

    /// Return the default `max_connection_window` value.
    #[must_use]
    pub const fn default_max_connection_window() -> u64 {
        24 * 1024 * 1024
    }

    /// Return the default `max_stream_window` value.
    #[must_use]
    pub const fn default_max_stream_window() -> u64 {
        16 * 1024 * 1024
    }

    /// Return the default `disable_active_migration` value.
    #[must_use]
    pub const fn default_disable_active_migration() -> bool {
        true
    }

    /// Return the default `enable_early_data` value.
    #[must_use]
    pub const fn default_enable_early_data() -> bool {
        true
    }

    /// Return the default `message_queue_capacity` value.
    #[must_use]
    pub const fn default_message_queue_capacity() -> usize {
        4 * 1024
    }
}

impl ReverseProxySettings {
    /// Create a configuration builder.
    pub fn builder() -> ReverseProxySettingsBuilder {
        ReverseProxySettingsBuilder::new()
    }

    /// Validate the origin address and slash-prefixed request path.
    ///
    /// # Errors
    /// Returns an error when the origin port is zero or the request path is invalid.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.server_address.port() == 0 {
            return Err(ValidationError::ReverseProxy(
                "Server address is not set".to_string(),
            ));
        }

        if self.path_mask.is_empty() || !self.path_mask.starts_with('/') {
            return Err(ValidationError::ReverseProxy(format!(
                "Invalid path mask: {}",
                self.path_mask
            )));
        }

        Ok(())
    }
}

impl IcmpSettings {
    /// Create a configuration builder.
    pub fn builder() -> IcmpSettingsBuilder {
        IcmpSettingsBuilder::new()
    }

    /// Return the default `interface_name` value.
    #[must_use]
    pub fn default_interface_name() -> String {
        if cfg!(target_os = "linux") {
            "eth0"
        } else {
            "en0"
        }
        .into()
    }

    /// Return the default `request_timeout` value.
    #[must_use]
    pub const fn default_request_timeout() -> Duration {
        Duration::from_secs(3)
    }

    /// Return the default `message_queue_capacity` value.
    #[must_use]
    pub const fn default_message_queue_capacity() -> usize {
        256
    }
}

impl MetricsSettings {
    /// Create a configuration builder.
    pub fn builder() -> MetricsSettingsBuilder {
        MetricsSettingsBuilder::new()
    }

    /// Return the default `listen_address` value.
    #[must_use]
    pub fn default_listen_address() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 1987).into()
    }

    /// Return the default `request_timeout` value.
    #[must_use]
    pub const fn default_request_timeout() -> Duration {
        Duration::from_secs(3)
    }

    /// Return the default `per_client_metrics` value.
    #[must_use]
    pub const fn default_per_client_metrics() -> bool {
        false
    }
}

impl Default for MetricsSettings {
    fn default() -> Self {
        Self {
            address: Self::default_listen_address(),
            request_timeout: Self::default_request_timeout(),
            per_client_metrics: Self::default_per_client_metrics(),
        }
    }
}

impl SettingsBuilder {
    fn new() -> Self {
        Self {
            settings: Settings {
                listen_address: Settings::default_listen_address(),
                ipv6_available: Settings::default_ipv6_available(),
                allow_private_network_connections:
                    Settings::default_allow_private_network_connections(),
                tls_handshake_timeout: Settings::default_tls_handshake_timeout(),
                client_listener_timeout: Settings::default_client_listener_timeout(),
                connection_establishment_timeout:
                    Settings::default_connection_establishment_timeout(),
                tcp_connections_timeout: Settings::default_tcp_connections_timeout(),
                udp_connections_timeout: Settings::default_udp_connections_timeout(),
                forward_protocol: ForwardProtocolSettings::default(),
                listen_protocols: ListenProtocolSettings::default(),
                clients: Vec::default(),
                reverse_proxy: None,
                subscription: None,
                icmp: None,
                metrics: None,
                rules_engine: Some(rules::RulesEngine::default_allow()),
                main_host_services: MainHostServices {
                    speedtest_enable: Settings::default_speedtest_enable(),
                    ping_enable: Settings::default_ping_enable(),
                },
                ping_path: Settings::default_ping_path(),
                speedtest_path: Settings::default_speedtest_path(),
                default_max_http2_conns_per_client: None,
                default_max_http3_conns_per_client: None,
                auth_failure_status_code: Settings::default_auth_failure_status_code(),
                non_connect_auth_failure_status_code: None,
                built: true,
            },
        }
    }

    /// Finalize [`Settings`]
    ///
    /// # Errors
    /// Returns an error when the endpoint configuration fails validation.
    pub fn build(self) -> Result<Settings, ValidationError> {
        self.settings.validate()?;

        Ok(self.settings)
    }

    /// Set the address to listen on
    ///
    /// # Errors
    /// Returns an error if address resolution fails or yields no addresses.
    pub fn listen_address<A: ToSocketAddrs>(mut self, addr: A) -> io::Result<Self> {
        self.settings.listen_address = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("Address is parsed to empty list"))?;
        Ok(self)
    }

    /// Set the reverse proxy settings.
    /// With this one set up the endpoint does TLS termination on such connections and
    /// translates HTTP/x traffic into HTTP/1.1 protocol towards the server and back
    /// into original HTTP/x towards the client. Like this:
    ///
    /// `(client) TLS(HTTP/x) <--(endpoint)--> (server) HTTP/1.1`
    ///
    /// The translated HTTP/1.1 requests have the custom header `X-Original-Protocol`
    /// appended. For now, its value can be either `HTTP1`, or `HTTP3`.
    /// TLS hosts for the reverse proxy channel are configured through [`TlsHostsSettings`].
    pub fn reverse_proxy(mut self, settings: ReverseProxySettings) -> Self {
        self.settings.reverse_proxy = Some(settings);
        self
    }

    /// Set the subscription endpoint settings.
    pub fn subscription(mut self, settings: SubscriptionSettings) -> Self {
        self.settings.subscription = Some(settings);
        self
    }

    /// Set `IPv6` availability
    pub const fn ipv6_available(mut self, v: bool) -> Self {
        self.settings.ipv6_available = v;
        self
    }

    /// Allow/disallow connections to private network of the endpoint
    pub const fn allow_private_network_connections(mut self, v: bool) -> Self {
        self.settings.allow_private_network_connections = v;
        self
    }

    /// Set timeout of TLS handshake
    pub const fn tls_handshake_timeout(mut self, v: Duration) -> Self {
        self.settings.tls_handshake_timeout = v;
        self
    }

    /// Set timeout of client listener
    pub const fn client_listener_timeout(mut self, v: Duration) -> Self {
        self.settings.client_listener_timeout = v;
        self
    }

    /// Set timeout of outgoing connection establishment.
    /// For example, it is related to client's connection requests.
    pub const fn connection_establishment_timeout(mut self, v: Duration) -> Self {
        self.settings.connection_establishment_timeout = v;
        self
    }

    /// Set timeout of tunneled TCP connections
    pub const fn tcp_connections_timeout(mut self, v: Duration) -> Self {
        self.settings.tcp_connections_timeout = v;
        self
    }

    /// Set timeout of tunneled UDP "connections"
    pub const fn udp_connections_timeout(mut self, v: Duration) -> Self {
        self.settings.udp_connections_timeout = v;
        self
    }

    /// Set the forwarder codec settings
    pub const fn forwarder_settings(mut self, settings: ForwardProtocolSettings) -> Self {
        self.settings.forward_protocol = settings;
        self
    }

    /// Set the listener codec settings
    pub const fn listen_protocols(mut self, settings: ListenProtocolSettings) -> Self {
        self.settings.listen_protocols = settings;
        self
    }

    /// Set the client authenticator
    pub fn clients(mut self, x: Vec<Client>) -> Self {
        self.settings.clients = x;
        self
    }

    /// Set the ICMP forwarder settings
    pub fn icmp(mut self, x: IcmpSettings) -> Self {
        self.settings.icmp = Some(x);
        self
    }

    /// Set the metrics request listener settings
    pub const fn metrics(mut self, x: MetricsSettings) -> Self {
        self.settings.metrics = Some(x);
        self
    }

    /// Set the rules engine for connection filtering
    pub fn rules_engine(mut self, x: rules::RulesEngine) -> Self {
        self.settings.rules_engine = Some(x);
        self
    }

    /// Set whether speedtest is available
    pub const fn speedtest_enable(mut self, x: bool) -> Self {
        self.settings.main_host_services.speedtest_enable = x;
        self
    }

    /// Set the default maximum HTTP/2 connections per client credentials
    pub const fn default_max_http2_conns_per_client(mut self, x: Option<u32>) -> Self {
        self.settings.default_max_http2_conns_per_client = x;
        self
    }

    /// Set the default maximum HTTP/3 connections per client credentials
    pub const fn default_max_http3_conns_per_client(mut self, x: Option<u32>) -> Self {
        self.settings.default_max_http3_conns_per_client = x;
        self
    }

    /// Set the HTTP status code for authentication failures on CONNECT requests (407, 405, 404, or 403)
    pub const fn auth_failure_status_code(mut self, x: u16) -> Self {
        self.settings.auth_failure_status_code = x;
        self
    }

    /// Set the HTTP status code for authentication failures on non-CONNECT requests (407, 405, 404, or 403)
    pub const fn non_connect_auth_failure_status_code(mut self, x: Option<u16>) -> Self {
        self.settings.non_connect_auth_failure_status_code = x;
        self
    }

    /// Set whether ping is available
    pub const fn ping_enable(mut self, x: bool) -> Self {
        self.settings.main_host_services.ping_enable = x;
        self
    }

    /// Set path prefix for ping requests on main hosts
    pub fn ping_path<S: Into<String>>(mut self, path: S) -> Self {
        self.settings.ping_path = Some(path.into());
        self
    }

    /// Set path prefix for speedtest requests on main hosts
    pub fn speedtest_path<S: Into<String>>(mut self, path: S) -> Self {
        self.settings.speedtest_path = Some(path.into());
        self
    }
}

impl TlsSettingsBuilder {
    fn new() -> Self {
        Self {
            settings: TlsHostsSettings {
                main_hosts: Vec::default(),
                ping_hosts: Vec::default(),
                speedtest_hosts: Vec::default(),
                reverse_proxy_hosts: Vec::default(),
                built: true,
            },
        }
    }

    /// Finalize [`TlsHostsSettings`]
    ///
    /// # Errors
    /// Returns an error for missing hosts, duplicate names, or invalid certificate/key files.
    pub fn build(self) -> Result<TlsHostsSettings, ValidationError> {
        self.settings.validate()?;
        Ok(self.settings)
    }

    /// Set the main TLS hosts.
    /// Used for traffic tunneling and service requests handling.
    pub fn main_hosts(mut self, hosts: Vec<TlsHostInfo>) -> Self {
        self.settings.main_hosts = hosts;
        self
    }

    /// Set the TLS hosts for HTTPS pinging.
    /// With this one set up the endpoint responds with `200 OK` to HTTPS `GET` requests
    /// to the specified domains.
    pub fn ping_hosts(mut self, hosts: Vec<TlsHostInfo>) -> Self {
        self.settings.ping_hosts = hosts;
        self
    }

    /// Set the TLS hosts for speed testing.
    /// With this one set up the endpoint accepts connections to the specified hosts and
    /// handles HTTP requests in the following way:
    ///     * `GET` requests with `/Nmb.bin` path (where `N` is 1 to 100, e.g. `/100mb.bin`)
    ///       are considered as download speedtest transferring `N` megabytes to a client
    ///     * `POST` requests with `/upload.html` path and `Content-Length: N`
    ///       are considered as upload speedtest receiving `N` bytes from a client,
    ///       where `N` is up to 120 * 1024 * 1024 bytes
    pub fn speedtest_hosts(mut self, hosts: Vec<TlsHostInfo>) -> Self {
        self.settings.speedtest_hosts = hosts;
        self
    }

    /// The TLS hosts for the connections must be forwarded to the reverse proxy
    /// (see `self::Settings::reverse_proxy`). Only makes sense if the reverse proxy
    /// is set up, otherwise it is ignored.
    pub fn reverse_proxy_hosts(mut self, hosts: Vec<TlsHostInfo>) -> Self {
        self.settings.reverse_proxy_hosts = hosts;
        self
    }
}

impl Socks5ForwarderSettingsBuilder {
    fn new() -> Self {
        Self {
            settings: Socks5ForwarderSettings {
                address: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                extended_auth: false,
            },
        }
    }

    /// Finalize [`Socks5ForwarderSettings`]
    ///
    /// # Errors
    /// Returns an error when the proxy address is unspecified.
    pub const fn build(self) -> Socks5BuilderResult<Socks5ForwarderSettings> {
        if self.settings.address.ip().is_unspecified() {
            return Err(Socks5Error::AddressNotSet);
        }

        Ok(self.settings)
    }

    /// Set the SOCKS proxy address
    ///
    /// # Errors
    /// Returns an error if address resolution fails or yields no addresses.
    pub fn server_address<A: ToSocketAddrs>(mut self, v: A) -> io::Result<Self> {
        self.settings.address = v
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("Address is parsed to empty list"))?;
        Ok(self)
    }

    /// Enable/disable extended authentication.
    /// See README for details.
    pub const fn extended_auth(mut self, v: bool) -> Self {
        self.settings.extended_auth = v;
        self
    }
}

impl Http1SettingsBuilder {
    const fn new() -> Self {
        Self {
            settings: Http1Settings {
                upload_buffer_size: Http1Settings::default_upload_buffer_size(),
            },
        }
    }

    /// Finalize [`Http1Settings`]
    #[must_use]
    pub const fn build(self) -> Http1Settings {
        self.settings
    }
}

impl Http2SettingsBuilder {
    const fn new() -> Self {
        Self {
            settings: Http2Settings {
                initial_connection_window_size:
                    Http2Settings::default_initial_connection_window_size(),
                initial_stream_window_size: Http2Settings::default_initial_stream_window_size(),
                max_concurrent_streams: Http2Settings::default_max_concurrent_streams(),
                max_frame_size: Http2Settings::default_max_frame_size(),
                header_table_size: Http2Settings::default_header_table_size(),
            },
        }
    }

    /// Finalize [`Http2Settings`]
    #[must_use]
    pub const fn build(self) -> Http2Settings {
        self.settings
    }

    /// Set the initial window size (in octets) for connection-level flow control for received data
    pub const fn initial_connection_window_size(mut self, v: u32) -> Self {
        self.settings.initial_connection_window_size = v;
        self
    }

    /// Set the initial window size (in octets) for stream-level flow control for received data
    pub const fn initial_stream_window_size(mut self, v: u32) -> Self {
        self.settings.initial_stream_window_size = v;
        self
    }

    /// Set the maximum number of concurrent streams
    pub const fn max_concurrent_streams(mut self, v: u32) -> Self {
        self.settings.max_concurrent_streams = v;
        self
    }

    /// Set the size (in octets) of the largest HTTP/2 frame payload that we are able to accept
    pub const fn max_frame_size(mut self, v: u32) -> Self {
        self.settings.max_frame_size = v;
        self
    }

    /// Set the max size of received header frames
    pub const fn header_table_size(mut self, v: u32) -> Self {
        self.settings.header_table_size = v;
        self
    }
}

impl QuicSettingsBuilder {
    const fn new() -> Self {
        Self {
            settings: QuicSettings {
                recv_udp_payload_size: QuicSettings::default_recv_udp_payload_size(),
                send_udp_payload_size: QuicSettings::default_send_udp_payload_size(),
                initial_max_data: QuicSettings::default_initial_max_data(),
                initial_max_stream_data_bidi_local:
                    QuicSettings::default_initial_max_stream_data_bidi_local(),
                initial_max_stream_data_bidi_remote:
                    QuicSettings::default_initial_max_stream_data_bidi_remote(),
                initial_max_stream_data_uni: QuicSettings::default_initial_max_stream_data_uni(),
                initial_max_streams_bidi: QuicSettings::default_initial_max_streams_bidi(),
                initial_max_streams_uni: QuicSettings::default_initial_max_streams_uni(),
                max_connection_window: QuicSettings::default_max_connection_window(),
                max_stream_window: QuicSettings::default_max_stream_window(),
                disable_active_migration: QuicSettings::default_disable_active_migration(),
                enable_early_data: QuicSettings::default_enable_early_data(),
                message_queue_capacity: QuicSettings::default_message_queue_capacity(),
            },
        }
    }

    /// Finalize [`QuicSettings`]
    #[must_use]
    pub const fn build(self) -> QuicSettings {
        self.settings
    }

    /// Set the `max_udp_payload_size transport` parameter
    pub const fn recv_udp_payload_size(mut self, v: usize) -> Self {
        self.settings.recv_udp_payload_size = v;
        self
    }

    /// Set the maximum outgoing UDP payload size
    pub const fn send_udp_payload_size(mut self, v: usize) -> Self {
        self.settings.send_udp_payload_size = v;
        self
    }

    /// Set the `initial_max_data` transport parameter
    pub const fn initial_max_data(mut self, v: u64) -> Self {
        self.settings.initial_max_data = v;
        self
    }

    /// Set the `initial_max_stream_data_bidi_local` transport parameter
    pub const fn max_stream_data_bidi_local(mut self, v: u64) -> Self {
        self.settings.initial_max_stream_data_bidi_local = v;
        self
    }

    /// Set the `initial_max_stream_data_bidi_remote` transport parameter
    pub const fn max_stream_data_bidi_remote(mut self, v: u64) -> Self {
        self.settings.initial_max_stream_data_bidi_remote = v;
        self
    }

    /// Set the `initial_max_stream_data_uni` transport parameter
    pub const fn max_stream_data_uni(mut self, v: u64) -> Self {
        self.settings.initial_max_stream_data_uni = v;
        self
    }

    /// Set the `initial_max_streams_bidi` transport parameter
    pub const fn max_streams_bidi(mut self, v: u64) -> Self {
        self.settings.initial_max_streams_bidi = v;
        self
    }

    /// Set the `initial_max_streams_uni` transport parameter
    pub const fn max_streams_uni(mut self, v: u64) -> Self {
        self.settings.initial_max_streams_uni = v;
        self
    }

    /// Set the maximum size of the connection window
    pub const fn max_connection_window(mut self, v: u64) -> Self {
        self.settings.max_connection_window = v;
        self
    }

    /// Set the maximum size of the stream window
    pub const fn max_stream_window(mut self, v: u64) -> Self {
        self.settings.max_stream_window = v;
        self
    }

    /// Set the `disable_active_migration` transport parameter
    pub const fn disable_active_migration(mut self, v: bool) -> Self {
        self.settings.disable_active_migration = v;
        self
    }

    /// Enable receiving early data
    pub const fn enable_early_data(mut self, v: bool) -> Self {
        self.settings.enable_early_data = v;
        self
    }

    /// Set the capacity of the QUIC multiplexer message queue
    pub const fn message_queue_capacity(mut self, v: usize) -> Self {
        self.settings.message_queue_capacity = v;
        self
    }
}

impl ReverseProxySettingsBuilder {
    fn new() -> Self {
        Self {
            settings: ReverseProxySettings {
                server_address: (Ipv4Addr::UNSPECIFIED, 0).into(),
                path_mask: String::default(),
                h3_backward_compatibility: false,
            },
        }
    }

    /// Finalize [`ReverseProxySettings`]
    ///
    /// # Errors
    /// Returns an error when the proxy address or request path is invalid.
    pub fn build(self) -> Result<ReverseProxySettings, ValidationError> {
        self.settings.validate()?;
        Ok(self.settings)
    }

    /// Set the proxy server address
    ///
    /// # Errors
    /// Returns an error if address resolution fails or yields no addresses.
    pub fn server_address<A: ToSocketAddrs>(mut self, v: A) -> io::Result<Self> {
        self.settings.server_address = v
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("Address is parsed to empty list"))?;
        Ok(self)
    }

    /// Connections to [the main hosts](TlsHostsSettings::get_main_hosts) with
    /// paths starting with this mask are routed to the reverse proxy server.
    /// MUST start with slash.
    pub fn path_mask(mut self, v: String) -> Self {
        self.settings.path_mask = v;
        self
    }

    /// With this one set to `true` the endpoint overrides the HTTP method while
    /// translating an HTTP3 request to HTTP1 in case the request has the `GET` method
    /// and its path is `/` or matches `ReverseProxySettings::path_mask`
    pub const fn h3_backward_compatibility(mut self, v: bool) -> Self {
        self.settings.h3_backward_compatibility = v;
        self
    }
}

impl IcmpSettingsBuilder {
    fn new() -> Self {
        Self {
            settings: IcmpSettings {
                interface_name: String::default(),
                request_timeout: IcmpSettings::default_request_timeout(),
                recv_message_queue_capacity: IcmpSettings::default_message_queue_capacity(),
            },
        }
    }

    /// Set the interface name to bind the socket to
    pub fn interface_name<S: Into<String>>(mut self, v: S) -> Self {
        self.settings.interface_name = v.into();
        self
    }

    /// Set the ICMP request timeout
    pub const fn request_timeout(mut self, v: Duration) -> Self {
        self.settings.request_timeout = v;
        self
    }

    /// Set the capacity of the ICMP multiplexer received messages queue
    pub const fn recv_message_queue_capacity(mut self, v: usize) -> Self {
        self.settings.recv_message_queue_capacity = v;
        self
    }

    /// Finalize [`IcmpSettings`]
    ///
    /// # Errors
    /// This builder currently performs no fallible validation.
    pub fn build(self) -> Result<IcmpSettings, ValidationError> {
        Ok(self.settings)
    }
}

impl MetricsSettingsBuilder {
    fn new() -> Self {
        Self {
            settings: MetricsSettings::default(),
        }
    }

    /// Set the address to listen on for settings export requests
    ///
    /// # Errors
    /// Returns an error if address resolution fails or yields no addresses.
    pub fn listen_address<A: ToSocketAddrs>(mut self, addr: A) -> io::Result<Self> {
        self.settings.address = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("Address is parsed to empty list"))?;
        Ok(self)
    }

    /// Set the metrics request timeout
    pub const fn request_timeout(mut self, v: Duration) -> Self {
        self.settings.request_timeout = v;
        self
    }

    /// Enable or disable per-client metrics labeled with the client username
    pub const fn per_client_metrics(mut self, v: bool) -> Self {
        self.settings.per_client_metrics = v;
        self
    }

    /// Finalize [`MetricsSettings`]
    ///
    /// # Errors
    /// This builder currently performs no fallible validation.
    pub const fn build(self) -> Result<MetricsSettings, ValidationError> {
        Ok(self.settings)
    }
}

impl Default for ForwardProtocolSettings {
    fn default() -> Self {
        Self::Direct(DirectForwarderSettings {})
    }
}

fn validate_file_path(path: &str) -> io::Result<()> {
    match std::fs::metadata(Path::new(path))? {
        m if m.is_file() => Ok(()),
        _ => Err(io::Error::other("Not a file")),
    }
}

fn deserialize_duration_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "an unsigned integer")
        }

        // toml parser library converts unsigned integers to signed
        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            (v >= 0)
                .then_some(v as u64)
                .ok_or_else(|| E::invalid_type(serde::de::Unexpected::Signed(v), &Self {}))
        }
    }

    let x = deserializer.deserialize_u64(Visitor)?;
    Ok(Duration::from_secs(x))
}

fn serialize_duration_secs<S>(x: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    serializer.serialize_u64(x.as_secs())
}

fn deserialize_file_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
        type Value = String;

        fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a path to an existent accessible file")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            validate_file_path(v).map(|()| v.to_string()).map_err(|e| {
                E::invalid_value(
                    serde::de::Unexpected::Other(&format!("path={v} error={e}")),
                    &Self {},
                )
            })
        }
    }

    deserializer.deserialize_str(Visitor)
}

fn deserialize_clients<'de, D>(deserializer: D) -> Result<Vec<Client>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let path = deserialize_file_path(deserializer)?;

    let content = std::fs::read_to_string(&path).map_err(|e| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Other(&format!("Couldn't read file: path={path} error={e}")),
            &"A readable file",
        )
    })?;

    let clients: Document = content.parse().map_err(|e| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Other(&format!("Couldn't parse file: path={path} error={e}")),
            &"A TOML-formatted file",
        )
    })?;

    let res: Vec<Client> = clients
        .get("client")
        .and_then(Item::as_array_of_tables)
        .ok_or_else(|| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Other("Not an array of clients"),
                &"An array of clients",
            )
        })?
        .iter()
        .enumerate()
        .map(|(idx, x)| {
            let username = demangle_toml_string(
                &x.get("username")
                    .map_or_else(String::new, ToString::to_string),
            );
            let password = demangle_toml_string(
                &x.get("password")
                    .map_or_else(String::new, ToString::to_string),
            );

            if username.is_empty() {
                return Err(serde::de::Error::custom(format!(
                    "Client #{}: username cannot be empty",
                    idx + 1
                )));
            }
            if password.is_empty() {
                return Err(serde::de::Error::custom(format!(
                    "Client #{}: password cannot be empty",
                    idx + 1
                )));
            }

            let max_http2_conns = x
                .get("max_http2_conns")
                .and_then(Item::as_integer)
                .and_then(|v| u32::try_from(v).ok());
            let max_http3_conns = x
                .get("max_http3_conns")
                .and_then(Item::as_integer)
                .and_then(|v| u32::try_from(v).ok());

            Ok(Client {
                username,
                password,
                max_http2_conns,
                max_http3_conns,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(res)
}

fn deserialize_rules<'de, D>(deserializer: D) -> Result<Option<rules::RulesEngine>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    RulesFile::deserialize(deserializer).map(|file| Some(file.0))
}

struct RulesFile(rules::RulesEngine);

impl<'de> Deserialize<'de> for RulesFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let Ok(path) = deserialize_file_path(deserializer) else {
            // No rules file specified, default to allow all
            return Ok(Self(rules::RulesEngine::default_allow()));
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) => {
                // Log warning but don't fail - default to allow all
                log::warn!(
                "Warning: Could not read rules file '{path}': {e}. Defaulting to allow all connections.");
                return Ok(Self(rules::RulesEngine::default_allow()));
            }
        };

        let rules_doc: Document = match content.parse() {
            Ok(doc) => doc,
            Err(e) => {
                log::warn!("Warning: Could not parse rules file '{path}': {e}. Defaulting to allow all connections.");
                return Ok(Self(rules::RulesEngine::default_allow()));
            }
        };

        let rules_config = rules_doc
            .get("rule")
            .and_then(Item::as_array_of_tables)
            .map_or_else(rules::RulesConfig::default, |rules_array| {
                let rules: Vec<rules::Rule> = rules_array
                    .iter()
                    .filter_map(|rule_table| {
                        let cidr = rule_table
                            .get("cidr")
                            .and_then(Item::as_str)
                            .map(str::to_owned);

                        let client_random_prefix = rule_table
                            .get("client_random_prefix")
                            .and_then(Item::as_str)
                            .map(str::to_owned);

                        let client_random_auth_key = rule_table
                            .get("client_random_auth_key")
                            .and_then(Item::as_str)
                            .map(str::to_owned);

                        let action = rule_table.get("action").and_then(Item::as_str).and_then(
                            |s| match s {
                                "allow" => Some(rules::RuleAction::Allow),
                                "deny" => Some(rules::RuleAction::Deny),
                                _ => None,
                            },
                        )?;

                        Some(rules::Rule {
                            cidr,
                            client_random_prefix,
                            client_random_auth_key,
                            action,
                        })
                    })
                    .collect();

                rules::RulesConfig { rule: rules }
            });

        Ok(Self(rules::RulesEngine::from_config(rules_config)))
    }
}

fn demangle_toml_string(x: &str) -> String {
    x.replace('"', "").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "rt_doc")]
    #[test]
    fn service_docs_preserve_generated_config_comments() {
        assert_eq!(
            Settings::doc_ipv6_available(),
            "Whether IPv6 connections can be routed or rejected with unreachable status"
        );
        assert_eq!(
            Settings::doc_ping_enable(),
            "Whether ping is available on the main hosts."
        );
        assert_eq!(
            Settings::doc_speedtest_enable(),
            "Whether speedtest is available on the main hosts."
        );
    }

    #[test]
    fn main_host_services_preserve_flat_config_keys() -> Result<(), Box<dyn std::error::Error>> {
        for ping in [false, true] {
            for speedtest in [false, true] {
                let input = format!(
                    "ping_enable = {ping}\nspeedtest_enable = {speedtest}\n[listen_protocols]\n"
                );
                let settings: Settings = toml::from_str(&input)?;
                if (
                    *settings.get_ping_enable(),
                    *settings.get_speedtest_enable(),
                ) != (ping, speedtest)
                {
                    return Err("flat TOML service switches changed meaning".into());
                }
                let serialized = serde_json::to_value(&settings)?;
                if serialized["ping_enable"].as_bool() != Some(ping)
                    || serialized["speedtest_enable"].as_bool() != Some(speedtest)
                    || serialized.get("main_host_services").is_some()
                {
                    return Err("service switches no longer serialize as flat config keys".into());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn deserialized_defaults_match_builder_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let parsed: Settings = toml::from_str("[listen_protocols]\n")?;
        let built = SettingsBuilder::new().settings;
        if parsed.ipv6_available != built.ipv6_available
            || parsed.allow_private_network_connections != built.allow_private_network_connections
            || parsed.get_ping_enable() != built.get_ping_enable()
            || parsed.get_speedtest_enable() != built.get_speedtest_enable()
            || parsed.ping_path != built.ping_path
            || parsed.speedtest_path != built.speedtest_path
            || parsed.client_listener_timeout != built.client_listener_timeout
            || parsed.tcp_connections_timeout != built.tcp_connections_timeout
        {
            return Err("deserialized defaults diverged from builder defaults".into());
        }
        if !parsed.ipv6_available
            || parsed.allow_private_network_connections
            || *parsed.get_ping_enable()
            || *parsed.get_speedtest_enable()
            || parsed.ping_path.as_deref() != Some("/ping")
            || parsed.speedtest_path.as_deref() != Some("/speedtest")
            || parsed.client_listener_timeout.as_secs() != 600
            || parsed.tcp_connections_timeout.as_secs() != 604_800
        {
            return Err("network, service, or timeout defaults changed".into());
        }
        Ok(())
    }

    #[test]
    fn rules_file_deserialization_preserves_rules_and_fallbacks(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;

        for (contents, expected) in [
            ("[[rule]]\naction = \"deny\"\n", rules::RuleEvaluation::Deny),
            ("not valid TOML [", rules::RuleEvaluation::Allow),
            ("unrelated = true\n", rules::RuleEvaluation::Allow),
        ] {
            let mut file = tempfile::NamedTempFile::new()?;
            file.write_all(contents.as_bytes())?;
            file.flush()?;
            let path = file.path().to_str().ok_or("non-UTF-8 rules path")?;
            let input = format!("rules_file = {path:?}\n[listen_protocols]\n");
            let settings: Settings = toml::from_str(&input)?;
            let engine = settings.rules_engine.ok_or("rules engine is absent")?;
            if engine.evaluate(&Ipv4Addr::LOCALHOST.into(), None, None) != expected {
                return Err(format!("rules-file handling changed for {contents:?}").into());
            }
        }
        let missing = tempfile::tempdir()?.path().join("missing.toml");
        let path = missing.to_str().ok_or("non-UTF-8 missing rules path")?;
        for value in [format!("{path:?}"), "false".to_owned()] {
            let input = format!("rules_file = {value}\n[listen_protocols]\n");
            let settings: Settings = toml::from_str(&input)?;
            let engine = settings
                .rules_engine
                .ok_or("default rules engine is absent")?;
            if engine.evaluate(&Ipv4Addr::LOCALHOST.into(), None, None)
                != rules::RuleEvaluation::Allow
            {
                return Err("invalid rules-file input changed the existing allow fallback".into());
            }
        }
        Ok(())
    }

    #[test]
    fn default_auth_failure_status_code_is_407() {
        let settings = Settings::default();
        assert_eq!(settings.auth_failure_status_code, 407);
    }

    #[test]
    fn auth_failure_status_code_407_valid() {
        let settings = Settings {
            auth_failure_status_code: 407,
            listen_address: (Ipv4Addr::LOCALHOST, 8443).into(),
            ..Settings::default()
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn auth_failure_status_code_405_valid() {
        let settings = Settings {
            auth_failure_status_code: 405,
            listen_address: (Ipv4Addr::LOCALHOST, 8443).into(),
            ..Settings::default()
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn auth_failure_status_code_404_valid() {
        let settings = Settings {
            auth_failure_status_code: 404,
            listen_address: (Ipv4Addr::LOCALHOST, 8443).into(),
            ..Settings::default()
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn auth_failure_status_code_403_valid() {
        let settings = Settings {
            auth_failure_status_code: 403,
            listen_address: (Ipv4Addr::LOCALHOST, 8443).into(),
            ..Settings::default()
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn auth_failure_status_code_200_invalid() {
        let settings = Settings {
            auth_failure_status_code: 200,
            listen_address: (Ipv4Addr::LOCALHOST, 8443).into(),
            ..Settings::default()
        };
        let err = settings.validate();
        assert!(matches!(
            err,
            Err(ValidationError::InvalidAuthFailureStatusCode(200))
        ));
    }

    #[test]
    fn non_connect_auth_failure_status_code_none_valid() {
        let settings = Settings {
            non_connect_auth_failure_status_code: None,
            listen_address: (Ipv4Addr::LOCALHOST, 8443).into(),
            ..Settings::default()
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn non_connect_auth_failure_status_code_404_valid() {
        let settings = Settings {
            non_connect_auth_failure_status_code: Some(404),
            listen_address: (Ipv4Addr::LOCALHOST, 8443).into(),
            ..Settings::default()
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn non_connect_auth_failure_status_code_200_invalid() {
        let settings = Settings {
            non_connect_auth_failure_status_code: Some(200),
            listen_address: (Ipv4Addr::LOCALHOST, 8443).into(),
            ..Settings::default()
        };
        let err = settings.validate();
        assert!(matches!(
            err,
            Err(ValidationError::InvalidAuthFailureStatusCode(200))
        ));
    }

    #[test]
    fn missing_credential_fields_return_validation_errors() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::io::Write;
        for (credentials, expected) in [
            (r#"password = "p""#, "username cannot be empty"),
            (r#"username = "u""#, "password cannot be empty"),
        ] {
            let mut file = tempfile::NamedTempFile::new()?;
            writeln!(file, "[[client]]\n{credentials}")?;
            let path = file.path().to_str().ok_or("non-UTF-8 credentials path")?;
            let input = format!("credentials_file = {path:?}\n[listen_protocols]\n");
            let parsed = toml::from_str::<Settings>(&input);
            if !parsed.is_err_and(|error| error.to_string().contains(expected)) {
                return Err(format!("missing credential field did not report {expected}").into());
            }
        }
        Ok(())
    }
}
