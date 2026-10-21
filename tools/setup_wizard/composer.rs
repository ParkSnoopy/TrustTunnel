use crate::template_settings;
use crate::WizardResult;
use std::io;
use std::iter::once;
use toml_edit::{value, Document};
use trusttunnel::settings::{
    ForwardProtocolSettings, Http1Settings, Http2Settings, IcmpSettings, ListenProtocolSettings,
    MetricsSettings, QuicSettings, Settings,
};
use trusttunnel::utils::{IterJoin, ToTomlComment};

pub fn compose_document(
    settings: &Settings,
    credentials_path: &str,
    rules_path: &str,
) -> WizardResult<String> {
    Ok(
        once(compose_main_table(settings, credentials_path, rules_path)?)
            .chain(once(compose_forward_protocol_table(
                settings.get_forward_protocol(),
            )?))
            .chain(once(compose_listener_protocol_table(
                settings.get_listen_protocols(),
            )?))
            .chain(once(compose_icmp_table(settings.get_icmp().as_ref())?))
            .chain(once(compose_metrics_table(
                settings.get_metrics().as_ref(),
            )?))
            .join("\n"),
    )
}

fn compose_main_table(
    settings: &Settings,
    credentials_path: &str,
    rules_path: &str,
) -> WizardResult<String> {
    let mut doc: Document = template_settings::MAIN_TABLE.parse()?;

    doc["listen_address"] = value(settings.get_listen_address().to_string());
    doc["credentials_file"] = value(credentials_path);
    doc["rules_file"] = value(rules_path);
    doc["ipv6_available"] = value(*settings.get_ipv6_available());
    doc["allow_private_network_connections"] =
        value(*settings.get_allow_private_network_connections());
    doc["tls_handshake_timeout_secs"] =
        value(settings.get_tls_handshake_timeout().as_secs() as i64);
    doc["client_listener_timeout_secs"] =
        value(settings.get_client_listener_timeout().as_secs() as i64);
    doc["connection_establishment_timeout_secs"] =
        value(settings.get_connection_establishment_timeout().as_secs() as i64);
    doc["tcp_connections_timeout_secs"] =
        value(settings.get_tcp_connections_timeout().as_secs() as i64);
    doc["udp_connections_timeout_secs"] =
        value(settings.get_udp_connections_timeout().as_secs() as i64);
    doc["speedtest_enable"] = value(*settings.get_speedtest_enable());
    if let Some(path) = settings.get_speedtest_path().as_ref() {
        doc["speedtest_path"] = value(path.clone());
    } else {
        doc.remove("speedtest_path");
    }
    doc["ping_enable"] = value(*settings.get_ping_enable());
    if let Some(path) = settings.get_ping_path().as_ref() {
        doc["ping_path"] = value(path.clone());
    } else {
        doc.remove("ping_path");
    }
    doc["auth_failure_status_code"] = value(i64::from(*settings.get_auth_failure_status_code()));

    Ok(doc.to_string())
}

fn compose_forward_protocol_table(settings: &ForwardProtocolSettings) -> WizardResult<String> {
    let spec = match settings {
        ForwardProtocolSettings::Direct(_) => template_settings::DIRECT_FORWARDER_TABLE.clone(),
        ForwardProtocolSettings::Socks5(x) => {
            let mut doc: Document = template_settings::SOCKS_FORWARDER_TABLE.parse()?;
            let table = doc["forward_protocol"]["socks5"]
                .as_table_mut()
                .ok_or_else(|| io::Error::other("Missing SOCKS5 forwarder table"))?;
            table["address"] = value(x.get_address().to_string());
            table["extended_auth"] = value(*x.get_extended_auth());
            doc.to_string()
        }
    };

    Ok(format!(
        "{}\n{spec}",
        *template_settings::FORWARD_PROTOCOL_COMMON_TABLE
    ))
}

fn compose_listener_protocol_table(settings: &ListenProtocolSettings) -> WizardResult<String> {
    Ok(once(template_settings::LISTENER_COMMON_TABLE.clone())
        .chain(once(compose_http1_listener_table(settings.http1.as_ref())?))
        .chain(once(compose_http2_listener_table(settings.http2.as_ref())?))
        .chain(once(compose_quic_listener_table(settings.quic.as_ref())?))
        .join("\n"))
}

fn compose_http1_listener_table(settings: Option<&Http1Settings>) -> WizardResult<String> {
    Ok(match settings {
        Some(x) => {
            let mut doc: Document = template_settings::HTTP1_LISTENER_TABLE.parse()?;
            let table = doc["listen_protocols"]["http1"]
                .as_table_mut()
                .ok_or_else(|| io::Error::other("Missing HTTP/1 listener table"))?;

            table["upload_buffer_size"] = value(*x.get_upload_buffer_size() as i64);

            doc.to_string()
        }
        None => template_settings::HTTP1_LISTENER_TABLE.to_toml_comment(),
    })
}

fn compose_http2_listener_table(settings: Option<&Http2Settings>) -> WizardResult<String> {
    Ok(match settings {
        Some(x) => {
            let mut doc: Document = template_settings::HTTP2_LISTENER_TABLE.parse()?;
            let table = doc["listen_protocols"]["http2"]
                .as_table_mut()
                .ok_or_else(|| io::Error::other("Missing HTTP/2 listener table"))?;

            table["initial_connection_window_size"] =
                value(i64::from(*x.get_initial_connection_window_size()));
            table["initial_stream_window_size"] =
                value(i64::from(*x.get_initial_stream_window_size()));
            table["max_concurrent_streams"] = value(i64::from(*x.get_max_concurrent_streams()));
            table["max_frame_size"] = value(i64::from(*x.get_max_frame_size()));
            table["header_table_size"] = value(i64::from(*x.get_header_table_size()));

            doc.to_string()
        }
        None => template_settings::HTTP2_LISTENER_TABLE.to_toml_comment(),
    })
}

fn compose_quic_listener_table(settings: Option<&QuicSettings>) -> WizardResult<String> {
    Ok(match settings {
        Some(x) => {
            let mut doc: Document = template_settings::QUIC_LISTENER_TABLE.parse()?;
            let table = doc["listen_protocols"]["quic"]
                .as_table_mut()
                .ok_or_else(|| io::Error::other("Missing QUIC listener table"))?;

            table["recv_udp_payload_size"] = value(*x.get_recv_udp_payload_size() as i64);
            table["send_udp_payload_size"] = value(*x.get_send_udp_payload_size() as i64);
            table["initial_max_data"] = value(*x.get_initial_max_data() as i64);
            table["initial_max_stream_data_bidi_local"] =
                value(*x.get_initial_max_stream_data_bidi_local() as i64);
            table["initial_max_stream_data_bidi_remote"] =
                value(*x.get_initial_max_stream_data_bidi_remote() as i64);
            table["initial_max_stream_data_uni"] =
                value(*x.get_initial_max_stream_data_uni() as i64);
            table["initial_max_streams_bidi"] = value(*x.get_initial_max_streams_bidi() as i64);
            table["initial_max_streams_uni"] = value(*x.get_initial_max_streams_uni() as i64);
            table["max_connection_window"] = value(*x.get_max_connection_window() as i64);
            table["max_stream_window"] = value(*x.get_max_stream_window() as i64);
            table["disable_active_migration"] = value(*x.get_disable_active_migration());
            table["enable_early_data"] = value(*x.get_enable_early_data());
            table["message_queue_capacity"] = value(*x.get_message_queue_capacity() as i64);

            doc.to_string()
        }
        None => template_settings::QUIC_LISTENER_TABLE.to_toml_comment(),
    })
}

fn compose_icmp_table(settings: Option<&IcmpSettings>) -> WizardResult<String> {
    Ok(match settings {
        Some(x) => {
            let mut doc: Document = template_settings::ICMP_TABLE.parse()?;
            let table = doc["icmp"]
                .as_table_mut()
                .ok_or_else(|| io::Error::other("Missing ICMP table"))?;

            table["interface_name"] = value(x.get_interface_name());
            table["request_timeout_secs"] = value(x.get_request_timeout().as_secs() as i64);
            table["recv_message_queue_capacity"] =
                value(*x.get_recv_message_queue_capacity() as i64);

            doc.to_string()
        }
        None => template_settings::ICMP_TABLE.to_toml_comment(),
    })
}

fn compose_metrics_table(settings: Option<&MetricsSettings>) -> WizardResult<String> {
    Ok(match settings {
        Some(x) => {
            let mut doc: Document = template_settings::METRICS_TABLE.parse()?;
            let table = doc["metrics"]
                .as_table_mut()
                .ok_or_else(|| io::Error::other("Missing metrics table"))?;

            table["address"] = value(x.get_address().to_string());
            table["request_timeout_secs"] = value(x.get_request_timeout().as_secs() as i64);

            doc.to_string()
        }
        None => template_settings::METRICS_TABLE.to_toml_comment(),
    })
}

#[cfg(test)]
mod tests {
    use super::compose_document;
    use crate::WizardResult;
    use std::io;
    use trusttunnel::settings::{Http1Settings, ListenProtocolSettings, Settings};

    #[test]
    fn generated_document_preserves_paths_protocols_and_optional_sections() -> WizardResult<()> {
        let settings = Settings::builder()
            .listen_address("127.0.0.1:443")?
            .listen_protocols(ListenProtocolSettings {
                http1: Some(Http1Settings::builder().build()),
                http2: None,
                quic: None,
            })
            .ping_path("/custom-ping")
            .speedtest_path("/custom-speedtest")
            .build()
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let credentials = "credentials/ali\"ce.toml";
        let rules = "rules/custom\\rules.toml";
        let content = compose_document(&settings, credentials, rules)?;
        let parsed: toml_edit::Document = content.parse()?;
        check_eq!(parsed["listen_address"].as_str(), Some("127.0.0.1:443"));
        check_eq!(parsed["credentials_file"].as_str(), Some(credentials));
        check_eq!(parsed["rules_file"].as_str(), Some(rules));
        check_eq!(parsed["ping_path"].as_str(), Some("/custom-ping"));
        check_eq!(parsed["speedtest_path"].as_str(), Some("/custom-speedtest"));
        check!(parsed["listen_protocols"]["http1"].is_table());
        check!(parsed["listen_protocols"].get("http2").is_none());
        check!(parsed["listen_protocols"].get("quic").is_none());
        check!(parsed.get("icmp").is_none());
        check!(content.contains("# [listen_protocols.http2]"));
        check!(content.contains("# [listen_protocols.quic]"));
        check!(content.contains("# [icmp]"));
        Ok(())
    }
}
