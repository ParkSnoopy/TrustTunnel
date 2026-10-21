use crate::user_interaction::{
    ask_for_agreement, ask_for_input, ask_for_password, checked_overwrite, select_variant,
};
use crate::{Mode, WizardResult};
use std::fs;
use std::io::{self, Write};
use toml_edit::{ArrayOfTables, Item, Key, Table};
use trusttunnel::authentication::registry_based::Client;
use trusttunnel::settings::{
    Http1Settings, Http2Settings, ListenProtocolSettings, QuicSettings, Settings,
};

pub const DEFAULT_CREDENTIALS_PATH: &str = "credentials.toml";
pub const DEFAULT_RULES_PATH: &str = "rules.toml";

pub struct Built {
    pub settings: Settings,
    pub credentials_path: String,
    pub rules_path: String,
}

pub fn build() -> WizardResult<Built> {
    let builder = Settings::builder().listen_address(
        crate::get_predefined_params()
            .listen_address
            .clone()
            .map_or_else(
                || {
                    ask_for_input(
                        &format!(
                            "{} (native: 0.0.0.0:443; Docker with 443:8443 mapping: 0.0.0.0:8443)",
                            Settings::doc_listen_address()
                        ),
                        Some(Settings::default_listen_address().to_string()),
                    )
                },
                Ok,
            )?,
    )?;

    // Collect credentials first, then build settings
    let (credentials_path, clients) = build_credentials()?;

    Ok(Built {
        settings: builder
            .listen_protocols(ListenProtocolSettings {
                http1: Some(Http1Settings::builder().build()),
                http2: Some(Http2Settings::builder().build()),
                quic: Some(QuicSettings::builder().build()),
            })
            .clients(clients)
            .build()
            .map_err(|error| {
                io::Error::other(format!("Couldn't build the library settings: {error:?}"))
            })?,
        credentials_path,
        rules_path: build_rules()?,
    })
}

fn build_credentials() -> WizardResult<(String, Vec<Client>)> {
    if crate::get_mode() != Mode::NonInteractive
        && check_file_exists(".", DEFAULT_CREDENTIALS_PATH)
        && ask_for_agreement(&format!(
            "Reuse the existing credentials file: {DEFAULT_CREDENTIALS_PATH}?"
        ))?
    {
        let clients = read_credentials_file(DEFAULT_CREDENTIALS_PATH)?;
        return Ok((DEFAULT_CREDENTIALS_PATH.into(), clients));
    }

    let path = ask_for_input::<String>(
        "Path to the credentials file",
        Some(DEFAULT_CREDENTIALS_PATH.into()),
    )?;

    let users = build_user_list()?;

    if checked_overwrite(&path, "Overwrite the existing credentials file?")? {
        fs::write(&path, compose_credentials_content(&users))?;
        writeln!(
            io::stdout().lock(),
            "The user credentials are written to the file: {path}"
        )?;
    }

    let clients = users
        .into_iter()
        .map(|(username, password)| Client {
            username,
            password,
            max_http2_conns: None,
            max_http3_conns: None,
        })
        .collect();

    Ok((path, clients))
}

fn read_credentials_file(path: &str) -> WizardResult<Vec<Client>> {
    Ok(parse_credentials_content(&fs::read_to_string(path)?)?)
}

fn parse_credentials_content(content: &str) -> Result<Vec<Client>, toml::de::Error> {
    #[derive(serde::Deserialize)]
    struct Credentials {
        client: Vec<Client>,
    }
    toml::from_str::<Credentials>(content).map(|credentials| credentials.client)
}

fn build_rules() -> WizardResult<String> {
    if crate::get_mode() != Mode::NonInteractive
        && check_file_exists(".", DEFAULT_RULES_PATH)
        && ask_for_agreement(&format!(
            "Reuse the existing rules file: {DEFAULT_RULES_PATH}?"
        ))?
    {
        Ok(DEFAULT_RULES_PATH.into())
    } else {
        let path =
            ask_for_input::<String>("Path to the rules file", Some(DEFAULT_RULES_PATH.into()))?;

        if checked_overwrite(&path, "Overwrite the existing rules file?")? {
            writeln!(
                io::stdout().lock(),
                "Let's create connection filtering rules"
            )?;
            let rules_config = crate::rules_settings::build()?;
            let rules_content = generate_rules_toml_content(&rules_config)?;
            fs::write(&path, rules_content)?;
            writeln!(
                io::stdout().lock(),
                "The rules configuration is written to the file: {path}"
            )?;
        }

        Ok(path)
    }
}

fn build_user_list() -> io::Result<Vec<(String, String)>> {
    if let Some(x) = crate::get_predefined_params().credentials.clone() {
        return Ok(vec![x]);
    }

    let mut list = vec![(
        ask_for_input::<String>("Username", None)?,
        ask_for_password("Password")?,
    )];

    loop {
        if "no" == select_variant("Add one more user?", &["yes", "no"], Some(1))? {
            break;
        }

        list.push((
            ask_for_input::<String>("Username", None)?,
            ask_for_password("Password")?,
        ));
    }

    Ok(list)
}

fn compose_credentials_content(clients: &[(String, String)]) -> String {
    let mut doc = toml_edit::Document::new();

    let x = clients
        .iter()
        .map(|(u, p)| {
            Table::from_iter(
                std::iter::once(("username", u.as_str()))
                    .chain(std::iter::once(("password", p.as_str()))),
            )
        })
        .collect::<ArrayOfTables>();

    doc.insert_formatted(&Key::new("client"), Item::ArrayOfTables(x));

    doc.to_string()
}

fn generate_rules_toml_content(
    rules_config: &trusttunnel::rules::RulesConfig,
) -> WizardResult<String> {
    let mut content = String::new();

    // Add header comments explaining the format
    content.push_str("# Rules configuration for VPN endpoint connection filtering\n");
    content.push_str("# \n");
    content.push_str("# This file defines filter rules for incoming connections.\n");
    content.push_str(
        "# Rules are evaluated in order, and the first matching rule's action is applied.\n",
    );
    content.push_str("# If no rules match, the connection is allowed by default.\n");
    content.push_str("#\n");
    content.push_str("# Each rule can specify:\n");
    content.push_str("# - cidr: IP address range in CIDR notation\n");
    content.push_str("# - client_random_prefix: Hex-encoded prefix of TLS client random data\n");
    content.push_str(
        "#   Can optionally include a mask in format \"prefix[/mask]\" for bitwise matching\n",
    );
    content.push_str(
        "# - client_random_auth_key: Hex-encoded auth key, 16 bytes (32 hex chars) or longer\n",
    );
    content.push_str(
        "#   Matches clients whose TLS client random is derived from this key and the SNI\n",
    );
    content.push_str("#   Mutually exclusive with client_random_prefix (the key takes priority)\n");
    content.push_str("# - action: \"allow\" or \"deny\"\n");
    content.push_str("#\n");
    content.push_str("# All fields except 'action' are optional - if specified, all conditions must match for the rule to apply.\n");
    content.push_str("#\n");
    content.push_str("# client_random_prefix formats:\n");
    content.push_str("# 1. Simple prefix matching:\n");
    content.push_str("#    client_random_prefix = \"aabbcc\"\n");
    content.push_str("#    → matches client_random starting with 0xaabbcc\n");
    content.push_str("#\n");
    content.push_str("# 2. Bitwise matching with mask:\n");
    content.push_str("#    client_random_prefix = \"a0b0/f0f0\"\n");
    content.push_str("#    → prefix=a0b0, mask=f0f0\n");
    content.push_str(
        "#    → matches client_random where (client_random & 0xf0f0) == (0xa0b0 & 0xf0f0)\n",
    );
    content.push_str("#    → e.g., 0xa5b5, 0xa9bf match, but 0xb0b0, 0xa0c0 don't match\n\n");

    // Serialize the actual rules (usually empty)
    if !rules_config.rule.is_empty() {
        content.push_str(&toml::ser::to_string(rules_config)?);
        content.push('\n');
    }

    Ok(content)
}

fn check_file_exists(path: &str, name: &str) -> bool {
    fs::read_dir(path).is_ok_and(|x| {
        x.filter_map(Result::ok)
            .filter(|entry| entry.metadata().is_ok_and(|meta| meta.is_file()))
            .any(|entry| entry.file_name() == name)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        compose_credentials_content, generate_rules_toml_content, parse_credentials_content,
    };
    use crate::WizardResult;
    use trusttunnel::rules::{Rule, RuleAction, RulesConfig};

    #[test]
    fn credentials_round_trip_quoted_and_multiline_values() -> WizardResult<()> {
        let clients = vec![("ali\"ce".to_owned(), "secret:\nwith\\escapes".to_owned())];
        let content = compose_credentials_content(&clients);
        let parsed = parse_credentials_content(&content)?;
        check_eq!(parsed.len(), clients.len());
        for (parsed, (username, password)) in parsed.iter().zip(&clients) {
            check_eq!(&parsed.username, username);
            check_eq!(&parsed.password, password);
        }
        Ok(())
    }

    #[test]
    fn credentials_reject_invalid_entries_and_connection_limits() {
        for content in [
            "[[client]]\nusername = 'alice'",
            "[[client]]\nusername = 'alice'\npassword = 'secret'\nmax_http2_conns = -1",
            "[[client]]\nusername = 'alice'\npassword = 'secret'\nmax_http3_conns = 4294967296",
        ] {
            assert!(parse_credentials_content(content).is_err());
        }
    }

    #[test]
    fn rules_document_preserves_comments_and_filter_fields() -> WizardResult<()> {
        let config = RulesConfig {
            rule: vec![Rule {
                cidr: Some("192.0.2.0/24".to_owned()),
                client_random_prefix: Some("a0b0/f0f0".to_owned()),
                client_random_auth_key: None,
                action: RuleAction::Deny,
            }],
        };
        let content = generate_rules_toml_content(&config)?;
        check!(content.starts_with("# Rules configuration for VPN endpoint connection filtering\n"));
        let parsed: RulesConfig = toml::from_str(&content)?;
        check_eq!(parsed.rule.len(), config.rule.len());
        for (parsed, expected) in parsed.rule.iter().zip(&config.rule) {
            check_eq!(parsed.cidr, expected.cidr);
            check_eq!(parsed.client_random_prefix, expected.client_random_prefix);
            check_eq!(
                parsed.client_random_auth_key,
                expected.client_random_auth_key
            );
            check!(matches!(parsed.action, RuleAction::Deny));
        }
        Ok(())
    }
}
