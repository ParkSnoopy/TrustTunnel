//! Generate endpoint configuration files and provision TLS certificates.

use crate::user_interaction::{ask_for_agreement, ask_for_input, checked_overwrite};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::OnceLock;
use trusttunnel::settings::{Settings, TlsHostsSettings};

#[cfg(test)]
macro_rules! check {
    ($condition:expr $(,)?) => {
        if !$condition {
            return Err(concat!("assertion failed: ", stringify!($condition)).into());
        }
    };
}

#[cfg(test)]
macro_rules! check_eq {
    ($left:expr, $right:expr $(,)?) => {{
        match (&$left, &$right) {
            (actual, expected) => {
                if actual != expected {
                    return Err(
                        format!("assertion failed: left {actual:?}, right {expected:?}").into(),
                    );
                }
            }
        }
    }};
}

mod acme;
mod acme_http_server;
mod composer;
mod library_settings;
mod rules_settings;
mod template_settings;
mod tls_hosts_settings;
mod user_interaction;

const MODE_PARAM_NAME: &str = "mode";
const MODE_NON_INTERACTIVE: &str = "non-interactive";
const LISTEN_ADDRESS_PARAM_NAME: &str = "addr";
const CREDENTIALS_PARAM_NAME: &str = "creds";
const HOSTNAME_PARAM_NAME: &str = "host";
const LIBRARY_SETTINGS_FILE_PARAM_NAME: &str = "lib_settings";
const TLS_HOSTS_SETTINGS_FILE_PARAM_NAME: &str = "hosts_settings";
const CERT_TYPE_PARAM_NAME: &str = "cert_type";
const CERT_CHAIN_PATH_PARAM_NAME: &str = "cert_chain_path";
const CERT_KEY_PATH_PARAM_NAME: &str = "cert_key_path";
const ACME_EMAIL_PARAM_NAME: &str = "acme_email";
const ACME_CHALLENGE_PARAM_NAME: &str = "acme_challenge";
const ACME_STAGING_PARAM_NAME: &str = "acme_staging";

type WizardResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
enum Mode {
    NonInteractive,
    Interactive,
}

static MODE: OnceLock<Mode> = OnceLock::new();

fn get_mode() -> Mode {
    MODE.get().copied().unwrap_or(Mode::Interactive)
}

#[derive(Debug, Default)]
struct PredefinedParameters {
    listen_address: Option<String>,
    credentials: Option<(String, String)>,
    hostname: Option<String>,
    library_settings_file: Option<String>,
    tls_hosts_settings_file: Option<String>,
    cert_type: Option<String>,
    cert_chain_path: Option<String>,
    cert_key_path: Option<String>,
    acme_email: Option<String>,
    acme_challenge: Option<String>,
    acme_staging: bool,
}

static PREDEFINED_PARAMS: OnceLock<PredefinedParameters> = OnceLock::new();

fn get_predefined_params() -> &'static PredefinedParameters {
    PREDEFINED_PARAMS.get_or_init(PredefinedParameters::default)
}

fn command() -> clap::Command {
    clap::Command::new("VPN endpoint setup wizard")
        .about("Generate configuration files for TrustTunnel endpoint")
        .after_help(
            r"EXAMPLES:
    # Interactive setup (recommended for first-time users)
    sudo ./setup_wizard

    # Non-interactive setup (for scripting/CI)
    sudo ./setup_wizard -m non-interactive \
        -a 0.0.0.0:443 \
        -c admin:secretpass \
        -n vpn.example.com \
        --lib-settings vpn.toml \
        --hosts-settings hosts.toml

    # After setup, export client configuration:
    sudo ./trusttunnel_endpoint vpn.toml hosts.toml -c admin -a 203.0.113.1

For detailed configuration options, see:
https://github.com/TrustTunnel/TrustTunnel/blob/master/CONFIGURATION.md
",
        )
        .disable_colored_help(false)
        .args(common_args())
        .args(certificate_args())
}

fn common_args() -> [clap::Arg; 6] {
    [
        clap::Arg::new(MODE_PARAM_NAME)
            .short('m')
            .long("mode")
            .action(clap::ArgAction::Set)
            .value_parser(["interactive", MODE_NON_INTERACTIVE])
            .default_value("interactive")
            .help(
                r"Available wizard running modes:
    * interactive - set up only the essential without deep diving into details
    * non-interactive - prepare the setup without interacting with a user,
                        requires some parameters set up via command-line arguments
",
            ),
        clap::Arg::new(LISTEN_ADDRESS_PARAM_NAME)
            .short('a')
            .long("address")
            .action(clap::ArgAction::Set)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .required_if_eq(MODE_PARAM_NAME, MODE_NON_INTERACTIVE)
            .help(Settings::doc_listen_address()),
        clap::Arg::new(CREDENTIALS_PARAM_NAME)
            .short('c')
            .long("creds")
            .action(clap::ArgAction::Set)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .required_if_eq(MODE_PARAM_NAME, MODE_NON_INTERACTIVE)
            .help(
                r"A user credentials formatted as: <username>:<password>.
Required in non-interactive mode.",
            ),
        clap::Arg::new(HOSTNAME_PARAM_NAME)
            .short('n')
            .long("hostname")
            .action(clap::ArgAction::Set)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .required_if_eq(MODE_PARAM_NAME, MODE_NON_INTERACTIVE)
            .help(
                r"A hostname of the certificate for serving TLS connections.
Required in non-interactive mode.",
            ),
        clap::Arg::new(LIBRARY_SETTINGS_FILE_PARAM_NAME)
            .long("lib-settings")
            .action(clap::ArgAction::Set)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .required_if_eq(MODE_PARAM_NAME, MODE_NON_INTERACTIVE)
            .help("Path to store the library settings file. Required in non-interactive mode."),
        clap::Arg::new(TLS_HOSTS_SETTINGS_FILE_PARAM_NAME)
            .long("hosts-settings")
            .action(clap::ArgAction::Set)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .required_if_eq(MODE_PARAM_NAME, MODE_NON_INTERACTIVE)
            .help("Path to store the TLS hosts settings file. Required in non-interactive mode."),
    ]
}

fn certificate_args() -> [clap::Arg; 6] {
    [
        clap::Arg::new(CERT_TYPE_PARAM_NAME)
            .long("cert-type")
            .action(clap::ArgAction::Set)
            .value_parser(["self-signed", "letsencrypt", "provided"])
            .help("Certificate type: 'self-signed', 'letsencrypt', or 'provided'"),
        clap::Arg::new(CERT_CHAIN_PATH_PARAM_NAME)
            .long("cert-chain-path")
            .action(clap::ArgAction::Set)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .required_if_eq(CERT_TYPE_PARAM_NAME, "provided")
            .help("Path to provided certificate chain (required when --cert-type=provided)"),
        clap::Arg::new(CERT_KEY_PATH_PARAM_NAME)
            .long("cert-key-path")
            .action(clap::ArgAction::Set)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .required_if_eq(CERT_TYPE_PARAM_NAME, "provided")
            .help("Path to provided private key (required when --cert-type=provided)"),
        clap::Arg::new(ACME_EMAIL_PARAM_NAME)
            .long("acme-email")
            .action(clap::ArgAction::Set)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .required_if_eq(CERT_TYPE_PARAM_NAME, "letsencrypt")
            .help(
                "Email address for Let's Encrypt account (required when --cert-type=letsencrypt)",
            ),
        clap::Arg::new(ACME_CHALLENGE_PARAM_NAME)
            .long("acme-challenge")
            .action(clap::ArgAction::Set)
            .value_parser(["http-01"])
            .default_value("http-01")
            .help(
                "ACME challenge method: 'http-01' (dns-01 is only available in interactive mode)",
            ),
        clap::Arg::new(ACME_STAGING_PARAM_NAME)
            .long("acme-staging")
            .action(clap::ArgAction::SetTrue)
            .help("Use Let's Encrypt staging environment (for testing)"),
    ]
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            if writeln!(io::stderr().lock(), "Error: {error}").is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> WizardResult<ExitCode> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .map_err(|_| io::Error::other("Couldn't install the TLS crypto provider"))?;
    }
    let args = match command().try_get_matches() {
        Ok(args) => args,
        Err(error) => {
            error.print()?;
            return Ok(ExitCode::from(u8::try_from(error.exit_code())?));
        }
    };

    let mode = match args.get_one::<String>(MODE_PARAM_NAME).map(String::as_str) {
        None | Some("interactive") => Mode::Interactive,
        Some(MODE_NON_INTERACTIVE) => Mode::NonInteractive,
        Some(mode) => return Err(io::Error::other(format!("Invalid mode: {mode}")).into()),
    };

    MODE.set(mode)
        .map_err(|_| io::Error::other("Wizard mode is already initialized"))?;

    if mode == Mode::Interactive && !io::stdin().is_terminal() {
        writeln!(
            io::stderr().lock(),
            "Error: Interactive mode requires a terminal (TTY)."
        )?;
        writeln!(
            io::stderr().lock(),
            "Please run setup_wizard from a terminal, or use non-interactive mode:"
        )?;
        writeln!(
            io::stderr().lock(),
            "  {} --help",
            std::env::args().next().unwrap_or_default()
        )?;
        return Ok(ExitCode::FAILURE);
    }

    let predefined = PredefinedParameters {
        listen_address: args.get_one::<String>(LISTEN_ADDRESS_PARAM_NAME).cloned(),
        credentials: args
            .get_one::<String>(CREDENTIALS_PARAM_NAME)
            .map(|credentials| parse_credentials(credentials))
            .transpose()?,
        hostname: args.get_one::<String>(HOSTNAME_PARAM_NAME).cloned(),
        library_settings_file: args
            .get_one::<String>(LIBRARY_SETTINGS_FILE_PARAM_NAME)
            .cloned(),
        tls_hosts_settings_file: args
            .get_one::<String>(TLS_HOSTS_SETTINGS_FILE_PARAM_NAME)
            .cloned(),
        cert_type: args.get_one::<String>(CERT_TYPE_PARAM_NAME).cloned(),
        cert_chain_path: args.get_one::<String>(CERT_CHAIN_PATH_PARAM_NAME).cloned(),
        cert_key_path: args.get_one::<String>(CERT_KEY_PATH_PARAM_NAME).cloned(),
        acme_email: args.get_one::<String>(ACME_EMAIL_PARAM_NAME).cloned(),
        acme_challenge: args.get_one::<String>(ACME_CHALLENGE_PARAM_NAME).cloned(),
        acme_staging: args.get_flag(ACME_STAGING_PARAM_NAME),
    };

    PREDEFINED_PARAMS
        .set(predefined)
        .map_err(|_| io::Error::other("Wizard parameters are already initialized"))?;

    writeln!(io::stdout().lock(), "Welcome to the setup wizard")?;
    let library_settings_path = build_library_settings()?;
    let (hosts_settings_path, cert_path, key_path) = build_hosts_settings()?;
    print_setup_complete_summary(
        &mut io::stdout().lock(),
        &library_settings_path,
        &hosts_settings_path,
        cert_path.as_deref(),
        key_path.as_deref(),
    )?;
    Ok(ExitCode::SUCCESS)
}

fn parse_credentials(credentials: &str) -> io::Result<(String, String)> {
    let (username, password) = credentials.split_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Credentials must be formatted as: <username>:<password>",
        )
    })?;
    if username.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Username cannot be empty",
        ));
    }
    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Password cannot be empty",
        ));
    }
    Ok((username.to_owned(), password.to_owned()))
}

fn build_library_settings() -> WizardResult<String> {
    if let Some(fname) = find_existent_settings::<Settings>(".") {
        if ask_for_agreement(&format!("Use the existing library settings {fname}?"))? {
            return Ok(fname);
        }
    }
    writeln!(io::stdout().lock(), "Let's build the library settings")?;
    let built = library_settings::build()?;
    writeln!(
        io::stdout().lock(),
        "The library settings are successfully built\n"
    )?;

    let path = get_predefined_params()
        .library_settings_file
        .clone()
        .map_or_else(
            || {
                ask_for_input::<String>(
                    "Path to a file to store the library settings",
                    Some("vpn.toml".into()),
                )
            },
            Ok,
        )?;
    if checked_overwrite(&path, "Overwrite the existing library settings file?")? {
        let doc = composer::compose_document(
            &built.settings,
            &built.credentials_path,
            &built.rules_path,
        )?;
        fs::write(&path, doc)?;
    }
    Ok(path)
}

fn build_hosts_settings() -> WizardResult<(String, Option<String>, Option<String>)> {
    if let Some(fname) = find_existent_settings::<TlsHostsSettings>(".") {
        if ask_for_agreement(&format!("Use the existing TLS hosts settings {fname}?"))? {
            return Ok((fname, None, None));
        }
    }
    writeln!(io::stdout().lock(), "Let's build the TLS hosts settings")?;
    let result = tls_hosts_settings::build()?;
    writeln!(
        io::stdout().lock(),
        "The TLS hosts settings are successfully built\n"
    )?;

    let path = get_predefined_params()
        .tls_hosts_settings_file
        .clone()
        .map_or_else(
            || {
                ask_for_input::<String>(
                    "Path to a file to store the TLS hosts settings",
                    Some("hosts.toml".into()),
                )
            },
            Ok,
        )?;
    if checked_overwrite(&path, "Overwrite the existing TLS hosts settings file?")? {
        fs::write(&path, toml::ser::to_string(&result.settings)?)?;
    }
    Ok((path, Some(result.cert_path), Some(result.key_path)))
}

fn print_setup_complete_summary(
    output: &mut impl Write,
    lib_settings_path: &str,
    hosts_settings_path: &str,
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> io::Result<()> {
    const CONFIG_URL: &str =
        "https://github.com/TrustTunnel/TrustTunnel/blob/master/CONFIGURATION.md";
    writeln!(output)?;
    writeln!(
        output,
        "═══════════════════════════════════════════════════════════════"
    )?;
    writeln!(output, "                    Setup Complete!")?;
    writeln!(
        output,
        "═══════════════════════════════════════════════════════════════"
    )?;
    writeln!(output)?;
    writeln!(output, "Configuration files created:")?;
    writeln!(
        output,
        "  • {lib_settings_path}          - Main endpoint settings"
    )?;
    writeln!(
        output,
        "  • {hosts_settings_path}    - TLS host configuration"
    )?;
    writeln!(
        output,
        "  • {}  - User credentials",
        library_settings::DEFAULT_CREDENTIALS_PATH
    )?;
    if let Some(cert) = cert_path {
        writeln!(output, "  • {cert}    - TLS certificate")?;
    }
    if let Some(key) = key_path {
        writeln!(output, "  • {key}     - TLS private key")?;
    }
    writeln!(output)?;
    writeln!(
        output,
        "───────────────────────────────────────────────────────────────"
    )?;
    writeln!(output, "                      Next Steps")?;
    writeln!(
        output,
        "───────────────────────────────────────────────────────────────"
    )?;
    writeln!(output)?;
    writeln!(output, "1. Start the endpoint:")?;
    writeln!(
        output,
        "   ./trusttunnel_endpoint {lib_settings_path} {hosts_settings_path}"
    )?;
    writeln!(output)?;
    writeln!(
        output,
        "2. Export client configuration (replace <username> and <address>):"
    )?;
    writeln!(output, "   ./trusttunnel_endpoint {lib_settings_path} {hosts_settings_path} -c <username> -a <address>")?;
    writeln!(
        output,
        "   where <address> is ip, ip:port, domain, or domain:port"
    )?;
    writeln!(output)?;
    writeln!(output, "3. Use the exported config with:")?;
    writeln!(
        output,
        "   • TrustTunnel CLI Client - Pass to setup_wizard --endpoint_config"
    )?;
    writeln!(
        output,
        "   • TrustTunnel Flutter Client - Enter the config manually"
    )?;
    writeln!(output)?;
    writeln!(
        output,
        "See \x1b]8;;{CONFIG_URL}\x1b\\{CONFIG_URL}\x1b]8;;\x1b\\ for advanced settings."
    )?;
    writeln!(
        output,
        "═══════════════════════════════════════════════════════════════"
    )
}

fn find_existent_settings<T: serde::de::DeserializeOwned>(path: &str) -> Option<String> {
    (get_mode() != Mode::NonInteractive)
        .then(|| {
            fs::read_dir(path)
                .ok()?
                .filter_map(Result::ok)
                .filter(|entry| entry.metadata().is_ok_and(|meta| meta.is_file()))
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter_map(|fname| fs::read_to_string(&fname).ok().zip(Some(fname)))
                .find_map(|(content, fname)| toml::from_str::<T>(&content).map(|_| fname).ok())
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::{command, parse_credentials, print_setup_complete_summary};
    use crate::WizardResult;

    const NONINTERACTIVE_ARGS: &[&str] = &[
        "setup_wizard",
        "-m",
        "non-interactive",
        "-a",
        "127.0.0.1:443",
        "-c",
        "alice:secret",
        "-n",
        "vpn.example.com",
        "--lib-settings",
        "vpn.toml",
        "--hosts-settings",
        "hosts.toml",
    ];

    #[test]
    fn equality_checks_retain_temporaries_and_report_mismatches() -> WizardResult<()> {
        let mut evaluations = 0;
        let value = String::from("value");
        check_eq!(
            {
                evaluations += 1;
                value.as_bytes()
            },
            String::from("value").as_bytes()
        );
        check_eq!(evaluations, 1);
        check_eq!(value, "value");
        let mismatch = (|| -> WizardResult<()> {
            check_eq!(value.to_uppercase().as_bytes(), b"different");
            Ok(())
        })();
        check!(mismatch.is_err());
        Ok(())
    }

    #[test]
    fn cli_preserves_noninteractive_certificate_requirements() -> WizardResult<()> {
        command().try_get_matches_from(NONINTERACTIVE_ARGS)?;
        check!(command()
            .try_get_matches_from(["setup_wizard", "-m", "non-interactive"])
            .is_err());
        for cert_type in ["provided", "letsencrypt"] {
            check!(command()
                .try_get_matches_from(
                    NONINTERACTIVE_ARGS
                        .iter()
                        .copied()
                        .chain(["--cert-type", cert_type])
                )
                .is_err());
        }
        command().try_get_matches_from(NONINTERACTIVE_ARGS.iter().copied().chain([
            "--cert-type",
            "provided",
            "--cert-chain-path",
            "cert.pem",
            "--cert-key-path",
            "key.pem",
        ]))?;
        command().try_get_matches_from(NONINTERACTIVE_ARGS.iter().copied().chain([
            "--cert-type",
            "letsencrypt",
            "--acme-email",
            "admin@example.com",
            "--acme-staging",
        ]))?;
        check!(command()
            .try_get_matches_from(
                NONINTERACTIVE_ARGS
                    .iter()
                    .copied()
                    .chain(["--acme-challenge", "dns-01",])
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn credentials_preserve_password_colons() -> WizardResult<()> {
        check_eq!(
            parse_credentials("alice:secret:with:colons")?,
            ("alice".to_owned(), "secret:with:colons".to_owned())
        );
        Ok(())
    }

    #[test]
    fn credentials_reject_missing_username_password_or_separator() {
        for credentials in [":secret", "alice:", "alice"] {
            assert!(parse_credentials(credentials).is_err());
        }
    }

    #[test]
    fn summary_preserves_config_paths_and_certificate_output() -> WizardResult<()> {
        let mut output = Vec::new();
        print_setup_complete_summary(
            &mut output,
            "custom-vpn.toml",
            "custom-hosts.toml",
            Some("certs/cert.pem"),
            Some("certs/key.pem"),
        )?;
        let output = String::from_utf8(output).map_err(std::io::Error::other)?;
        check!(output.contains("  • certs/cert.pem    - TLS certificate\n"));
        check!(output.contains("  • certs/key.pem     - TLS private key\n"));
        check!(output.contains("./trusttunnel_endpoint custom-vpn.toml custom-hosts.toml"));
        Ok(())
    }

    #[test]
    fn summary_reports_output_failure() {
        let mut buffer = [0_u8; 0];
        let mut output = std::io::Cursor::new(buffer.as_mut_slice());
        let result =
            print_setup_complete_summary(&mut output, "vpn.toml", "hosts.toml", None, None);
        assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::WriteZero));
    }
}
