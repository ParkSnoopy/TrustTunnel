//! Command-line endpoint startup and client configuration export.

use log::{debug, error, info, warn, LevelFilter};
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::signal;
use toml_edit::{Document, Item, Table};
use trusttunnel::authentication::registry_based::RegistryBasedAuthenticator;
use trusttunnel::authentication::Authenticator;
use trusttunnel::client_config;
use trusttunnel::client_random_prefix::{self, GeneratorParams};
use trusttunnel::core::Core;
use trusttunnel::settings::Settings;
use trusttunnel::shutdown::Shutdown;
use trusttunnel::{log_utils, settings};

const VERSION_STRING: &str = env!("TRUSTTUNNEL_VERSION");
const VERSION_PARAM_NAME: &str = "v_e_r_s_i_o_n_do_not_change_this_name_it_will_break";
const LOG_LEVEL_PARAM_NAME: &str = "log_level";
const LOG_FILE_PARAM_NAME: &str = "log_file";
const SETTINGS_PARAM_NAME: &str = "settings";
const TLS_HOSTS_SETTINGS_PARAM_NAME: &str = "tls_hosts_settings";
const CLIENT_CONFIG_PARAM_NAME: &str = "client_config";
const ADDRESS_PARAM_NAME: &str = "address";
const CUSTOM_SNI_PARAM_NAME: &str = "custom_sni";
const CLIENT_RANDOM_PREFIX_PARAM_NAME: &str = "client_random_prefix";
const CLIENT_RANDOM_AUTH_KEY_PARAM_NAME: &str = "client_random_auth_key";
const GENERATE_CLIENT_RANDOM_PREFIX_PARAM_NAME: &str = "generate_client_random_prefix";
const PREFIX_LENGTH_PARAM_NAME: &str = "prefix_length";
const PREFIX_PERCENT_PARAM_NAME: &str = "prefix_percent";
const PREFIX_MASK_PARAM_NAME: &str = "prefix_mask";
const FORMAT_PARAM_NAME: &str = "format";
const NAME_PARAM_NAME: &str = "name";
const DNS_UPSTREAM_PARAM_NAME: &str = "dns_upstream";
const SUBSCRIPTION_URL_PARAM_NAME: &str = "subscription_url";
const SUBSCRIPTION_ONLY_PARAM_NAME: &str = "subscription_only";
const SENTRY_DSN_PARAM_NAME: &str = "sentry_dsn";
const THREADS_NUM_PARAM_NAME: &str = "threads_num";
const TRUSTTUNNEL_QR_URL: &str = "https://trusttunnel.org/qr.html";

#[derive(Debug)]
struct CliError {
    message: String,
    exit_code: ExitCode,
}

impl CliError {
    fn failure(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: ExitCode::FAILURE,
        }
    }

    fn startup(context: &str, err: impl std::fmt::Debug) -> Self {
        Self::fatal(format!("{context}: {err:?}"))
    }

    fn fatal(message: impl Into<String>) -> Self {
        let message = message.into();
        sentry::capture_event(sentry::protocol::Event {
            exception: vec![sentry::protocol::Exception {
                ty: "panic".into(),
                mechanism: Some(sentry::protocol::Mechanism {
                    ty: "panic".into(),
                    handled: Some(false),
                    ..Default::default()
                }),
                value: Some(message.clone()),
                stacktrace: sentry::integrations::backtrace::current_stacktrace(),
                ..Default::default()
            }]
            .into(),
            level: sentry::Level::Fatal,
            ..Default::default()
        });
        Self {
            message,
            exit_code: ExitCode::from(101),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

fn report_result(
    result: Result<ExitCode, CliError>,
    output: &mut impl Write,
) -> io::Result<ExitCode> {
    match result {
        Ok(exit_code) => Ok(exit_code),
        Err(err) => {
            writeln!(output, "{err}")?;
            Ok(err.exit_code)
        }
    }
}

fn write_version(output: &mut impl Write) -> Result<ExitCode, CliError> {
    writeln!(output, "{VERSION_STRING}")
        .map_err(|err| CliError::startup("Failed to write version", err))?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(unix)]
fn increase_fd_limit() {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    let max_rlim = 65_536;

    let (soft, hard) = match getrlimit(Resource::RLIMIT_NOFILE) {
        Ok(limits) => limits,
        Err(err) => {
            warn!("Failed to get file descriptor limit: {err}");
            return;
        }
    };

    let target_limit = std::cmp::min(hard, max_rlim);
    if soft >= target_limit {
        debug!("File descriptor limit is already {soft} (target: {target_limit})");
        return;
    }

    if let Err(err) = setrlimit(Resource::RLIMIT_NOFILE, target_limit, hard) {
        warn!("Failed to increase file descriptor limit from {soft} to {target_limit}: {err}");
        return;
    }

    debug!("Successfully increased file descriptor limit to {target_limit}");
}

#[cfg(not(unix))]
fn increase_fd_limit() {}

fn command() -> clap::Command {
    clap::Command::new("VPN endpoint")
        .args(startup_arguments())
        .args(client_arguments())
        .args(prefix_arguments())
        .args(export_arguments())
        .disable_version_flag(true)
}

fn startup_arguments() -> [clap::Arg; 8] {
    [
            // Built-in version parameter handling is deficient in that it
            // outputs `<program name> <version>` instead of just `<version>`
            // and also uses `-V` instead of `-v` as the shorthand.
            clap::Arg::new(VERSION_PARAM_NAME)
                .short('v')
                .long("version")
                .action(clap::ArgAction::SetTrue)
                .help("Print the version of this software and exit"),
            clap::Arg::new(LOG_LEVEL_PARAM_NAME)
                .short('l')
                .long("loglvl")
                .action(clap::ArgAction::Set)
                .value_parser(["info", "debug", "trace"])
                .default_value("info")
                .help("Logging level"),
            clap::Arg::new(LOG_FILE_PARAM_NAME)
                .long("logfile")
                .action(clap::ArgAction::Set)
                .help("File path for storing logs. If not specified, the logs are printed to stdout"),
            clap::Arg::new(SENTRY_DSN_PARAM_NAME)
                .long(SENTRY_DSN_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .help("Sentry DSN (see https://docs.sentry.io/product/sentry-basics/dsn-explainer/ for details)"),
            clap::Arg::new(THREADS_NUM_PARAM_NAME)
                .long("jobs")
                .action(clap::ArgAction::Set)
                .value_parser(clap::value_parser!(usize))
                .help("The number of worker threads. If not specified, set to the number of CPUs on the machine."),
            clap::Arg::new(SETTINGS_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .required_unless_present(VERSION_PARAM_NAME)
                .help("Path to a settings file"),
            clap::Arg::new(TLS_HOSTS_SETTINGS_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .required_unless_present(VERSION_PARAM_NAME)
                .help("Path to a file containing TLS hosts settings. Sending SIGHUP to the process causes reloading the settings."),
            clap::Arg::new(CLIENT_CONFIG_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .short('c')
                .long("client_config")
                .value_names(["client_name"])
                .help("Print the endpoint config for specified client and exit."),
    ]
}

fn client_arguments() -> [clap::Arg; 4] {
    [
            clap::Arg::new(ADDRESS_PARAM_NAME)
                .action(clap::ArgAction::Append)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .short('a')
                .long("address")
                .help("Endpoint address to be added to client's config. Accepts ip, ip:port, domain, or domain:port. Optional when [subscription] is enabled in vpn.toml: the subscription address is used as the fallback."),
            clap::Arg::new(CUSTOM_SNI_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .short('s')
                .long("custom-sni")
                .help("Custom SNI override for client connection. Must match an allowed_sni in hosts.toml."),
            clap::Arg::new(CLIENT_RANDOM_PREFIX_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .short('r')
                .long("client-random-prefix")
                .help("TLS client random hex prefix for connection filtering. Must have a corresponding rule in rules.toml."),
            clap::Arg::new(CLIENT_RANDOM_AUTH_KEY_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .long("client-random-auth-key")
                .conflicts_with(CLIENT_RANDOM_PREFIX_PARAM_NAME)
                .conflicts_with(GENERATE_CLIENT_RANDOM_PREFIX_PARAM_NAME)
                .help("TLS client random auth key (hex). Derives full client_random via HKDF+AES. Must have a corresponding rule with client_random_auth_key in rules.toml."),
    ]
}

fn prefix_arguments() -> [clap::Arg; 4] {
    [
            clap::Arg::new(GENERATE_CLIENT_RANDOM_PREFIX_PARAM_NAME)
                .action(clap::ArgAction::SetTrue)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .long("generate-client-random-prefix")
                .conflicts_with(CLIENT_RANDOM_PREFIX_PARAM_NAME)
                .help("Generate a new TLS client random prefix for connection filtering and use it in the exported client config."),
            clap::Arg::new(PREFIX_LENGTH_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(GENERATE_CLIENT_RANDOM_PREFIX_PARAM_NAME)
                .long("prefix-length")
                .value_parser(clap::value_parser!(usize))
                .default_value("4")
                .help("Generated client random prefix length in bytes."),
            clap::Arg::new(PREFIX_PERCENT_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(GENERATE_CLIENT_RANDOM_PREFIX_PARAM_NAME)
                .long("prefix-percent")
                .value_parser(clap::value_parser!(u8))
                .default_value("70")
                .help("Percentage of one bits in the generated client random mask."),
            clap::Arg::new(PREFIX_MASK_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(GENERATE_CLIENT_RANDOM_PREFIX_PARAM_NAME)
                .long("prefix-mask")
                .conflicts_with_all([PREFIX_LENGTH_PARAM_NAME, PREFIX_PERCENT_PARAM_NAME])
                .help("Explicit mask for generated client random prefix in hex format."),
    ]
}

fn export_arguments() -> [clap::Arg; 5] {
    [
            clap::Arg::new(FORMAT_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .short('f')
                .long("format")
                .value_parser(["toml", "deeplink"])
                .default_value("deeplink")
                .help("Output format for client configuration: 'deeplink' produces tt://? URI, 'toml' produces traditional config file"),
            clap::Arg::new(NAME_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .short('n')
                .long("name")
                .help("Human-readable server display name for the client configuration."),
            clap::Arg::new(DNS_UPSTREAM_PARAM_NAME)
                .action(clap::ArgAction::Append)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .short('d')
                .long("dns-upstream")
                .help("DNS upstream address to include in the client configuration. Can be specified multiple times."),
            clap::Arg::new(SUBSCRIPTION_URL_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .long("subscription-url")
                .help("Override the subscription base URL (host and path only) in the exported client config. Credentials are always appended from credentials.toml."),
            clap::Arg::new(SUBSCRIPTION_ONLY_PARAM_NAME)
                .action(clap::ArgAction::SetTrue)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .long("subscription-only")
                .help("With --format deeplink, export a minimal deep link that contains only the subscription URL (no static connection parameters). Requires [subscription] to be enabled in vpn.toml and the subscription host certificate to be verifiable by system CAs."),
    ]
}

fn main() -> io::Result<ExitCode> {
    let args = match command().try_get_matches() {
        Ok(args) => args,
        Err(err) => {
            err.print()?;
            return Ok(ExitCode::from(
                u8::try_from(err.exit_code()).map_err(io::Error::other)?,
            ));
        }
    };

    if args.contains_id(VERSION_PARAM_NAME)
        && Some(true) == args.get_one::<bool>(VERSION_PARAM_NAME).copied()
    {
        return report_result(
            write_version(&mut io::stdout().lock()),
            &mut io::stderr().lock(),
        );
    }

    #[cfg(feature = "tracing")]
    console_subscriber::init();

    let _guard = args.get_one::<String>(SENTRY_DSN_PARAM_NAME).map(|x| {
        sentry::init((
            x.clone(),
            sentry::ClientOptions {
                release: sentry::release_name!(),
                ..Default::default()
            },
        ))
    });

    let _guard = log_utils::LogFlushGuard;
    report_result(run(&args), &mut io::stderr().lock())
}

fn run(args: &clap::ArgMatches) -> Result<ExitCode, CliError> {
    log::set_logger(match args.get_one::<String>(LOG_FILE_PARAM_NAME) {
        None => log_utils::make_stdout_logger(),
        Some(file) => log_utils::make_file_logger(file)
            .map_err(|err| CliError::startup("Couldn't open the logging file", err))?,
    })
    .map_err(|err| CliError::startup("Couldn't set logger", err))?;

    log::set_max_level(
        match args
            .get_one::<String>(LOG_LEVEL_PARAM_NAME)
            .map(String::as_str)
        {
            None | Some("info") => LevelFilter::Info,
            Some("debug") => LevelFilter::Debug,
            Some("trace") => LevelFilter::Trace,
            Some(x) => return Err(CliError::startup("Unexpected log level", x)),
        },
    );

    increase_fd_limit();

    let settings_path = required_argument::<String>(args, SETTINGS_PARAM_NAME)?;
    let settings_contents = std::fs::read_to_string(settings_path)
        .map_err(|err| CliError::startup("Couldn't read the settings file", err))?;
    let settings: Settings = toml::from_str(&settings_contents)
        .map_err(|err| CliError::startup("Couldn't parse the settings file", err))?;

    if settings.get_clients().is_empty() && settings.get_listen_address().ip().is_loopback() {
        warn!(
            "No credentials configured (credentials_file is missing). \
            Anyone can connect to this endpoint. This is acceptable for local development \
            but should not be used in production."
        );
    }

    let tls_hosts_settings_path = required_argument::<String>(args, TLS_HOSTS_SETTINGS_PARAM_NAME)?;
    let tls_hosts_settings = load_tls_hosts_settings(tls_hosts_settings_path)?;

    let subscription_host = settings
        .get_subscription()
        .as_ref()
        .map(|sub| {
            trusttunnel::subscription::validate_with_hosts(sub, &settings, &tls_hosts_settings)
                .map_err(|err| CliError::failure(format!("Error: {err:?}")))
        })
        .transpose()?;

    if args.contains_id(CLIENT_CONFIG_PARAM_NAME) {
        export_client_config(
            args,
            &settings,
            &tls_hosts_settings,
            subscription_host,
            &settings_contents,
            settings_path,
        )?;
        return Ok(ExitCode::SUCCESS);
    }

    run_endpoint(
        args,
        settings,
        &tls_hosts_settings,
        settings_path,
        tls_hosts_settings_path,
    )
}

fn required_argument<'a, T: Clone + Send + Sync + 'static>(
    args: &'a clap::ArgMatches,
    name: &str,
) -> Result<&'a T, CliError> {
    args.get_one::<T>(name)
        .ok_or_else(|| CliError::startup("Missing required argument", name))
}

fn load_tls_hosts_settings(path: &str) -> Result<settings::TlsHostsSettings, CliError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|err| CliError::startup("Couldn't read the TLS hosts settings file", err))?;
    toml::from_str(&contents)
        .map_err(|err| CliError::startup("Couldn't parse the TLS hosts settings file", err))
}

fn export_client_config(
    args: &clap::ArgMatches,
    settings: &Settings,
    tls_hosts_settings: &settings::TlsHostsSettings,
    subscription_host: Option<&settings::TlsHostInfo>,
    settings_contents: &str,
    settings_path: &str,
) -> Result<(), CliError> {
    let username = required_argument::<String>(args, CLIENT_CONFIG_PARAM_NAME)?;
    let listen_port = settings.get_listen_address().port();
    let explicit_addresses: Vec<String> = args
        .get_many::<String>(ADDRESS_PARAM_NAME)
        .map_or_default(|vals| vals.cloned().collect());
    let addresses = select_client_addresses(
        &explicit_addresses,
        settings.get_subscription().as_ref(),
        listen_port,
    )?;

    let custom_sni = args.get_one::<String>(CUSTOM_SNI_PARAM_NAME).cloned();
    validate_client_hosts(&addresses, custom_sni.as_deref(), tls_hosts_settings)?;

    let generated_client_random_prefix = generate_client_random_prefix(
        args,
        settings_contents,
        settings_path,
        &mut io::stderr().lock(),
    )?;
    let is_generated = generated_client_random_prefix.is_some();
    let client_random_prefix = generated_client_random_prefix.or_else(|| {
        args.get_one::<String>(CLIENT_RANDOM_PREFIX_PARAM_NAME)
            .cloned()
    });

    // Validate explicit --client-random-prefix (skip for generated prefix)
    if !is_generated {
        if let Some(ref prefix) = client_random_prefix {
            validate_client_random_prefix(prefix, settings)?;
        }
    }

    let name = args.get_one::<String>(NAME_PARAM_NAME).cloned();
    let dns_upstreams: Vec<String> = args
        .get_many::<String>(DNS_UPSTREAM_PARAM_NAME)
        .map_or_default(|vals| vals.cloned().collect());

    let subscription_url = client_subscription_url(args, settings, username)?;

    let subscription_enabled = subscription_url.is_some();

    let subscription_only = args.get_flag(SUBSCRIPTION_ONLY_PARAM_NAME);
    if !explicit_addresses.is_empty() && subscription_enabled && !subscription_only {
        writeln!(
            io::stderr().lock(),
            "Warning: [subscription] is enabled: the exported addresses will be \
                 rewritten on the first subscription fetch, so --address can be omitted."
        )
        .map_err(|err| CliError::startup("Failed to write subscription warning", err))?;
    }

    let client_random_auth_key = args
        .get_one::<String>(CLIENT_RANDOM_AUTH_KEY_PARAM_NAME)
        .cloned();

    if let Some(ref auth_key) = client_random_auth_key {
        validate_client_random_auth_key(auth_key, settings)?;
    }

    let client_config = client_config::build(
        username,
        addresses,
        settings.get_clients(),
        tls_hosts_settings,
        client_config::BuildOptions {
            custom_sni,
            client_random_prefix,
            client_random_auth_key,
            name,
            dns_upstreams,
            subscription_url,
        },
    )
    .map_err(|err| {
        if err.kind() == io::ErrorKind::InvalidInput {
            CliError::fatal(err.to_string())
        } else {
            CliError::startup("Failed to load certificate", err)
        }
    })?;

    let format = args
        .get_one::<String>(FORMAT_PARAM_NAME)
        .map_or("deeplink", String::as_str);

    validate_subscription_only(args, subscription_enabled, subscription_host)?;
    write_client_config(
        &client_config,
        format,
        subscription_only,
        &mut io::stdout().lock(),
    )
}

fn run_endpoint(
    args: &clap::ArgMatches,
    settings: Settings,
    tls_hosts_settings: &settings::TlsHostsSettings,
    settings_path: &str,
    tls_hosts_settings_path: &str,
) -> Result<ExitCode, CliError> {
    let rt = {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_io();
        builder.enable_time();

        if let Some(n) = args.get_one::<usize>(THREADS_NUM_PARAM_NAME) {
            if *n == 0 {
                return Err(CliError::fatal("Worker threads cannot be set to 0"));
            }
            builder.worker_threads(*n);
        }

        builder
            .build()
            .map_err(|err| CliError::startup("Failed to set up runtime", err))?
    };

    let shutdown = Shutdown::new();
    let authenticator: Option<Arc<dyn Authenticator>> = if settings.get_clients().is_empty() {
        None
    } else {
        Some(Arc::new(RegistryBasedAuthenticator::new(
            settings.get_clients(),
        )))
    };
    let core = Arc::new(
        Core::new(
            settings,
            authenticator,
            tls_hosts_settings,
            shutdown.clone(),
        )
        .map_err(|err| CliError::startup("Couldn't create core instance", err))?,
    );

    let listen_task = {
        let core = Arc::clone(&core);
        async move { core.listen().await }
    };

    let reload_tls_hosts_and_subscription_task =
        reload_tls_hosts_and_subscription(&core, tls_hosts_settings_path, settings_path);

    let interrupt_task = async move {
        tokio::signal::ctrl_c()
            .await
            .map_err(|err| CliError::startup("Couldn't listen for Ctrl-C", err))?;
        complete_shutdown(&shutdown).await
    };

    rt.block_on(async move {
        tokio::select! {
            listen_result = listen_task => match listen_result {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(e) => {
                    error!("Error while listening IO events: {e}");
                    Ok(ExitCode::FAILURE)
                }
            },
            reload_result = reload_tls_hosts_and_subscription_task => {
                reload_result?;
                error!("Error while reloading TLS hosts and subscription");
                Ok(ExitCode::FAILURE)
            },
            interrupt_result = interrupt_task => {
                interrupt_result?;
                info!("Interrupted by user");
                Ok(ExitCode::SUCCESS)
            },
        }
    })
}

fn validate_client_hosts(
    addresses: &[String],
    custom_sni: Option<&str>,
    tls_hosts_settings: &settings::TlsHostsSettings,
) -> Result<(), CliError> {
    for addr in addresses {
        if let Some(domain) = extract_domain_for_warning(addr) {
            if !domain_matches_tls_hosts(domain, tls_hosts_settings) {
                warn!(
                    "Domain '{domain}' does not match any hostname in TLS hosts settings. \
                     Please verify this is correct (it may be a typo)."
                );
            }
        }
    }
    if let Some(sni) = custom_sni {
        let is_valid = tls_hosts_settings.get_main_hosts().iter().any(|host| {
            host.hostname == sni || host.allowed_sni.iter().any(|allowed| allowed == sni)
        });
        if !is_valid {
            return Err(CliError::failure(format!(
                "Error: custom SNI '{sni}' does not match any hostname or allowed_sni in hosts.toml"
            )));
        }
    }
    Ok(())
}

fn generate_client_random_prefix(
    args: &clap::ArgMatches,
    settings_contents: &str,
    settings_path: &str,
    output: &mut impl Write,
) -> Result<Option<String>, CliError> {
    if !args.get_flag(GENERATE_CLIENT_RANDOM_PREFIX_PARAM_NAME) {
        return Ok(None);
    }
    let generated = if let Some(mask_hex) = args.get_one::<String>(PREFIX_MASK_PARAM_NAME) {
        let mask = hex::decode(mask_hex).map_err(|_| {
            CliError::failure(format!("Error: prefix_mask '{mask_hex}' is not valid hex"))
        })?;
        client_random_prefix::generate_with_mask(mask)
    } else {
        client_random_prefix::generate(GeneratorParams {
            length: *required_argument::<usize>(args, PREFIX_LENGTH_PARAM_NAME)?,
            percent: *required_argument::<u8>(args, PREFIX_PERCENT_PARAM_NAME)?,
        })
    }
    .map_err(|err| CliError::failure(format!("Error: {err}")))?;
    let generated_prefix = generated.to_masked_hex_string();
    let rules_path =
        extract_rules_file_path(settings_contents, settings_path).ok_or_else(|| {
            CliError::failure(
                "Error: rules_file must be configured in settings to generate client_random_prefix",
            )
        })?;
    append_allow_rule(&rules_path, &generated_prefix).map_err(|err| {
        CliError::failure(format!(
            "Error: failed to append generated client_random_prefix to '{}': {err}",
            rules_path.display(),
        ))
    })?;
    writeln!(
        output,
        "Added allow rule to '{}': {generated_prefix}",
        rules_path.display()
    )
    .map_err(|err| CliError::startup("Failed to write generated prefix", err))?;
    Ok(Some(generated_prefix))
}

fn validate_client_random_prefix(prefix: &str, settings: &Settings) -> Result<(), CliError> {
    let has_slash = prefix.contains('/');
    let (input_prefix, input_mask) = prefix.split_once('/').unwrap_or((prefix, ""));

    // Validate hex format
    if hex::decode(input_prefix).is_err() {
        return Err(CliError::failure(format!(
            "Error: client_random_prefix '{prefix}' is not valid hex"
        )));
    }
    if (has_slash && input_mask.is_empty())
        || (!input_mask.is_empty() && hex::decode(input_mask).is_err())
    {
        return Err(CliError::failure(format!(
            "Error: client_random_prefix mask '{input_mask}' is not valid hex"
        )));
    }

    // Validate against rules.toml
    if let Some(rules_engine) = settings.get_rules_engine() {
        let input_mask = if input_mask.is_empty() {
            None
        } else {
            Some(input_mask)
        };
        let matching_rule = rules_engine.config().rule.iter().find(|rule| {
            rule.client_random_prefix
                .as_ref()
                .is_some_and(|p| prefix_matches_rule(input_prefix, input_mask, p))
        });
        match matching_rule {
            None => return Err(CliError::failure(format!(
                "Error: No rule found in rules.toml matching client_random_prefix '{prefix}'. Add the rule first or omit --client-random-prefix."
            ))),
            Some(rule) if rule.action == trusttunnel::rules::RuleAction::Deny => {
                return Err(CliError::failure(format!(
                    "Error: Matched rule in rules.toml for client_random_prefix '{prefix}' has action 'deny'."
                )));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn prefix_matches_rule(input_prefix: &str, input_mask: Option<&str>, p: &str) -> bool {
    let (rule_prefix, rule_mask) = p.split_once('/').map_or((p, None), |(a, b)| (a, Some(b)));

    // Prefix parts must be equal
    if rule_prefix != input_prefix {
        return false;
    }

    // Mask compatibility: input mask must be same or stronger than rule mask.
    // "Stronger" means more bits set, i.e. (input_mask & rule_mask) == rule_mask.
    match (input_mask, rule_mask) {
        // Rule has no mask, any input mask is at least as strong
        (_, None)
        // Input has no mask, strongest possible
        | (None, Some(_)) => true,
        // Both have masks, input mask must cover all bits of rule mask
        (Some(input_mask_hex), Some(rule_mask_hex)) => {
            match (hex::decode(input_mask_hex), hex::decode(rule_mask_hex)) {
                (Ok(input), Ok(rule)) => input.len() >= rule.len()
                    && input.iter().zip(&rule).all(|(i, r)| i & r == *r),
                _ => false,
            }
        }
    }
}

fn client_subscription_url(
    args: &clap::ArgMatches,
    settings: &Settings,
    username: &str,
) -> Result<Option<String>, CliError> {
    let Some(sub) = settings
        .get_subscription()
        .as_ref()
        .filter(|sub| sub.enabled)
    else {
        return Ok(None);
    };
    let Some(user) = settings
        .get_clients()
        .iter()
        .find(|c| c.username == username)
    else {
        return Ok(None);
    };
    let Some(hostname) = sub.hostname.as_deref() else {
        return Ok(None);
    };
    let base = if let Some(override_url) = args.get_one::<String>(SUBSCRIPTION_URL_PARAM_NAME) {
        client_config::validate_subscription_url_override(override_url)
            .map_err(CliError::failure)?;
        override_url.clone()
    } else {
        let port = client_config::subscription_url_port(sub.address.as_deref())
            .map_or_default(|port| format!(":{port}"));
        format!("https://{hostname}{port}{}", sub.path.as_str())
    };
    Ok(Some(client_config::build_subscription_url(
        &base,
        &user.username,
        &user.password,
    )))
}

fn validate_client_random_auth_key(auth_key: &str, settings: &Settings) -> Result<(), CliError> {
    if !trusttunnel::rules::is_valid_hex(auth_key) {
        // The auth key is a secret, do not log its value
        return Err(CliError::failure(
            "Error: client_random_auth_key is not valid hex",
        ));
    }
    // Validate against rules.toml
    if let Some(rules_engine) = settings.get_rules_engine() {
        let matching_rule = rules_engine.config().rule.iter().find(|r| {
            r.client_random_auth_key
                .as_ref()
                .is_some_and(|s| s.eq_ignore_ascii_case(auth_key))
        });
        match matching_rule {
            None => {
                // The auth key is a secret, do not log its value
                return Err(CliError::failure(
                    "Error: No rule found in rules.toml with matching client_random_auth_key. \
                     Add the rule first or omit --client-random-auth-key.",
                ));
            }
            Some(rule) if rule.action == trusttunnel::rules::RuleAction::Deny => {
                return Err(CliError::failure("Error: Matched rule in rules.toml for client_random_auth_key has action 'deny'."));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn validate_subscription_only(
    args: &clap::ArgMatches,
    subscription_enabled: bool,
    subscription_host: Option<&settings::TlsHostInfo>,
) -> Result<(), CliError> {
    if !args.get_flag(SUBSCRIPTION_ONLY_PARAM_NAME) {
        return Ok(());
    }
    if args
        .get_one::<String>(FORMAT_PARAM_NAME)
        .is_some_and(|format| format != "deeplink")
    {
        return Err(CliError::failure(
            "Error: --subscription-only is only valid with --format deeplink.",
        ));
    }
    if !subscription_enabled {
        return Err(CliError::failure(
            "Error: --subscription-only requires [subscription] to be enabled in vpn.toml.",
        ));
    }
    if args
        .get_one::<String>(SUBSCRIPTION_URL_PARAM_NAME)
        .is_none()
    {
        if let Some(host) = subscription_host {
            let system_verifiable = trusttunnel::cert_verification::CertificateVerifier::new()
                .is_ok_and(|verifier| {
                    verifier.is_system_verifiable(&host.cert_chain_path, &host.hostname)
                });
            if !system_verifiable {
                return Err(CliError::failure(format!(
                    "Error: --subscription-only requires the certificate of the subscription \
                     host '{}' to be verifiable by system CAs. Export without \
                     --subscription-only so the certificate is embedded in the deep link.",
                    host.hostname
                )));
            }
        }
    }
    Ok(())
}

fn write_client_config(
    client_config: &client_config::ClientConfig,
    format: &str,
    subscription_only: bool,
    output: &mut impl Write,
) -> Result<(), CliError> {
    match format {
        "toml" => writeln!(output, "{}", client_config.compose_toml())
            .map_err(|err| CliError::startup("Failed to write client configuration", err)),
        "deeplink" => {
            let deeplink = if subscription_only {
                client_config.compose_deeplink_subscription_only()
            } else {
                client_config.compose_deeplink()
            }
            .map_err(|err| CliError::failure(format!("Error generating deep-link: {err}")))?;
            write_deeplink(&deeplink, output)
        }
        _ => Err(CliError::failure(format!(
            "Error: unsupported format '{format}'. Use 'toml' or 'deeplink'."
        ))),
    }
}

fn write_deeplink(deep_link: &str, output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "{deep_link}")
        .map_err(|err| CliError::startup("Failed to write deep-link", err))?;
    let payload = deep_link
        .strip_prefix("tt://?")
        .ok_or_else(|| CliError::fatal("Generated deep-link is missing tt://? prefix"))?;
    writeln!(output,
        "\nTo connect on mobile, you can scan QR code on the page: {TRUSTTUNNEL_QR_URL}#tt={payload}"
    ).map_err(|err| CliError::startup("Failed to write deep-link QR URL", err))
}

async fn reload_tls_hosts_and_subscription(
    core: &Core,
    tls_hosts_settings_path: &str,
    settings_path: &str,
) -> Result<(), CliError> {
    let mut sighup_listener = signal::unix::signal(signal::unix::SignalKind::hangup())
        .map_err(|err| CliError::startup("Couldn't start SIGHUP listener", err))?;
    loop {
        sighup_listener
            .recv()
            .await
            .ok_or_else(|| CliError::failure("Error while reloading TLS hosts and subscription"))?;
        info!("Reloading TLS hosts settings");
        let tls_hosts_settings = load_tls_hosts_settings(tls_hosts_settings_path)?;
        core.reload_tls_hosts_settings(&tls_hosts_settings)
            .map_err(|err| CliError::startup("Couldn't apply new settings", err))?;
        info!("TLS hosts settings are successfully reloaded");

        info!("Reloading subscription settings");
        let subscription = std::fs::read_to_string(settings_path).and_then(|contents| {
            extract_subscription(&contents).map_err(|e| {
                io::Error::other(format!("Couldn't parse the subscription section: {e}"))
            })
        });
        match subscription {
            Ok(sub) => {
                if let Err(e) = core.reload_subscription_settings(sub, &tls_hosts_settings) {
                    error!("Failed to reload subscription settings: {e}; keeping previous");
                } else {
                    info!("Subscription settings are successfully reloaded");
                }
            }
            Err(e) => error!("Failed to reload subscription settings: {e}; keeping previous"),
        }
    }
}

async fn complete_shutdown(shutdown: &Mutex<Shutdown>) -> Result<(), CliError> {
    shutdown
        .lock()
        .map_err(|err| CliError::startup("Couldn't lock shutdown", err))?
        .submit();
    // Poll while locked so completion never holds the mutex across an await.
    std::future::poll_fn(|context| {
        let mut shutdown = shutdown
            .lock()
            .map_err(|err| CliError::startup("Couldn't lock shutdown", err))?;
        let result = {
            let mut completion = std::pin::pin!(shutdown.completion());
            completion.as_mut().poll(context).map(Ok)
        };
        drop(shutdown);
        result
    })
    .await
}

/// Returns the domain part of an address string if it is a domain (not an IP).
/// Returns `None` for IP addresses (both `IPv4` and `IPv6`).
fn extract_domain_for_warning(addr: &str) -> Option<&str> {
    if SocketAddr::from_str(addr).is_ok() {
        return None;
    }
    if addr.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let domain = addr.rsplit_once(':').map_or(addr, |(d, _)| d);
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(domain)
}

fn domain_matches_tls_hosts(domain: &str, tls_hosts_settings: &settings::TlsHostsSettings) -> bool {
    tls_hosts_settings
        .get_main_hosts()
        .iter()
        .any(|h| h.hostname == domain || h.allowed_sni.iter().any(|s| s == domain))
}

fn append_allow_rule(rules_path: &Path, client_random_prefix: &str) -> std::io::Result<()> {
    let content = match std::fs::read_to_string(rules_path) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err),
    };
    let mut doc: Document = content
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut new_rule = Table::new();
    new_rule.insert(
        "client_random_prefix",
        toml_edit::value(client_random_prefix),
    );
    new_rule.insert("action", toml_edit::value("allow"));

    let rules = doc
        .entry("rule")
        .or_insert_with(|| Item::ArrayOfTables(toml_edit::ArrayOfTables::default()))
        .as_array_of_tables_mut()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid rules format")
        })?;

    let tail: Vec<Table> = rules.iter().cloned().collect();
    rules.clear();
    rules.push(new_rule);
    for table in tail {
        rules.push(table);
    }

    std::fs::write(rules_path, doc.to_string())
}

fn extract_rules_file_path(settings_contents: &str, settings_path: &str) -> Option<PathBuf> {
    let value = settings_contents.parse::<toml::Value>().ok()?;
    let rules_file = value.get("rules_file")?.as_str()?;
    let path = Path::new(rules_file);

    if path.is_absolute() {
        return Some(path.to_path_buf());
    }

    let settings_dir = Path::new(settings_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    Some(settings_dir.join(path))
}

/// Select the `addresses` list for the exported client config: explicit
/// `--address` values, or the `[subscription] address` as fallback.
fn select_client_addresses(
    explicit: &[String],
    subscription: Option<&trusttunnel::subscription::SubscriptionSettings>,
    listen_port: u16,
) -> Result<Vec<String>, CliError> {
    if !explicit.is_empty() {
        return explicit
            .iter()
            .map(|a| parse_endpoint_address(a, listen_port))
            .collect();
    }
    let address = subscription
        .filter(|sub| sub.enabled)
        .and_then(|sub| sub.address.as_deref())
        .ok_or_else(|| {
            CliError::failure(
                "Error: no --address specified and [subscription] is not usable as a fallback \
                 (requires enabled = true and hostname and address set in vpn.toml)",
            )
        })?;
    Ok(vec![parse_endpoint_address(address, listen_port)?])
}

/// Parse an endpoint address string into a normalized `host:port` format.
///
/// Accepts the following formats:
/// - `IP:port` (e.g. `1.2.3.4:443`, `[::1]:443`)
/// - `IP` without port (e.g. `1.2.3.4`, `::1`) — `default_port` is appended
/// - `domain:port` (e.g. `vpn.example.com:443`)
/// - `domain` without port (e.g. `vpn.example.com`) — `default_port` is appended
fn parse_endpoint_address(input: &str, default_port: u16) -> Result<String, CliError> {
    if let Ok(addr) = SocketAddr::from_str(input) {
        return Ok(addr.to_string());
    }
    if let Ok(addr) = SocketAddr::from_str(&format!("{input}:{default_port}")) {
        return Ok(addr.to_string());
    }
    if let Ok(ip) = input.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port).to_string());
    }
    if let Some((domain, port_str)) = input.rsplit_once(':') {
        let port: u16 = port_str.parse().map_err(|_| {
            CliError::fatal(format!(
                "Failed to parse port in address '{input}'. \
                 Expected `ip`, `ip:port`, `domain`, or `domain:port` format."
            ))
        })?;
        Ok(format!("{domain}:{port}"))
    } else {
        Ok(format!("{input}:{default_port}"))
    }
}

#[derive(serde::Deserialize)]
struct SubscriptionOnly {
    #[serde(default)]
    subscription: Option<trusttunnel::subscription::SubscriptionSettings>,
}

/// Extract just the `[subscription]` section from `vpn.toml` contents.
///
/// Re-parsing the whole `Settings` would re-read `credentials.toml` and
/// re-validate unrelated fields; this wrapper ignores all other keys (serde
/// ignores unknown fields by default) and only validates `[subscription]` via
/// `Core::reload_subscription_settings`.
fn extract_subscription(
    contents: &str,
) -> Result<Option<trusttunnel::subscription::SubscriptionSettings>, toml::de::Error> {
    let only: SubscriptionOnly = toml::from_str(contents)?;
    Ok(only.subscription)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    macro_rules! check {
        ($condition:expr $(,)?) => {
            check!(
                $condition,
                concat!("assertion failed: ", stringify!($condition))
            );
        };
        ($condition:expr, $message:expr $(,)?) => {
            if !$condition {
                return Err($message.into());
            }
        };
    }

    macro_rules! check_eq {
        ($left:expr, $right:expr $(,)?) => {{
            match (&$left, &$right) {
                (actual, expected) => {
                    if actual != expected {
                        return Err(format!(
                            "assertion failed: left {actual:?}, right {expected:?}"
                        )
                        .into());
                    }
                }
            }
        }};
    }

    #[test]
    fn equality_check_borrows_operands_once_and_retains_temporaries() -> TestResult {
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
        let mismatch = (|| -> TestResult {
            check_eq!(value.to_uppercase().as_bytes(), b"different");
            Ok(())
        })();
        check!(mismatch.is_err());
        Ok(())
    }

    fn temporary_path(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("trusttunnel_{name}_{}_{id}", std::process::id()))
    }

    fn path_as_str(path: &Path) -> io::Result<&str> {
        path.to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 test path"))
    }

    fn make_tls_hosts(
        hostnames: &[&str],
    ) -> Result<settings::TlsHostsSettings, Box<dyn std::error::Error>> {
        use std::fmt::Write as _;
        let tmp = temporary_path("cert.pem");
        std::fs::write(&tmp, b"")?;
        let path = path_as_str(&tmp)?;
        let mut entries = String::new();
        for h in hostnames {
            writeln!(entries,
                "[[main_hosts]]\nhostname = {h:?}\ncert_chain_path = {path:?}\nprivate_key_path = {path:?}"
            )?;
        }
        let result = toml::from_str(&entries);
        std::fs::remove_file(&tmp)?;
        Ok(result?)
    }

    #[test]
    fn test_extract_domain_ipv4_returns_none() -> TestResult {
        check_eq!(extract_domain_for_warning("1.2.3.4:443"), None);
        Ok(())
    }

    #[test]
    fn test_extract_domain_ipv6_returns_none() -> TestResult {
        check_eq!(extract_domain_for_warning("[::1]:443"), None);
        Ok(())
    }

    #[test]
    fn test_extract_domain_bare_ipv6_returns_none() -> TestResult {
        check_eq!(extract_domain_for_warning("::1"), None);
        Ok(())
    }

    #[test]
    fn test_extract_domain_with_port_returns_domain() -> TestResult {
        check_eq!(
            extract_domain_for_warning("vpn.example.com:443"),
            Some("vpn.example.com")
        );
        Ok(())
    }

    #[test]
    fn test_extract_domain_without_port_returns_domain() -> TestResult {
        check_eq!(
            extract_domain_for_warning("vpn.example.com"),
            Some("vpn.example.com")
        );
        Ok(())
    }

    #[test]
    fn test_domain_matches_tls_hosts_exact() -> TestResult {
        let hosts = make_tls_hosts(&["vpn.example.com"])?;
        check!(domain_matches_tls_hosts("vpn.example.com", &hosts));
        Ok(())
    }

    #[test]
    fn test_domain_matches_tls_hosts_no_match() -> TestResult {
        let hosts = make_tls_hosts(&["vpn.example.com"])?;
        check!(!domain_matches_tls_hosts("other.example.com", &hosts));
        Ok(())
    }

    #[test]
    fn test_domain_matches_tls_hosts_allowed_sni() -> TestResult {
        let tmp = temporary_path("allowed_sni.pem");
        std::fs::write(&tmp, b"")?;
        let path = path_as_str(&tmp)?;
        let toml = format!(
            "[[main_hosts]]\nhostname = \"vpn.example.com\"\ncert_chain_path = {path:?}\nprivate_key_path = {path:?}\nallowed_sni = [\"alias.example.com\"]\n"
        );
        let hosts: settings::TlsHostsSettings = toml::from_str(&toml)?;
        check!(domain_matches_tls_hosts("alias.example.com", &hosts));
        std::fs::remove_file(tmp)?;
        Ok(())
    }

    #[test]
    fn test_domain_matches_tls_hosts_different_host() -> TestResult {
        let hosts = make_tls_hosts(&["other.example.com"])?;
        check!(!domain_matches_tls_hosts("vpn.example.com", &hosts));
        Ok(())
    }

    #[test]
    fn test_parse_ipv4_with_port() -> TestResult {
        check_eq!(parse_endpoint_address("1.2.3.4:443", 8443)?, "1.2.3.4:443");
        Ok(())
    }

    #[test]
    fn test_parse_ipv4_without_port() -> TestResult {
        check_eq!(parse_endpoint_address("1.2.3.4", 443)?, "1.2.3.4:443");
        Ok(())
    }

    #[test]
    fn test_parse_ipv6_with_port() -> TestResult {
        check_eq!(parse_endpoint_address("[::1]:443", 8443)?, "[::1]:443");
        Ok(())
    }

    #[test]
    fn test_parse_ipv6_without_port() -> TestResult {
        check_eq!(parse_endpoint_address("::1", 443)?, "[::1]:443");
        Ok(())
    }

    #[test]
    fn test_parse_domain_with_port() -> TestResult {
        check_eq!(
            parse_endpoint_address("vpn.example.com:8443", 443)?,
            "vpn.example.com:8443"
        );
        Ok(())
    }

    #[test]
    fn test_parse_domain_without_port() -> TestResult {
        check_eq!(
            parse_endpoint_address("vpn.example.com", 443)?,
            "vpn.example.com:443"
        );
        Ok(())
    }

    #[test]
    fn test_parse_domain_default_port_applied() -> TestResult {
        check_eq!(
            parse_endpoint_address("my-vpn.example.org", 8443)?,
            "my-vpn.example.org:8443"
        );
        Ok(())
    }

    #[test]
    fn test_parse_domain_invalid_port() -> TestResult {
        let err = parse_endpoint_address("vpn.example.com:notaport", 443)
            .err()
            .ok_or("invalid port was accepted")?;
        check!(err.message.starts_with("Failed to parse port"));
        check_eq!(err.exit_code, ExitCode::from(101));
        Ok(())
    }

    #[test]
    fn test_parse_ipv6_with_port_bracket_notation() -> TestResult {
        check_eq!(
            parse_endpoint_address("[2001:db8::1]:443", 8443)?,
            "[2001:db8::1]:443"
        );
        Ok(())
    }

    #[test]
    fn test_parse_bare_ipv6_without_port_gets_default() -> TestResult {
        check_eq!(
            parse_endpoint_address("2001:db8::1", 443)?,
            "[2001:db8::1]:443"
        );
        Ok(())
    }

    #[test]
    fn test_extract_rules_file_path_resolves_relative_to_settings_file() -> TestResult {
        let settings_dir = temporary_path("settings_dir_relative");
        let settings_path = settings_dir.join("vpn.toml");
        let settings_contents = r#"rules_file = "rules.toml""#;

        let rules_path = extract_rules_file_path(settings_contents, path_as_str(&settings_path)?)
            .ok_or("rules path is missing")?;

        check_eq!(rules_path, settings_dir.join("rules.toml"));
        Ok(())
    }

    #[test]
    fn test_extract_rules_file_path_keeps_absolute_path() -> TestResult {
        let absolute_rules = temporary_path("absolute_rules.toml");
        let settings_path = temporary_path("settings.toml");
        let settings_contents = format!("rules_file = \"{}\"", absolute_rules.display());

        let rules_path = extract_rules_file_path(&settings_contents, path_as_str(&settings_path)?)
            .ok_or("rules path is missing")?;

        check_eq!(rules_path, absolute_rules);
        Ok(())
    }

    #[test]
    fn test_extract_rules_file_path_returns_none_without_rules_file() -> TestResult {
        check!(extract_rules_file_path("listen_address = \"127.0.0.1:443\"", "vpn.toml").is_none());
        Ok(())
    }

    #[test]
    fn test_append_allow_rule_creates_new_rule() -> TestResult {
        let rules_path = temporary_path("append_allow_rule_create.toml");

        append_allow_rule(&rules_path, "abcd/fff0")?;

        let contents = std::fs::read_to_string(&rules_path)?;
        check!(contents.contains("[[rule]]"));
        check!(contents.contains("client_random_prefix = \"abcd/fff0\""));
        check!(contents.contains("action = \"allow\""));

        std::fs::remove_file(&rules_path)?;
        Ok(())
    }

    #[test]
    fn test_append_allow_rule_appends_after_existing_allow() -> TestResult {
        let rules_path = temporary_path("append_allow_rule_append.toml");
        std::fs::write(
            &rules_path,
            "[[rule]]\ncidr = \"10.0.0.0/8\"\naction = \"allow\"\n",
        )?;

        append_allow_rule(&rules_path, "1234/ff00")?;

        let contents = std::fs::read_to_string(&rules_path)?;
        check!(contents.contains("cidr = \"10.0.0.0/8\""));
        check!(contents.contains("client_random_prefix = \"1234/ff00\""));

        std::fs::remove_file(&rules_path)?;
        Ok(())
    }

    #[test]
    fn test_append_allow_rule_inserts_before_catchall_deny() -> TestResult {
        let rules_path = temporary_path("append_allow_rule_before_catchall.toml");
        std::fs::write(&rules_path, "[[rule]]\naction = \"deny\"\n")?;

        append_allow_rule(&rules_path, "abcd/fff0")?;

        let contents = std::fs::read_to_string(&rules_path)?;
        let allow_pos = contents
            .find("client_random_prefix")
            .ok_or("missing allow rule")?;
        let deny_pos = contents
            .find("action = \"deny\"")
            .ok_or("missing deny rule")?;
        check!(
            allow_pos < deny_pos,
            "allow rule should appear before catch-all deny"
        );

        std::fs::remove_file(&rules_path)?;
        Ok(())
    }

    #[test]
    fn test_append_allow_rule_inserts_before_specific_deny() -> TestResult {
        let rules_path = temporary_path("append_allow_rule_specific_deny.toml");
        std::fs::write(
            &rules_path,
            "[[rule]]\ncidr = \"192.168.0.0/16\"\naction = \"deny\"\n",
        )?;

        append_allow_rule(&rules_path, "abcd/fff0")?;

        let contents = std::fs::read_to_string(&rules_path)?;
        let allow_pos = contents
            .find("client_random_prefix")
            .ok_or("missing allow rule")?;
        let deny_pos = contents
            .find("action = \"deny\"")
            .ok_or("missing deny rule")?;
        check!(
            allow_pos < deny_pos,
            "allow rule should appear before any existing rule"
        );

        std::fs::remove_file(&rules_path)?;
        Ok(())
    }

    #[test]
    fn extract_subscription_parses_enabled_section() -> TestResult {
        let toml = "[subscription]\nenabled = true\nhostname = \"vpn.example.com\"\naddress = \"1.2.3.4:443\"\n";
        let sub = extract_subscription(toml)?.ok_or("missing subscription")?;
        check!(sub.enabled);
        check_eq!(sub.hostname.as_deref(), Some("vpn.example.com"));
        check_eq!(sub.path, "/subscription");
        Ok(())
    }

    #[test]
    fn extract_subscription_returns_none_when_absent() -> TestResult {
        let toml = "listen_address = \"0.0.0.0:443\"\n";
        check!(extract_subscription(toml)?.is_none());
        Ok(())
    }

    #[test]
    fn extract_subscription_ignores_other_keys() -> TestResult {
        let toml = "listen_address = \"0.0.0.0:443\"\n[subscription]\nenabled = true\n";
        let sub = extract_subscription(toml)?.ok_or("missing subscription")?;
        check!(sub.enabled);
        Ok(())
    }

    #[test]
    fn cli_version_preserves_flags_and_output() -> TestResult {
        for flag in ["-v", "--version"] {
            let args = command().try_get_matches_from(["endpoint", flag])?;
            check!(args.get_flag(VERSION_PARAM_NAME));
            let mut output = Vec::new();
            check_eq!(write_version(&mut output)?, ExitCode::SUCCESS);
            check_eq!(output, format!("{VERSION_STRING}\n").as_bytes());
        }
        Ok(())
    }

    #[test]
    fn cli_defaults_and_repeated_export_flags_are_preserved() -> TestResult {
        let args = command().try_get_matches_from([
            "endpoint",
            "vpn.toml",
            "hosts.toml",
            "-c",
            "alice",
            "-a",
            "1.2.3.4",
            "--address",
            "[::1]:8443",
            "-d",
            "1.1.1.1",
            "--dns-upstream",
            "tls://8.8.8.8",
            "-s",
            "alias.example.com",
            "-r",
            "abcd/fff0",
            "-n",
            "My VPN",
            "--jobs",
            "2",
            "--loglvl",
            "debug",
            "--logfile",
            "endpoint.log",
            "--sentry_dsn",
            "https://example.com/1",
        ])?;
        check_eq!(
            required_argument::<String>(&args, SETTINGS_PARAM_NAME)?,
            "vpn.toml"
        );
        check_eq!(
            required_argument::<String>(&args, TLS_HOSTS_SETTINGS_PARAM_NAME)?,
            "hosts.toml"
        );
        check_eq!(
            required_argument::<String>(&args, CLIENT_CONFIG_PARAM_NAME)?,
            "alice"
        );
        check_eq!(
            required_argument::<String>(&args, FORMAT_PARAM_NAME)?,
            "deeplink"
        );
        check_eq!(
            *required_argument::<usize>(&args, PREFIX_LENGTH_PARAM_NAME)?,
            4
        );
        check_eq!(
            *required_argument::<u8>(&args, PREFIX_PERCENT_PARAM_NAME)?,
            70
        );
        check_eq!(
            *required_argument::<usize>(&args, THREADS_NUM_PARAM_NAME)?,
            2
        );
        check_eq!(
            args.get_many::<String>(ADDRESS_PARAM_NAME)
                .ok_or("missing addresses")?
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["1.2.3.4", "[::1]:8443"]
        );
        check_eq!(
            args.get_many::<String>(DNS_UPSTREAM_PARAM_NAME)
                .ok_or("missing DNS upstreams")?
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["1.1.1.1", "tls://8.8.8.8"]
        );
        Ok(())
    }

    #[test]
    fn cli_help_and_usage_exit_codes_are_preserved() -> TestResult {
        for (arguments, exit_code) in [
            (vec!["endpoint", "--help"], 0),
            (vec!["endpoint"], 2),
            (
                vec![
                    "endpoint",
                    "vpn.toml",
                    "hosts.toml",
                    "-c",
                    "alice",
                    "-f",
                    "json",
                ],
                2,
            ),
            (
                vec!["endpoint", "vpn.toml", "hosts.toml", "-a", "1.2.3.4"],
                2,
            ),
            (
                vec![
                    "endpoint",
                    "vpn.toml",
                    "hosts.toml",
                    "-c",
                    "alice",
                    "-r",
                    "abcd",
                    "--client-random-auth-key",
                    "abcd",
                ],
                2,
            ),
        ] {
            let err = command()
                .try_get_matches_from(arguments)
                .err()
                .ok_or("invalid CLI accepted")?;
            check_eq!(err.exit_code(), exit_code);
        }
        Ok(())
    }

    #[test]
    fn cli_errors_preserve_diagnostics_and_statuses() -> TestResult {
        let mut output = Vec::new();
        check_eq!(
            report_result(Err(CliError::failure("Error: invalid export")), &mut output)?,
            ExitCode::FAILURE
        );
        check_eq!(output, b"Error: invalid export\n");
        output.clear();
        check_eq!(
            report_result(
                Err(CliError::fatal("Couldn't read the settings file")),
                &mut output
            )?,
            ExitCode::from(101)
        );
        check_eq!(output, b"Couldn't read the settings file\n");
        output.clear();
        check_eq!(
            report_result(Ok(ExitCode::SUCCESS), &mut output)?,
            ExitCode::SUCCESS
        );
        check!(output.is_empty());
        Ok(())
    }

    #[test]
    fn deeplink_output_preserves_qr_url_and_newlines() -> TestResult {
        let mut output = Vec::new();
        write_deeplink("tt://?encoded", &mut output)?;
        check_eq!(output, b"tt://?encoded\n\nTo connect on mobile, you can scan QR code on the page: https://trusttunnel.org/qr.html#tt=encoded\n");
        Ok(())
    }

    #[test]
    fn client_export_writers_preserve_toml_and_deeplink_bytes() -> TestResult {
        let cert_path = temporary_path("export_cert.pem");
        std::fs::write(&cert_path, b"")?;
        let path = path_as_str(&cert_path)?;
        let hosts = toml::from_str(&format!(
            "[[main_hosts]]\nhostname = 'vpn.example.com'\ncert_chain_path = {path:?}\nprivate_key_path = {path:?}\n"
        ))?;
        let client = toml::from_str("username = 'alice'\npassword = 'test-password'\n")?;
        let config = client_config::build(
            "alice",
            vec!["1.2.3.4:443".into()],
            &[client],
            &hosts,
            client_config::BuildOptions {
                subscription_url: Some(
                    "https://alice:test-password@sub.example.com/subscription".into(),
                ),
                ..Default::default()
            },
        )?;
        let mut output = Vec::new();
        write_client_config(&config, "toml", false, &mut output)?;
        check_eq!(output, format!("{}\n", config.compose_toml()).as_bytes());
        let parsed: toml::Value = toml::from_str(std::str::from_utf8(&output)?)?;
        check_eq!(parsed["username"].as_str(), Some("alice"));
        check_eq!(
            parsed["addresses"]
                .as_array()
                .ok_or("missing addresses")?
                .len(),
            1
        );
        for subscription_only in [false, true] {
            output.clear();
            write_client_config(&config, "deeplink", subscription_only, &mut output)?;
            let deep_link = if subscription_only {
                config.compose_deeplink_subscription_only()?
            } else {
                config.compose_deeplink()?
            };
            let payload = deep_link
                .strip_prefix("tt://?")
                .ok_or("missing deep-link prefix")?;
            check_eq!(output, format!(
                "{deep_link}\n\nTo connect on mobile, you can scan QR code on the page: {TRUSTTUNNEL_QR_URL}#tt={payload}\n"
            ).as_bytes());
        }
        std::fs::remove_file(cert_path)?;
        Ok(())
    }

    #[test]
    fn output_failures_are_not_swallowed() -> TestResult {
        let mut storage = [];
        let mut output = io::Cursor::new(storage.as_mut_slice());
        let err = write_version(&mut output)
            .err()
            .ok_or("output failure was swallowed")?;
        check_eq!(err.exit_code, ExitCode::from(101));
        check!(report_result(Err(err), &mut output).is_err());
        check!(write_deeplink("tt://?encoded", &mut output).is_err());
        Ok(())
    }

    #[test]
    fn prefix_rule_mask_compatibility_is_preserved() -> TestResult {
        check!(prefix_matches_rule("abcd", None, "abcd"));
        check!(prefix_matches_rule("abcd", Some("fff0"), "abcd"));
        check!(prefix_matches_rule("abcd", None, "abcd/fff0"));
        check!(prefix_matches_rule("abcd", Some("fff0"), "abcd/fff0"));
        check!(prefix_matches_rule("abcd", Some("ffff"), "abcd/fff0"));
        check!(!prefix_matches_rule("abcd", Some("ff00"), "abcd/fff0"));
        check!(!prefix_matches_rule("abcd", Some("ff"), "abcd/fff0"));
        check!(!prefix_matches_rule("abce", None, "abcd"));
        check!(!prefix_matches_rule("abcd", Some("zz"), "abcd/fff0"));
        Ok(())
    }

    #[test]
    fn prefix_and_auth_key_validation_preserves_errors_and_redaction() -> TestResult {
        let settings: Settings = toml::from_str("[listen_protocols]\n")?;
        for (prefix, message) in [
            ("zz", "Error: client_random_prefix 'zz' is not valid hex"),
            (
                "abcd/",
                "Error: client_random_prefix mask '' is not valid hex",
            ),
            (
                "abcd/zz",
                "Error: client_random_prefix mask 'zz' is not valid hex",
            ),
        ] {
            let err = validate_client_random_prefix(prefix, &settings)
                .err()
                .ok_or("invalid prefix accepted")?;
            check_eq!(err.message, message);
            check_eq!(err.exit_code, ExitCode::FAILURE);
        }
        let err = validate_client_random_auth_key("SECRET-not-hex", &settings)
            .err()
            .ok_or("invalid key accepted")?;
        check_eq!(
            err.message,
            "Error: client_random_auth_key is not valid hex"
        );
        check!(!err.to_string().contains("SECRET"));
        Ok(())
    }

    #[test]
    fn generated_prefix_updates_rules_and_preserves_confirmation() -> TestResult {
        let rules_path = temporary_path("generated_prefix.toml");
        let settings_contents = format!("rules_file = {:?}", path_as_str(&rules_path)?);
        std::fs::write(&rules_path, "[[rule]]\naction = \"deny\"\n")?;
        let args = command().try_get_matches_from([
            "endpoint",
            "vpn.toml",
            "hosts.toml",
            "-c",
            "alice",
            "--generate-client-random-prefix",
            "--prefix-mask",
            "fff0",
        ])?;
        let mut output = Vec::new();
        let prefix =
            generate_client_random_prefix(&args, &settings_contents, "vpn.toml", &mut output)?
                .ok_or("prefix was not generated")?;
        check!(prefix.ends_with("/fff0"));
        check_eq!(
            output,
            format!("Added allow rule to '{}': {prefix}\n", rules_path.display()).as_bytes()
        );
        let contents = std::fs::read_to_string(&rules_path)?;
        let doc: Document = contents.parse()?;
        let rules = doc["rule"].as_array_of_tables().ok_or("missing rules")?;
        let mut rules = rules.iter();
        let allow = rules.next().ok_or("missing generated rule")?;
        check_eq!(
            allow["client_random_prefix"].as_str(),
            Some(prefix.as_str())
        );
        check_eq!(allow["action"].as_str(), Some("allow"));
        check_eq!(
            rules.next().ok_or("missing deny rule")?["action"].as_str(),
            Some("deny")
        );
        std::fs::remove_file(rules_path)?;
        Ok(())
    }

    #[test]
    fn append_allow_rule_does_not_overwrite_invalid_or_unreadable_input() -> TestResult {
        let path = temporary_path("invalid_rules.toml");
        std::fs::write(&path, "invalid = [")?;
        check!(append_allow_rule(&path, "abcd/fff0").is_err());
        check_eq!(std::fs::read_to_string(&path)?, "invalid = [");
        std::fs::remove_file(&path)?;
        std::fs::create_dir(&path)?;
        check!(append_allow_rule(&path, "abcd/fff0").is_err());
        check!(path.is_dir());
        std::fs::remove_dir(path)?;
        Ok(())
    }

    #[test]
    fn subscription_only_constraints_and_override_are_preserved() -> TestResult {
        let args = command().try_get_matches_from([
            "endpoint",
            "vpn.toml",
            "hosts.toml",
            "-c",
            "alice",
            "--subscription-only",
            "-f",
            "toml",
        ])?;
        let err = validate_subscription_only(&args, true, None)
            .err()
            .ok_or("TOML subscription-only export accepted")?;
        check_eq!(
            err.message,
            "Error: --subscription-only is only valid with --format deeplink."
        );
        let args = command().try_get_matches_from([
            "endpoint",
            "vpn.toml",
            "hosts.toml",
            "-c",
            "alice",
            "--subscription-only",
            "--subscription-url",
            "https://sub.example.com/subscription",
        ])?;
        let err = validate_subscription_only(&args, false, None)
            .err()
            .ok_or("disabled subscription accepted")?;
        check_eq!(
            err.message,
            "Error: --subscription-only requires [subscription] to be enabled in vpn.toml."
        );
        let host = settings::TlsHostInfo {
            hostname: "vpn.example.com".into(),
            ..Default::default()
        };
        validate_subscription_only(&args, true, Some(&host))?;
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_completion_releases_the_coordinator_lock() -> TestResult {
        let shutdown = Shutdown::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            complete_shutdown(&shutdown),
        )
        .await??;
        check!(shutdown.try_lock().is_ok());
        Ok(())
    }

    fn sub_settings(
        enabled: bool,
        hostname: Option<&str>,
        address: Option<&str>,
    ) -> trusttunnel::subscription::SubscriptionSettings {
        trusttunnel::subscription::SubscriptionSettings {
            enabled,
            hostname: hostname.map(str::to_string),
            address: address.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn select_addresses_explicit_wins() -> TestResult {
        let explicit = vec!["1.2.3.4:443".to_string(), "10.0.0.1:8443".to_string()];
        let sub = sub_settings(true, Some("vpn.example.com"), Some("5.6.7.8:443"));
        let result = select_client_addresses(&explicit, Some(&sub), 443)?;
        check_eq!(result, explicit);
        Ok(())
    }

    #[test]
    fn select_addresses_falls_back_to_subscription() -> TestResult {
        let sub = sub_settings(true, Some("vpn.example.com"), Some("5.6.7.8:8000"));
        let result = select_client_addresses(&[], Some(&sub), 443)?;
        check_eq!(result, vec!["5.6.7.8:8000".to_string()]);
        Ok(())
    }

    #[test]
    fn select_addresses_subscription_fallback_gets_listen_port_when_missing() -> TestResult {
        let sub = sub_settings(true, Some("vpn.example.com"), Some("5.6.7.8"));
        let result = select_client_addresses(&[], Some(&sub), 8443)?;
        check_eq!(result, vec!["5.6.7.8:8443".to_string()]);
        Ok(())
    }

    #[test]
    fn select_addresses_errors_without_address_and_subscription() -> TestResult {
        check!(select_client_addresses(&[], None, 443).is_err());
        Ok(())
    }

    #[test]
    fn select_addresses_errors_when_subscription_disabled() -> TestResult {
        let sub = sub_settings(false, Some("vpn.example.com"), Some("5.6.7.8:443"));
        check!(select_client_addresses(&[], Some(&sub), 443).is_err());
        Ok(())
    }

    #[test]
    fn select_addresses_errors_when_subscription_has_no_address() -> TestResult {
        let sub = sub_settings(true, Some("vpn.example.com"), None);
        check!(select_client_addresses(&[], Some(&sub), 443).is_err());
        Ok(())
    }
}
