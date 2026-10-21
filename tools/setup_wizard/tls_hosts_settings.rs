use crate::acme::{
    issue_certificate, validate_domain, validate_email, AcmeConfig, ChallengeMethod, IssuedCert,
};
use crate::user_interaction::{ask_for_agreement, ask_for_input, checked_overwrite, select_index};
use crate::{Mode, PredefinedParameters, WizardResult};
use chrono::{Datelike, Duration, Local};
use rcgen::DnType;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use trusttunnel::settings::{TlsHostInfo, TlsHostsSettings};
use trusttunnel::utils;
use trusttunnel::utils::Either;
use x509_parser::extensions::GeneralName;

const DEFAULT_CERTIFICATE_DURATION_DAYS: u64 = 365;
const DEFAULT_CERTIFICATE_FOLDER: &str = "certs";
const DEFAULT_HOSTNAME: &str = "vpn.endpoint";

pub struct TlsHostsSettingsResult {
    pub settings: TlsHostsSettings,
    pub cert_path: String,
    pub key_path: String,
}

pub fn build() -> WizardResult<TlsHostsSettingsResult> {
    loop {
        if let Some(cert) = build_with_runtime()? {
            let cert_path = cert.cert_path.clone();
            let key_path = cert.key_path.clone();
            return Ok(TlsHostsSettingsResult {
                settings: build_settings_from_cert(cert)?,
                cert_path,
                key_path,
            });
        }
        // In non-interactive mode, we can't retry
        if crate::get_mode() == Mode::NonInteractive {
            return Err(io::Error::other("Certificate is required in non-interactive mode").into());
        }
        writeln!(
            io::stdout().lock(),
            "\nNo certificate was created. Let's try again.\n"
        )?;
    }
}

fn build_with_runtime() -> WizardResult<Option<Certificate>> {
    // Check for non-interactive mode with ACME parameters
    if crate::get_mode() == Mode::NonInteractive {
        // Check if Let's Encrypt is requested via CLI
        if let Some(ref cert_type) = crate::get_predefined_params().cert_type {
            if cert_type == "provided" {
                return load_provided_cert_noninteractive();
            }
            if cert_type == "letsencrypt" {
                return generate_letsencrypt_cert_noninteractive();
            }
        }
        // Default to self-signed for non-interactive
        return generate_cert();
    }

    // Interactive mode
    if let Some(x) = lookup_existent_cert()? {
        if ask_for_agreement(&format!("Use an existing certificate? {x:?}"))? {
            return Ok(Some(x));
        }
    }
    let options = [
        "Issue a Let's Encrypt certificate (requires a public domain)",
        "Generate a self-signed certificate",
        "Provide path to existing certificate",
    ];

    let selection = select_index(
        "How would you like to create a certificate?",
        &options,
        Some(0),
    )?;

    match selection {
        0 => generate_letsencrypt_cert(),
        1 => generate_cert(),
        2 => ask_for_existing_cert(),
        _ => Err(io::Error::other("Invalid certificate selection").into()),
    }
}

fn ask_for_existing_cert() -> WizardResult<Option<Certificate>> {
    let pair = ask_for_input::<String>(
        "Path to certificate file(s):\n  \
         - Single file containing both cert and key: /path/to/combined.pem\n  \
         - Separate files: /path/to/cert.pem /path/to/key.pem\n",
        None,
    )?;

    let x = pair.split_once(char::is_whitespace).map_or_else(
        || Either::Left(pair.as_str()),
        |(a, b)| Either::Right((a, b)),
    );

    let x = parse_cert(x)?;
    if x.is_none() {
        writeln!(
            io::stdout().lock(),
            "Couldn't parse the provided key/certificate pair"
        )?;
    }
    Ok(x)
}

fn build_settings_from_cert(cert: Certificate) -> WizardResult<TlsHostsSettings> {
    let allowed_sni = ask_for_alternative_snis()?;

    Ok(TlsHostsSettings::builder()
        .main_hosts(vec![TlsHostInfo {
            hostname: cert.common_name,
            cert_chain_path: cert.cert_path,
            private_key_path: cert.key_path,
            allowed_sni,
        }])
        .build()
        .map_err(|error| {
            io::Error::other(format!("Couldn't build TLS hosts settings: {error:?}"))
        })?)
}

#[derive(Clone)]
struct Certificate {
    common_name: String,
    // needed only for logging
    alt_names: Vec<String>,
    // needed only for logging
    expiration_date: String,
    cert_path: String,
    key_path: String,
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cert")
            .field("common_name", &self.common_name)
            .field("alt_names", &self.alt_names)
            .field("expiration_date", &self.expiration_date)
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .finish()
    }
}

fn lookup_existent_cert() -> io::Result<Option<Certificate>> {
    let Ok(files) = fs::read_dir(DEFAULT_CERTIFICATE_FOLDER) else {
        return Ok(None);
    };
    let files = files
        .filter_map(Result::ok)
        .filter(|entry| entry.metadata().is_ok_and(|meta| meta.is_file()))
        .filter_map(|entry| entry.path().to_str().map(String::from))
        .collect::<Vec<_>>();

    let cert_key_pair = match files.as_slice() {
        [a] => Either::Left(a.as_str()),
        [a, b] => Either::Right((a.as_str(), b.as_str())),
        _ => return Ok(None),
    };

    parse_cert(cert_key_pair)
}

fn print_cert_error(path: &str, error: &std::io::Error) -> io::Result<()> {
    let message = match error.kind() {
        std::io::ErrorKind::PermissionDenied => {
            format!("Permission denied: cannot read '{path}'")
        }
        std::io::ErrorKind::NotFound => {
            format!("File not found: '{path}'")
        }
        std::io::ErrorKind::InvalidInput => {
            format!("Invalid certificate or key format in '{path}': {error}")
        }
        _ => {
            format!("Failed to read '{path}': {error}")
        }
    };
    writeln!(io::stderr().lock(), "Error: {message}")
}

fn parse_cert(cert: Either<&str, (&str, &str)>) -> io::Result<Option<Certificate>> {
    let (chain, cert_path, key_path) = match cert {
        Either::Left(pair) => {
            match utils::load_private_key(pair).and_then(|_| utils::load_certs(pair)) {
                Ok(chain) => (chain, pair, pair),
                Err(error) => {
                    print_cert_error(pair, &error)?;
                    return Ok(None);
                }
            }
        }
        Either::Right((a, b)) => match (
            utils::load_certs(a),
            utils::load_private_key(b),
            utils::load_certs(b),
            utils::load_private_key(a),
        ) {
            (Ok(chain), Ok(_), _, _) => (chain, a, b),
            (_, _, Ok(chain), Ok(_)) => (chain, b, a),
            (Err(error), _, _, _) => {
                print_cert_error(a, &error)?;
                return Ok(None);
            }
            (_, Err(error), _, _) => {
                print_cert_error(b, &error)?;
                return Ok(None);
            }
        },
    };

    let Some(first) = chain.first() else {
        return Ok(None);
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(first.as_ref()) else {
        return Ok(None);
    };
    if !cert.validity.is_valid() {
        return Ok(None);
    }
    let x = cert.subject.to_string();
    Ok(Some(Certificate {
        common_name: x
            .strip_prefix("CN=")
            .map_or_else(|| x.clone(), String::from),
        alt_names: cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .map_or_default(|x| {
                x.value
                    .general_names
                    .iter()
                    .map(GeneralName::to_string)
                    .collect()
            }),
        expiration_date: cert.validity.not_after.to_string(),
        cert_path: cert_path.into(),
        key_path: key_path.into(),
    }))
}

fn generate_cert() -> WizardResult<Option<Certificate>> {
    let (common_name, alt_names) = {
        writeln!(
            io::stdout().lock(),
            "Let's generate a self-signed certificate."
        )?;
        let name = crate::get_predefined_params()
            .hostname
            .clone()
            .map_or_else(
                || {
                    ask_for_input::<String>(
                        "Endpoint hostname (used for serving TLS connections)",
                        Some(DEFAULT_HOSTNAME.into()),
                    )
                },
                Ok,
            )?;
        (name.clone(), vec![name.clone(), format!("*.{name}")])
    };
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    let mut params = rcgen::CertificateParams::new(alt_names.clone())?;
    let now = chrono::Local::now();
    let end_date = now
        .checked_add_days(chrono::Days::new(DEFAULT_CERTIFICATE_DURATION_DAYS))
        .ok_or_else(|| io::Error::other("Certificate expiration date is out of range"))?;
    params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    params.not_after = rcgen::date_time_ymd(
        end_date.year(),
        end_date.month() as u8,
        end_date.day() as u8,
    );
    params
        .distinguished_name
        .push(DnType::CommonName, &common_name);

    let cert = params.self_signed(&key_pair)?;
    let cert_path = format!("{DEFAULT_CERTIFICATE_FOLDER}/cert.pem");
    if !checked_overwrite(&cert_path, "Overwrite the existing certificate file?")? {
        return Ok(None);
    }

    let key_path = format!("{DEFAULT_CERTIFICATE_FOLDER}/key.pem");
    if !checked_overwrite(&key_path, "Overwrite the existing private key file?")? {
        return Ok(None);
    }

    fs::create_dir_all(DEFAULT_CERTIFICATE_FOLDER)?;
    fs::write(&cert_path, cert.pem())?;
    writeln!(
        io::stdout().lock(),
        "The generated certificate is stored in file: {cert_path}"
    )?;

    if key_path == cert_path {
        fs::OpenOptions::new()
            .append(true)
            .open(&key_path)?
            .write_all(key_pair.serialize_pem().as_bytes())?;
    } else {
        fs::write(&key_path, key_pair.serialize_pem())?;
    }
    writeln!(
        io::stdout().lock(),
        "The generated private key is stored in file: {key_path}"
    )?;

    Ok(Some(Certificate {
        common_name,
        alt_names,
        expiration_date: end_date.to_string(),
        cert_path,
        key_path,
    }))
}

fn save_issued_cert(issued: IssuedCert, interactive: bool) -> WizardResult<Option<Certificate>> {
    let cert_path = format!("{DEFAULT_CERTIFICATE_FOLDER}/cert.pem");
    let key_path = format!("{DEFAULT_CERTIFICATE_FOLDER}/key.pem");

    if interactive {
        if !checked_overwrite(&cert_path, "Overwrite the existing certificate file?")? {
            return Ok(None);
        }
        if !checked_overwrite(&key_path, "Overwrite the existing private key file?")? {
            return Ok(None);
        }
    }

    fs::create_dir_all(DEFAULT_CERTIFICATE_FOLDER)?;

    fs::write(&cert_path, &issued.cert_pem)?;
    writeln!(io::stdout().lock(), "Certificate saved to: {cert_path}")?;

    fs::write(&key_path, &issued.key_pem)?;
    writeln!(io::stdout().lock(), "Private key saved to: {key_path}")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_path, perms)?;
    }

    let expiration_date = parse_cert_expiration(&issued.cert_pem).unwrap_or_else(|| {
        Local::now()
            .checked_add_signed(Duration::days(90))
            .map_or_else(
                || "90 days from now".to_string(),
                |d| d.format("%Y-%m-%d").to_string(),
            )
    });

    Ok(Some(Certificate {
        common_name: issued.domain.clone(),
        alt_names: vec![issued.domain],
        expiration_date,
        cert_path,
        key_path,
    }))
}

fn print_acme_error(e: &crate::acme::AcmeError) -> io::Result<()> {
    writeln!(
        io::stdout().lock(),
        "\n❌ Failed to issue Let's Encrypt certificate: {e}"
    )?;
    writeln!(io::stdout().lock(), "\nPossible solutions:")?;
    match e {
        crate::acme::AcmeError::PortInUse(_) => {
            writeln!(
                io::stdout().lock(),
                "  • Stop any service using port 80, or"
            )?;
            writeln!(io::stdout().lock(), "  • Use DNS-01 challenge instead")?;
        }
        crate::acme::AcmeError::ChallengeFailed(_) => {
            writeln!(
                io::stdout().lock(),
                "  • Verify your domain resolves to this server's IP"
            )?;
            writeln!(
                io::stdout().lock(),
                "  • Check firewall allows inbound HTTP (port 80)"
            )?;
            writeln!(
                io::stdout().lock(),
                "  • For DNS-01, ensure TXT record is correct and propagated"
            )?;
        }
        _ => {
            writeln!(io::stdout().lock(), "  • Check your internet connection")?;
            writeln!(
                io::stdout().lock(),
                "  • Try using the staging environment first"
            )?;
        }
    }
    Ok(())
}

fn generate_letsencrypt_cert() -> WizardResult<Option<Certificate>> {
    writeln!(
        io::stdout().lock(),
        "Let's issue a Let's Encrypt certificate."
    )?;

    // Get domain name
    let domain: String = loop {
        let domain: String =
            ask_for_input("Enter your domain name (must be publicly accessible)", None)?;
        if validate_domain(&domain) {
            break domain;
        }
        writeln!(
            io::stdout().lock(),
            "Invalid domain format. Please enter a valid domain name (e.g., vpn.example.com)."
        )?;
    };

    // Get email address
    let email: String = loop {
        let email: String = ask_for_input(
            "Enter your email address (for Let's Encrypt notifications)",
            None,
        )?;
        if validate_email(&email) {
            break email;
        }
        writeln!(
            io::stdout().lock(),
            "Invalid email format. Please try again."
        )?;
    };

    // Select challenge method
    let challenge_options = [
        "HTTP-01 (requires port 80 accessible from internet)",
        "DNS-01 (requires adding a TXT record to your DNS)",
    ];
    let challenge_selection = select_index("Select challenge method", &challenge_options, Some(0))?;
    let challenge_method = match challenge_selection {
        0 => ChallengeMethod::Http01,
        1 => ChallengeMethod::Dns01,
        _ => return Err(io::Error::other("Invalid challenge selection").into()),
    };

    // Ask about staging environment
    let use_staging = ask_for_agreement(
        "Use Let's Encrypt staging environment for testing? (recommended for first attempt)",
    )?;

    if use_staging {
        writeln!(
            io::stdout().lock(),
            "\n⚠️  Using staging environment. Certificate will NOT be trusted by browsers."
        )?;
        writeln!(
            io::stdout().lock(),
            "   Run again without staging for a production certificate.\n"
        )?;
    }

    let config = AcmeConfig {
        domain,
        email,
        challenge_method,
        use_staging,
    };

    // Run the async ACME flow
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(issue_certificate(&config));

    match result {
        Ok(issued) => save_issued_cert(issued, true),
        Err(ref e) => {
            print_acme_error(e)?;

            if ask_for_agreement("Would you like to generate a self-signed certificate instead?")? {
                generate_cert()
            } else {
                Ok(None)
            }
        }
    }
}

fn noninteractive_acme_config(predefined: &PredefinedParameters) -> io::Result<AcmeConfig> {
    let domain = predefined.hostname.clone().ok_or_else(|| {
        io::Error::other("Hostname is required for Let's Encrypt in non-interactive mode")
    })?;
    if !validate_domain(&domain) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid domain format: {domain}"),
        ));
    }
    let email = predefined.acme_email.clone().ok_or_else(|| {
        io::Error::other("ACME email is required for Let's Encrypt in non-interactive mode")
    })?;
    if !validate_email(&email) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid email format: {email}"),
        ));
    }
    let challenge_method = predefined
        .acme_challenge
        .as_deref()
        .map(str::parse::<ChallengeMethod>)
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(ChallengeMethod::Http01);
    if challenge_method == ChallengeMethod::Dns01 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS-01 challenge is not supported in non-interactive mode (requires manual DNS record confirmation)"));
    }

    Ok(AcmeConfig {
        domain,
        email,
        challenge_method,
        use_staging: predefined.acme_staging,
    })
}

fn generate_letsencrypt_cert_noninteractive() -> WizardResult<Option<Certificate>> {
    let config = noninteractive_acme_config(crate::get_predefined_params())?;
    if config.use_staging {
        writeln!(
            io::stdout().lock(),
            "⚠️  Using Let's Encrypt staging environment"
        )?;
    }

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(issue_certificate(&config));

    match result {
        Ok(issued) => save_issued_cert(issued, false),
        Err(e) => {
            writeln!(
                io::stderr().lock(),
                "Failed to issue Let's Encrypt certificate: {e}"
            )?;
            Ok(None)
        }
    }
}

fn load_provided_cert_noninteractive() -> WizardResult<Option<Certificate>> {
    let predefined = crate::get_predefined_params();
    let cert_chain_path = predefined.cert_chain_path.clone().ok_or_else(|| {
        io::Error::other("Certificate chain path is required for provided cert type")
    })?;
    let cert_key_path = predefined.cert_key_path.clone().ok_or_else(|| {
        io::Error::other("Certificate key path is required for provided cert type")
    })?;

    let cert = parse_cert(Either::Right((&cert_chain_path, &cert_key_path)))?;
    if cert.is_none() {
        writeln!(
            io::stderr().lock(),
            "Failed to load provided certificate and key from '{cert_chain_path}' and '{cert_key_path}'"
        )?;
    }

    Ok(cert)
}

fn parse_cert_expiration(cert_pem: &str) -> Option<String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).ok()?;
    let not_after = cert.validity.not_after.to_datetime();
    Some(format!(
        "{:04}-{:02}-{:02}",
        not_after.year(),
        not_after.month(),
        not_after.day()
    ))
}

fn ask_for_alternative_snis() -> io::Result<Vec<String>> {
    if crate::get_mode() == Mode::NonInteractive {
        return Ok(vec![]);
    }

    if !ask_for_agreement("Do you want to configure alternative SNIs?")? {
        return Ok(vec![]);
    }

    let input: String = ask_for_input(
        "Enter alternative SNIs (comma-separated)",
        Some(String::new()),
    )?;

    if input.trim().is_empty() {
        return Ok(vec![]);
    }

    Ok(input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{noninteractive_acme_config, Certificate};
    use crate::acme::ChallengeMethod;
    use crate::PredefinedParameters;

    #[test]
    fn certificate_debug_preserves_existing_field_names() -> crate::WizardResult<()> {
        let certificate = Certificate {
            common_name: "vpn.example.com".to_owned(),
            alt_names: vec!["vpn.example.com".to_owned()],
            expiration_date: "2030-01-01".to_owned(),
            cert_path: "cert.pem".to_owned(),
            key_path: "key.pem".to_owned(),
        };
        check_eq!(
            format!("{certificate:?}"),
            r#"Cert { common_name: "vpn.example.com", alt_names: ["vpn.example.com"], expiration_date: "2030-01-01", cert_path: "cert.pem", key_path: "key.pem" }"#
        );
        Ok(())
    }

    #[test]
    fn noninteractive_acme_preserves_http01_and_staging() -> crate::WizardResult<()> {
        let params = PredefinedParameters {
            hostname: Some("vpn.example.com".to_owned()),
            acme_email: Some("admin@example.com".to_owned()),
            acme_staging: true,
            ..PredefinedParameters::default()
        };
        let config = noninteractive_acme_config(&params)?;
        check_eq!(config.domain, "vpn.example.com");
        check_eq!(config.email, "admin@example.com");
        check_eq!(config.challenge_method, ChallengeMethod::Http01);
        check!(config.use_staging);
        Ok(())
    }

    #[test]
    fn noninteractive_acme_rejects_missing_invalid_or_manual_parameters() {
        let mut params = PredefinedParameters::default();
        assert!(noninteractive_acme_config(&params).is_err());
        params.hostname = Some("vpn.example.com".to_owned());
        assert!(noninteractive_acme_config(&params).is_err());
        params.acme_email = Some("admin@example.com".to_owned());
        for challenge in ["dns-01", "unknown"] {
            params.acme_challenge = Some(challenge.to_owned());
            assert!(noninteractive_acme_config(&params).is_err());
        }
        params.acme_challenge = None;
        params.hostname = Some("-invalid.example.com".to_owned());
        assert!(noninteractive_acme_config(&params).is_err());
        params.hostname = Some("vpn.example.com".to_owned());
        params.acme_email = Some("invalid".to_owned());
        assert!(noninteractive_acme_config(&params).is_err());
    }
}
