use crate::acme_http_server::run_http01_challenge_server;
use crate::user_interaction::ask_for_agreement;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use std::io::{self, Write};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeMethod {
    Http01,
    Dns01,
}

impl std::fmt::Display for ChallengeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http01 => write!(f, "http-01"),
            Self::Dns01 => write!(f, "dns-01"),
        }
    }
}

impl std::str::FromStr for ChallengeMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "http-01" | "http01" => Ok(Self::Http01),
            "dns-01" | "dns01" => Ok(Self::Dns01),
            _ => Err(format!("Unknown challenge method: {s}")),
        }
    }
}

#[derive(Debug)]
pub struct AcmeConfig {
    pub domain: String,
    pub email: String,
    pub challenge_method: ChallengeMethod,
    pub use_staging: bool,
}

pub struct IssuedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub domain: String,
}

#[derive(Debug)]
pub enum AcmeError {
    AccountCreation(String),
    OrderCreation(String),
    Authorization(String),
    ChallengeNotFound(ChallengeType),
    ChallengeFailed(String),
    CsrGeneration(String),
    Finalization(String),
    CertificateDownload(String),
    Timeout(String),
    PortInUse(u16),
    PermissionDenied(u16),
    Other(String),
    Io(io::Error),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccountCreation(e) => write!(f, "Failed to create ACME account: {e}"),
            Self::OrderCreation(e) => write!(f, "Failed to create certificate order: {e}"),
            Self::Authorization(e) => write!(f, "Authorization failed: {e}"),
            Self::ChallengeNotFound(t) => write!(f, "Challenge type {t:?} not found"),
            Self::ChallengeFailed(e) => write!(f, "Challenge failed: {e}"),
            Self::CsrGeneration(e) => write!(f, "Failed to generate CSR: {e}"),
            Self::Finalization(e) => write!(f, "Failed to finalize order: {e}"),
            Self::CertificateDownload(e) => write!(f, "Failed to download certificate: {e}"),
            Self::Timeout(e) => write!(f, "Timeout: {e}"),
            Self::PortInUse(port) => write!(f, "Port {port} is already in use"),
            Self::PermissionDenied(port) => write!(
                f,
                "Permission denied: cannot bind to port {port}. Try running as root or use sudo."
            ),
            Self::Other(e) => write!(f, "{e}"),
            Self::Io(error) => std::fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for AcmeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for AcmeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct AcmeClient {
    account: Account,
}

impl AcmeClient {
    async fn new(email: &str, staging: bool) -> Result<Self, AcmeError> {
        let directory_url = if staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        writeln!(
            io::stdout().lock(),
            "Creating ACME account with {} environment...",
            if staging { "staging" } else { "production" }
        )?;

        let (account, _credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{email}")],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .map_err(|e| AcmeError::AccountCreation(e.to_string()))?;

        writeln!(io::stdout().lock(), "✓ ACME account created successfully")?;
        Ok(Self { account })
    }

    async fn issue_cert(
        &self,
        domain: &str,
        challenge_method: ChallengeMethod,
    ) -> Result<IssuedCert, AcmeError> {
        writeln!(
            io::stdout().lock(),
            "Requesting certificate for {domain}..."
        )?;

        // 1. Create order
        let identifiers = vec![Identifier::Dns(domain.to_string())];
        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .map_err(|e| AcmeError::OrderCreation(e.to_string()))?;

        writeln!(io::stdout().lock(), "✓ Certificate order created")?;

        // 2. Get authorizations and complete challenges
        Self::complete_authorizations(&mut order, domain, challenge_method).await?;

        // 3. Wait for order to be ready
        Self::wait_for_ready(&mut order).await?;

        // 4. Generate key pair and CSR
        writeln!(
            io::stdout().lock(),
            "Generating certificate signing request..."
        )?;

        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| AcmeError::CsrGeneration(e.to_string()))?;

        let mut params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| AcmeError::CsrGeneration(e.to_string()))?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, domain);

        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| AcmeError::CsrGeneration(e.to_string()))?;

        let csr_der = csr.der().as_ref();

        // 5. Finalize order
        if order.state().status == OrderStatus::Ready {
            order
                .finalize(csr_der)
                .await
                .map_err(|e| AcmeError::Finalization(e.to_string()))?;
            writeln!(io::stdout().lock(), "✓ Order finalized")?;
        }

        let key_pem = key_pair.serialize_pem();

        // 6. Wait for certificate
        Self::wait_for_certificate(&mut order).await?;

        // 7. Download certificate
        let cert_chain = order
            .certificate()
            .await
            .map_err(|e| AcmeError::CertificateDownload(e.to_string()))?
            .ok_or_else(|| AcmeError::CertificateDownload("No certificate returned".to_string()))?;

        writeln!(io::stdout().lock(), "✓ Certificate issued successfully!")?;

        Ok(IssuedCert {
            cert_pem: cert_chain,
            key_pem,
            domain: domain.to_string(),
        })
    }

    async fn complete_authorizations(
        order: &mut instant_acme::Order,
        domain: &str,
        challenge_method: ChallengeMethod,
    ) -> Result<(), AcmeError> {
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| AcmeError::Authorization(e.to_string()))?;

        for auth in &authorizations {
            match auth.status {
                AuthorizationStatus::Valid => {
                    writeln!(io::stdout().lock(), "✓ Authorization already valid")?;
                    continue;
                }
                AuthorizationStatus::Pending => {}
                status => {
                    return Err(AcmeError::Authorization(format!(
                        "Unexpected authorization status: {status:?}"
                    )));
                }
            }

            let challenge = match challenge_method {
                ChallengeMethod::Http01 => auth
                    .challenges
                    .iter()
                    .find(|c| c.r#type == ChallengeType::Http01)
                    .ok_or(AcmeError::ChallengeNotFound(ChallengeType::Http01))?,
                ChallengeMethod::Dns01 => auth
                    .challenges
                    .iter()
                    .find(|c| c.r#type == ChallengeType::Dns01)
                    .ok_or(AcmeError::ChallengeNotFound(ChallengeType::Dns01))?,
            };

            let key_auth = order.key_authorization(challenge);

            match challenge_method {
                ChallengeMethod::Http01 => {
                    Self::complete_http01_challenge(
                        &challenge.token,
                        key_auth.as_str(),
                        order,
                        challenge,
                    )
                    .await?;
                }
                ChallengeMethod::Dns01 => {
                    let dns_value = key_auth.dns_value();
                    Self::complete_dns01_challenge(domain, &dns_value, order, challenge).await?;
                }
            }
        }
        Ok(())
    }

    async fn wait_for_ready(order: &mut instant_acme::Order) -> Result<(), AcmeError> {
        writeln!(io::stdout().lock(), "Waiting for order to be ready...")?;
        let mut attempts = 0;
        let max_attempts = 30;
        loop {
            sleep(Duration::from_secs(2)).await;
            order
                .refresh()
                .await
                .map_err(|e| AcmeError::Other(e.to_string()))?;

            match order.state().status {
                OrderStatus::Ready => {
                    writeln!(io::stdout().lock(), "✓ Order is ready for finalization")?;
                    break;
                }
                OrderStatus::Invalid => {
                    return Err(AcmeError::Finalization("Order became invalid".to_string()));
                }
                OrderStatus::Valid => {
                    writeln!(io::stdout().lock(), "✓ Order is already valid")?;
                    break;
                }
                _ => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        return Err(AcmeError::Timeout(
                            "Timed out waiting for order to be ready".to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    async fn wait_for_certificate(order: &mut instant_acme::Order) -> Result<(), AcmeError> {
        let max_attempts = 30;
        writeln!(io::stdout().lock(), "Waiting for certificate...")?;
        let mut attempts = 0;
        loop {
            sleep(Duration::from_secs(2)).await;
            order
                .refresh()
                .await
                .map_err(|e| AcmeError::Other(e.to_string()))?;

            match order.state().status {
                OrderStatus::Valid => break,
                OrderStatus::Invalid => {
                    return Err(AcmeError::Finalization(
                        "Order became invalid after finalization".to_string(),
                    ));
                }
                _ => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        return Err(AcmeError::Timeout(
                            "Timed out waiting for certificate".to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    async fn complete_http01_challenge(
        token: &str,
        key_authorization: &str,
        order: &mut instant_acme::Order,
        challenge: &instant_acme::Challenge,
    ) -> Result<(), AcmeError> {
        writeln!(io::stdout().lock(), "Starting HTTP-01 challenge...")?;
        writeln!(io::stdout().lock(), "  Token: {token}")?;

        // Start HTTP server to serve the challenge
        let (shutdown_tx, server_handle) =
            run_http01_challenge_server(token.to_string(), key_authorization.to_string()).await?;

        let result = async {
            // Notify ACME server that challenge is ready
            writeln!(
                io::stdout().lock(),
                "Notifying ACME server that challenge is ready..."
            )?;
            order
                .set_challenge_ready(&challenge.url)
                .await
                .map_err(|e| AcmeError::ChallengeFailed(e.to_string()))?;

            // Wait for validation
            Self::wait_for_http01_validation(order).await
        }
        .await;

        // Shutdown the HTTP server
        let shutdown_sent = shutdown_tx.send(()).is_ok();
        let server_result = server_handle
            .await
            .map_err(|error| AcmeError::Other(error.to_string()))?;
        result?;
        server_result?;
        if !shutdown_sent {
            return Err(AcmeError::Other(
                "HTTP challenge server stopped before shutdown".to_owned(),
            ));
        }
        Ok(())
    }

    async fn wait_for_http01_validation(order: &mut instant_acme::Order) -> Result<(), AcmeError> {
        // Wait for validation
        writeln!(
            io::stdout().lock(),
            "Waiting for ACME server to validate challenge..."
        )?;
        let mut attempts = 0;
        let max_attempts = 30;
        loop {
            sleep(Duration::from_secs(2)).await;

            let auths = order
                .authorizations()
                .await
                .map_err(|e| AcmeError::Authorization(e.to_string()))?;

            let all_valid = auths.iter().all(|a| a.status == AuthorizationStatus::Valid);

            if all_valid {
                writeln!(
                    io::stdout().lock(),
                    "✓ HTTP-01 challenge completed successfully"
                )?;
                break;
            }

            let any_invalid = auths
                .iter()
                .any(|a| a.status == AuthorizationStatus::Invalid);

            if any_invalid {
                return Err(AcmeError::ChallengeFailed(
                    "Authorization became invalid".to_string(),
                ));
            }

            attempts += 1;
            if attempts >= max_attempts {
                return Err(AcmeError::Timeout(
                    "Timed out waiting for challenge validation".to_string(),
                ));
            }
        }

        Ok(())
    }

    async fn complete_dns01_challenge(
        domain: &str,
        digest: &str,
        order: &mut instant_acme::Order,
        challenge: &instant_acme::Challenge,
    ) -> Result<(), AcmeError> {
        print_dns01_challenge(domain, digest)?;

        if crate::get_mode() == crate::Mode::NonInteractive {
            return Err(AcmeError::Other(
                "DNS-01 challenge requires interactive mode to confirm DNS record addition"
                    .to_string(),
            ));
        }

        if !ask_for_agreement("Have you added the DNS TXT record? (Press Enter when ready)")? {
            return Err(AcmeError::ChallengeFailed(
                "User cancelled DNS-01 challenge".to_string(),
            ));
        }

        // Notify ACME server that challenge is ready
        writeln!(
            io::stdout().lock(),
            "Notifying ACME server that challenge is ready..."
        )?;
        order
            .set_challenge_ready(&challenge.url)
            .await
            .map_err(|e| AcmeError::ChallengeFailed(e.to_string()))?;

        // Wait for validation
        writeln!(
            io::stdout().lock(),
            "Waiting for ACME server to validate DNS record..."
        )?;
        writeln!(
            io::stdout().lock(),
            "(This may take a few minutes due to DNS propagation)"
        )?;

        let mut attempts = 0;
        let max_attempts = 60; // Longer timeout for DNS propagation
        loop {
            sleep(Duration::from_secs(5)).await;

            let auths = order
                .authorizations()
                .await
                .map_err(|e| AcmeError::Authorization(e.to_string()))?;

            let all_valid = auths.iter().all(|a| a.status == AuthorizationStatus::Valid);

            if all_valid {
                writeln!(
                    io::stdout().lock(),
                    "✓ DNS-01 challenge completed successfully"
                )?;
                break;
            }

            let any_invalid = auths
                .iter()
                .any(|a| a.status == AuthorizationStatus::Invalid);

            if any_invalid {
                return Err(AcmeError::ChallengeFailed(
                    "DNS validation failed. Please verify the TXT record is correct.".to_string(),
                ));
            }

            attempts += 1;
            if attempts >= max_attempts {
                return Err(AcmeError::Timeout(
                    "Timed out waiting for DNS validation. DNS propagation may take longer."
                        .to_string(),
                ));
            }

            if attempts % 6 == 0 {
                writeln!(
                    io::stdout().lock(),
                    "  Still waiting for DNS validation... ({} seconds)",
                    attempts * 5
                )?;
            }
        }

        Ok(())
    }
}

fn print_dns01_challenge(domain: &str, digest: &str) -> io::Result<()> {
    let record_name = format!("_acme-challenge.{domain}");
    writeln!(
        io::stdout().lock(),
        "\n╔════════════════════════════════════════════════════════════════╗"
    )?;
    writeln!(
        io::stdout().lock(),
        "║                    DNS-01 Challenge                            ║"
    )?;
    writeln!(
        io::stdout().lock(),
        "╠════════════════════════════════════════════════════════════════╣"
    )?;
    writeln!(
        io::stdout().lock(),
        "║ Please add the following TXT record to your DNS:               ║"
    )?;
    writeln!(
        io::stdout().lock(),
        "╟────────────────────────────────────────────────────────────────╢"
    )?;
    writeln!(
        io::stdout().lock(),
        "║ Name:  {:<56} ║",
        truncate_str(&record_name, 56)
    )?;
    writeln!(
        io::stdout().lock(),
        "║ Type:  TXT                                                     ║"
    )?;
    writeln!(
        io::stdout().lock(),
        "║ Value: {:<56} ║",
        truncate_str(digest, 56)
    )?;
    writeln!(
        io::stdout().lock(),
        "╚════════════════════════════════════════════════════════════════╝\n"
    )?;
    Ok(())
}

pub async fn issue_certificate(config: &AcmeConfig) -> Result<IssuedCert, AcmeError> {
    let client = AcmeClient::new(&config.email, config.use_staging).await?;
    client
        .issue_cert(&config.domain, config.challenge_method)
        .await
}

pub fn validate_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !domain.contains('@') && domain.contains('.')
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

pub fn validate_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    // Must not start or end with a dot or hyphen
    if domain.starts_with('.')
        || domain.ends_with('.')
        || domain.starts_with('-')
        || domain.ends_with('-')
    {
        return false;
    }
    // Must contain at least one dot (TLD required)
    if !domain.contains('.') {
        return false;
    }
    // Each label must be valid
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}
