//! System-trust checks used when exporting endpoint certificates.

use crate::utils;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use std::io;
use std::sync::Arc;

/// Checks if certificate chain would be verifiable by system CAs.
///
/// The server-side check only determines whether to omit the certificate from
/// the deep-link to reduce its size. Security validation happens client-side
/// during deep-link import.
#[derive(Debug)]
pub struct CertificateVerifier {
    root_store: Arc<RootCertStore>,
}

impl CertificateVerifier {
    /// Create a new verifier with system trust anchors loaded.
    ///
    /// # Errors
    /// Returns an error if native roots cannot be loaded or added to the trust store.
    pub fn new() -> io::Result<Self> {
        let mut root_store = RootCertStore::empty();

        let native_certs = rustls_native_certs::load_native_certs()
            .map_err(|e| io::Error::other(format!("failed to load system CAs: {e}")))?;
        for cert in native_certs {
            root_store
                .add(cert)
                .map_err(|e| io::Error::other(format!("failed to add CA cert: {e}")))?;
        }

        Ok(Self {
            root_store: Arc::new(root_store),
        })
    }

    /// Check if a certificate chain is verifiable by system CAs.
    ///
    /// Returns `true` if the certificate chain can be verified, `false` otherwise.
    /// This is used to determine if the certificate can be omitted from deep-links.
    ///
    /// # Arguments
    /// * `cert_path` - Path to the certificate chain file (PEM format)
    /// * `hostname` - The hostname to verify against
    #[must_use]
    pub fn is_system_verifiable(&self, cert_path: &str, hostname: &str) -> bool {
        // Load certificates from file
        let certs = match utils::load_certs(cert_path) {
            Ok(certs) => certs,
            Err(e) => {
                debug!("Failed to load certificates from {cert_path}: {e}");
                return false;
            }
        };

        if certs.is_empty() {
            debug!("No certificates found in {cert_path}");
            return false;
        }

        // Parse hostname as ServerName
        let server_name = match ServerName::try_from(hostname) {
            Ok(name) => name,
            Err(e) => {
                debug!("Invalid hostname {hostname}: {e}");
                return false;
            }
        };

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = match WebPkiServerVerifier::builder_with_provider(
            Arc::clone(&self.root_store),
            provider,
        )
        .build()
        {
            Ok(v) => v,
            Err(e) => {
                debug!("Failed to build verifier: {e}");
                return false;
            }
        };
        let Some((end_entity, intermediates)) = certs.split_first() else {
            return false;
        };
        let now = rustls_pki_types::UnixTime::now();

        match verifier.verify_server_cert(end_entity, intermediates, &server_name, &[], now) {
            Ok(_) => {
                debug!("Certificate chain for {hostname} is system-verifiable");
                true
            }
            Err(e) => {
                debug!("Certificate chain for {hostname} is not system-verifiable: {e}");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_verifier_creation() {
        let verifier = CertificateVerifier::new();
        assert!(verifier.is_ok(), "Should be able to load system CAs");
    }

    #[test]
    fn test_self_signed_cert_not_verifiable() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = CertificateVerifier {
            root_store: Arc::new(RootCertStore::empty()),
        };

        let self_signed_pem = r"-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ3ZUD30jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1+fWIcPm15A8SE0MNvYhggo4ExRbEW9dUg
YpSMEo5c4rF6VhqzNb8s6G8E2Yfl1hP8xECvH8VGCE1aEhD9yEV4YgDJTVfD7aL+
hBNDhjKQqPJq7L2xCBQm8KqTFsXjPWvqLy3L0eLCCNTPqQGNmjZ9YPqC2RLxXEhz
pV+9K2qI3qJ6lV0tQwVKPPZEJ/9KPZQF1zEivQJqv1+5+DH2lxU5SG7tEXe6S7F/
VLRVBiEA1sYmZWqFQ9Jc5qLqbEz1RvGGfWqPdHVhU4KOzxXPFALLNRDR0KjWGVCG
ljD7r2K7qNjLpF9cOXJHAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGQSqg==
-----END CERTIFICATE-----";

        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(self_signed_pem.as_bytes())?;
        temp_file.flush()?;

        let result = verifier.is_system_verifiable(
            temp_file
                .path()
                .to_str()
                .ok_or("non-UTF-8 certificate path")?,
            "localhost",
        );
        if result {
            return Err("Self-signed certificate should not be system-verifiable".into());
        }
        Ok(())
    }

    #[test]
    fn test_invalid_cert_path() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = CertificateVerifier {
            root_store: Arc::new(RootCertStore::empty()),
        };
        let result = verifier.is_system_verifiable("/nonexistent/path/cert.pem", "example.com");
        if result {
            return Err("Invalid cert path should return false".into());
        }
        Ok(())
    }

    #[test]
    fn test_invalid_hostname() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = CertificateVerifier {
            root_store: Arc::new(RootCertStore::empty()),
        };

        let valid_pem = r"-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ3ZUD30jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1+fWIcPm15A8SE0MNvYhggo4ExRbEW9dUg
YpSMEo5c4rF6VhqzNb8s6G8E2Yfl1hP8xECvH8VGCE1aEhD9yEV4YgDJTVfD7aL+
hBNDhjKQqPJq7L2xCBQm8KqTFsXjPWvqLy3L0eLCCNTPqQGNmjZ9YPqC2RLxXEhz
pV+9K2qI3qJ6lV0tQwVKPPZEJ/9KPZQF1zEivQJqv1+5+DH2lxU5SG7tEXe6S7F/
VLRVBiEA1sYmZWqFQ9Jc5qLqbEz1RvGGfWqPdHVhU4KOzxXPFALLNRDR0KjWGVCG
ljD7r2K7qNjLpF9cOXJHAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGQSqg==
-----END CERTIFICATE-----";

        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(valid_pem.as_bytes())?;
        temp_file.flush()?;

        let result = verifier.is_system_verifiable(
            temp_file
                .path()
                .to_str()
                .ok_or("non-UTF-8 certificate path")?,
            "not a valid hostname!!!",
        );
        if result {
            return Err("Invalid hostname should return false".into());
        }
        Ok(())
    }
}
