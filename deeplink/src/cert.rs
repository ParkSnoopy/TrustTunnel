use crate::error::{DeepLinkError, Result};
use std::io::Cursor;

/// Convert PEM certificate(s) to concatenated DER bytes.
/// Handles multiple PEM blocks (certificate chains).
///
/// # Errors
///
/// Returns [`DeepLinkError::InvalidCertificate`] if PEM parsing fails or no
/// certificates are present.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(pem.as_bytes());

    let certs = rustls_pemfile::certs(&mut cursor)
        .map_err(|e| DeepLinkError::InvalidCertificate(format!("PEM parsing failed: {e}")))?;

    if certs.is_empty() {
        return Err(DeepLinkError::InvalidCertificate(
            "no PEM blocks found in certificate field".to_string(),
        ));
    }

    let total_len: usize = certs.iter().map(std::vec::Vec::len).sum();
    let mut der_output = Vec::with_capacity(total_len);

    for cert in certs {
        der_output.extend_from_slice(cert.as_ref());
    }

    Ok(der_output)
}

/// Read ASN.1 length at the given offset.
/// Returns (length, `new_offset`).
fn read_asn1_length(data: &[u8], offset: usize) -> Result<(usize, usize)> {
    if offset >= data.len() {
        return Err(DeepLinkError::InvalidCertificate(
            "unexpected end of data in ASN.1 length".to_string(),
        ));
    }

    let first = data[offset];
    if first < 0x80 {
        // Short form: length is in the first byte
        return Ok((first as usize, offset + 1));
    }

    // Long form: first byte tells us how many bytes encode the length
    let num_bytes = (first & 0x7F) as usize;
    if num_bytes == 0 || offset + 1 + num_bytes > data.len() {
        return Err(DeepLinkError::InvalidCertificate(
            "invalid ASN.1 length encoding".to_string(),
        ));
    }

    let mut length = 0usize;
    for i in 0..num_bytes {
        length = (length << 8) | (data[offset + 1 + i] as usize);
    }

    Ok((length, offset + 1 + num_bytes))
}

/// Split concatenated DER certificates into individual certificate blobs.
fn split_der_certs(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Each certificate is an ASN.1 SEQUENCE (tag 0x30)
        if data[offset] != 0x30 {
            return Err(DeepLinkError::InvalidCertificate(format!(
                "expected ASN.1 SEQUENCE (0x30) at offset {}, got 0x{:02X}",
                offset, data[offset]
            )));
        }

        let (body_len, hdr_end) = read_asn1_length(data, offset + 1)?;
        let cert_end = hdr_end.checked_add(body_len).ok_or_else(|| {
            DeepLinkError::InvalidCertificate("certificate length overflow".to_string())
        })?;

        if cert_end > data.len() {
            return Err(DeepLinkError::InvalidCertificate(
                "truncated DER certificate".to_string(),
            ));
        }

        certs.push(data[offset..cert_end].to_vec());
        offset = cert_end;
    }

    Ok(certs)
}

/// Convert concatenated DER certificates to PEM format.
///
/// # Errors
///
/// Returns [`DeepLinkError::InvalidCertificate`] if the DER sequence tags or
/// lengths are invalid, truncated, or overflow.
pub fn der_to_pem(der: &[u8]) -> Result<String> {
    let certs = split_der_certs(der)?;
    let mut pem_blocks = Vec::new();

    for cert_der in certs {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_der);

        // Split into 64-character lines
        let lines: Vec<String> = b64
            .as_bytes()
            .chunks(64)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect();

        pem_blocks.push(format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            lines.join("\n")
        ));
    }

    Ok(pem_blocks.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prop_assert, prop_assert_eq, prop_assert_ne};

    type TestResult = proptest::test_runner::TestCaseResult;

    const SAMPLE_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU7PWMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAw9nQx8KLBs9LKVqK
6WZ7aYvMQXAA1tP9VbFqFBDzDYJoFZxKZPbZKGOZOmKMJMxLCqN6qLlPWnZrYWXL
+3A8PqYqLqvMVxQ8QZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQCAQIDAQABMA0GCSqG
SIb3DQEBCwUAA4GBAJKCfpqLG3PkKE4L7VVzLqH4E7FkLqZxMQZQZQZQZQZQZQZQ
-----END CERTIFICATE-----";

    #[test]
    fn test_pem_to_der() -> TestResult {
        let result = pem_to_der(SAMPLE_PEM);
        prop_assert!(result.is_ok());
        let der = result?;
        prop_assert_ne!(der, Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn test_pem_to_der_empty() -> TestResult {
        let result = pem_to_der("");
        prop_assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_pem_to_der_invalid() -> TestResult {
        let result = pem_to_der("not a certificate");
        prop_assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_der_to_pem_single_cert() -> TestResult {
        // Simple DER certificate: SEQUENCE with short length
        let der = vec![0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let result = der_to_pem(&der);
        prop_assert!(result.is_ok());
        let pem = result?;
        prop_assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        prop_assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        prop_assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 1);
        Ok(())
    }

    #[test]
    fn test_der_to_pem_multiple_certs() -> TestResult {
        // Two small DER certificates concatenated
        let cert1 = vec![0x30, 0x03, 0x01, 0x02, 0x03]; // SEQUENCE of 3 bytes
        let cert2 = vec![0x30, 0x04, 0x04, 0x05, 0x06, 0x07]; // SEQUENCE of 4 bytes
        let mut der = cert1;
        der.extend_from_slice(&cert2);

        let result = der_to_pem(&der);
        prop_assert!(result.is_ok());
        let pem = result?;

        // Should have two PEM blocks
        prop_assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 2);
        prop_assert_eq!(pem.matches("-----END CERTIFICATE-----").count(), 2);
        Ok(())
    }

    #[test]
    fn test_der_to_pem_long_form_length() -> TestResult {
        // DER certificate with long form length: 0x30 0x81 0x05 (length = 5)
        let der = vec![0x30, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let result = der_to_pem(&der);
        prop_assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_der_to_pem_invalid_tag() -> TestResult {
        // Invalid tag (not 0x30 SEQUENCE)
        let der = vec![0x31, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let result = der_to_pem(&der);
        prop_assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_der_to_pem_truncated() -> TestResult {
        // Claims to have 10 bytes but only provides 5
        let der = vec![0x30, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05];
        let result = der_to_pem(&der);
        prop_assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_roundtrip_der_pem_der() -> TestResult {
        // Use synthetic DER certificate (valid ASN.1 SEQUENCE structure)
        let original_der = vec![0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];

        // DER -> PEM
        let pem = der_to_pem(&original_der)?;

        // Should produce valid PEM
        prop_assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        prop_assert!(pem.contains("-----END CERTIFICATE-----"));

        // PEM -> DER (roundtrip)
        let der_again = pem_to_der(&pem)?;
        prop_assert_eq!(original_der, der_again);
        Ok(())
    }

    #[test]
    fn test_roundtrip_multi_cert_chain() -> TestResult {
        // Two synthetic DER certificates
        let cert1 = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let cert2 = vec![0x30, 0x04, 0x04, 0x05, 0x06, 0x07];
        let mut original_der = cert1;
        original_der.extend_from_slice(&cert2);

        // DER -> PEM
        let pem = der_to_pem(&original_der)?;

        // Should have two certificates
        prop_assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 2);

        // PEM -> DER (roundtrip)
        let der_again = pem_to_der(&pem)?;
        prop_assert_eq!(original_der, der_again);
        Ok(())
    }

    #[test]
    fn test_split_der_certs_empty() -> TestResult {
        let result = split_der_certs(&[]);
        prop_assert!(result.is_ok());
        prop_assert_eq!(result?.len(), 0);
        Ok(())
    }

    #[test]
    fn test_read_asn1_length_short_form() -> TestResult {
        let data = vec![0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let (length, offset) = read_asn1_length(&data, 0)?;
        prop_assert_eq!(length, 5);
        prop_assert_eq!(offset, 1);
        Ok(())
    }

    #[test]
    fn test_read_asn1_length_long_form() -> TestResult {
        // Long form: 0x81 means next 1 byte is the length
        let data = vec![0x81, 0x7F, 0x00]; // length = 127
        let (length, offset) = read_asn1_length(&data, 0)?;
        prop_assert_eq!(length, 127);
        prop_assert_eq!(offset, 2);
        Ok(())
    }

    #[test]
    fn test_read_asn1_length_two_byte_long_form() -> TestResult {
        // Long form: 0x82 means next 2 bytes are the length
        let data = vec![0x82, 0x01, 0x00, 0x00]; // length = 256
        let (length, offset) = read_asn1_length(&data, 0)?;
        prop_assert_eq!(length, 256);
        prop_assert_eq!(offset, 3);
        Ok(())
    }
}
