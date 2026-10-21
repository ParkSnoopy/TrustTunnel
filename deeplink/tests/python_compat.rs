//! Wire-format compatibility with the reference Python scripts.

use proptest::{prop_assert, prop_assert_eq};
use std::io::Write;
use std::process::Command;
use trusttunnel_deeplink::{decode, encode, DeepLinkConfig, Protocol};

type TestResult<T = ()> = Result<T, proptest::test_runner::TestCaseError>;

/// Get the workspace root directory
fn workspace_root() -> TestResult<std::path::PathBuf> {
    Ok(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| {
            proptest::test_runner::TestCaseError::fail("Failed to get parent directory")
        })?
        .to_path_buf())
}

/// Run the Python `config_to_deeplink.py` script
fn python_encode(toml_config: &str) -> TestResult<String> {
    use rand::RngExt;

    let mut rng = rand::rng();
    let workspace = workspace_root()?;
    let temp_file = std::env::temp_dir().join(format!("test_config_{}.toml", rng.random::<u64>()));
    let mut file = std::fs::File::create_new(&temp_file)?;

    let script_path = workspace.join("scripts/config_to_deeplink.py");

    let output = (|| {
        file.write_all(toml_config.as_bytes())?;
        Command::new("python3")
            .arg(&script_path)
            .arg(&temp_file)
            .current_dir(&workspace)
            .output()
    })();
    drop(file);
    std::fs::remove_file(&temp_file)?;
    let output = output?;

    if !output.status.success() {
        return Err(proptest::test_runner::TestCaseError::fail(format!(
            "Python script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Run the Python `deeplink_to_config.py` script
fn python_decode(uri: &str) -> TestResult<String> {
    let workspace = workspace_root()?;
    let script_path = workspace.join("scripts/deeplink_to_config.py");

    let output = Command::new("python3")
        .arg(&script_path)
        .arg(uri)
        .current_dir(&workspace)
        .output()?;

    if !output.status.success() {
        return Err(proptest::test_runner::TestCaseError::fail(format!(
            "Python script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(String::from_utf8(output.stdout)?)
}

#[test]
fn test_python_encode_reports_invalid_toml() -> TestResult {
    let error = python_encode("hostname = [")
        .err()
        .ok_or_else(|| proptest::test_runner::TestCaseError::fail("invalid TOML was accepted"))?;
    prop_assert!(error.to_string().contains("Python script failed: "));
    Ok(())
}

#[test]
fn test_python_decode_reports_invalid_uri() -> TestResult {
    let error = python_decode("http://example.com")
        .err()
        .ok_or_else(|| proptest::test_runner::TestCaseError::fail("invalid URI was accepted"))?;
    prop_assert!(error.to_string().contains("Python script failed: "));
    Ok(())
}

#[test]
fn test_minimal_config_matches_python() -> TestResult {
    let toml = r#"
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "secret123"
"#;

    // Rust encode
    let config = DeepLinkConfig::builder()
        .hostname("vpn.example.com".to_string())
        .addresses(vec!["1.2.3.4:443".to_string()])
        .username("alice".to_string())
        .password("secret123".to_string())
        .build()?;

    let rust_uri = encode(&config)?;
    let python_uri = python_encode(toml)?;

    prop_assert_eq!(
        &rust_uri,
        &python_uri,
        "Rust and Python encoders produced different URIs"
    );

    // Verify roundtrip through Python decoder
    let python_decoded = python_decode(&rust_uri)?;
    prop_assert!(
        python_decoded.contains("hostname = \"vpn.example.com\""),
        "Python decoder failed to decode Rust-encoded URI"
    );
    prop_assert!(
        python_decoded.contains("username = \"alice\""),
        "Python decoder failed to decode username"
    );
    Ok(())
}

#[test]
fn test_full_config_matches_python() -> TestResult {
    let toml = r#"
hostname = "secure.vpn.example.com"
addresses = ["192.168.1.1:8443", "10.0.0.1:443"]
username = "premium_user"
password = "very_secret_password"
custom_sni = "cdn.example.org"
has_ipv6 = false
upstream_protocol = "http3"
anti_dpi = true
skip_verification = false
"#;

    // Rust encode
    let config = DeepLinkConfig::builder()
        .hostname("secure.vpn.example.com".to_string())
        .addresses(vec![
            "192.168.1.1:8443".to_string(),
            "10.0.0.1:443".to_string(),
        ])
        .username("premium_user".to_string())
        .password("very_secret_password".to_string())
        .custom_sni(Some("cdn.example.org".to_string()))
        .has_ipv6(false)
        .upstream_protocol(Protocol::Http3)
        .anti_dpi(true)
        .build()?;

    let rust_uri = encode(&config)?;
    let python_uri = python_encode(toml)?;

    prop_assert_eq!(
        &rust_uri,
        &python_uri,
        "Rust and Python encoders produced different URIs for full config"
    );

    // Verify roundtrip through Python decoder
    let python_decoded = python_decode(&rust_uri)?;
    prop_assert!(
        python_decoded.contains("hostname = \"secure.vpn.example.com\""),
        "Python decoder failed on hostname"
    );
    prop_assert!(
        python_decoded.contains("custom_sni = \"cdn.example.org\""),
        "Python decoder failed on custom_sni"
    );
    prop_assert!(
        python_decoded.contains("has_ipv6 = false"),
        "Python decoder failed on has_ipv6"
    );
    prop_assert!(
        python_decoded.contains("upstream_protocol = \"http3\""),
        "Python decoder failed on upstream_protocol"
    );
    prop_assert!(
        python_decoded.contains("anti_dpi = true"),
        "Python decoder failed on anti_dpi"
    );
    Ok(())
}

#[test]
fn test_decode_python_encoded_uri() -> TestResult {
    let toml = r#"
hostname = "test.example.org"
addresses = ["203.0.113.1:9443"]
username = "testuser"
password = "testpass"
upstream_protocol = "http2"
"#;

    // Get Python-encoded URI
    let python_uri = python_encode(toml)?;

    // Decode with Rust
    let rust_config = decode(&python_uri)?;

    // Verify fields
    prop_assert_eq!(rust_config.hostname.as_deref(), Some("test.example.org"));
    prop_assert_eq!(rust_config.addresses.len(), 1);
    prop_assert_eq!(&rust_config.addresses[0], "203.0.113.1:9443");
    prop_assert_eq!(rust_config.username.as_deref(), Some("testuser"));
    prop_assert_eq!(rust_config.password.as_deref(), Some("testpass"));
    prop_assert_eq!(rust_config.upstream_protocol, Protocol::Http2);
    prop_assert!(rust_config.has_ipv6); // default
    prop_assert!(!rust_config.anti_dpi); // default
    Ok(())
}

#[test]
fn test_client_random_prefix_matches_python() -> TestResult {
    let toml = r#"
hostname = "crp.example.com"
addresses = ["10.20.30.40:8443"]
username = "testuser"
password = "testpass"
client_random_prefix = "aabbccddee"
"#;

    // Rust encode
    let config = DeepLinkConfig::builder()
        .hostname("crp.example.com".to_string())
        .addresses(vec!["10.20.30.40:8443".to_string()])
        .username("testuser".to_string())
        .password("testpass".to_string())
        .client_random_prefix(Some("aabbccddee".to_string()))
        .build()?;

    let rust_uri = encode(&config)?;
    let python_uri = python_encode(toml)?;

    prop_assert_eq!(
        &rust_uri,
        &python_uri,
        "Rust and Python encoders produced different URIs for client_random_prefix"
    );

    // Verify roundtrip through Python decoder
    let python_config_str = python_decode(&rust_uri)?;
    prop_assert!(
        python_config_str.contains("client_random_prefix = \"aabbccddee\""),
        "Python decoder did not preserve client_random_prefix"
    );
    Ok(())
}

#[test]
fn test_roundtrip_through_both_implementations() -> TestResult {
    // Start with Rust config
    let original_config = DeepLinkConfig::builder()
        .hostname("roundtrip.example.com".to_string())
        .addresses(vec!["198.51.100.1:443".to_string()])
        .username("roundtrip_user".to_string())
        .password("roundtrip_pass".to_string())
        .custom_sni(Some("sni.example.com".to_string()))
        .has_ipv6(false)
        .anti_dpi(true)
        .build()?;

    // Encode with Rust
    let rust_uri = encode(&original_config)?;

    // Decode with Python (outputs TOML)
    let python_toml = python_decode(&rust_uri)?;

    // Re-encode with Python
    let python_uri = python_encode(&python_toml)?;

    // URIs should match after roundtrip
    prop_assert_eq!(
        &rust_uri,
        &python_uri,
        "URI changed after roundtrip through Python"
    );

    // Decode with Rust
    let decoded_config = decode(&python_uri)?;

    // Verify all fields match
    prop_assert_eq!(decoded_config.hostname, original_config.hostname);
    prop_assert_eq!(decoded_config.addresses, original_config.addresses);
    prop_assert_eq!(decoded_config.username, original_config.username);
    prop_assert_eq!(decoded_config.password, original_config.password);
    prop_assert_eq!(decoded_config.custom_sni, original_config.custom_sni);
    prop_assert_eq!(decoded_config.has_ipv6, original_config.has_ipv6);
    prop_assert_eq!(decoded_config.anti_dpi, original_config.anti_dpi);
    prop_assert_eq!(
        decoded_config.upstream_protocol,
        original_config.upstream_protocol
    );
    Ok(())
}

#[test]
fn test_name_and_dns_upstreams_matches_python() -> TestResult {
    let toml = r#"
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "secret123"
name = "My Server"
dns_upstreams = ["1.1.1.1", "8.8.8.8"]
"#;

    let config = DeepLinkConfig::builder()
        .hostname("vpn.example.com".to_string())
        .addresses(vec!["1.2.3.4:443".to_string()])
        .username("alice".to_string())
        .password("secret123".to_string())
        .name(Some("My Server".to_string()))
        .dns_upstreams(vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()])
        .build()?;

    let rust_uri = encode(&config)?;
    let python_uri = python_encode(toml)?;

    prop_assert_eq!(
        &rust_uri,
        &python_uri,
        "Rust and Python encoders produced different URIs for name/dns_upstreams"
    );

    let python_decoded = python_decode(&rust_uri)?;
    prop_assert!(
        python_decoded.contains("name = \"My Server\""),
        "Python decoder failed on name"
    );
    prop_assert!(
        python_decoded.contains("dns_upstreams"),
        "Python decoder failed on dns_upstreams"
    );
    Ok(())
}

#[test]
fn test_subscription_url_matches_python() -> TestResult {
    let toml = r#"
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cret"
subscription_url = "https://alice:s3cret@vpn.example.com/subscription"
"#;

    let config = DeepLinkConfig::builder()
        .hostname("vpn.example.com".to_string())
        .addresses(vec!["1.2.3.4:443".to_string()])
        .username("alice".to_string())
        .password("s3cret".to_string())
        .subscription_url(Some(
            "https://alice:s3cret@vpn.example.com/subscription".to_string(),
        ))
        .build()?;

    let rust_uri = encode(&config)?;
    let python_uri = python_encode(toml)?;

    prop_assert_eq!(
        &rust_uri,
        &python_uri,
        "Rust and Python encoders produced different URIs for subscription_url"
    );

    let python_decoded = python_decode(&rust_uri)?;
    prop_assert!(
        python_decoded
            .contains("subscription_url = \"https://alice:s3cret@vpn.example.com/subscription\""),
        "Python decoder failed on subscription_url"
    );
    Ok(())
}

#[test]
fn test_subscription_only_matches_python() -> TestResult {
    let toml = r#"
subscription_url = "https://alice:s3cret@vpn.example.com/subscription"
"#;

    let config = DeepLinkConfig::builder()
        .subscription_url(Some(
            "https://alice:s3cret@vpn.example.com/subscription".to_string(),
        ))
        .build()?;

    let rust_uri = encode(&config)?;
    let python_uri = python_encode(toml)?;

    prop_assert_eq!(
        &rust_uri,
        &python_uri,
        "Rust and Python encoders produced different URIs for subscription-only config"
    );

    // Rust can decode the Python-encoded subscription-only URI.
    let decoded = decode(&python_uri)?;
    prop_assert_eq!(
        decoded.subscription_url.as_deref(),
        Some("https://alice:s3cret@vpn.example.com/subscription")
    );
    prop_assert_eq!(decoded.hostname, None);
    Ok(())
}
