//! Public-API surface tests: secret redaction, error paths, and machine-path resolution.

use dig_cert::{
    generate_ca, issue_leaf, load_server_config, needs_ca_renewal, ReloadableCertResolver,
    TlsPaths, CA_ORGANIZATION,
};
use time::{Duration, OffsetDateTime};

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_752_000_000).unwrap()
}

#[test]
fn debug_never_leaks_private_key_material() {
    let ca = generate_ca("host", now()).unwrap();
    let dbg = format!("{ca:?}");
    assert!(dbg.contains("<redacted>"), "CA Debug must redact the key");
    assert!(
        !dbg.contains("PRIVATE KEY"),
        "CA Debug must not render the PEM key"
    );

    let parsed = dig_cert::ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
    let leaf = issue_leaf(&parsed, now()).unwrap();
    let leaf_dbg = format!("{leaf:?}");
    assert!(leaf_dbg.contains("<redacted>"));
    assert!(!leaf_dbg.contains("PRIVATE KEY"));
}

#[test]
fn ca_subject_carries_the_organization_and_dated_hostname() {
    let ca = generate_ca("my-box", now()).unwrap();
    // The subject is embedded in the cert; a quick parse confirms the org + host label.
    let (_, pem) = x509_parser::pem::parse_x509_pem(ca.cert_pem.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();
    let subject = cert.subject().to_string();
    assert!(
        subject.contains(CA_ORGANIZATION),
        "subject has the org: {subject}"
    );
    assert!(
        subject.contains("my-box"),
        "subject has the hostname: {subject}"
    );
}

#[test]
fn resolver_rejects_a_corrupt_certificate_file() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("leaf.crt");
    let key = dir.path().join("leaf.key");
    std::fs::write(&cert, "not a pem certificate").unwrap();
    std::fs::write(&key, "not a pem key").unwrap();
    assert!(ReloadableCertResolver::from_files(&cert, &key).is_err());
}

#[test]
fn server_config_builds_from_a_freshly_issued_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let paths = TlsPaths::under(dir.path());
    let ca = generate_ca("host", now()).unwrap();
    let parsed = dig_cert::ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
    let leaf = issue_leaf(&parsed, now()).unwrap();
    std::fs::write(paths.leaf_cert(), &leaf.cert_pem).unwrap();
    std::fs::write(paths.leaf_key(), &leaf.key_pem).unwrap();

    let (config, _resolver) = load_server_config(paths.leaf_cert(), paths.leaf_key()).unwrap();
    // A usable server config never negotiates client auth for this browser-facing listener.
    let _ = config; // building it without panicking is the assertion (single CryptoProvider).
}

#[test]
fn machine_layout_resolves_and_flags_expiry() {
    // The machine root resolves on this platform without creating anything.
    let paths = TlsPaths::machine().expect("machine TLS root resolves");
    assert!(paths.ca_cert().ends_with("ca.crt"));

    // A garbage CA cert is treated as due for rotation (self-heal).
    assert!(needs_ca_renewal("garbage", now()));
    // A brand-new CA is not.
    let ca = generate_ca("host", now()).unwrap();
    assert!(!needs_ca_renewal(&ca.cert_pem, now()));
    // One a day before its 10y expiry is.
    let old = generate_ca("host", now() - Duration::days(3650)).unwrap();
    assert!(needs_ca_renewal(&old.cert_pem, now()));
}
