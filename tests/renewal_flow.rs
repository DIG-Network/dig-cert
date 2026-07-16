//! End-to-end renewal + rustls-loader flow against a real temp filesystem (SPEC §6/§7).

use std::sync::Arc;

use dig_cert::{
    generate_ca, issue_leaf, load_server_config, needs_ca_renewal, rotate_ca, BackoffSchedule,
    ParsedCa, ReloadableCertResolver, RenewalManager, Sleeper, TlsPaths,
};
use time::{Duration, OffsetDateTime};

/// A sleeper that never actually sleeps — keeps the retry-path tests instant.
struct NoSleep;
impl Sleeper for NoSleep {
    fn sleep(&self, _dur: std::time::Duration) {}
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_752_000_000).unwrap()
}

/// Lay a CA + leaf down on disk, the leaf issued at `leaf_issued_at`.
fn seed(
    root: &std::path::Path,
    ca_issued_at: OffsetDateTime,
    leaf_issued_at: OffsetDateTime,
) -> TlsPaths {
    let paths = TlsPaths::under(root);
    let ca = generate_ca("testhost", ca_issued_at).unwrap();
    std::fs::write(paths.ca_cert(), &ca.cert_pem).unwrap();
    std::fs::write(paths.ca_key(), &ca.key_pem).unwrap();
    let parsed = ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
    let leaf = issue_leaf(&parsed, leaf_issued_at).unwrap();
    std::fs::write(paths.leaf_cert(), &leaf.cert_pem).unwrap();
    std::fs::write(paths.leaf_key(), &leaf.key_pem).unwrap();
    paths
}

#[test]
fn maintain_renews_a_near_expiry_leaf_and_reloads_without_a_new_config() {
    let dir = tempfile::tempdir().unwrap();
    // Leaf issued 61 days ago -> 29 days remaining -> due for renewal.
    let leaf_issued = now() - Duration::days(61);
    let paths = seed(dir.path(), now(), leaf_issued);
    let before = std::fs::read_to_string(paths.leaf_cert()).unwrap();

    let (_config, resolver) = load_server_config(paths.leaf_cert(), paths.leaf_key()).unwrap();
    let manager = RenewalManager::new(paths.clone(), Arc::clone(&resolver))
        .with_backoff(BackoffSchedule::new(vec![]))
        .with_sleeper(Arc::new(NoSleep));

    let report = manager.maintain(now()).unwrap();
    assert!(report.leaf_renewed, "a 29-day-remaining leaf is renewed");
    assert_eq!(report.attempts, 1);
    assert!(!report.ca_renewal_due, "a fresh CA is not due for rotation");

    let after = std::fs::read_to_string(paths.leaf_cert()).unwrap();
    assert_ne!(before, after, "the leaf on disk was re-issued");
    // The resolver reloaded in place — reloading again still succeeds (same handle, no new config).
    resolver.reload().unwrap();
}

#[test]
fn maintain_leaves_a_fresh_leaf_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let paths = seed(dir.path(), now(), now());
    let before = std::fs::read_to_string(paths.leaf_cert()).unwrap();

    let manager = RenewalManager::without_resolver(paths.clone());
    let report = manager.maintain(now()).unwrap();

    assert!(!report.leaf_renewed, "a day-old leaf is not renewed");
    assert_eq!(report.attempts, 0);
    assert_eq!(std::fs::read_to_string(paths.leaf_cert()).unwrap(), before);
}

#[test]
fn maintain_issues_a_leaf_when_none_exists() {
    let dir = tempfile::tempdir().unwrap();
    let paths = TlsPaths::under(dir.path());
    let ca = generate_ca("testhost", now()).unwrap();
    std::fs::write(paths.ca_cert(), &ca.cert_pem).unwrap();
    std::fs::write(paths.ca_key(), &ca.key_pem).unwrap();
    // No leaf on disk.

    let manager = RenewalManager::without_resolver(paths.clone());
    let report = manager.maintain(now()).unwrap();

    assert!(report.leaf_renewed, "a missing leaf is issued");
    assert!(paths.leaf_cert().exists() && paths.leaf_key().exists());
}

#[test]
fn maintain_flags_a_near_expiry_ca_for_rotation() {
    let dir = tempfile::tempdir().unwrap();
    // CA issued so long ago it is within 180 days of its 10-year expiry.
    let ca_issued = now() - Duration::days(3650 - 179);
    let paths = seed(dir.path(), ca_issued, now());

    let manager = RenewalManager::without_resolver(paths.clone());
    let report = manager.maintain(now()).unwrap();
    assert!(
        report.ca_renewal_due,
        "a CA within 180d of expiry is flagged"
    );

    let ca_pem = std::fs::read_to_string(paths.ca_cert()).unwrap();
    assert!(needs_ca_renewal(&ca_pem, now()));
}

#[test]
fn rotate_ca_writes_a_fresh_anchor_and_matching_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let paths = seed(dir.path(), now() - Duration::days(3600), now());
    let old_ca = std::fs::read_to_string(paths.ca_cert()).unwrap();

    rotate_ca(&paths, "testhost", now()).unwrap();

    let new_ca = std::fs::read_to_string(paths.ca_cert()).unwrap();
    assert_ne!(old_ca, new_ca, "rotation replaces the CA");
    // The new leaf loads under the new CA (proves they are a matching pair).
    load_server_config(paths.leaf_cert(), paths.leaf_key()).unwrap();
    assert!(!needs_ca_renewal(&new_ca, now()), "the rotated CA is fresh");
}

#[test]
fn resolver_picks_up_an_externally_swapped_leaf() {
    // dig-dns's model: it watches the files and calls reload() when they change (SPEC §7).
    let dir = tempfile::tempdir().unwrap();
    let paths = seed(dir.path(), now(), now());
    let resolver = ReloadableCertResolver::from_files(paths.leaf_cert(), paths.leaf_key()).unwrap();

    // A newer leaf is written under the resolver.
    let ca = std::fs::read_to_string(paths.ca_cert()).unwrap();
    let key = std::fs::read_to_string(paths.ca_key()).unwrap();
    let parsed = ParsedCa::from_pem(&ca, &key).unwrap();
    let fresh = issue_leaf(&parsed, now() + Duration::days(1)).unwrap();
    std::fs::write(paths.leaf_key(), &fresh.key_pem).unwrap();
    std::fs::write(paths.leaf_cert(), &fresh.cert_pem).unwrap();

    resolver.reload().expect("reload picks up the swapped leaf");
}

#[test]
fn resolver_rejects_a_missing_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let paths = TlsPaths::under(dir.path());
    let err = ReloadableCertResolver::from_files(paths.leaf_cert(), paths.leaf_key());
    assert!(
        err.is_err(),
        "a missing leaf must fail fast, not at handshake"
    );
}
