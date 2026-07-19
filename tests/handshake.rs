//! The serving hot path, end-to-end (SPEC §7).
//!
//! `load_server_config` hands a listener a `rustls::ServerConfig` backed by a
//! [`ReloadableCertResolver`]. rustls calls the resolver's `resolve()` on EVERY inbound handshake to
//! choose the leaf to present. These tests drive a real in-memory TLS handshake — a client and
//! server connection pumped over `Vec` buffers, no sockets — so the actually-served certificate is
//! asserted byte-for-byte. They are the proof that:
//!
//! - a config from `load_server_config` completes a handshake and presents the on-disk leaf, and
//! - after `ReloadableCertResolver::reload()`, a fresh handshake presents the ROTATED leaf — the
//!   hot-swap contract the renewal manager depends on for zero-downtime rotation.
//!
//! The client uses a capturing verifier that records the presented leaf and accepts it, so the
//! handshake exercises the resolver path without depending on the `*.dig` wildcard name limitation
//! pinned in `conformance.rs` (design #620 C1).

use std::sync::{Arc, Mutex};

use dig_cert::{generate_ca, issue_leaf, load_server_config, ParsedCa, TlsPaths};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, ServerConnection, SignatureScheme};
use time::OffsetDateTime;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_752_000_000).unwrap()
}

/// Lay a CA + leaf (issued at `leaf_issued_at`) on disk under `root` and return the paths.
fn seed(root: &std::path::Path, leaf_issued_at: OffsetDateTime) -> TlsPaths {
    let paths = TlsPaths::under(root);
    let ca = generate_ca("testhost", now()).unwrap();
    std::fs::write(paths.ca_cert(), &ca.cert_pem).unwrap();
    std::fs::write(paths.ca_key(), &ca.key_pem).unwrap();
    let parsed = ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
    let leaf = issue_leaf(&parsed, leaf_issued_at).unwrap();
    std::fs::write(paths.leaf_cert(), &leaf.cert_pem).unwrap();
    std::fs::write(paths.leaf_key(), &leaf.key_pem).unwrap();
    paths
}

/// A client verifier that records the presented end-entity certificate and accepts the chain, so a
/// handshake reaches completion regardless of name/anchor policy — signatures are still verified
/// against the ring provider so the served key must genuinely match its certificate.
#[derive(Debug)]
struct CapturingVerifier {
    provider: Arc<CryptoProvider>,
    seen: Mutex<Option<CertificateDer<'static>>>,
}

impl CapturingVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(ring::default_provider()),
            seen: Mutex::new(None),
        })
    }

    /// The end-entity certificate the server presented during the last handshake.
    fn presented(&self) -> CertificateDer<'static> {
        self.seen
            .lock()
            .unwrap()
            .clone()
            .expect("a leaf was presented")
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = Some(end_entity.clone().into_owned());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Complete a full in-memory handshake between `client` and `server`, ferrying TLS records over
/// `Vec` buffers until both sides are done (or a bounded number of rounds elapses).
fn drive_handshake(client: &mut rustls::Connection, server: &mut rustls::Connection) {
    for _ in 0..16 {
        pump(client, server);
        pump(server, client);
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }
    panic!("handshake did not converge");
}

/// Move all pending TLS output from `from` into `to`.
fn pump(from: &mut rustls::Connection, to: &mut rustls::Connection) {
    while from.wants_write() {
        let mut buf = Vec::new();
        from.write_tls(&mut buf).unwrap();
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            to.read_tls(&mut cursor).unwrap();
        }
        to.process_new_packets().unwrap();
    }
}

/// Build a client whose verifier records the presented leaf, and the server config under test, then
/// run one handshake — returning the certificate the server actually presented.
fn handshake_presenting(server_config: rustls::ServerConfig) -> CertificateDer<'static> {
    let verifier = CapturingVerifier::new();
    let client_config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();

    let name = ServerName::try_from("dig.local").unwrap();
    let client = ClientConnection::new(Arc::new(client_config), name).unwrap();
    let server = ServerConnection::new(Arc::new(server_config)).unwrap();

    let mut client = rustls::Connection::from(client);
    let mut server = rustls::Connection::from(server);
    drive_handshake(&mut client, &mut server);
    verifier.presented()
}

#[test]
fn load_server_config_serves_the_on_disk_leaf_through_a_real_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let paths = seed(dir.path(), now());
    let (config, _resolver) = load_server_config(paths.leaf_cert(), paths.leaf_key()).unwrap();

    let presented = handshake_presenting(config);

    let on_disk = std::fs::read_to_string(paths.leaf_cert()).unwrap();
    let expected = rustls_pemfile::certs(&mut on_disk.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        presented, expected,
        "resolve() must present exactly the leaf on disk"
    );
}

#[test]
fn reload_hot_swaps_the_leaf_served_by_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let paths = seed(dir.path(), now());
    let (config, resolver) = load_server_config(paths.leaf_cert(), paths.leaf_key()).unwrap();

    // The first handshake presents the original leaf.
    let first = handshake_presenting(config);

    // Rotate the leaf on disk (a distinct issuance instant yields a distinct certificate) and reload.
    let ca_cert = std::fs::read_to_string(paths.ca_cert()).unwrap();
    let ca_key = std::fs::read_to_string(paths.ca_key()).unwrap();
    let parsed = ParsedCa::from_pem(&ca_cert, &ca_key).unwrap();
    let rotated = issue_leaf(&parsed, now() + time::Duration::days(1)).unwrap();
    std::fs::write(paths.leaf_key(), &rotated.key_pem).unwrap();
    std::fs::write(paths.leaf_cert(), &rotated.cert_pem).unwrap();
    resolver.reload().unwrap();

    // A fresh handshake — building a new config from the SAME resolver handle — serves the new leaf.
    let reloaded_config =
        rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
    let second = handshake_presenting(reloaded_config);

    let rotated_der = rustls_pemfile::certs(&mut rotated.cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    assert_ne!(first, second, "reload() must change the served leaf");
    assert_eq!(
        second, rotated_der,
        "after reload() resolve() serves the rotated leaf"
    );
}

#[test]
fn resolver_debug_shows_the_paths_without_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let paths = seed(dir.path(), now());
    let (_config, resolver) = load_server_config(paths.leaf_cert(), paths.leaf_key()).unwrap();

    let rendered = format!("{resolver:?}");
    assert!(rendered.contains("ReloadableCertResolver"));
    assert!(
        rendered.contains("leaf_cert_path"),
        "Debug surfaces the cert path for diagnostics"
    );
}
