//! Per-machine, name-constrained local Certificate Authority (SPEC §2).
//!
//! The CA is generated on the machine it protects and never shipped or shared. Its critical
//! `nameConstraints` extension is the load-bearing containment property: even a leaked CA key can
//! only ever vouch for `dig.local`, the `.dig` TLD, and the loopback addresses (SPEC §8).

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, GeneralSubtree,
    IsCa, KeyPair, KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256,
};
use time::{Duration, OffsetDateTime};

use crate::error::{Error, Result};

/// The organization name on every DIG local CA, so a trust-store listing is self-identifying.
pub const CA_ORGANIZATION: &str = "DIG Network local trust";

/// CA validity window: ~10 years. Rotated only on reinstall (SPEC §6.4).
pub const CA_LIFETIME: Duration = Duration::days(3650);

/// Backdate every `not_before` by an hour so a serving peer with a slightly slow clock does not
/// reject a freshly minted certificate as "not yet valid".
pub(crate) const CLOCK_SKEW_BACKDATE: Duration = Duration::hours(1);

/// A freshly generated CA: the self-signed certificate and its private key, both PEM-encoded.
///
/// The key is plain PKCS#8 PEM — read unattended by root/SYSTEM services (SPEC §1), so it is never
/// password-sealed. It MUST be written only under the admin/root-only TLS root (SPEC §5).
#[derive(Clone)]
pub struct CaMaterial {
    /// The self-signed CA certificate, PEM-encoded (`ca.crt`).
    pub cert_pem: String,
    /// The CA private key, PKCS#8 PEM-encoded (`ca.key`).
    pub key_pem: String,
}

impl std::fmt::Debug for CaMaterial {
    /// Never renders the private key (SPEC §8 key confidentiality).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaMaterial")
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// The permitted subtrees of the CA's `nameConstraints`, in the exact order they are encoded
/// (SPEC §2). Shared with the conformance test so the golden fixture and the issuer agree by
/// construction.
pub(crate) fn permitted_subtrees() -> Vec<GeneralSubtree> {
    vec![
        GeneralSubtree::DnsName("dig.local".to_string()),
        GeneralSubtree::DnsName(".dig".to_string()),
        GeneralSubtree::IpAddress(
            CidrSubnet::from_str_checked("127.0.0.0/8").expect("static IPv4 CIDR is valid"),
        ),
        GeneralSubtree::IpAddress(
            CidrSubnet::from_str_checked("::1/128").expect("static IPv6 CIDR is valid"),
        ),
    ]
}

/// `CidrSubnet::from_str` returns `Result<_, ()>`; give the caller a real message.
trait CidrParse: Sized {
    fn from_str_checked(s: &str) -> Result<Self>;
}
impl CidrParse for CidrSubnet {
    fn from_str_checked(s: &str) -> Result<Self> {
        s.parse()
            .map_err(|_| Error::Generation(format!("invalid CIDR subnet: {s}")))
    }
}

/// Generate a fresh per-machine CA (SPEC §2).
///
/// `hostname` labels the certificate so a human scanning their trust store recognizes it; `now` is
/// the issuance instant (injected so tests are deterministic). ECDSA P-256; 10-year validity;
/// `CA:TRUE` path-length 0; `keyCertSign` + `cRLSign`; critical `nameConstraints` permitting only
/// `dig.local`, `.dig`, and loopback.
pub fn generate_ca(hostname: &str, now: OffsetDateTime) -> Result<CaMaterial> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::Generation(format!("generate CA key: {e}")))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| Error::Generation(format!("CA params: {e}")))?;

    params.not_before = now - CLOCK_SKEW_BACKDATE;
    params.not_after = now + CA_LIFETIME;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, ca_common_name(hostname, now));
    dn.push(DnType::OrganizationName, CA_ORGANIZATION);
    params.distinguished_name = dn;

    // CA:TRUE, and a path length of 0 — it signs only end-entity leaves, never intermediates.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;

    // The containment property (SPEC §8): critical name constraints scope the anchor to the DIG
    // local namespace, so the key can never vouch for a public site even if it leaks.
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: permitted_subtrees(),
        excluded_subtrees: Vec::new(),
    });

    let cert = params
        .self_signed(&key)
        .map_err(|e| Error::Generation(format!("self-sign CA: {e}")))?;

    Ok(CaMaterial {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// The CA CommonName: `DIG Local CA (<hostname>, <YYYY-MM-DD>)` (SPEC §2).
fn ca_common_name(hostname: &str, now: OffsetDateTime) -> String {
    let d = now.date();
    format!(
        "DIG Local CA ({hostname}, {:04}-{:02}-{:02})",
        d.year(),
        d.month() as u8,
        d.day()
    )
}

/// A CA loaded back from its stored PEM, ready to sign leaves (SPEC §3).
///
/// Reconstructs the issuer metadata (distinguished name, key) from `ca.crt` + `ca.key` so leaf
/// issuance and renewal need only the on-disk material — the only two operations that touch the CA
/// key (SPEC §8).
pub struct ParsedCa {
    pub(crate) cert: rcgen::Certificate,
    pub(crate) key: KeyPair,
}

impl ParsedCa {
    /// Load the CA from its PEM certificate + key.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem)
            .map_err(|e| Error::KeyParse(format!("parse CA key: {e}")))?;
        // Rematerialize the issuer certificate from the stored CA cert. `self_signed` here only
        // rebuilds the in-memory issuer handle (distinguished name + key identifier); the persisted
        // `ca.crt` on disk is unchanged and remains the trusted anchor.
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| Error::CertificateParse(format!("parse CA cert: {e}")))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| Error::Generation(format!("rematerialize CA issuer: {e}")))?;
        Ok(Self { cert, key })
    }
}
