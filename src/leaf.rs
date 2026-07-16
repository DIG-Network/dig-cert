//! Short-lived leaf issuance from the per-machine CA (SPEC §3).
//!
//! One wildcard leaf serves both `dig.local` (dig-node, 127.0.0.2) and the `.dig` gateway
//! (dig-dns, 127.0.0.5). A wildcard keeps the CA key cold — touched only at install and renewal —
//! rather than issuing per-name leaves at connection time.

use std::net::IpAddr;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String, KeyPair,
    KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use time::{Duration, OffsetDateTime};

use crate::ca::{ParsedCa, CLOCK_SKEW_BACKDATE};
use crate::error::{Error, Result};

/// Leaf validity window: 90 days (SPEC §3/§6).
pub const LEAF_LIFETIME: Duration = Duration::days(90);

/// The DNS names on every leaf, in SAN order (SPEC §3).
const LEAF_DNS_SANS: [&str; 2] = ["dig.local", "*.dig"];

/// The IP addresses on every leaf, in SAN order (SPEC §3): dig-node's local host IP, dig-node's
/// `dig.local` service IP, dig-dns's `.dig` gateway IP, and IPv6 loopback.
const LEAF_IP_SANS: [&str; 4] = ["127.0.0.1", "127.0.0.2", "127.0.0.5", "::1"];

/// A freshly issued leaf: the certificate and its private key, both PEM-encoded.
#[derive(Clone)]
pub struct LeafMaterial {
    /// The leaf certificate, PEM-encoded (`leaf.crt`).
    pub cert_pem: String,
    /// The leaf private key, PKCS#8 PEM-encoded (`leaf.key`).
    pub key_pem: String,
}

impl std::fmt::Debug for LeafMaterial {
    /// Never renders the private key (SPEC §8).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafMaterial")
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Issue a leaf signed by `ca`, valid `now − 1h .. now + 90d`, with the canonical SAN set and
/// `serverAuth` EKU (SPEC §3). This and CA generation/renewal are the only operations that use the
/// CA key.
pub fn issue_leaf(ca: &ParsedCa, now: OffsetDateTime) -> Result<LeafMaterial> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::Generation(format!("generate leaf key: {e}")))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| Error::Generation(format!("leaf params: {e}")))?;

    params.not_before = now - CLOCK_SKEW_BACKDATE;
    params.not_after = now + LEAF_LIFETIME;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "dig.local");
    params.distinguished_name = dn;

    params.subject_alt_names = leaf_sans()?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .map_err(|e| Error::Generation(format!("sign leaf: {e}")))?;

    Ok(LeafMaterial {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Build the canonical SAN list (SPEC §3) — DNS names first, then IPs, in fixed order.
fn leaf_sans() -> Result<Vec<SanType>> {
    let mut sans = Vec::with_capacity(LEAF_DNS_SANS.len() + LEAF_IP_SANS.len());
    for name in LEAF_DNS_SANS {
        let ia5 = Ia5String::try_from(name.to_string())
            .map_err(|e| Error::Generation(format!("invalid DNS SAN {name}: {e}")))?;
        sans.push(SanType::DnsName(ia5));
    }
    for ip in LEAF_IP_SANS {
        let addr: IpAddr = ip
            .parse()
            .map_err(|e| Error::Generation(format!("invalid IP SAN {ip}: {e}")))?;
        sans.push(SanType::IpAddress(addr));
    }
    Ok(sans)
}
