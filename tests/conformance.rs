//! Conformance fixtures for `dig-cert` (SPEC §9).
//!
//! These are the load-bearing security proofs: the golden `nameConstraints` bytes, and — through an
//! INDEPENDENT path-validation library (rustls-webpki) — that the CA can vouch for `dig.local` /
//! `*.dig` but is REJECTED when it tries to vouch for a public domain, even with its own key.

use dig_cert::{generate_ca, issue_leaf, needs_renewal, ParsedCa};
use rustls_pki_types::{CertificateDer, UnixTime};
use time::{Duration, OffsetDateTime};

/// A fixed issuance instant so fixtures are deterministic.
fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_752_000_000).unwrap() // 2025-07-08T18:40:00Z
}

fn unix(now: OffsetDateTime) -> UnixTime {
    UnixTime::since_unix_epoch(std::time::Duration::from_secs(now.unix_timestamp() as u64))
}

fn to_der(pem: &str) -> CertificateDer<'static> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
}

/// Extract the raw DER value + criticality of the nameConstraints (OID 2.5.29.30) extension.
fn name_constraints_ext(cert_pem: &str) -> (bool, Vec<u8>) {
    use x509_parser::prelude::*;
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == "2.5.29.30")
        .expect("CA must carry a nameConstraints extension");
    (ext.critical, ext.value.to_vec())
}

#[test]
fn ca_name_constraints_match_the_golden_der_and_are_critical() {
    let ca = generate_ca("goldenhost", fixed_now()).unwrap();
    let (critical, der) = name_constraints_ext(&ca.cert_pem);

    assert!(critical, "nameConstraints MUST be critical (SPEC §2)");

    // The hand-derived RFC-5280 encoding of the four permitted subtrees (SPEC §2), in order:
    //   NameConstraints ::= SEQUENCE { permittedSubtrees [0] SEQUENCE OF GeneralSubtree }
    //   GeneralSubtree  ::= SEQUENCE { base GeneralName }         (minimum DEFAULT 0 omitted)
    //   dNSName  = [2] IA5String        (0x82)
    //   iPAddress= [7] OCTET STRING     (0x87)  addr || mask
    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        0x30, 0x47,                                     // NameConstraints SEQUENCE, len 71
          0xA0, 0x45,                                   //  permittedSubtrees [0], len 69
            // dNSName "dig.local"
            0x30, 0x0B, 0x82, 0x09,
              b'd', b'i', b'g', b'.', b'l', b'o', b'c', b'a', b'l',
            // dNSName ".dig"
            0x30, 0x06, 0x82, 0x04,
              b'.', b'd', b'i', b'g',
            // iPAddress 127.0.0.0/8  -> 7f000000 ff000000
            0x30, 0x0A, 0x87, 0x08,
              0x7F, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00,
            // iPAddress ::1/128 -> 16-byte addr (…01) || 16-byte mask (all ff)
            0x30, 0x22, 0x87, 0x20,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];
    assert_eq!(
        hex(&der),
        hex(&expected),
        "nameConstraints DER drifted from the golden fixture"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Forge a leaf with an arbitrary SAN set, signed by the given CA's own key — the tool for both the
/// "assume the key leaked" negative proof and the concrete-name positive proof.
fn leaf_signed_by_ca(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    sans: &[&str],
    now: OffsetDateTime,
) -> CertificateDer<'static> {
    let ca_key = rcgen::KeyPair::from_pem(ca_key_pem).unwrap();
    let ca_cert = rcgen::CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .unwrap()
        .self_signed(&ca_key)
        .unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(90);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
    CertificateDer::from(leaf.der().to_vec())
}

fn verify(
    ca_cert_pem: &str,
    leaf_der: &CertificateDer<'_>,
    now: OffsetDateTime,
) -> Result<(), webpki::Error> {
    let ca_der = to_der(ca_cert_pem);
    let anchor = webpki::anchor_from_trusted_cert(&ca_der).unwrap();
    let ee = webpki::EndEntityCert::try_from(leaf_der).unwrap();
    ee.verify_for_usage(
        &[webpki::ring::ECDSA_P256_SHA256],
        &[anchor],
        &[],
        unix(now),
        webpki::KeyUsage::server_auth(),
        None,
        None,
    )
    .map(|_| ())
}

#[test]
fn ca_vouches_for_concrete_names_inside_the_permitted_subtrees() {
    // The positive containment proof: the CA + its name constraints ALLOW the DIG namespace. An
    // independent verifier accepts concrete `dig.local` and `*.dig`-subtree names.
    let now = fixed_now();
    let ca = generate_ca("host", now).unwrap();
    for name in ["dig.local", "app.dig", "foo.bar.dig"] {
        let leaf = leaf_signed_by_ca(&ca.cert_pem, &ca.key_pem, &[name], now);
        verify(&ca.cert_pem, &leaf, now)
            .unwrap_or_else(|e| panic!("CA should vouch for {name}: {e:?}"));
    }
}

#[test]
fn webpki_rejects_a_wildcard_directly_under_the_single_label_dig_tld() {
    // RECORDED SPIKE FINDING (design #620 C1): the shipped wildcard leaf (`issue_leaf`, SAN `*.dig`)
    // is REJECTED by rustls-webpki — a browser-representative verifier — with MalformedDnsIdentifier,
    // because a wildcard immediately under a single-label TLD (`*.dig`) violates the wildcard rule
    // most modern verifiers enforce (a wildcard needs >=2 labels beneath it). Concrete `.dig` names
    // validate fine (see `ca_vouches_for_concrete_names_inside_the_permitted_subtrees`). This test
    // PINS the known limitation so the dig-dns SNI per-name contingency (a #620 follow-up) is driven
    // by a regression, not rediscovered. See SPEC §3 + the crate CHANGELOG/DEVELOPMENT_LOG.
    let now = fixed_now();
    let ca = generate_ca("host", now).unwrap();
    let parsed = ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
    let leaf = issue_leaf(&parsed, now).unwrap();
    let leaf_der = to_der(&leaf.cert_pem);

    let err = verify(&ca.cert_pem, &leaf_der, now)
        .expect_err("the *.dig wildcard leaf is rejected by rustls-webpki today");
    assert_eq!(err, webpki::Error::MalformedDnsIdentifier);
}

#[test]
fn ca_cannot_vouch_for_a_public_domain_even_with_its_own_key() {
    // The containment proof (SPEC §8): forge a leaf for example.com signed by the CA's OWN key —
    // i.e. assume the CA key leaked — and show an independent verifier REJECTS it on the CA's name
    // constraints.
    let now = fixed_now();
    let ca = generate_ca("host", now).unwrap();

    let ca_key = rcgen::KeyPair::from_pem(&ca.key_pem).unwrap();
    let ca_params = rcgen::CertificateParams::from_ca_cert_pem(&ca.cert_pem).unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let evil_key = rcgen::KeyPair::generate().unwrap();
    let mut evil = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    evil.not_before = now - Duration::hours(1);
    evil.not_after = now + Duration::days(90);
    evil.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let evil_leaf = evil.signed_by(&evil_key, &ca_cert, &ca_key).unwrap();
    let evil_der = CertificateDer::from(evil_leaf.der().to_vec());

    let ca_der = to_der(&ca.cert_pem);
    let anchor = webpki::anchor_from_trusted_cert(&ca_der).unwrap();
    let ee = webpki::EndEntityCert::try_from(&evil_der).unwrap();

    let err = ee
        .verify_for_usage(
            &[webpki::ring::ECDSA_P256_SHA256],
            &[anchor],
            &[],
            unix(now),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_| ())
        .expect_err("a forged example.com leaf MUST NOT validate under the CA");
    assert_eq!(
        err,
        webpki::Error::NameConstraintViolation,
        "rejection MUST be on the name constraints, not some incidental failure"
    );
}

#[test]
fn leaf_carries_the_canonical_san_set_and_ninety_day_validity() {
    use x509_parser::prelude::*;
    let now = fixed_now();
    let ca = generate_ca("host", now).unwrap();
    let parsed = ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
    let leaf = issue_leaf(&parsed, now).unwrap();

    let (_, pem) = parse_x509_pem(leaf.cert_pem.as_bytes()).unwrap();
    let cert = pem.parse_x509().unwrap();

    // 90-day window (allowing the 1h skew backdate on not_before).
    let span = cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
    assert_eq!(
        span,
        90 * 86400 + 3600,
        "leaf validity is 90d + 1h backdate"
    );

    let san = cert
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(s) => Some(s),
            _ => None,
        })
        .expect("leaf must have SANs");
    let names: Vec<String> = san.general_names.iter().map(|g| format!("{g:?}")).collect();
    let joined = names.join(",");
    // x509-parser renders IPs as byte arrays; match on both DNS text and the IP byte tuples.
    for expected in [
        "dig.local",
        "*.dig",
        "127, 0, 0, 1",
        "127, 0, 0, 2",
        "127, 0, 0, 5",
        "0, 0, 0, 1", // ::1 (tail of the 16-byte v6 array)
    ] {
        assert!(
            joined.contains(expected),
            "SAN set missing {expected}: {joined}"
        );
    }
}

#[test]
fn needs_renewal_flips_at_the_thirty_day_boundary() {
    let issue = fixed_now();
    let ca = generate_ca("host", issue).unwrap();
    let parsed = ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
    let leaf = issue_leaf(&parsed, issue).unwrap();

    // Leaf expires at issue + 90d. At 31 days remaining -> not due; at 29 -> due.
    let at_31_left = issue + Duration::days(90) - Duration::days(31);
    let at_29_left = issue + Duration::days(90) - Duration::days(29);
    assert!(
        !needs_renewal(&leaf.cert_pem, at_31_left),
        "31d left is not due"
    );
    assert!(needs_renewal(&leaf.cert_pem, at_29_left), "29d left is due");

    // A garbage / missing leaf is always due (self-heal).
    assert!(needs_renewal("not a certificate", issue));
}
