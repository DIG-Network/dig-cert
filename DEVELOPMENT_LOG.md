# Development log — dig-cert

Durable, high-signal realizations. Not a change diary.

## `*.dig` wildcard is rejected by rustls-webpki (and browser-class verifiers)

A wildcard SAN directly under a single-label TLD — `*.dig` — is rejected by `rustls-webpki` with
`MalformedDnsIdentifier`, because the common wildcard rule requires at least two labels beneath the
`*` (so `*.example.com` is fine, `*.com` / `*.dig` are not). Concrete `.dig` names (`app.dig`,
`foo.bar.dig`) validate fine under the CA + its name constraints. This is the #620 C1 "*.dig
wildcard acceptance" spike surfacing at the library level. Pinned by
`webpki_rejects_a_wildcard_directly_under_the_single_label_dig_tld`. If production browsers likewise
reject `*.dig`, the contingency is dig-dns issuing per-name leaves at SNI (a #620 follow-up); the
issuance path already signs any name inside the permitted subtrees, so no new crypto is needed.

## rustls posture must match consumers exactly (ring, no default provider)

`rustls` is pinned to 0.23 `default-features = false` with `ring, std, tls12, logging` — byte-identical
to dig-dns and dig-node-core — and the `ServerConfig` is built with an EXPLICIT
`ring::default_provider()` via `builder_with_provider`, never the process-default. A consumer that
links dig-cert alongside those crates then installs exactly one `CryptoProvider`; relying on the
process-default (or enabling `aws-lc`) is what triggers the "multiple CryptoProviders" install panic.

## Name constraints are read from the trust anchor by webpki

`webpki::anchor_from_trusted_cert` extracts the CA's `nameConstraints` into the `TrustAnchor`, and
`verify_for_usage` enforces them during path building. That is why a leaf forged for `example.com`
and signed by the (leaked) CA key is rejected with `NameConstraintViolation` — the containment proof.
The golden DER of the extension is hand-derived in the conformance test and matches rcgen's output
byte-for-byte (RFC 5280: `minimum` DEFAULT 0 omitted; dNSName `[2]`, iPAddress `[7]` = addr‖mask).

## CA rotation is installer-coordinated, never an automatic side effect

The renewal manager renews the LEAF automatically but only FLAGS an approaching-expiry CA
(`ca_renewal_due`); it never rewrites `ca.{key,crt}` during a maintenance pass. Rotating the trust
anchor invalidates every installed-trust relationship until dig-installer re-installs the new CA, so
rotation is the explicit `rotate_ca` operation the installer drives — not something that can silently
break HTTPS on a daily timer.
