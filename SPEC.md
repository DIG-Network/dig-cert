# `dig-cert` — normative specification

`dig-cert` is the single source of truth for DIG local-TLS material: a per-machine,
name-constrained local Certificate Authority, short-lived leaf issuance for `dig.local` and the
`.dig` TLD, automatic leaf renewal, and a reloadable `rustls` server configuration. Every consumer
(dig-installer, dig-node, dig-dns) links this crate so the CA model exists in exactly ONE place; a
second implementation of any value below is a specification violation.

The key words MUST, MUST NOT, SHOULD, and MAY are used per RFC 2119.

---

## 1. Scope

This crate:

- Generates a per-machine CA (§2).
- Issues leaf certificates from that CA (§3).
- Decides when a leaf (and the CA) needs renewal and performs renewal with an atomic on-disk swap
  and a reload hook (§6).
- Loads a `rustls::ServerConfig` backed by a hot-reloadable certificate resolver (§7).
- Computes the canonical on-disk paths and the intended file modes for the TLS material (§5).

This crate does NOT, and MUST NOT:

- Install the CA into any operating-system or browser trust store — that is dig-installer's
  responsibility (issue #623). This crate only writes the material to disk and reports where.
- Escalate privilege, create directories with elevated permissions, or enforce ACLs — it computes
  the *intended* mode; enforcement is dig-installer's.
- Open any network socket or run any listener — consumers own their sockets.
- Password-seal the private keys. The CA and leaf keys are read unattended by root/SYSTEM-run
  services, so they are stored as plain PEM in an admin/root-only directory; dig-keystore
  (password-sealed) is deliberately NOT used.

---

## 2. CA certificate profile

`generate_ca` MUST produce a CA meeting this profile.

- **Key algorithm:** ECDSA P-256 (`PKCS_ECDSA_P256_SHA256`). See §4.
- **Uniqueness:** the key MUST be freshly generated on the calling machine. No CA key is shipped,
  embedded, committed, or shared between machines. This per-machine uniqueness is the PRIMARY
  containment property (§8).
- **Subject / Issuer** (self-signed, so equal): CommonName = `DIG Local CA (<hostname>, <YYYY-MM-DD>)`,
  OrganizationName = `DIG Network local trust`. `<hostname>` is the caller-supplied machine hostname;
  `<YYYY-MM-DD>` is the UTC date of `now`.
- **Validity:** `not_before = now − 1h` (clock-skew tolerance), `not_after = now + 3650 days`
  (≈10 years). The CA is rotated only on reinstall (§6.4).
- **basicConstraints:** `CA:TRUE`, critical, path-length 0 (issues only end-entity leaves).
- **keyUsage:** `keyCertSign`, `cRLSign`, critical.
- **nameConstraints:** present and marked **critical**, with `permittedSubtrees` (and empty
  `excludedSubtrees`) equal to exactly, in this order:
  1. dNSName `dig.local`
  2. dNSName `.dig`
  3. iPAddress `127.0.0.0/8`
  4. iPAddress `::1/128`

  Any certificate chain asserting a name outside these subtrees MUST fail path validation on a
  verifier that enforces name constraints on the trust anchor. The exact DER encoding of this
  extension is a normative conformance fixture (§9).

---

## 3. Leaf certificate profile

`issue_leaf` MUST sign, with the CA key, a leaf meeting this profile.

- **Key algorithm:** ECDSA P-256, a freshly generated key distinct from the CA key.
- **Subject:** CommonName = `dig.local`.
- **Validity:** `not_before = now − 1h`, `not_after = now + 90 days` (§6).
- **subjectAltName** (exactly, in this order):
  - dNSName `dig.local`
  - dNSName `*.dig`
  - iPAddress `127.0.0.1`
  - iPAddress `127.0.0.2`
  - iPAddress `127.0.0.5`
  - iPAddress `::1`
- **extendedKeyUsage:** `serverAuth`.
- **keyUsage:** `digitalSignature`.
- **Issuer:** the CA subject; the authority-key-identifier links to the CA.

Every SAN above lies within the CA's permittedSubtrees (§2), so an honestly issued leaf validates;
a leaf naming any other host does not (§8, §9).

### 3.1 Known limitation — the `*.dig` wildcard (recorded spike finding)

A wildcard immediately under a single-label TLD (`*.dig`) is rejected by verifiers that enforce the
common wildcard rule that a `*` must have at least two labels beneath it — including `rustls-webpki`
(proven in the conformance suite: `webpki_rejects_a_wildcard_directly_under_the_single_label_dig_tld`).
Concrete `.dig` names (`app.dig`, `foo.bar.dig`) validate under the CA and its name constraints
without issue (`ca_vouches_for_concrete_names_inside_the_permitted_subtrees`). Consequently:

- The wildcard leaf serves `dig.local` universally and `.dig` names for verifiers that accept the
  `*.dig` wildcard (the exact acceptance across production browsers is a #620 follow-up spike).
- If a target verifier rejects `*.dig`, the contingency (a #620 follow-up, NOT built here) is for the
  `.dig` gateway (dig-dns) to issue short-lived per-name leaves on demand at SNI — which this crate
  already supports mechanically, since `issue_leaf`'s issuance path signs any name inside the
  permitted subtrees.

This limitation is pinned by a regression test so the contingency is driven by evidence rather than
rediscovered.

---

## 4. Key algorithm

ECDSA P-256 (`PKCS_ECDSA_P256_SHA256`) is used for both the CA and every leaf. It is small, fast,
and universally trusted by the target platforms; RSA buys nothing for a local anchor. Keys are
serialized as PKCS#8 PEM. Key material MUST NOT be logged.

---

## 5. On-disk layout and intended file modes

`dig-cert` reads and writes these files by absolute path. It computes the paths and the intended
modes; it does NOT create the directory with privilege or enforce the mode (dig-installer, #623).

- **TLS root:** Windows `%ProgramData%\DIG\tls`; Unix `/etc/dig/tls`.
- **Files:** `ca.key`, `ca.crt`, `leaf.key`, `leaf.crt`, `trust-manifest.json`.
- **Intended modes (Unix):** directory `0700`; private keys (`ca.key`, `leaf.key`) `0600`;
  certificates (`ca.crt`, `leaf.crt`) `0644`. On Windows the equivalent is an Admin/SYSTEM-only
  DACL, enforced by dig-installer.

Private-key files MUST NOT be world-readable, logged, or committed.

---

## 6. Renewal contract

- **Leaf lifetime** is 90 days; a leaf MUST be renewed once its remaining validity drops below
  **30 days**: `needs_renewal(leaf, now)` returns `true` iff `not_after − now < 30 days` (also
  `true` if the leaf is absent or unparseable).
- **Renewal** re-issues a fresh leaf from the on-disk CA (§3) and writes `leaf.key` + `leaf.crt`
  via **write-temp-then-atomic-rename within the TLS root**, so a concurrent reader never observes a
  torn key/cert pair. On POSIX this is `rename(2)`; on Windows it is `ReplaceFile` semantics.
- **No-downtime pickup:** after the swap the renewal manager fires the reload hook
  (`ReloadableCertResolver::reload`, §7); the serving process begins presenting the new leaf without
  a restart and without dropping connections.
- **Never-lapse retry:** a renewal pass retries transient failures (I/O, transient issuance error)
  on a bounded exponential backoff schedule; a single transient failure MUST NOT let the leaf lapse.
  The manager is invoked by dig-node (the runtime owner, #624) at service start and once daily —
  the 30-day trigger against a 90-day lifetime leaves ample margin for retries.
- **CA renewal (§6.4):** the manager detects when the CA is within 180 days of expiry and REPORTS
  it (`ca_renewal_due`). It MUST NOT silently rotate the CA during an automatic maintenance pass:
  rotating the trust anchor invalidates every installed-trust relationship until dig-installer
  re-installs the new CA, so CA rotation is an explicit, installer-coordinated operation
  (`rotate_ca`), never an automatic side effect. Given the 10-year horizon this detection is a
  long-lead alert, not an inline action.

---

## 7. rustls loader and hot-reload contract

- `load_server_config(leaf_crt, leaf_key)` returns a `rustls::ServerConfig` whose certificate
  resolver is a shared `ReloadableCertResolver`, plus a handle to that resolver.
- `ReloadableCertResolver` holds the current `CertifiedKey` behind a lock-free atomic pointer swap;
  the serving thread reads it without blocking.
- `reload()` re-reads the leaf key + certificate files and atomically replaces the in-memory
  `CertifiedKey`. In-flight and subsequent handshakes use whichever `CertifiedKey` was current when
  they began; `reload()` never tears down the `ServerConfig`. A failed `reload()` (e.g. a
  half-written or missing file) leaves the previously served `CertifiedKey` in place.
- The rustls stack is pinned to `rustls` 0.23 with `default-features = false` and features
  `ring`, `std`, `tls12`, `logging` — byte-identical to dig-node and dig-dns — so a consumer linking
  all of them installs exactly one `CryptoProvider` (ring) and never triggers the multiple-provider
  install panic.

---

## 8. Security properties

- **Per-machine uniqueness (primary containment).** Each machine's CA key is unique and generated
  locally; there is no shared secret to steal once and reuse against every install (the Superfish
  anti-pattern is explicitly excluded).
- **Name-constraint containment (defense-in-depth).** The critical nameConstraints (§2) mean the CA
  cannot vouch for any public domain even if its key leaks: a chain for `example.com` (or any name
  outside `dig.local`/`.dig`/loopback) MUST be rejected by a name-constraint-enforcing verifier
  (§9). Some legacy platforms ignore constraints on a directly trusted anchor; the primary
  containment (per-machine key + admin-only key ACL) holds regardless, and constraints are marked
  critical so modern verifiers enforce them.
- **Key confidentiality.** Private keys are stored only under the admin/root-only TLS root (§5),
  never logged, never committed. Only two operations read `ca.key`: install (dig-installer) and
  leaf renewal (dig-node via this crate's manager).

---

## 9. Conformance fixtures

An implementation conforms only if:

1. **Golden nameConstraints bytes.** The CA's nameConstraints extension is critical and its DER
   value equals the fixture in the test suite (the four permitted subtrees of §2, in order).
2. **Containment.** A leaf issued honestly by the CA chain-validates for `dig.local` and for a
   `*.dig` name under the CA as trust anchor; a leaf forged for `example.com` and signed by the same
   CA is REJECTED with a name-constraint violation by an independent path-validation library.
3. **Leaf profile.** An issued leaf carries exactly the SAN set of §3, serverAuth EKU, and a
   90-day validity window.
4. **Renewal math.** `needs_renewal` is `false` at 31 days remaining and `true` at 29 days
   remaining and when the leaf is absent.
5. **Atomic swap.** A renewal never leaves a torn key/cert pair readable on disk.
6. **Loader / reload.** `load_server_config` yields a working `ServerConfig`; `reload()` swaps to a
   newly issued leaf without constructing a new `ServerConfig`.
