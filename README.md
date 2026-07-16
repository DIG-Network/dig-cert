# dig-cert

Per-machine, name-constrained local TLS CA + leaf issuance + automatic renewal for `dig.local` and
the `.dig` TLD. The single source of truth for DIG local-HTTPS material, shared by dig-installer,
dig-node, and dig-dns (part of the #620 local-HTTPS epic).

## What it does

- **`generate_ca`** — a fresh, per-machine ECDSA P-256 CA whose **critical `nameConstraints`** permit
  only `dig.local`, the `.dig` TLD, and loopback. Even a leaked CA key can never vouch for a public
  domain — the load-bearing containment property.
- **`issue_leaf`** — a 90-day leaf (SAN `dig.local`, `*.dig`, `127.0.0.1/2/5`, `::1`, `serverAuth`),
  signed by the CA.
- **`RenewalManager` / `needs_renewal`** — automatic renewal: renews the leaf at <30 days remaining,
  writes the new pair atomically (temp + rename), fires a reload hook, and retries transient failures
  on a backoff so a leaf never lapses. dig-node is the runtime owner that drives it.
- **`load_server_config` / `ReloadableCertResolver`** — a `rustls` 0.23 (ring) `ServerConfig` whose
  leaf hot-swaps at runtime with no restart and no dropped connections.
- **`TlsPaths`** — the canonical on-disk layout (`%ProgramData%\DIG\tls` / `/etc/dig/tls`) and intended
  file modes.

## What it does NOT do

Install into trust stores, escalate privilege, enforce ACLs, open sockets, or password-seal keys —
those belong to dig-installer (#623) and the serving consumers. See `SPEC.md` for the normative
contract and `runbooks/` for build/run.

## Consumed as a git dependency

```toml
[dependencies]
dig-cert = { git = "https://github.com/DIG-Network/dig-cert", tag = "v0.1.0" }
```

Pin the released tag — never `main` — so the CA model never drifts between consumers.
