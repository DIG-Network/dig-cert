//! `dig-cert` — the single source of truth for DIG local-TLS material.
//!
//! DIG serves `https://dig.local` (dig-node) and the `.dig` TLD gateway (dig-dns) with a locally
//! trusted certificate. This crate owns the model those consumers share (see `SPEC.md`):
//!
//! - a **per-machine, name-constrained CA** ([`generate_ca`]) whose critical `nameConstraints`
//!   scope it to `dig.local`, the `.dig` TLD, and loopback — so even a leaked CA key can never
//!   vouch for a public domain (the load-bearing containment property);
//! - short-lived **leaf issuance** ([`issue_leaf`]) for those names;
//! - **automatic renewal** ([`RenewalManager`], [`needs_renewal`]) with an atomic on-disk swap and a
//!   reload hook, so a leaf never lapses and rotation causes no downtime;
//! - a **reloadable `rustls` loader** ([`load_server_config`], [`ReloadableCertResolver`]);
//! - the **canonical on-disk layout** ([`TlsPaths`]) every consumer agrees on.
//!
//! # Boundaries
//!
//! This crate generates and reads material and reports where it belongs. It does NOT install the CA
//! into any trust store, escalate privilege, enforce file ACLs, open sockets, or password-seal keys
//! — those are the responsibilities of dig-installer (#623) and the serving consumers. See SPEC §1.
//!
//! # Example
//!
//! ```no_run
//! use dig_cert::{generate_ca, issue_leaf, ParsedCa};
//! use time::OffsetDateTime;
//!
//! let now = OffsetDateTime::now_utc();
//! let ca = generate_ca("my-host", now)?;               // per-machine CA (dig-installer)
//! let parsed = ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem)?;
//! let leaf = issue_leaf(&parsed, now)?;                 // 90-day wildcard leaf
//! # Ok::<(), dig_cert::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

mod ca;
mod error;
mod leaf;
mod paths;
mod renewal;
mod resolver;

pub use ca::{generate_ca, CaMaterial, ParsedCa, CA_LIFETIME, CA_ORGANIZATION};
pub use error::{Error, Result};
pub use leaf::{issue_leaf, LeafMaterial, LEAF_LIFETIME};
pub use paths::{TlsPaths, CERT_FILE_MODE, DIR_MODE, KEY_FILE_MODE};
pub use renewal::{
    needs_ca_renewal, needs_renewal, rotate_ca, BackoffSchedule, RenewalManager, RenewalReport,
    Sleeper, ThreadSleeper, CA_RENEW_REMAINING, LEAF_RENEW_REMAINING,
};
pub use resolver::{load_server_config, ReloadableCertResolver};
