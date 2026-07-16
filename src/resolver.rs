//! The reloadable `rustls` server configuration (SPEC §7).
//!
//! A serving process ([dig-node] on `127.0.0.2:443`, [dig-dns] on `127.0.0.5:443`) builds its
//! `ServerConfig` once via [`load_server_config`] and keeps the returned resolver handle. When the
//! leaf rotates (SPEC §6) the renewal manager calls [`ReloadableCertResolver::reload`], which swaps
//! the in-memory certificate atomically — no restart, no dropped connections.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::crypto::ring;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{io_at, Error, Result};

/// A `rustls` certificate resolver whose leaf can be hot-swapped at runtime (SPEC §7).
///
/// The current [`CertifiedKey`] lives behind an [`ArcSwap`], so the serving thread reads it
/// lock-free while a renewal thread publishes a replacement.
pub struct ReloadableCertResolver {
    current: ArcSwap<CertifiedKey>,
    leaf_cert_path: PathBuf,
    leaf_key_path: PathBuf,
}

impl ReloadableCertResolver {
    /// Build a resolver from the leaf certificate + key on disk, reading them immediately so a
    /// missing or corrupt leaf fails fast rather than at first handshake.
    pub fn from_files(
        leaf_cert_path: impl Into<PathBuf>,
        leaf_key_path: impl Into<PathBuf>,
    ) -> Result<Arc<Self>> {
        let leaf_cert_path = leaf_cert_path.into();
        let leaf_key_path = leaf_key_path.into();
        let key = load_certified_key(&leaf_cert_path, &leaf_key_path)?;
        Ok(Arc::new(Self {
            current: ArcSwap::from_pointee(key),
            leaf_cert_path,
            leaf_key_path,
        }))
    }

    /// Re-read the leaf files and atomically replace the served certificate (SPEC §7). On failure
    /// (a half-written or missing file) the previously served certificate stays in place, so a
    /// torn read during rotation never takes the listener down — the next reload picks up the
    /// completed pair.
    pub fn reload(&self) -> Result<()> {
        let key = load_certified_key(&self.leaf_cert_path, &self.leaf_key_path)?;
        self.current.store(Arc::new(key));
        Ok(())
    }
}

impl std::fmt::Debug for ReloadableCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadableCertResolver")
            .field("leaf_cert_path", &self.leaf_cert_path)
            .field("leaf_key_path", &self.leaf_key_path)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for ReloadableCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

/// Build a `rustls::ServerConfig` backed by a fresh [`ReloadableCertResolver`], returning both the
/// config (hand to your listener) and the resolver handle (hand to the renewal manager).
///
/// The config is built against the explicit ring provider — never the fragile process-default — so
/// a consumer that also links dig-node/dig-dns installs exactly one `CryptoProvider` (SPEC §7).
pub fn load_server_config(
    leaf_cert_path: impl Into<PathBuf>,
    leaf_key_path: impl Into<PathBuf>,
) -> Result<(ServerConfig, Arc<ReloadableCertResolver>)> {
    let resolver = ReloadableCertResolver::from_files(leaf_cert_path, leaf_key_path)?;
    let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Generation(format!("rustls protocol versions: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    Ok((config, resolver))
}

/// Load a leaf PEM cert chain + key into a signed `CertifiedKey`.
fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let chain = load_cert_chain(cert_path)?;
    let key_der = load_private_key(key_path)?;
    let signing_key = ring::sign::any_ecdsa_type(&key_der)
        .map_err(|e| Error::KeyParse(format!("leaf key is not a usable ECDSA key: {e}")))?;
    Ok(CertifiedKey::new(chain, signing_key))
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path).map_err(|e| io_at(path, e))?);
    let chain: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let chain = chain.map_err(|e| io_at(path, e))?;
    if chain.is_empty() {
        return Err(Error::CertificateParse(format!(
            "no certificates in {}",
            path.display()
        )));
    }
    Ok(chain)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path).map_err(|e| io_at(path, e))?);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| io_at(path, e))?
        .ok_or_else(|| Error::KeyParse(format!("no private key in {}", path.display())))
}
