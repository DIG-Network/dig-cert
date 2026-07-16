//! Canonical on-disk layout and intended file modes for the TLS material (SPEC §5).
//!
//! This module is compute-only: it reports *where* the material lives and *what* mode it should
//! have. It never creates the directory with privilege or enforces an ACL — dig-installer (#623)
//! owns enforcement.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Intended Unix mode for private-key files (`ca.key`, `leaf.key`): owner read/write only.
pub const KEY_FILE_MODE: u32 = 0o600;
/// Intended Unix mode for certificate files (`ca.crt`, `leaf.crt`): world-readable, owner-writable.
pub const CERT_FILE_MODE: u32 = 0o644;
/// Intended Unix mode for the TLS root directory: owner access only.
pub const DIR_MODE: u32 = 0o700;

/// The canonical set of file paths under a TLS root (SPEC §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPaths {
    /// The TLS root directory.
    pub root: PathBuf,
}

impl TlsPaths {
    /// Build the layout under an explicit root — used by tests and by callers with a custom root.
    pub fn under(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Build the layout under the machine's canonical TLS root (SPEC §5):
    /// `%ProgramData%\DIG\tls` on Windows, `/etc/dig/tls` elsewhere.
    pub fn machine() -> Result<Self> {
        Ok(Self::under(machine_tls_root()?))
    }

    /// The CA private key (`ca.key`).
    pub fn ca_key(&self) -> PathBuf {
        self.root.join("ca.key")
    }
    /// The CA certificate (`ca.crt`) — the trust anchor dig-installer installs.
    pub fn ca_cert(&self) -> PathBuf {
        self.root.join("ca.crt")
    }
    /// The leaf private key (`leaf.key`).
    pub fn leaf_key(&self) -> PathBuf {
        self.root.join("leaf.key")
    }
    /// The leaf certificate (`leaf.crt`).
    pub fn leaf_cert(&self) -> PathBuf {
        self.root.join("leaf.crt")
    }
    /// The trust-store ledger (`trust-manifest.json`) dig-installer writes and uninstall walks.
    pub fn trust_manifest(&self) -> PathBuf {
        self.root.join("trust-manifest.json")
    }

    /// The intended Unix mode for a path within this layout (SPEC §5). Windows callers ignore this
    /// and apply an Admin/SYSTEM-only DACL instead.
    pub fn intended_mode(&self, path: &Path) -> u32 {
        match path.extension().and_then(|e| e.to_str()) {
            Some("key") => KEY_FILE_MODE,
            _ => CERT_FILE_MODE,
        }
    }
}

/// Resolve the machine TLS root (SPEC §5) without creating it.
fn machine_tls_root() -> Result<PathBuf> {
    if cfg!(windows) {
        let program_data = std::env::var_os("ProgramData")
            .ok_or_else(|| Error::TlsRoot("%ProgramData% is not set".to_string()))?;
        Ok(PathBuf::from(program_data).join("DIG").join("tls"))
    } else {
        Ok(PathBuf::from("/etc/dig/tls"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_places_every_file_under_the_root() {
        let p = TlsPaths::under("/etc/dig/tls");
        assert!(p.ca_key().ends_with("ca.key"));
        assert!(p.ca_cert().ends_with("ca.crt"));
        assert!(p.leaf_key().ends_with("leaf.key"));
        assert!(p.leaf_cert().ends_with("leaf.crt"));
        assert!(p.trust_manifest().ends_with("trust-manifest.json"));
        for f in [p.ca_key(), p.leaf_cert(), p.trust_manifest()] {
            assert!(f.starts_with("/etc/dig/tls"));
        }
    }

    #[test]
    fn keys_get_owner_only_mode_certs_get_readable_mode() {
        let p = TlsPaths::under("/etc/dig/tls");
        assert_eq!(p.intended_mode(&p.ca_key()), KEY_FILE_MODE);
        assert_eq!(p.intended_mode(&p.leaf_key()), KEY_FILE_MODE);
        assert_eq!(p.intended_mode(&p.ca_cert()), CERT_FILE_MODE);
        assert_eq!(p.intended_mode(&p.leaf_cert()), CERT_FILE_MODE);
    }
}
