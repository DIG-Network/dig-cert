//! The crate's error type.

use std::path::PathBuf;

/// Everything that can go wrong generating, issuing, renewing, or loading DIG local-TLS material.
///
/// Errors never carry private-key bytes (§8 key confidentiality) — only paths, positions, and the
/// underlying library message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A certificate or key could not be generated or signed by `rcgen`.
    #[error("certificate generation failed: {0}")]
    Generation(String),

    /// A stored certificate could not be parsed (e.g. a corrupt `ca.crt` or `leaf.crt`).
    #[error("certificate parse failed: {0}")]
    CertificateParse(String),

    /// A stored private key could not be parsed (e.g. a corrupt `ca.key`).
    #[error("private key parse failed: {0}")]
    KeyParse(String),

    /// A file under the TLS root could not be read or written. The path is included; the key
    /// contents never are.
    #[error("i/o error at {path}: {source}")]
    Io {
        /// The file the operation targeted.
        path: PathBuf,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The current machine's TLS root could not be resolved (e.g. `%ProgramData%` unset).
    #[error("could not resolve the TLS root directory: {0}")]
    TlsRoot(String),

    /// A leaf renewal exhausted its retry budget without succeeding.
    #[error("leaf renewal failed after {attempts} attempts: {last}")]
    RenewalExhausted {
        /// How many attempts were made before giving up.
        attempts: u32,
        /// The final underlying error message.
        last: String,
    },
}

/// Attach the offending path to a `std::io::Error`.
pub(crate) fn io_at(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}

/// The crate's result alias.
pub type Result<T> = std::result::Result<T, Error>;
