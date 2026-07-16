//! Automatic leaf renewal (SPEC §6).
//!
//! The renewal logic lives here — in one tested place — not in each consumer. dig-node (#624) is
//! the runtime OWNER: it constructs a [`RenewalManager`] and drives [`RenewalManager::maintain`] at
//! service start and once daily. The manager decides whether the leaf needs renewal, re-issues it
//! from the on-disk CA, writes the new pair atomically, fires the reload hook, and retries transient
//! failures on a backoff so a leaf never lapses.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use time::{Duration, OffsetDateTime};

use crate::ca::{generate_ca, ParsedCa};
use crate::error::{io_at, Error, Result};
use crate::leaf::issue_leaf;
use crate::paths::TlsPaths;
use crate::resolver::ReloadableCertResolver;

/// Renew the leaf once its remaining validity drops below this (SPEC §6).
pub const LEAF_RENEW_REMAINING: Duration = Duration::days(30);

/// Flag the CA for installer-coordinated rotation once it is within this of expiry (SPEC §6.4).
pub const CA_RENEW_REMAINING: Duration = Duration::days(180);

/// Does this leaf need renewal now (SPEC §6)? True when it expires within [`LEAF_RENEW_REMAINING`],
/// and also when it cannot be parsed — an unreadable leaf is treated as due so the manager heals it.
pub fn needs_renewal(leaf_cert_pem: &str, now: OffsetDateTime) -> bool {
    match not_after(leaf_cert_pem) {
        Some(expiry) => expiry - now < LEAF_RENEW_REMAINING,
        None => true,
    }
}

/// Is the CA within [`CA_RENEW_REMAINING`] of expiry? Unparseable ⇒ treated as due.
pub fn needs_ca_renewal(ca_cert_pem: &str, now: OffsetDateTime) -> bool {
    match not_after(ca_cert_pem) {
        Some(expiry) => expiry - now < CA_RENEW_REMAINING,
        None => true,
    }
}

/// Parse the `notAfter` instant out of a PEM certificate, or `None` if it does not parse.
fn not_after(cert_pem: &str) -> Option<OffsetDateTime> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let cert = pem.parse_x509().ok()?;
    OffsetDateTime::from_unix_timestamp(cert.validity().not_after.timestamp()).ok()
}

/// What a maintenance pass did (SPEC §6/§9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalReport {
    /// Whether the leaf was re-issued this pass.
    pub leaf_renewed: bool,
    /// Whether the CA is within its renewal window and needs an installer-coordinated rotation
    /// (SPEC §6.4). The manager reports this; it never rotates the anchor automatically.
    pub ca_renewal_due: bool,
    /// How many issue+write attempts a renewal took (1 on first success).
    pub attempts: u32,
}

/// Abstracts sleeping so the backoff is testable without real delays.
pub trait Sleeper: Send + Sync {
    /// Block for `dur`.
    fn sleep(&self, dur: StdDuration);
}

/// Sleeps for real via [`std::thread::sleep`] — the production sleeper.
#[derive(Debug, Default)]
pub struct ThreadSleeper;
impl Sleeper for ThreadSleeper {
    fn sleep(&self, dur: StdDuration) {
        std::thread::sleep(dur);
    }
}

/// The delays between renewal retries (SPEC §6 never-lapse). One attempt is always made; each delay
/// adds one more retry after a transient failure.
#[derive(Debug, Clone)]
pub struct BackoffSchedule {
    delays: Vec<StdDuration>,
}

impl Default for BackoffSchedule {
    /// Three retries at 1s, 5s, 30s — bounded, and negligible against a 30-day renewal margin.
    fn default() -> Self {
        Self {
            delays: vec![
                StdDuration::from_secs(1),
                StdDuration::from_secs(5),
                StdDuration::from_secs(30),
            ],
        }
    }
}

impl BackoffSchedule {
    /// A schedule with the given retry delays (empty ⇒ a single attempt, no retries).
    pub fn new(delays: Vec<StdDuration>) -> Self {
        Self { delays }
    }
}

/// Drives leaf renewal for one machine's TLS material (SPEC §6).
pub struct RenewalManager {
    paths: TlsPaths,
    resolver: Option<Arc<ReloadableCertResolver>>,
    backoff: BackoffSchedule,
    sleeper: Arc<dyn Sleeper>,
}

impl RenewalManager {
    /// A manager over `paths` that fires `resolver.reload()` after a successful renewal so the
    /// serving process picks up the new leaf without a restart (SPEC §7).
    pub fn new(paths: TlsPaths, resolver: Arc<ReloadableCertResolver>) -> Self {
        Self {
            paths,
            resolver: Some(resolver),
            backoff: BackoffSchedule::default(),
            sleeper: Arc::new(ThreadSleeper),
        }
    }

    /// A manager with no reload hook — for a caller that renews on disk but reloads elsewhere
    /// (e.g. dig-dns watching the files).
    pub fn without_resolver(paths: TlsPaths) -> Self {
        Self {
            paths,
            resolver: None,
            backoff: BackoffSchedule::default(),
            sleeper: Arc::new(ThreadSleeper),
        }
    }

    /// Override the retry backoff (mainly for tests).
    pub fn with_backoff(mut self, backoff: BackoffSchedule) -> Self {
        self.backoff = backoff;
        self
    }

    /// Override the sleeper (mainly for tests).
    pub fn with_sleeper(mut self, sleeper: Arc<dyn Sleeper>) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// Run one maintenance pass (SPEC §6): renew the leaf if due (or missing), retrying transient
    /// failures on the backoff; then report whether the CA is approaching expiry. dig-node calls
    /// this at start and daily.
    pub fn maintain(&self, now: OffsetDateTime) -> Result<RenewalReport> {
        let ca_cert_pem = read_to_string(&self.paths.ca_cert())?;
        let ca_key_pem = read_to_string(&self.paths.ca_key())?;

        let leaf_due = match std::fs::read_to_string(self.paths.leaf_cert()) {
            Ok(pem) => needs_renewal(&pem, now),
            Err(_) => true, // missing/unreadable leaf ⇒ issue one
        };

        let mut attempts = 0;
        if leaf_due {
            attempts = self.renew_with_retry(&ca_cert_pem, &ca_key_pem, now)?;
        }

        Ok(RenewalReport {
            leaf_renewed: leaf_due,
            ca_renewal_due: needs_ca_renewal(&ca_cert_pem, now),
            attempts,
        })
    }

    /// Issue a fresh leaf and atomically swap it in, retrying transient failures. Returns the
    /// attempt count on success.
    fn renew_with_retry(
        &self,
        ca_cert_pem: &str,
        ca_key_pem: &str,
        now: OffsetDateTime,
    ) -> Result<u32> {
        run_with_backoff(&self.backoff, self.sleeper.as_ref(), || {
            self.renew_once(ca_cert_pem, ca_key_pem, now)
        })
    }

    /// One issue+write+reload cycle, no retry.
    fn renew_once(&self, ca_cert_pem: &str, ca_key_pem: &str, now: OffsetDateTime) -> Result<()> {
        let ca = ParsedCa::from_pem(ca_cert_pem, ca_key_pem)?;
        let leaf = issue_leaf(&ca, now)?;
        // Write the key first, then the cert. Each write is individually atomic (temp + rename), so
        // no reader ever sees a partially written file; the resolver validates the pair on reload
        // and keeps the previous certificate if it reads a momentarily mismatched pair.
        atomic_write_secret(&self.paths.leaf_key(), leaf.key_pem.as_bytes())?;
        atomic_write_public(&self.paths.leaf_cert(), leaf.cert_pem.as_bytes())?;
        if let Some(resolver) = &self.resolver {
            resolver.reload()?;
        }
        Ok(())
    }
}

/// Run `attempt` up to `1 + schedule.delays.len()` times, sleeping the scheduled delay between
/// tries, until it succeeds. The never-lapse guarantee (SPEC §6): a transient failure is retried
/// rather than allowed to leave the leaf un-renewed. Returns the attempt count on success (1 on
/// first try), or [`Error::RenewalExhausted`] carrying the final error.
fn run_with_backoff(
    schedule: &BackoffSchedule,
    sleeper: &dyn Sleeper,
    mut attempt: impl FnMut() -> Result<()>,
) -> Result<u32> {
    let total = schedule.delays.len() + 1;
    let mut last = String::new();
    for i in 0..total {
        match attempt() {
            Ok(()) => return Ok((i + 1) as u32),
            Err(e) => {
                last = e.to_string();
                if i < schedule.delays.len() {
                    sleeper.sleep(schedule.delays[i]);
                }
            }
        }
    }
    Err(Error::RenewalExhausted {
        attempts: total as u32,
        last,
    })
}

/// Rotate the CA (and re-issue the leaf) — an EXPLICIT, installer-coordinated operation (SPEC §6.4),
/// never an automatic maintenance side effect. Generates a brand-new per-machine CA, writes both
/// key files with owner-only mode, and issues a fresh leaf. The caller (dig-installer) must
/// re-install the new `ca.crt` into every trust store afterward, or trust breaks until it does.
pub fn rotate_ca(paths: &TlsPaths, hostname: &str, now: OffsetDateTime) -> Result<()> {
    let ca = generate_ca(hostname, now)?;
    atomic_write_secret(&paths.ca_key(), ca.key_pem.as_bytes())?;
    atomic_write_public(&paths.ca_cert(), ca.cert_pem.as_bytes())?;
    let parsed = ParsedCa::from_pem(&ca.cert_pem, &ca.key_pem)?;
    let leaf = issue_leaf(&parsed, now)?;
    atomic_write_secret(&paths.leaf_key(), leaf.key_pem.as_bytes())?;
    atomic_write_public(&paths.leaf_cert(), leaf.cert_pem.as_bytes())?;
    Ok(())
}

/// Atomically write a private key file with owner-only mode (SPEC §5/§6): write a same-directory
/// temp with `0600` set BEFORE any bytes land, then rename over the target. A reader sees either the
/// complete old file or the complete new one — never a partial write, and never a world-readable
/// window.
pub(crate) fn atomic_write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    atomic_write(path, contents, crate::paths::KEY_FILE_MODE)
}

/// Atomically write a certificate (world-readable) — same temp+rename discipline.
pub(crate) fn atomic_write_public(path: &Path, contents: &[u8]) -> Result<()> {
    atomic_write(path, contents, crate::paths::CERT_FILE_MODE)
}

fn atomic_write(path: &Path, contents: &[u8], _mode: u32) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::TlsRoot(format!("{} has no parent directory", path.display())))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".dig-cert-")
        .suffix(".tmp")
        .tempfile_in(dir)
        .map_err(|e| io_at(dir, e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Tighten the temp file BEFORE writing secret bytes, so the key is never briefly readable.
        let perms = std::fs::Permissions::from_mode(_mode);
        std::fs::set_permissions(tmp.path(), perms).map_err(|e| io_at(tmp.path(), e))?;
    }

    tmp.write_all(contents).map_err(|e| io_at(tmp.path(), e))?;
    tmp.flush().map_err(|e| io_at(tmp.path(), e))?;
    tmp.as_file().sync_all().map_err(|e| io_at(tmp.path(), e))?;
    tmp.persist(path).map_err(|e| io_at(path, e.error))?;
    Ok(())
}

fn read_to_string(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| io_at(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// Records how many times it was asked to sleep, and for how long, without ever blocking.
    #[derive(Default)]
    struct RecordingSleeper {
        slept: Mutex<Vec<StdDuration>>,
    }
    impl Sleeper for RecordingSleeper {
        fn sleep(&self, dur: StdDuration) {
            self.slept.lock().unwrap().push(dur);
        }
    }

    #[test]
    fn backoff_retries_transient_failures_then_succeeds() {
        // A transient failure on the first two attempts must NOT let the leaf lapse — the third
        // attempt succeeds and the pass reports 3 attempts (SPEC §6 never-lapse).
        let sleeper = RecordingSleeper::default();
        let schedule = BackoffSchedule::new(vec![
            StdDuration::from_millis(1),
            StdDuration::from_millis(1),
            StdDuration::from_millis(1),
        ]);
        let calls = AtomicU32::new(0);
        let attempts = run_with_backoff(&schedule, &sleeper, || {
            if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                Err(Error::Generation("transient".into()))
            } else {
                Ok(())
            }
        })
        .expect("should succeed on the third attempt");
        assert_eq!(attempts, 3);
        assert_eq!(
            sleeper.slept.lock().unwrap().len(),
            2,
            "slept once per retry"
        );
    }

    #[test]
    fn backoff_gives_up_after_exhausting_retries() {
        let sleeper = RecordingSleeper::default();
        let schedule = BackoffSchedule::new(vec![StdDuration::from_millis(1)]);
        let err = run_with_backoff(&schedule, &sleeper, || {
            Err(Error::Generation("nope".into()))
        })
        .unwrap_err();
        match err {
            Error::RenewalExhausted { attempts, .. } => assert_eq!(attempts, 2),
            other => panic!("expected RenewalExhausted, got {other:?}"),
        }
    }

    #[test]
    fn atomic_write_secret_is_complete_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leaf.key");
        atomic_write_secret(&path, b"PRIVATE-KEY-BYTES").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"PRIVATE-KEY-BYTES");
        // No leftover temp files — a reader scanning the directory sees only the finished file.
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "only the finished key file remains");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                crate::paths::KEY_FILE_MODE,
                "key is owner read/write only"
            );
        }
    }

    #[test]
    fn atomic_write_overwrites_existing_completely() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leaf.crt");
        atomic_write_public(&path, b"OLD-LONGER-CONTENT").unwrap();
        atomic_write_public(&path, b"NEW").unwrap();
        // A rename replaces the inode wholesale — no trailing bytes from the longer old content.
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW");
    }
}
