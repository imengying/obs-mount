mod fs;
mod obs;
#[cfg(test)]
mod test_support;

use clap::Parser;
use fs::ObsFs;
use fuser::MountOption;
use obs::{BucketKind, ObsClient};
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;

/// Configuration file contents (YAML only). Every field is optional:
/// anything missing here can still come from a command-line flag or an
/// environment variable, which take precedence over the file.
/// Precedence: CLI flag > environment variable > config file.
/// Unknown fields are rejected at startup (`deny_unknown_fields`)
/// instead of being silently ignored.
/// The file itself is the recommended home for AK/SK and the mountpoint:
/// keep it at 0600, e.g. /etc/obs/obs.yaml.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    mountpoint: Option<PathBuf>,
    bucket: Option<String>,
    endpoint: Option<String>,
    ak: Option<String>,
    sk: Option<String>,
    multipart_threshold: Option<u64>,
    /// Multipart chunk size in bytes. Optional; obsfs mounts with 10 MB,
    /// the default here is 10 MB. Raised automatically for files big enough
    /// to exceed the 10000-part limit.
    multipart_part_size: Option<usize>,
    upload_concurrency: Option<usize>,
    min_free_space: Option<u64>,
    metadata_cache_entries: Option<usize>,
    request_timeout_secs: Option<u64>,
    transfer_timeout_secs: Option<u64>,
}

impl FileConfig {
    fn load(path: &PathBuf) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config file {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path)
                && meta.permissions().mode() & 0o077 != 0
            {
                tracing::warn!(
                    path = %path.display(),
                    "config file holds credentials but is readable by group/other; run: chmod 0600 {}",
                    path.display()
                );
            }
        }
        serde_yaml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("cannot parse config file {}: {e}", path.display()))
    }
}

/// Version string reported by `--version`.
///
/// A release build sets `OBS_MOUNT_VERSION` from the git tag that triggered
/// it, so the published binary reports exactly the tag it was built from
/// instead of whatever happened to be in Cargo.toml. Local builds fall back
/// to the crate version.
fn version_string() -> &'static str {
    resolve_version(option_env!("OBS_MOUNT_VERSION"))
}

/// Pick the version to report.
///
/// CI stamps `OBS_MOUNT_VERSION` from the git tag. An *empty* value means a
/// non-tag build (an unset workflow variable expands to ""), which must fall
/// back to the crate version rather than printing a bare program name.
/// A leading "v" from the tag is trimmed so `--version` reads "0.2.0".
fn resolve_version(injected: Option<&'static str>) -> &'static str {
    match injected {
        Some(v) if !v.trim().is_empty() => v.trim().trim_start_matches('v'),
        _ => env!("CARGO_PKG_VERSION"),
    }
}

/// Mount a Huawei Cloud OBS bucket as a local directory via FUSE.
#[derive(Parser, Debug)]
#[command(version = version_string(), about)]
struct Args {
    /// Config file (YAML) to read at startup. Defaults to
    /// $OBS_MOUNT_CONFIG, else /etc/obs/obs.yaml if it exists.
    /// Flags and env vars override values from the file.
    #[arg(short = 'c', env = "OBS_MOUNT_CONFIG")]
    config: Option<PathBuf>,

    /// Local directory to mount on (must exist and be empty).
    /// Falls back to `mountpoint` in the config file.
    mountpoint: Option<PathBuf>,

    /// OBS bucket name. Defaults to $OBS_BUCKET, else config file.
    #[arg(long, env = "OBS_BUCKET")]
    bucket: Option<String>,

    /// Bucket virtual-host endpoint, e.g.
    /// https://my-bucket.obs.cn-north-4.myhuaweicloud.com
    /// Defaults to $OBS_ENDPOINT, else config file.
    #[arg(long, env = "OBS_ENDPOINT")]
    endpoint: Option<String>,

    /// Access key. Defaults to $OBS_AK, else config file.
    #[arg(long, env = "OBS_AK", hide_env_values = true)]
    ak: Option<String>,

    /// Secret key. Defaults to $OBS_SK, else config file.
    #[arg(long, env = "OBS_SK", hide_env_values = true)]
    sk: Option<String>,

    /// Files at or above this size use multipart upload (bytes).
    /// Optional: defaults to $OBS_MULTIPART_THRESHOLD, else config file,
    /// else 26214400 (25 MB) when not configured anywhere.
    #[arg(long, env = "OBS_MULTIPART_THRESHOLD")]
    multipart_threshold: Option<u64>,

    /// Multipart chunk size in bytes (default 10485760, i.e. 10 MB, matching
    /// Huawei's obsfs). Allowed range: 100 KiB to 5 GiB.
    #[arg(long, env = "OBS_MULTIPART_PART_SIZE")]
    multipart_part_size: Option<usize>,
    /// Number of upload workers, 1..32 (default 4).
    #[arg(long, env = "OBS_UPLOAD_CONCURRENCY")]
    upload_concurrency: Option<usize>,
    /// Minimum free bytes on the system temporary filesystem (default 64 MiB).
    #[arg(long, env = "OBS_MIN_FREE_SPACE")]
    min_free_space: Option<u64>,
    /// Maximum cached metadata entries, excluding files staged locally (default 10000).
    #[arg(long, env = "OBS_METADATA_CACHE_ENTRIES")]
    metadata_cache_entries: Option<usize>,
    /// Timeout per metadata request attempt (seconds, default 120).
    #[arg(long, env = "OBS_REQUEST_TIMEOUT_SECS")]
    request_timeout_secs: Option<u64>,
    /// Timeout per file transfer/copy/completion attempt (seconds, default 3600).
    #[arg(long, env = "OBS_TRANSFER_TIMEOUT_SECS")]
    transfer_timeout_secs: Option<u64>,
}

struct ActiveMount {
    unmount: fuser::SessionUnmounter,
    path: PathBuf,
    id: String,
}

/// Mount identity is read without entering the FUSE filesystem. This avoids
/// detaching a different filesystem if the user has already replaced it.
fn mount_id(path: &std::path::Path) -> std::io::Result<Option<String>> {
    use std::os::unix::ffi::OsStrExt;
    let mut encoded = Vec::new();
    for &byte in path.as_os_str().as_bytes() {
        match byte {
            b' ' => encoded.extend_from_slice(b"\\040"),
            b'\t' => encoded.extend_from_slice(b"\\011"),
            b'\n' => encoded.extend_from_slice(b"\\012"),
            b'\\' => encoded.extend_from_slice(b"\\134"),
            _ => encoded.push(byte),
        }
    }
    let mounts = std::fs::read("/proc/self/mountinfo")?;
    Ok(mounts
        .split(|b| *b == b'\n')
        .filter_map(|line| {
            let fields: Vec<_> = line.split(|b| *b == b' ').collect();
            if fields.get(4).copied() == Some(encoded.as_slice()) {
                Some(String::from_utf8_lossy(fields[0]).into_owned())
            } else {
                None
            }
        })
        .next_back())
}

impl ActiveMount {
    fn detach(mut self) -> std::io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        if mount_id(&self.path)?.as_deref() == Some(self.id.as_str()) {
            let path = std::ffi::CString::new(self.path.as_os_str().as_bytes())?;
            // Explicit detachment works while workers still service requests.
            // Closing AutoUnmount's socket alone can leave cleanup to a helper
            // that has already exited; retain it as abnormal-exit protection.
            if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) }
                != 0
            {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EPERM) {
                    return Err(error);
                }
                let output = std::process::Command::new("fusermount3")
                    .args(["-uz", "--"])
                    .arg(&self.path)
                    .output()?;
                if !output.status.success() {
                    return Err(std::io::Error::other(
                        String::from_utf8_lossy(&output.stderr).into_owned(),
                    ));
                }
            }
        }
        self.unmount.unmount()
    }
}

/// Receive termination signals on an ordinary thread so unmounting never runs
/// in an async signal handler. Install before HTTP/FUSE threads are created.
struct Shutdown {
    unmount: std::sync::Arc<std::sync::Mutex<Option<ActiveMount>>>,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    previous_mask: libc::sigset_t,
}

impl Shutdown {
    fn install() -> std::io::Result<Self> {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        };
        let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // The initialized set contains only process termination signals. New
        // threads inherit this mask and the receiver consumes queued signals.
        let (signals, previous_mask) = unsafe {
            libc::sigemptyset(signals.as_mut_ptr());
            libc::sigaddset(signals.as_mut_ptr(), libc::SIGTERM);
            libc::sigaddset(signals.as_mut_ptr(), libc::SIGINT);
            let error =
                libc::pthread_sigmask(libc::SIG_BLOCK, signals.as_ptr(), previous.as_mut_ptr());
            if error != 0 {
                return Err(std::io::Error::from_raw_os_error(error));
            }
            (signals.assume_init(), previous.assume_init())
        };
        let unmount: Arc<Mutex<Option<ActiveMount>>> = Arc::new(Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));
        let receiver = unmount.clone();
        let stopped = done.clone();
        let worker = std::thread::Builder::new()
            .name("obs-shutdown".into())
            .spawn(move || {
                let timeout = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 100_000_000,
                };
                while !stopped.load(Ordering::Acquire) {
                    let signal =
                        unsafe { libc::sigtimedwait(&signals, std::ptr::null_mut(), &timeout) };
                    if signal == libc::SIGTERM || signal == libc::SIGINT {
                        if let Some(mount) = receiver.lock().unwrap().take() {
                            tracing::debug!(signal, "unmounting before exit");
                            if let Err(e) = mount.detach() {
                                tracing::error!(error=%e,"could not unmount during shutdown");
                                std::process::exit(1);
                            }
                            // Lazy detachment may leave client descriptors alive.
                            // Pending writes and upload journals already live on disk.
                            let deadline =
                                std::time::Instant::now() + std::time::Duration::from_secs(3);
                            while std::time::Instant::now() < deadline {
                                if stopped.load(Ordering::Acquire) {
                                    return;
                                }
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                            tracing::debug!(
                                "mount detached; stopping remaining requests with staging retained"
                            );
                            std::process::exit(0);
                        } else {
                            // Startup has not attached the session yet.
                            // AutoUnmount covers that race.
                            std::process::exit(128 + signal);
                        }
                    } else if signal == -1 {
                        let e = std::io::Error::last_os_error();
                        if !matches!(e.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
                            tracing::error!(error=%e,"termination signal receiver failed");
                            std::process::exit(1);
                        }
                    }
                }
            });
        match worker {
            Ok(worker) => Ok(Self {
                unmount,
                done,
                worker: Some(worker),
                previous_mask,
            }),
            Err(e) => {
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut());
                }
                Err(e)
            }
        }
    }

    fn attach(
        &self,
        unmount: fuser::SessionUnmounter,
        path: &std::path::Path,
    ) -> std::io::Result<()> {
        let id = mount_id(path)?
            .ok_or_else(|| std::io::Error::other("new mount missing from mountinfo"))?;
        *self.unmount.lock().unwrap() = Some(ActiveMount {
            unmount,
            path: path.to_owned(),
            id,
        });
        Ok(())
    }
}

impl Drop for Shutdown {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous_mask, std::ptr::null_mut());
        }
    }
}

fn main() -> anyhow::Result<()> {
    let shutdown = Shutdown::install()?;
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            // Keep normal mounts quiet unless RUST_LOG requests more detail.
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .init();
    let args = Args::parse();
    // An explicit -c wins over the default path; no file is fine as long
    // as every required value comes from a flag or the environment.
    let config_path = args.config.or_else(|| {
        let p = PathBuf::from("/etc/obs/obs.yaml");
        p.is_file().then_some(p)
    });
    let cfg = match &config_path {
        Some(p) => FileConfig::load(p)?,
        None => FileConfig::default(),
    };
    let missing = |name: &str| {
        anyhow::anyhow!(
            "{name} is not set: pass the flag, set the env var, or put it in the config file"
        )
    };
    let mountpoint = args
        .mountpoint
        .or(cfg.mountpoint)
        .ok_or_else(|| missing("mountpoint"))?;
    if !mountpoint.is_dir() {
        anyhow::bail!("mountpoint {} is not a directory", mountpoint.display());
    }
    let mountpoint = mountpoint.canonicalize()?;
    let bucket = args
        .bucket
        .or(cfg.bucket)
        .ok_or_else(|| missing("bucket"))?;
    let endpoint = args
        .endpoint
        .or(cfg.endpoint)
        .ok_or_else(|| missing("endpoint"))?;
    let ak = args.ak.or(cfg.ak).ok_or_else(|| missing("ak"))?;
    let sk = args.sk.or(cfg.sk).ok_or_else(|| missing("sk"))?;
    let defaults = obs::UploadTuning::default();
    let upload = obs::UploadTuning {
        threshold: args
            .multipart_threshold
            .or(cfg.multipart_threshold)
            .unwrap_or(defaults.threshold),
        part_size: args
            .multipart_part_size
            .or(cfg.multipart_part_size)
            .unwrap_or(defaults.part_size),
        concurrency: args
            .upload_concurrency
            .or(cfg.upload_concurrency)
            .unwrap_or(defaults.concurrency),
    };
    upload.validate()?;
    let request_timeout = args
        .request_timeout_secs
        .or(cfg.request_timeout_secs)
        .unwrap_or(120);
    let transfer_timeout = args
        .transfer_timeout_secs
        .or(cfg.transfer_timeout_secs)
        .unwrap_or(3600);
    if request_timeout == 0 || transfer_timeout == 0 {
        anyhow::bail!("request/transfer timeouts must be positive");
    }
    let client = ObsClient::new(ak, sk, bucket.clone(), endpoint.clone())
        .with_timeouts(request_timeout, transfer_timeout);
    tracing::debug!(
        endpoint = %endpoint,
        addressing = if client.uses_path_style() { "path-style" } else { "virtual-host" },
        "OBS client configured"
    );
    // Startup self-check 1: refuse a POSIX/file bucket.
    //
    // OBS exposes both flat object buckets and POSIX file buckets behind the
    // same endpoint. This program implements object-bucket semantics
    // (placeholder objects for directories, copy+delete rename, whole-file
    // uploads), so running it against a file bucket would silently misbehave.
    // Huawei's obsfs makes the same distinction via `HEAD /` and
    // x-obs-bucket-type / x-obs-fs-file-interface.
    match client.bucket_kind() {
        Ok(BucketKind::File) => {
            anyhow::bail!(
                "bucket {bucket} is an OBS POSIX/file bucket (HEAD / reports x-obs-bucket-type: POSIX). \
                 This program only supports object buckets; a file bucket is already POSIX and \
                 does not need a FUSE translation layer."
            );
        }
        Ok(BucketKind::Object) => tracing::debug!(bucket = %bucket, "bucket is an object bucket"),
        Ok(BucketKind::Unknown) => tracing::debug!(
            bucket = %bucket,
            "bucket type not reported; assuming an object bucket"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "HEAD / for bucket-type detection failed; continuing, the listing check below decides"
        ),
    }
    // Startup self-check 2: the bucket must be listable before we mount,
    // otherwise a bad AK/SK or region shows up as an empty-looking mount.
    match client.list_objects("", "/", None, 1) {
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "OBS bucket check failed; refusing to mount (check AK/SK, bucket, region/endpoint, and clock/NTP)");
            anyhow::bail!("OBS bucket check failed: {e}");
        }
    }
    let min_free_space = args
        .min_free_space
        .or(cfg.min_free_space)
        .unwrap_or(64 * 1024 * 1024);
    let cache_entries = args
        .metadata_cache_entries
        .or(cfg.metadata_cache_entries)
        .unwrap_or(10_000);
    if cache_entries == 0 {
        anyhow::bail!("metadata_cache_entries must be positive");
    }
    tracing::debug!(
        threshold = upload.threshold,
        part_size = upload.part_size,
        "upload tuning"
    );
    let temp_dir = std::env::temp_dir();
    match existing_staging_dirs(&temp_dir, current_uid()) {
        Ok(dirs) => {
            for dir in dirs {
                // Only reclaim a directory whose lock nobody holds. Testing
                // emptiness alone is wrong: a second mount that has not
                // written anything yet also looks empty, and deleting its
                // directory makes that mount fail on its next write.
                if holds_no_data(&dir) {
                    if staging_dir_is_abandoned(&dir) {
                        let _ = std::fs::remove_file(dir.join(STAGING_LOCK));
                        let _ = std::fs::remove_dir(&dir);
                    }
                    continue;
                }
                tracing::error!(path = %dir.display(), "existing staging directory; may belong to a running mount or contain recovery data; inspect before manual cleanup");
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not check existing staging directories"),
    }
    let staging_dir = staging_dir_for(&temp_dir, current_uid())?;
    // Held for the whole run: startup in another process uses this lock to
    // decide the directory is in use rather than abandoned.
    let _staging_lock = lock_staging_dir(&staging_dir)?;
    tracing::debug!(path = %staging_dir.display(), "staging directory");
    let fs = ObsFs::new(client, staging_dir, upload).with_limits(min_free_space, cache_entries);
    // Every local user may use the mount. This is a personal backup mount
    // shared with other services on the same box (OpenList, nginx, rsync),
    // and an owner-only session silently locks them out with EACCES.
    //
    // auto_unmount needs a session other than Owner, so All gives both. It
    // keeps a helper for abnormal exits. SIGTERM/SIGINT use the session's
    // unmounter while FUSE workers are still able to finish requests.
    let acl = fuser::SessionACL::All;
    // No DefaultPermissions on purpose. With it, the kernel would enforce the
    // mode stored in object metadata. Mode bits and ownership are reported
    // by `ls -l` but do not restrict access; the mount
    // is shared by everyone who can reach the mountpoint.
    let mount_options = vec![
        MountOption::FSName("obs-mount".to_string()),
        MountOption::AutoUnmount,
    ];
    // Config is #[non_exhaustive], so build it from Default and mutate.
    let mut config = fuser::Config::default();
    config.mount_options = mount_options;
    config.acl = acl;
    config.n_threads = Some(4);
    tracing::info!(
        bucket = %bucket,
        mountpoint = %mountpoint.display(),
        endpoint = %endpoint,
        "mounted"
    );
    let run = (|| {
        let mut session = fuser::Session::new(fs, &mountpoint, &config)?;
        shutdown.attach(session.unmount_callable(), &mountpoint)?;
        session.run()
    })();
    run.map_err(|e| {
        let msg = e.to_string();
        let hint = if msg.contains("No such file or directory") {
            "  If /dev/fuse exists, the fusermount helper is missing: \
             apt-get install fuse3."
        } else if msg.contains("allow_other") {
            // Only an unprivileged mount can hit this: fusermount refuses
            // allow_other for non-root unless /etc/fuse.conf opts in.
            "  fusermount refused allow_other: add `user_allow_other` to \
             /etc/fuse.conf, or mount as root."
        } else {
            ""
        };
        anyhow::anyhow!("cannot mount {}: {e}\n{hint}", mountpoint.display())
    })?;
    Ok(())
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Discover this user's sessions without touching their contents.
fn existing_staging_dirs(base: &std::path::Path, uid: u32) -> std::io::Result<Vec<PathBuf>> {
    use std::os::unix::fs::MetadataExt;
    let prefix = format!("obs-mount-staging-{uid}-");
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(base)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if metadata.is_dir() && metadata.uid() == uid {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// Live sessions hold an exclusive lock on this file.
const STAGING_LOCK: &str = ".lock";

/// Take this session's lock on `dir` for as long as the returned file lives.
///
/// The directory must outlive the process, so the lock is advisory: it is
/// dropped when the process dies, including on SIGKILL, which is exactly the
/// signal startup needs to decide whether a directory is safe to remove.
fn lock_staging_dir(dir: &std::path::Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(STAGING_LOCK))?;
    flock_exclusive(&file)?;
    Ok(file)
}

/// Try to lock a staging directory someone else may hold. Returns true when
/// the lock was acquired, which means no live session owns it.
fn staging_dir_is_abandoned(dir: &std::path::Path) -> bool {
    lock_staging_dir(dir).is_ok()
}

fn flock_exclusive(file: &File) -> std::io::Result<()> {
    let ret = unsafe {
        libc::flock(
            std::os::unix::io::AsRawFd::as_raw_fd(file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Whether a directory holds nothing but the lock file.
fn holds_no_data(path: &std::path::Path) -> bool {
    let Ok(mut entries) = std::fs::read_dir(path) else {
        return false;
    };
    entries.all(|entry| entry.is_ok_and(|e| e.file_name() == STAGING_LOCK))
}

/// Allocate a private directory atomically for each mount. Never reuse or
/// remove earlier sessions: they may contain the only copy of an upload.
fn staging_dir_for(base: &std::path::Path, uid: u32) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    loop {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!(
            "obs-mount-staging-{uid}-{}-{stamp}-{sequence}",
            std::process::id()
        ));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comes_from_the_tag_when_present() {
        assert_eq!(resolve_version(Some("v0.2.0")), "0.2.0");
        assert_eq!(resolve_version(Some("0.2.0")), "0.2.0");
        assert_eq!(resolve_version(Some(" v1.2.3 ")), "1.2.3");
    }

    #[test]
    fn version_falls_back_to_crate_version() {
        const CRATE: &str = env!("CARGO_PKG_VERSION");
        assert_eq!(resolve_version(None), CRATE);
        // An unset workflow variable expands to the empty string.
        assert_eq!(resolve_version(Some("")), CRATE);
        assert_eq!(resolve_version(Some("   ")), CRATE);
    }

    #[test]
    fn unknown_config_field_is_rejected_not_ignored() {
        // Any unknown field fails, no special-casing.
        let bad = "mountpoint: /mnt/obs\nbucket: b\nfoo: bar\n";
        assert!(serde_yaml::from_str::<FileConfig>(bad).is_err());
        let ok = "mountpoint: /mnt/obs\nbucket: b\nmultipart_threshold: 26214400\n";
        let cfg = serde_yaml::from_str::<FileConfig>(ok).unwrap();
        assert_eq!(cfg.multipart_threshold, Some(26_214_400));
    }

    #[test]
    fn staging_sessions_are_private_and_do_not_reuse_old_data() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir();
        let first = staging_dir_for(&base, current_uid()).unwrap();
        std::fs::write(first.join("ino-2"), b"unsent backup").unwrap();
        let second = staging_dir_for(&base, current_uid()).unwrap();
        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(base.as_path()));
        assert_eq!(
            std::fs::metadata(&first).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read(first.join("ino-2")).unwrap(),
            b"unsent backup"
        );
        std::fs::remove_dir_all(first).unwrap();
        std::fs::remove_dir_all(second).unwrap();
    }

    /// A live mount that has not written yet has an empty staging directory.
    /// Startup must not treat it as abandoned: deleting it would make every
    /// later write in that mount fail, and only the second mount would look
    /// healthy.
    #[test]
    fn live_session_directory_is_not_reclaimed_by_another_startup() {
        let base = staging_dir_for(&std::env::temp_dir(), current_uid()).unwrap();
        let live = staging_dir_for(&base, current_uid()).unwrap();
        let lock = lock_staging_dir(&live).unwrap();

        assert!(holds_no_data(&live), "a fresh session holds no data");
        assert!(
            !staging_dir_is_abandoned(&live),
            "a directory whose lock is held must not look abandoned"
        );

        // Dropping the lock is what a crash does, and then it is reclaimable.
        drop(lock);
        assert!(
            staging_dir_is_abandoned(&live),
            "after the lock is released the directory is reclaimable"
        );

        std::fs::remove_dir_all(live).unwrap();
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn startup_reports_sessions_without_deleting_data_or_live_directories() {
        let uid = current_uid();
        let base = staging_dir_for(&std::env::temp_dir(), uid).unwrap();
        let empty = staging_dir_for(&base, uid).unwrap();
        let pending = staging_dir_for(&base, uid).unwrap();
        std::fs::write(pending.join("ino-2"), b"unsent backup").unwrap();
        std::os::unix::fs::symlink(&pending, base.join(format!("obs-mount-staging-{uid}-link")))
            .unwrap();
        std::fs::create_dir(base.join("unrelated")).unwrap();
        std::fs::create_dir(base.join(format!("obs-mount-staging-{}-other", uid + 1))).unwrap();
        let mut expected = vec![empty.clone(), pending.clone()];
        expected.sort();
        assert_eq!(existing_staging_dirs(&base, uid).unwrap(), expected);
        assert!(empty.is_dir());
        assert_eq!(
            std::fs::read(pending.join("ino-2")).unwrap(),
            b"unsent backup"
        );
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    #[ignore = "requires a built obs-mount binary"]
    fn rejects_file_bucket_before_mounting() {
        let mock = crate::test_support::MockObs::with_config(crate::test_support::Config {
            file_bucket: true,
            ..Default::default()
        });
        let mut process = crate::test_support::MountProcess::spawn(&mock, "rejected", None);
        assert!(!process.wait_exit().success());
        assert!(
            process.log().contains("POSIX/file bucket"),
            "{}",
            process.log()
        );
        assert!(!crate::test_support::is_mounted(&process.mountpoint));
        assert_eq!(mock.stats().signature_failures, 0);
    }
}
