//! FUSE filesystem: POSIX operations translated to OBS objects.
//!
//! Backup-first semantics (the user's stated use case: drop backup files
//! into the mounted folder):
//! * `create`/`write` never PUT on every write. Writes go to a local
//!   staging file and are uploaded once, on `flush`/`fsync`/`release`
//!   (close). Small files use a single PUT, files at/above the multipart
//!   threshold use multipart upload.
//! * `read` is a Range GET, so a backup can be verified with `cat`/`sha256sum`
//!   without downloading the whole object first (except write-mode opens,
//!   which stage the full object for read-modify-write).
//! * OBS objects are immutable: there is no in-place append. `rename` is
//!   Copy+Delete and is not atomic. Unix attributes live in object metadata.
//!
//! fuser 0.18 calls the Filesystem trait through `&self`, so all mutable
//! namespace and writable state are protected by one Mutex. Namespace
//! transactions remain serialized. Reads, statfs and ordinary writeback release
//! it during network requests; same-inode writers wait for writeback to finish.
//! Upload workers stream independent file ranges with bounded memory.

use crate::obs::{ObsClient, ObsError, UnixMeta};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use fuser::{
    AccessFlags, BsdFileFlags, Errno, FileAttr, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, LockOwner, OpenAccMode, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, TimeOrNow, WriteFlags,
};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

const TTL: Duration = Duration::from_secs(1);
/// Extra bytes fetched beyond what a read asked for, so the kernel's next few
/// 128 KiB reads hit the local window instead of the network. 1 MiB is eight
/// kernel read chunks: enough to matter, small enough not to waste bandwidth
/// on a seek-heavy workload.
const READ_AHEAD_BYTES: u64 = 1024 * 1024;
/// How long a statfs answer is reused before asking OBS again. `df` is often
/// polled by monitoring every few seconds and each miss costs two requests.
const USAGE_TTL: Duration = Duration::from_secs(60);
/// Capacity reported when the bucket has no quota configured. It is not a
/// real limit -- it only keeps tools that precheck free space from treating
/// the mount as full.
///
/// Matches Huawei's own obsfs, which fills `f_blocks`/`f_bfree`/`f_bavail`
/// with `0xFFFFFFFF` blocks of 4096 bytes and comments "S3 doesn't have a real
/// concept of filesystem size/limits" (src/s3fs_operations.cpp:3109).
/// Aligning with the vendor keeps `df` output recognizable to anyone who has
/// used obsfs, and 16 TiB is the ceiling they settled on.
const OBSFS_SYNTHETIC_BLOCKS: u64 = 0xFFFF_FFFF;
const STATFS_BLOCK_SIZE: u32 = 4096;
const SYNTHETIC_TOTAL: u64 = OBSFS_SYNTHETIC_BLOCKS * STATFS_BLOCK_SIZE as u64;
/// OBS object keys are limited to 1023 bytes; obsfs uses NAME_MAX (255)
/// because it also serves generic S3 endpoints. Reporting the real key limit
/// keeps `getconf NAME_MAX` honest for tools that check it.
const STATFS_NAME_MAX: u32 = 1023;
const ROOT_INO: u64 = 1;

#[derive(Clone)]
struct CachedMeta {
    size: u64,
    is_dir: bool,
    mtime: SystemTime,
    expires: Instant,
    /// Attributes read from object metadata. External objects without Unix
    /// attributes are shown with defaults.
    unix: Option<UnixAttrs>,
    /// All non-Unix object metadata, including xattrs and symlink targets.
    extra_meta: Vec<(String, String)>,
    system_meta: Vec<(String, String)>,
}

/// Cached ownership and mode; CachedMeta::mtime is the only timestamp copy.
#[derive(Clone, Copy)]
struct UnixAttrs {
    mode: u32,
    uid: u32,
    gid: u32,
}

impl From<UnixMeta> for UnixAttrs {
    fn from(value: UnixMeta) -> Self {
        Self {
            mode: value.mode,
            uid: value.uid,
            gid: value.gid,
        }
    }
}

/// A span of an object fetched ahead of demand.
struct ReadWindow {
    start: u64,
    data: Vec<u8>,
}

impl ReadWindow {
    /// Serve only a complete request. A short FUSE reply before EOF can make
    /// the kernel fill the remainder with zeros and corrupt cached file data.
    fn slice(&self, offset: u64, size: usize) -> Option<&[u8]> {
        let from = usize::try_from(offset.checked_sub(self.start)?).ok()?;
        self.data.get(from..from.checked_add(size)?)
    }
}

#[derive(Default)]
struct OpenFile {
    ino: u64,
    etag: Option<String>,
    /// Read-ahead window: the last Range GET result, kept so the following
    /// reads of the same region are served locally.
    ///
    /// The kernel reads FUSE in 128 KiB chunks, so reading a 20 MiB object
    /// meant 160 sequential HTTP round-trips through a global mutex. Fetching
    /// a larger window per request cuts that by an order of magnitude at the
    /// cost of transferring at most one window of extra data.
    window: Option<ReadWindow>,
    /// Size of the remote object, resolved once when the handle is opened.
    ///
    /// Without this, every `read` did a HEAD before its Range GET: the kernel
    /// issues 128 KiB reads, so reading a 20 MiB file cost 160 GETs plus 160
    /// extra HEADs and ran at a fraction of the achievable throughput.
    size: Option<u64>,
}

#[derive(Default)]
struct FileState {
    path: Option<String>,
    detached: Option<CachedMeta>,
    pending: bool,
    reported_failure: bool,
    uploading: bool,
}

struct Inner {
    client: ObsClient,
    staging_dir: PathBuf,
    upload: crate::obs::UploadTuning,
    next_ino: u64,
    files: HashMap<u64, FileState>,
    path_to_ino: HashMap<String, u64>,
    meta_cache: HashMap<String, CachedMeta>,
    open_files: HashMap<u64, OpenFile>,
    next_fh: u64,
    lookups: HashMap<u64, u64>,
    directories: HashMap<u64, Directory>,
    min_free_space: u64,
    cache_limit: usize,
    last_reclaim: Instant,
    /// Cached answer for statfs; `df` is cheap to call and usually polled by
    /// monitoring, so the bucket is queried at most once per TTL instead of
    /// once per request.
    usage_cache: Option<(Instant, UsageSnapshot)>,
}

struct Directory {
    ino: u64,
    entries: Option<Vec<(String, FileType)>>,
}

/// Pick what to report from what OBS can tell us. Split out from the query
/// path so the decision (and the 0-means-unlimited rule) is unit-testable.
fn decide_usage(used: u64, quota: Option<u64>) -> UsageSnapshot {
    match quota.filter(|q| *q > 0) {
        Some(total) => UsageSnapshot {
            // A bucket can exceed its quota (writes start failing rather than
            // stored data shrinking), so never report used > total.
            total: total.max(used),
            used,
            total_is_synthetic: false,
        },
        None => UsageSnapshot {
            total: SYNTHETIC_TOTAL,
            used,
            total_is_synthetic: true,
        },
    }
}

/// What `statfs` reports, in bytes, plus a note on where the numbers came
/// from so the log can explain `df` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UsageSnapshot {
    total: u64,
    used: u64,
    /// True when `total` is not a real limit (no quota configured).
    total_is_synthetic: bool,
}

pub struct ObsFs {
    inner: Mutex<Inner>,
    uploads_done: Condvar,
    /// Clone of the client for paths that must not hold the global lock
    /// across a network round-trip (see `read`).
    client: ObsClient,
}

/// Serve a read out of a local staging file.
fn read_staging(staging: &Path, offset: u64, size: u32, reply: ReplyData) {
    let mut f = match File::open(staging) {
        Ok(f) => f,
        Err(e) => {
            reply.error(io_errno(&e));
            return;
        }
    };
    if f.seek(SeekFrom::Start(offset)).is_err() {
        reply.error(Errno::EIO);
        return;
    }
    let mut buf = vec![0u8; size as usize];
    match f.read(&mut buf) {
        Ok(n) => reply.data(&buf[..n]),
        Err(e) => reply.error(io_errno(&e)),
    }
}

/// Map an OBS error to an errno without needing `&Inner`.
fn errno_for_obs(e: &ObsError) -> Errno {
    match e {
        ObsError::Http { status: 403, .. } => Errno::EACCES,
        ObsError::Http { status: 404, .. } => Errno::ENOENT,
        ObsError::Http { status: 412, .. } => Errno::ESTALE,
        ObsError::Io(e) => io_errno(e),
        _ => Errno::EIO,
    }
}

/// Hex uses a case-insensitive alphabet, unlike base64 in HTTP header names.
fn xattr_key(name: &str) -> String {
    let encoded: String = name.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!("{}{encoded}", crate::obs::meta_keys::XATTR_PREFIX)
}

fn xattr_name_from_key(key: &str) -> Option<Vec<u8>> {
    let encoded = key.strip_prefix(crate::obs::meta_keys::XATTR_PREFIX)?;
    if encoded.len() % 2 != 0 {
        return None;
    }
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hex = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(hex, 16).ok()
        })
        .collect()
}

/// Cache stores xattr keys without the header prefix (that is how HEAD returns
/// them, minus `x-obs-meta-`); outgoing metadata needs the full header name.
fn xattr_header_key(key: &str) -> String {
    format!("x-obs-meta-{key}")
}

fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => path[..i].to_string(),
        None => String::new(),
    }
}

fn file_name(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn dir_prefix(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!("{path}/")
    }
}

/// Build the cache entry for an object we just HEADed.
fn cached_from_meta(meta: &crate::obs::ObjectMeta, is_dir: bool) -> CachedMeta {
    CachedMeta {
        size: meta.size,
        is_dir,
        mtime: meta
            .unix
            .map(|u| unix_time(u.mtime))
            .or_else(|| {
                meta.last_modified
                    .as_deref()
                    .and_then(|v| chrono::DateTime::parse_from_rfc2822(v).ok())
                    .map(|t| unix_time(t.timestamp()))
            })
            .unwrap_or(SystemTime::UNIX_EPOCH),
        expires: Instant::now() + Duration::from_secs(5),
        unix: meta.unix.map(Into::into),
        system_meta: meta.system_meta.clone(),
        extra_meta: meta
            .x_obs_meta
            .iter()
            .filter(|(k, _)| !matches!(k.as_str(), "mode" | "uid" | "gid" | "mtime"))
            .cloned()
            .collect(),
    }
}

/// Cache entry for something we know exists but have no object metadata for:
/// a directory (real or implied by a key prefix) or a freshly staged file.
fn synthetic_meta(size: u64, is_dir: bool, mtime: SystemTime) -> CachedMeta {
    CachedMeta {
        size,
        is_dir,
        mtime,
        expires: Instant::now() + Duration::from_secs(5),
        unix: None,
        extra_meta: Vec::new(),
        system_meta: Vec::new(),
    }
}

fn unix_time(seconds: i64) -> SystemTime {
    if seconds >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs())
    }
}

fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Map an io error to the closest FUSE errno (raw OS codes only).
fn io_errno(e: &std::io::Error) -> Errno {
    match e.raw_os_error() {
        Some(libc::ENOENT) => Errno::ENOENT,
        Some(libc::EACCES) => Errno::EACCES,
        Some(libc::EPERM) => Errno::EPERM,
        Some(libc::ENOTEMPTY) => Errno::ENOTEMPTY,
        Some(libc::EEXIST) => Errno::EEXIST,
        Some(libc::EINVAL) => Errno::EINVAL,
        Some(libc::E2BIG) => Errno::E2BIG,
        Some(libc::EFBIG) => Errno::EFBIG,
        Some(libc::ESTALE) => Errno::ESTALE,
        Some(libc::EOPNOTSUPP) => Errno::EOPNOTSUPP,
        Some(libc::ENOSPC) => Errno::ENOSPC,
        Some(libc::EROFS) => Errno::EROFS,
        Some(libc::ENOTDIR) => Errno::ENOTDIR,
        Some(libc::EISDIR) => Errno::EISDIR,
        _ => Errno::EIO,
    }
}

impl ObsFs {
    pub fn new(client: ObsClient, staging_dir: PathBuf, upload: crate::obs::UploadTuning) -> Self {
        Self {
            client: client.clone(),
            uploads_done: Condvar::new(),
            inner: Mutex::new(Inner {
                client,
                staging_dir,
                upload,
                next_ino: 2,
                files: HashMap::new(),
                path_to_ino: HashMap::new(),
                meta_cache: HashMap::new(),
                open_files: HashMap::new(),
                next_fh: 1,
                lookups: HashMap::new(),
                directories: HashMap::new(),
                min_free_space: 64 * 1024 * 1024,
                cache_limit: 10_000,
                last_reclaim: Instant::now(),
                usage_cache: None,
            }),
        }
    }
    pub fn with_limits(self, min_free_space: u64, cache_limit: usize) -> Self {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.min_free_space = min_free_space;
            inner.cache_limit = cache_limit;
        }
        self
    }
}

impl Drop for ObsFs {
    fn drop(&mut self) {
        if let Ok(inner) = self.inner.get_mut() {
            // Only remove an empty session directory. Pending recovery data
            // and files left by interrupted operations must survive exit.
            let _ = fs::remove_dir(&inner.staging_dir);
        }
    }
}

impl Inner {
    fn ensure_space(&self, growth: u64) -> Result<(), ObsError> {
        if growth == 0 {
            return Ok(());
        }
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(self.staging_dir.as_os_str().as_bytes())
            .map_err(|e| ObsError::Other(e.to_string()))?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let stat = unsafe { stat.assume_init() };
        let free = stat.f_bavail.saturating_mul(stat.f_frsize);
        if free < growth.saturating_add(self.min_free_space) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into());
        }
        Ok(())
    }

    fn maybe_reclaim(&mut self) {
        // Avoid scanning the entire inode table on every lookup in a large tree.
        if self.last_reclaim.elapsed() >= Duration::from_secs(1) {
            self.reclaim();
        }
    }

    fn reclaim(&mut self) {
        self.last_reclaim = Instant::now();
        let pinned: HashSet<u64> = self
            .open_files
            .values()
            .map(|f| f.ino)
            .chain(self.directories.values().map(|d| d.ino))
            .chain(
                self.lookups
                    .iter()
                    .filter(|(_, n)| **n > 0)
                    .map(|(ino, _)| *ino),
            )
            .collect();
        let removable: Vec<_> = self
            .files
            .iter()
            .filter(|(ino, file)| !pinned.contains(ino) && !file.uploading && !file.pending)
            .filter(|(ino, _)| !self.staging_path(**ino).exists())
            .map(|(ino, file)| (*ino, file.path.clone()))
            .collect();
        for (ino, path) in removable {
            self.files.remove(&ino);
            if let Some(path) = path
                && self.path_to_ino.get(&path) == Some(&ino)
            {
                self.path_to_ino.remove(&path);
            }
        }
        if self.meta_cache.len() > self.cache_limit {
            let mut candidates: Vec<_> = self
                .meta_cache
                .iter()
                .filter(|(p, _)| self.staging_size(p).is_none())
                .map(|(p, m)| (m.expires, p.clone()))
                .collect();
            candidates.sort_by_key(|(at, _)| *at);
            let remove = self.meta_cache.len().saturating_sub(self.cache_limit);
            for (_, path) in candidates.into_iter().take(remove) {
                self.meta_cache.remove(&path);
            }
        }
    }

    /// Preserve bytes for open handles before unlink or replacement. Only
    /// detach after the remote operation succeeds; failure leaves the name live.
    fn prepare_detach(&mut self, path: &str) -> Result<(), ObsError> {
        let Some(ino) = self.path_to_ino.get(path).copied() else {
            return Ok(());
        };
        if self.open_files.values().any(|f| f.ino == ino) {
            self.stage_existing(ino, path, false)?;
        }
        Ok(())
    }

    fn path(&self, ino: &u64) -> Option<&String> {
        self.files.get(ino)?.path.as_ref()
    }

    fn detach_path(&mut self, path: &str) {
        if let Some(ino) = self.path_to_ino.remove(path) {
            let meta = self.meta_cache.remove(path);
            if let Some(file) = self.files.get_mut(&ino) {
                file.path = None;
                file.detached = meta;
                file.pending = false;
                file.reported_failure = false;
            }
            // Keep unfinished upload journals for manual cancellation.
            let _ = fs::remove_file(self.staging_path(ino).with_extension("yaml"));
            self.release_staging(ino);
        }
        self.meta_cache.remove(path);
    }

    fn rename_path(&mut self, old: &str, new: &str, flags: u32) -> Result<(), ObsError> {
        let error = |code| ObsError::Io(std::io::Error::from_raw_os_error(code));
        if flags & !libc::RENAME_NOREPLACE != 0 {
            return Err(error(libc::EOPNOTSUPP));
        }
        if old == new {
            return Ok(());
        }
        if new.starts_with(&dir_prefix(old)) {
            return Err(error(libc::EINVAL));
        }
        let (_, is_dir, _, _) = self.resolve(old)?.ok_or_else(|| error(libc::ENOENT))?;
        let destination = self.resolve(new)?;
        if destination.is_some() && flags & libc::RENAME_NOREPLACE != 0 {
            return Err(error(libc::EEXIST));
        }
        if let Some((_, dest_dir, _, _)) = destination {
            if is_dir != dest_dir {
                return Err(error(if is_dir { libc::ENOTDIR } else { libc::EISDIR }));
            }
            if dest_dir {
                let prefix = dir_prefix(new);
                let page = self.client.list_dir(&prefix)?;
                if page.keys.iter().any(|key| *key != prefix)
                    || !page.prefixes.is_empty()
                    || self
                        .path_to_ino
                        .keys()
                        .any(|p| p.starts_with(&prefix) && self.staging_size(p).is_some())
                {
                    return Err(error(libc::ENOTEMPTY));
                }
            }
        }
        // Publish any local source data first, including files still open.
        let prefix = dir_prefix(old);
        let staged: Vec<_> = self
            .path_to_ino
            .iter()
            .filter(|(p, _)| p.as_str() == old || (is_dir && p.starts_with(&prefix)))
            .filter(|(_, ino)| self.files.get(ino).is_some_and(|f| f.pending))
            .map(|(p, _)| p.clone())
            .collect();
        for key in staged {
            self.upload_staged_path(&key)?;
        }
        if !is_dir {
            self.prepare_detach(new)?;
        }
        let keys = if is_dir {
            self.client.list_all_keys(&prefix)?
        } else {
            vec![old.to_string()]
        };
        // Keep every source until all copies have succeeded.
        for key in &keys {
            let target = if is_dir {
                format!("{new}{}", &key[old.len()..])
            } else {
                new.to_string()
            };
            self.client.copy_object(key, &target)?;
        }
        for key in &keys {
            if let Err(e) = self.client.delete_object(key) {
                tracing::error!(old, new, stranded_key=%key, error=%e, "rename copied but could not delete source; both exist");
            }
        }
        if destination.is_some() {
            self.detach_path(new);
        }
        self.remap_subtree(old, new);
        Ok(())
    }

    fn alloc_ino(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.files.insert(
            ino,
            FileState {
                path: Some(path.to_string()),
                ..FileState::default()
            },
        );
        self.path_to_ino.insert(path.to_string(), ino);
        ino
    }

    fn forget_subtree(&mut self, path: &str) {
        let prefix = format!("{path}/");
        let doomed: Vec<String> = self
            .path_to_ino
            .keys()
            .filter(|p| *p == path || p.starts_with(&prefix))
            .cloned()
            .collect();
        for p in doomed {
            if let Some(ino) = self.path_to_ino.remove(&p) {
                self.files.remove(&ino);
            }
            self.meta_cache.remove(&p);
        }
    }

    fn staging_refs(&self, ino: u64) -> usize {
        self.open_files.values().filter(|f| f.ino == ino).count()
    }

    fn release_staging(&mut self, ino: u64) {
        if self.staging_refs(ino) == 0
            && self
                .files
                .get(&ino)
                .is_none_or(|f| !f.pending && !f.uploading)
        {
            let staging = self.staging_path(ino);
            let _ = fs::remove_file(&staging);
            let _ = fs::remove_file(staging.with_extension("yaml"));
        }
    }

    /// Move every inode/meta entry under `old` to `new`, keeping the inode
    /// numbers stable.
    ///
    /// A successful rename must NOT drop the inode mapping for the new path:
    /// the kernel keeps using the inode numbers it already handed out, and a
    /// forgotten inode makes the next `open`/`getattr` fail with ENOENT
    /// without a single request reaching the backend (the classic
    /// `mv a b && cat b` breakage). The inode follows the object instead.
    fn remap_subtree(&mut self, old: &str, new: &str) {
        let old_prefix = format!("{old}/");
        let successors: Vec<String> = self
            .path_to_ino
            .keys()
            .filter(|p| *p == old || p.starts_with(&old_prefix))
            .cloned()
            .collect();
        for old_path in successors {
            let Some(ino) = self.path_to_ino.remove(&old_path) else {
                continue;
            };
            let new_path = if old_path == old {
                new.to_string()
            } else {
                format!("{new}{}", &old_path[old.len()..])
            };
            if let Some(file) = self.files.get_mut(&ino) {
                file.path = Some(new_path.clone());
            }
            self.path_to_ino.insert(new_path.clone(), ino);
            if let Some(c) = self.meta_cache.remove(&old_path) {
                self.meta_cache.insert(new_path.clone(), c);
            }
            let staging = self.staging_path(ino);
            if staging.exists()
                && let Err(e) = self.save_recovery(&new_path, &staging)
            {
                tracing::error!(error = %e, path = %staging.display(), key = %new_path, "could not update recovery mapping after rename");
            }
        }
        self.meta_cache.remove(old);
    }

    fn staging_path(&self, ino: u64) -> PathBuf {
        self.staging_dir.join(format!("ino-{ino}"))
    }

    fn attr(
        &self,
        req: &Request,
        ino: u64,
        kind: FileType,
        size: u64,
        mtime: SystemTime,
    ) -> FileAttr {
        self.attr_with_meta(req, ino, kind, size, mtime, None)
    }

    /// Like `attr`, but honours attributes persisted in object metadata.
    ///
    /// External objects without Unix attributes use 0755/0644 and the
    /// requesting user as their owner.
    fn attr_with_meta(
        &self,
        req: &Request,
        ino: u64,
        kind: FileType,
        size: u64,
        mtime: SystemTime,
        cached: Option<&CachedMeta>,
    ) -> FileAttr {
        let unix = cached.and_then(|c| c.unix);
        // A persisted mtime wins over the caller-supplied one: `resolve`
        // reports "now" for anything it synthesized (staging files,
        // directories), which would otherwise mask `touch -d`.
        let mtime = cached.map_or(mtime, |c| c.mtime);
        let kind = match unix.map(|u| u.mode & libc::S_IFMT) {
            Some(m) if m == libc::S_IFLNK => FileType::Symlink,
            _ => kind,
        };
        let default_perm = if kind == FileType::Directory {
            0o755
        } else if kind == FileType::Symlink {
            0o777
        } else {
            0o644
        };
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm: unix
                .map(|u| (u.mode & 0o7777) as u16)
                .unwrap_or(default_perm),
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid: unix.map(|u| u.uid).unwrap_or_else(|| req.uid()),
            gid: unix.map(|u| u.gid).unwrap_or_else(|| req.gid()),
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn staging_size(&self, path: &str) -> Option<u64> {
        let ino = self.path_to_ino.get(path)?;
        fs::metadata(self.staging_path(*ino)).ok().map(|m| m.len())
    }

    fn object_key(&self, path: &str) -> String {
        if self.meta_cache.get(path).is_some_and(|m| m.is_dir) {
            dir_prefix(path)
        } else {
            path.to_string()
        }
    }

    fn ensure_meta(&mut self, path: &str) -> Result<&CachedMeta, ObsError> {
        let has_local_meta =
            self.staging_size(path).is_some() && self.meta_cache.contains_key(path);
        let fresh = self
            .meta_cache
            .get(path)
            .is_some_and(|m| m.expires > Instant::now());
        if !has_local_meta && !fresh && self.resolve(path)?.is_none() {
            return Err(ObsError::Http {
                status: 404,
                method: "HEAD".into(),
                path: path.into(),
                body: String::new(),
            });
        }
        self.meta_cache
            .get(path)
            .ok_or_else(|| ObsError::Other(format!("missing metadata for {path}")))
    }

    /// Fetch before publishing staging. Any HEAD/GET failure leaves no file
    /// that could later be mistaken for a complete writable copy.
    fn stage_existing(
        &mut self,
        ino: u64,
        path: &str,
        truncate: bool,
    ) -> Result<PathBuf, ObsError> {
        let staging = self.staging_path(ino);
        if staging.exists() {
            return Ok(staging);
        }
        let meta = self
            .client
            .head_object(path)?
            .ok_or_else(|| ObsError::Http {
                status: 404,
                method: "HEAD".into(),
                path: path.into(),
                body: String::new(),
            })?;
        if !truncate
            && self
                .open_files
                .values()
                .filter(|f| f.ino == ino)
                .any(|f| f.etag.is_some() && f.etag != meta.etag)
        {
            return Err(std::io::Error::from_raw_os_error(libc::ESTALE).into());
        }
        self.ensure_space(if truncate { 0 } else { meta.size })?;
        if truncate {
            File::create(&staging)?;
        } else {
            self.client.download_to(path, &staging, &meta)?;
        }
        self.meta_cache
            .insert(path.into(), cached_from_meta(&meta, false));
        // Readers opened before the writer must follow the shared copy too.
        for open in self.open_files.values_mut().filter(|f| f.ino == ino) {
            open.window = None;
        }
        Ok(staging)
    }

    fn metadata_headers(&self, path: &str) -> Result<Vec<(String, String)>, ObsError> {
        let cached = self
            .meta_cache
            .get(path)
            .ok_or_else(|| ObsError::Other(format!("missing metadata for {path}")))?;
        let mut headers: Vec<_> = cached
            .extra_meta
            .iter()
            .map(|(k, v)| (xattr_header_key(k), v.clone()))
            .collect();
        if let Some(unix) = cached.unix {
            headers.extend(crate::obs::unix_meta_headers(UnixMeta {
                mode: unix.mode,
                uid: unix.uid,
                gid: unix.gid,
                mtime: unix_seconds(cached.mtime),
            }));
        }
        headers.extend(cached.system_meta.clone());
        crate::obs::validate_metadata(&headers)?;
        Ok(headers)
    }

    /// A durable sidecar makes retained data identifiable after a restart.
    /// It contains no credentials and is inside the private session directory.
    fn save_recovery(&self, path: &str, staging: &Path) -> Result<(), ObsError> {
        #[derive(serde::Serialize)]
        struct Recovery<'a> {
            endpoint: &'a str,
            bucket: &'a str,
            key: &'a str,
            metadata: Vec<(String, String)>,
        }
        let record = Recovery {
            endpoint: self.client.endpoint(),
            bucket: self.client.bucket(),
            key: path,
            metadata: self.metadata_headers(path)?,
        };
        crate::persist::write_yaml(&staging.with_extension("yaml"), &record).map_err(ObsError::from)
    }

    fn mark_pending(&mut self, path: &str, staging: &Path) -> Result<(), ObsError> {
        let ino = self
            .path_to_ino
            .get(path)
            .copied()
            .ok_or_else(|| ObsError::Other(format!("missing inode for {path}")))?;
        if self.files.get(&ino).is_some_and(|f| f.pending) {
            return Ok(());
        }
        self.save_recovery(path, staging)?;
        self.files
            .get_mut(&ino)
            .ok_or_else(|| ObsError::Other("missing file state".into()))?
            .pending = true;
        Ok(())
    }

    fn content_changed(&mut self, path: &str, size: u64) {
        if let Some(meta) = self.meta_cache.get_mut(path) {
            meta.size = size;
            meta.mtime = SystemTime::now();
            meta.expires = Instant::now() + Duration::from_secs(5);
        }
    }

    /// Resolve a path to (ino, is_dir, size). Uses the cache, then HEAD,
    /// then a one-entry directory probe. Returns None when absent.
    fn resolve(&mut self, path: &str) -> Result<Option<(u64, bool, u64, SystemTime)>, ObsError> {
        if path.is_empty() {
            return Ok(Some((ROOT_INO, true, 4096, SystemTime::now())));
        }
        if let Some(size) = self.staging_size(path) {
            let ino = self.alloc_ino(path);
            let mtime = self
                .meta_cache
                .get(path)
                .map(|m| m.mtime)
                .unwrap_or(SystemTime::UNIX_EPOCH);
            return Ok(Some((ino, false, size, mtime)));
        }
        // Copy the cached entry out first so the borrow does not overlap
        // the mutable alloc_ino() call below.
        if let Some(c) = self.meta_cache.get(path).cloned()
            && c.expires > Instant::now()
        {
            let ino = self.alloc_ino(path);
            return Ok(Some((ino, c.is_dir, c.size, c.mtime)));
        }
        // File?
        match self.client.head_object(path) {
            Ok(Some(meta)) => {
                // A symlink is stored as a zero-byte object whose mode says
                // S_IFLNK, so it shows up here as a "file" but must be
                // reported as a link.
                let cached = cached_from_meta(&meta, false);
                let mtime = cached.mtime;
                let size = meta.size;
                self.meta_cache.insert(path.to_string(), cached);
                let ino = self.alloc_ino(path);
                return Ok(Some((ino, false, size, mtime)));
            }
            Ok(None) => {}
            Err(e) => {
                return Err(e);
            }
        }
        // Directory placeholder object?
        let placeholder = format!("{path}/");
        if let Some(meta) = self.client.head_object(&placeholder)? {
            let cached = cached_from_meta(&meta, true);
            let mtime = cached.mtime;
            self.meta_cache.insert(path.to_string(), cached);
            let ino = self.alloc_ino(path);
            return Ok(Some((ino, true, 4096, mtime)));
        }
        // Any key below this prefix?
        match self.client.list_objects(&dir_prefix(path), "/", None, 1) {
            Ok(page) if !page.keys.is_empty() || !page.prefixes.is_empty() => {
                self.meta_cache.insert(
                    path.to_string(),
                    synthetic_meta(4096, true, SystemTime::now()),
                );
                let ino = self.alloc_ino(path);
                Ok(Some((ino, true, 4096, SystemTime::now())))
            }
            Ok(_) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Merge attribute changes, preserving other metadata, and persist them
    /// through SetObjectMetadata or the staged file's recovery record.
    #[allow(clippy::too_many_arguments)]
    fn update_unix_meta(
        &mut self,
        path: &str,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        mtime: Option<SystemTime>,
        extra: &[(String, String)],
    ) -> Result<(), ObsError> {
        let mut current = self.ensure_meta(path)?.clone();
        current
            .extra_meta
            .retain(|(k, _)| !extra.iter().any(|(ek, _)| ek == k));
        current.extra_meta.extend_from_slice(extra);
        let base = current.unix.unwrap_or(UnixAttrs {
            mode: if current.is_dir {
                libc::S_IFDIR | 0o755
            } else {
                libc::S_IFREG | 0o644
            },
            uid: 0,
            gid: 0,
        });
        current.unix = Some(UnixAttrs {
            mode: mode
                .map(|m| (base.mode & libc::S_IFMT) | (m & 0o7777))
                .unwrap_or(base.mode),
            uid: uid.unwrap_or(base.uid),
            gid: gid.unwrap_or(base.gid),
        });
        if let Some(mtime) = mtime {
            current.mtime = mtime;
        }
        current.expires = Instant::now() + Duration::from_secs(5);
        self.persist_meta(path, current)
    }

    fn persist_meta(&mut self, path: &str, current: CachedMeta) -> Result<(), ObsError> {
        let previous = self.meta_cache.insert(path.into(), current);
        let result = (|| {
            let headers = self.metadata_headers(path)?;
            if self.staging_size(path).is_some() {
                let ino = self
                    .path_to_ino
                    .get(path)
                    .ok_or_else(|| ObsError::Other(format!("missing inode for {path}")))?;
                let staging = self.staging_path(*ino);
                self.save_recovery(path, &staging)?;
                if let Some(file) = self.files.get_mut(ino) {
                    file.pending = true;
                }
                Ok(())
            } else {
                self.client
                    .set_object_meta(&self.object_key(path), &headers)
            }
        })();
        if result.is_err() {
            if let Some(previous) = previous {
                self.meta_cache.insert(path.into(), previous);
            } else {
                self.meta_cache.remove(path);
            }
        }
        result
    }

    fn prepare_upload(&mut self, ino: u64) -> Result<Option<UploadTask>, ObsError> {
        let file = self
            .files
            .get(&ino)
            .ok_or_else(|| ObsError::Other("missing file state".into()))?;
        let staging = self.staging_path(ino);
        let Some(key) = file.path.clone() else {
            if staging.is_file() {
                File::open(staging)?.sync_all()?;
            }
            return Ok(None);
        };
        if !file.pending {
            return Ok(None);
        }
        self.save_recovery(&key, &staging)?;
        let metadata = self.metadata_headers(&key)?;
        if let Some(file) = self.files.get_mut(&ino) {
            file.uploading = true;
        }
        Ok(Some(UploadTask {
            ino,
            key,
            staging,
            metadata,
            tuning: self.upload,
        }))
    }

    fn finish_upload(&mut self, task: &UploadTask, result: &Result<(), ObsError>) {
        if let Some(file) = self.files.get_mut(&task.ino) {
            file.uploading = false;
            match result {
                Ok(()) => {
                    file.pending = false;
                    file.reported_failure = false;
                }
                Err(e) => {
                    if !file.reported_failure {
                        tracing::error!(key=%task.key, error=%e, path=%task.staging.display(), "upload failed; recovery data retained");
                        file.reported_failure = true;
                    } else {
                        tracing::debug!(key=%task.key, error=%e, "upload still failing");
                    }
                }
            }
        }
    }

    // Namespace transactions keep their lock through copy/delete. Ordinary
    // flush/fsync use ObsFs::flush_handle to release it during the transfer.
    fn upload_staged_path(&mut self, key: &str) -> Result<(), ObsError> {
        let ino = *self
            .path_to_ino
            .get(key)
            .ok_or_else(|| ObsError::Other("missing inode".into()))?;
        if let Some(task) = self.prepare_upload(ino)? {
            let result = task.run(&self.client);
            self.finish_upload(&task, &result);
            result?;
        }
        Ok(())
    }
}

struct UploadTask {
    ino: u64,
    key: String,
    staging: PathBuf,
    metadata: Vec<(String, String)>,
    tuning: crate::obs::UploadTuning,
}

impl UploadTask {
    fn run(&self, client: &ObsClient) -> Result<(), ObsError> {
        File::open(&self.staging)?.sync_all()?;
        client.upload_file_with_meta(&self.key, &self.staging, self.tuning, &self.metadata)
    }
}

impl ObsFs {
    /// Resolve what to report to `statfs`.
    ///
    /// OBS does not model a "disk": a bucket has a *used* figure
    /// (`GET /?storageinfo`) and, optionally, a byte *quota* (`GET /?quota`).
    /// So:
    /// * quota > 0: real total, real used, real free. This is the only case
    ///   where `df` means something.
    /// * quota == 0: no limit configured. Reporting 0 free would make
    ///   monitoring scream "disk full" and can make writers bail out on a
    ///   statvfs() precheck, so report a large synthetic ceiling instead and
    ///   flag it as synthetic.
    /// * query fails: keep the last good answer, or fall back to the
    ///   synthetic ceiling without usage numbers.
    fn usage_snapshot(&self) -> UsageSnapshot {
        let previous = self.inner.lock().unwrap().usage_cache;
        if let Some((at, cached)) = previous
            && at.elapsed() < USAGE_TTL
        {
            return cached;
        }
        let used = self
            .client
            .bucket_storage_size()
            .ok()
            .flatten()
            .or_else(|| previous.map(|(_, c)| c.used))
            .unwrap_or(0);
        let quota = self.client.bucket_quota().ok().flatten();
        let snapshot = decide_usage(used, quota);
        if snapshot.total_is_synthetic {
            tracing::debug!(
                used,
                synthetic_total = SYNTHETIC_TOTAL,
                "no bucket quota configured; statfs reports a synthetic capacity"
            );
        }
        self.inner.lock().unwrap().usage_cache = Some((Instant::now(), snapshot));
        snapshot
    }

    // Same-inode writes wait for their upload; other files can keep working.
    fn lock_inode(&self, ino: u64) -> MutexGuard<'_, Inner> {
        self.uploads_done
            .wait_while(self.inner.lock().unwrap(), |inner| {
                inner.files.get(&ino).is_some_and(|f| f.uploading)
            })
            .unwrap()
    }

    fn lock_namespace(&self) -> MutexGuard<'_, Inner> {
        self.uploads_done
            .wait_while(self.inner.lock().unwrap(), |inner| {
                inner.files.values().any(|f| f.uploading)
            })
            .unwrap()
    }

    fn flush_handle(&self, fh: u64) -> Result<(), Errno> {
        let ino = self
            .inner
            .lock()
            .unwrap()
            .open_files
            .get(&fh)
            .map(|f| f.ino)
            .ok_or(Errno::EBADF)?;
        let task = self
            .lock_inode(ino)
            .prepare_upload(ino)
            .map_err(|e| errno_for_obs(&e))?;
        if let Some(task) = task {
            let result = task.run(&self.client);
            self.inner.lock().unwrap().finish_upload(&task, &result);
            self.uploads_done.notify_all();
            result.map_err(|e| errno_for_obs(&e))?;
        }
        Ok(())
    }
}

impl Filesystem for ObsFs {
    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(count) = inner.lookups.get_mut(&ino.0) {
            *count = count.saturating_sub(nlookup);
            if *count == 0 {
                inner.lookups.remove(&ino.0);
            }
        }
        inner.maybe_reclaim();
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let mut inner = self.inner.lock().unwrap();
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.directories.insert(
            fh,
            Directory {
                ino: ino.0,
                entries: None,
            },
        );
        reply.opened(fuser::FileHandle(fh), FopenFlags::empty());
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: fuser::FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.directories.remove(&fh.0);
        inner.maybe_reclaim();
        reply.ok();
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut inner = self.inner.lock().unwrap();
        inner.maybe_reclaim();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.path(&parent.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name = name.to_string_lossy().into_owned();
        let path = join_path(&parent_path, &name);
        match inner.resolve(&path) {
            Ok(Some((ino, is_dir, size, mtime))) => {
                let kind = if is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                let cached = inner.meta_cache.get(&path).cloned();
                let attr = inner.attr_with_meta(req, ino, kind, size, mtime, cached.as_ref());
                *inner.lookups.entry(ino).or_default() += 1;
                reply.entry(&TTL, &attr, Generation(0));
            }
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => reply.error(errno_for_obs(&e)),
        }
    }

    fn getattr(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: Option<fuser::FileHandle>,
        reply: ReplyAttr,
    ) {
        let mut inner = self.inner.lock().unwrap();
        if ino == INodeNo::ROOT {
            let attr = inner.attr(req, ROOT_INO, FileType::Directory, 4096, SystemTime::now());
            reply.attr(&TTL, &attr);
            return;
        }
        if let Some(meta) = inner.files.get(&ino.0).and_then(|f| f.detached.as_ref()) {
            let mut attr = inner.attr_with_meta(
                req,
                ino.0,
                FileType::RegularFile,
                meta.size,
                meta.mtime,
                Some(meta),
            );
            attr.nlink = 0;
            reply.attr(&TTL, &attr);
            return;
        }
        let Some(path) = inner.path(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match inner.resolve(&path) {
            Ok(Some((_, is_dir, size, mtime))) => {
                let kind = if is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                let cached = inner.meta_cache.get(&path).cloned();
                let attr = inner.attr_with_meta(req, ino.0, kind, size, mtime, cached.as_ref());
                reply.attr(&TTL, &attr);
            }
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => reply.error(errno_for_obs(&e)),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = (if ino == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.path(&ino.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if !inner.directories.contains_key(&fh.0) {
            reply.error(Errno::EBADF);
            return;
        }
        if inner
            .directories
            .get(&fh.0)
            .is_some_and(|d| d.entries.is_none())
        {
            let prefix = dir_prefix(&path);
            let page = match inner.client.list_dir(&prefix) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(path, error = %e, "list_dir failed");
                    let err = errno_for_obs(&e);
                    reply.error(err);
                    return;
                }
            };
            // (name, kind), deduplicated; known-but-not-yet-listed children
            // (e.g. a file created and still open) are merged in.
            let mut entries: Vec<(String, FileType)> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            for p in &page.prefixes {
                if let Some(rest) = p.strip_prefix(&prefix) {
                    let name = rest.trim_end_matches('/').to_string();
                    if !name.is_empty() && !name.contains('/') && seen.insert(name.clone()) {
                        entries.push((name, FileType::Directory));
                    }
                }
            }
            for key in &page.keys {
                if let Some(rest) = key.strip_prefix(&prefix) {
                    if rest.is_empty() {
                        continue; // the directory's own placeholder
                    }
                    if rest.ends_with('/') {
                        let name = rest.trim_end_matches('/').to_string();
                        if !name.contains('/') && seen.insert(name.clone()) {
                            entries.push((name, FileType::Directory));
                        }
                    } else if !rest.contains('/') && seen.insert(rest.to_string()) {
                        entries.push((rest.to_string(), FileType::RegularFile));
                    }
                }
            }
            for known in inner.path_to_ino.keys() {
                if parent_path(known) == path && inner.staging_size(known).is_some() {
                    let name = file_name(known).to_string();
                    if !name.is_empty() && seen.insert(name.clone()) {
                        // Best-effort kind: a trailing-slash placeholder is a dir.
                        let kind = if inner
                            .meta_cache
                            .get(known)
                            .map(|c| c.is_dir)
                            .unwrap_or(false)
                        {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        };
                        entries.push((name, kind));
                    }
                }
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            if let Some(dir) = inner.directories.get_mut(&fh.0) {
                dir.entries = Some(entries);
            }
        }
        let parent_ino = if path.is_empty() {
            ROOT_INO
        } else {
            inner
                .path_to_ino
                .get(&parent_path(&path))
                .copied()
                .unwrap_or(ROOT_INO)
        };
        let count = inner
            .directories
            .get(&fh.0)
            .and_then(|d| d.entries.as_ref())
            .map_or(0, Vec::len);
        for i in offset as usize..count + 2 {
            let (child_ino, kind, name) = match i {
                0 => (ino.0, FileType::Directory, ".".to_string()),
                1 => (parent_ino, FileType::Directory, "..".to_string()),
                _ => {
                    let Some((name, kind)) = inner
                        .directories
                        .get(&fh.0)
                        .and_then(|d| d.entries.as_ref())
                        .and_then(|entries| entries.get(i - 2))
                        .cloned()
                    else {
                        reply.error(Errno::EIO);
                        return;
                    };
                    let child = join_path(&path, &name);
                    (inner.alloc_ino(&child), kind, name)
                }
            };
            if reply.add(INodeNo(child_ino), (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    /// Check existence; this shared mount does not enforce stored Unix modes.
    fn access(&self, _req: &Request, ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = inner.path(&ino.0).cloned() else {
            // The root inode is not in the map; it always exists.
            if ino.0 == ROOT_INO {
                reply.ok();
            } else {
                reply.error(Errno::ENOENT);
            }
            return;
        };
        match inner.resolve(&path) {
            Ok(Some(_)) => reply.ok(),
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => reply.error(errno_for_obs(&e)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let mut inner = self.lock_inode(ino.0);
        let Some(path) = inner.path(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let write_mode = matches!(
            flags.acc_mode(),
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR
        );
        // A file that still has a staging file (created or being written in
        // this session) is not on OBS yet, or is stale there. Both read and
        // write handles must look at it, otherwise a second `open` returns
        // ENOENT for a file the first handle just created.
        let staging = inner.staging_path(ino.0);
        if !write_mode && !staging.exists() {
            // Bind each open handle to a fresh remote object generation.
            let meta = match inner.client.head_object(&path) {
                Ok(Some(meta)) if meta.etag.as_ref().is_some_and(|s| !s.is_empty()) => meta,
                Ok(Some(_)) => {
                    reply.error(Errno::EIO);
                    return;
                }
                Ok(None) => {
                    reply.error(Errno::ENOENT);
                    return;
                }
                Err(e) => {
                    reply.error(errno_for_obs(&e));
                    return;
                }
            };
            let size = Some(meta.size);
            let etag = meta.etag.clone();
            inner
                .meta_cache
                .insert(path.clone(), cached_from_meta(&meta, false));
            let fh = inner.next_fh;
            inner.next_fh += 1;
            inner.open_files.insert(
                fh,
                OpenFile {
                    ino: ino.0,
                    etag,
                    size,
                    window: None,
                },
            );
            // Kernel pages are shared by inode, not by object generation.
            // Keep remote caching per handle so a later open cannot feed new
            // object bytes to an older handle without an If-Match check.
            reply.opened(fuser::FileHandle(fh), FopenFlags::FOPEN_DIRECT_IO);
            return;
        }
        if !write_mode {
            let fh = inner.next_fh;
            inner.next_fh += 1;
            inner.open_files.insert(
                fh,
                OpenFile {
                    ino: ino.0,
                    etag: None,
                    size: fs::metadata(&staging).ok().map(|m| m.len()),
                    window: None,
                },
            );
            reply.opened(fuser::FileHandle(fh), FopenFlags::empty());
            return;
        }
        let trunc = flags.0 & libc::O_TRUNC != 0;
        let staging = match inner.stage_existing(ino.0, &path, trunc) {
            Ok(staging) => staging,
            Err(e) => {
                reply.error(errno_for_obs(&e));
                return;
            }
        };
        if trunc {
            if let Err(e) = inner.mark_pending(&path, &staging) {
                reply.error(errno_for_obs(&e));
                return;
            }
            if let Err(e) = OpenOptions::new()
                .write(true)
                .open(&staging)
                .and_then(|f| f.set_len(0))
            {
                reply.error(io_errno(&e));
                return;
            }
            inner.content_changed(&path, 0);
        }
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.open_files.insert(
            fh,
            OpenFile {
                ino: ino.0,
                etag: None,
                size: None,
                window: None,
            },
        );
        reply.opened(fuser::FileHandle(fh), FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        tracing::debug!(offset, size, "read");
        // Resolve everything needed for the request while holding the lock,
        // then drop it before the network round-trip. Range GETs are the hot
        // path for restore/verify and holding the global mutex across the
        // HTTP call serialised them: a 20 MiB read ran at a fraction of the
        // link speed purely because reads could not overlap.
        let (key, file_size, staging, etag) = {
            let inner = self.inner.lock().unwrap();
            let Some(open) = inner.open_files.get(&fh.0) else {
                reply.error(Errno::EBADF);
                return;
            };
            let Some(file) = inner.files.get(&open.ino) else {
                reply.error(Errno::EBADF);
                return;
            };
            let staging = inner.staging_path(open.ino);
            (
                file.path.clone().unwrap_or_default(),
                open.size.unwrap_or(0),
                staging.is_file().then_some(staging),
                open.etag.clone(),
            )
        };
        if let Some(staging) = staging {
            return read_staging(&staging, offset, size, reply);
        }
        if key.is_empty() {
            reply.error(Errno::EBADF);
            return;
        }
        if offset >= file_size {
            reply.data(&[]);
            return;
        }
        let want = (size as u64).min(file_size - offset) as usize;

        // Serve from the read-ahead window when it already covers this range.
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(open) = inner.open_files.get_mut(&fh.0)
                && let Some(w) = &open.window
                && let Some(bytes) = w.slice(offset, want)
            {
                reply.data(bytes);
                return;
            }
        }

        // Fetch this range plus a look-ahead tail so the next few 128 KiB
        // kernel reads are free. Never read past EOF.
        let fetch_len = (want as u64 + READ_AHEAD_BYTES).min(file_size - offset) as usize;
        let Some(etag) = etag else {
            reply.error(Errno::EIO);
            return;
        };
        let data = match self
            .client
            .get_range_checked(&key, offset, fetch_len, &etag, file_size)
        {
            Ok(d) => d,
            Err(e) => {
                if let Some(open) = self.inner.lock().unwrap().open_files.get_mut(&fh.0) {
                    open.window = None;
                }
                reply.error(errno_for_obs(&e));
                return;
            }
        };
        reply.data(&data[..want]);
        if let Some(open) = self.inner.lock().unwrap().open_files.get_mut(&fh.0) {
            open.window = Some(ReadWindow {
                start: offset,
                data,
            });
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut inner = self.lock_inode(ino.0);
        let Some(open) = inner.open_files.get(&fh.0) else {
            reply.error(Errno::EBADF);
            return;
        };
        let ino = open.ino;
        let Some(file) = inner.files.get(&ino) else {
            reply.error(Errno::EBADF);
            return;
        };
        let key = file.path.clone();
        let deleted = key.is_none();
        let key = key.unwrap_or_default();
        let staging = inner.staging_path(ino);
        if !staging.is_file() {
            reply.error(Errno::EBADF);
            return;
        }
        let current_size = fs::metadata(&staging).map(|m| m.len()).unwrap_or(0);
        let end = if flags.0 & libc::O_APPEND != 0 {
            current_size
        } else {
            offset
        };
        let Some(end) = end
            .checked_add(data.len() as u64)
            .filter(|end| *end <= crate::obs::MAX_OBJECT_SIZE)
        else {
            reply.error(Errno::EFBIG);
            return;
        };
        if let Err(e) = inner.ensure_space(end.saturating_sub(current_size)) {
            reply.error(errno_for_obs(&e));
            return;
        }
        if !deleted && let Err(e) = inner.mark_pending(&key, &staging) {
            reply.error(errno_for_obs(&e));
            return;
        }
        let result = (|| -> std::io::Result<u64> {
            let mut file = OpenOptions::new().write(true).open(&staging)?;
            file.seek(if flags.0 & libc::O_APPEND != 0 {
                SeekFrom::End(0)
            } else {
                SeekFrom::Start(offset)
            })?;
            file.write_all(data)?;
            Ok(file.metadata()?.len())
        })();
        match result {
            Ok(size) => {
                if deleted {
                    if let Some(meta) = inner.files.get_mut(&ino).and_then(|f| f.detached.as_mut())
                    {
                        meta.size = size;
                        meta.mtime = SystemTime::now();
                    }
                } else {
                    inner.content_changed(&key, size);
                }
                reply.written(data.len() as u32);
            }
            Err(e) => reply.error(io_errno(&e)),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let mut inner = self.lock_namespace();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.path(&parent.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name = name.to_string_lossy().into_owned();
        let path = join_path(&parent_path, &name);
        match inner.resolve(&path) {
            Ok(Some(_)) => {
                reply.error(if flags & libc::O_EXCL != 0 {
                    Errno::EEXIST
                } else {
                    Errno::EAGAIN
                });
                return;
            }
            Err(e) => {
                reply.error(errno_for_obs(&e));
                return;
            }
            _ => {}
        }
        if let Err(e) = inner.ensure_space(0) {
            reply.error(errno_for_obs(&e));
            return;
        }
        let ino = inner.alloc_ino(&path);
        let staging = inner.staging_path(ino);
        if let Err(e) = fs::write(&staging, []) {
            reply.error(io_errno(&e));
            return;
        }
        let mut cached = synthetic_meta(0, false, SystemTime::now());
        cached.unix = Some(UnixAttrs {
            mode: libc::S_IFREG | (mode & !umask & 0o7777),
            uid: req.uid(),
            gid: req.gid(),
        });
        inner.meta_cache.insert(path.clone(), cached);
        if let Err(e) = inner.mark_pending(&path, &staging) {
            reply.error(errno_for_obs(&e));
            return;
        }
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.open_files.insert(
            fh,
            OpenFile {
                ino,

                etag: None,
                size: Some(0),
                window: None,
            },
        );
        // Pending even when empty, so closing a created file still uploads a
        // zero-byte object (a backup tool's `touch` must be visible in OBS).
        let attr = inner.attr_with_meta(
            req,
            ino,
            FileType::RegularFile,
            0,
            SystemTime::now(),
            inner.meta_cache.get(&path),
        );
        *inner.lookups.entry(ino).or_default() += 1;
        reply.created(
            &TTL,
            &attr,
            Generation(0),
            fuser::FileHandle(fh),
            FopenFlags::empty(),
        );
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: fuser::FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        match self.flush_handle(fh.0) {
            Err(err) => reply.error(err),
            Ok(()) => reply.ok(),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: fuser::FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        // Same as flush: OBS objects are immutable, so an fsync is a full
        // re-upload of the staged file. Apps that fsync often (databases,
        // VM images) must not run on this mount.
        match self.flush_handle(fh.0) {
            Err(err) => reply.error(err),
            Ok(()) => reply.ok(),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: fuser::FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let result = self.flush_handle(fh.0);
        let mut inner = self.inner.lock().unwrap();
        if let Some(open) = inner.open_files.remove(&fh.0) {
            inner.release_staging(open.ino);
        }
        inner.maybe_reclaim();
        match result {
            Err(e) => reply.error(e),
            Ok(()) => reply.ok(),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let mut inner = self.lock_namespace();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.path(&parent.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name = name.to_string_lossy().into_owned();
        let path = join_path(&parent_path, &name);
        let placeholder = format!("{path}/");
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let meta = crate::obs::unix_meta_headers(UnixMeta {
            mode: libc::S_IFDIR | (mode & !umask & 0o7777),
            uid: req.uid(),
            gid: req.gid(),
            mtime: now,
        });
        if let Err(e) = inner.client.put_object_with_meta(&placeholder, &[], &meta) {
            tracing::error!(error = %e, "mkdir placeholder upload failed");
            let err = errno_for_obs(&e);
            reply.error(err);
            return;
        }
        let ino = inner.alloc_ino(&path);
        let mut cached = synthetic_meta(4096, true, SystemTime::now());
        cached.unix = Some(UnixAttrs {
            mode: libc::S_IFDIR | (mode & !umask & 0o7777),
            uid: req.uid(),
            gid: req.gid(),
        });
        inner.meta_cache.insert(path.clone(), cached);
        let attr = inner.attr_with_meta(
            req,
            ino,
            FileType::Directory,
            4096,
            SystemTime::now(),
            inner.meta_cache.get(&path),
        );
        *inner.lookups.entry(ino).or_default() += 1;
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut inner = self.lock_namespace();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.path(&parent.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = join_path(&parent_path, &name.to_string_lossy());
        let prefix = dir_prefix(&path);
        if inner
            .path_to_ino
            .keys()
            .any(|p| p.starts_with(&prefix) && inner.staging_size(p).is_some())
        {
            reply.error(Errno::ENOTEMPTY);
            return;
        }
        match inner.client.list_dir(&prefix) {
            Ok(page) => {
                // The directory's own placeholder object does not count.
                let others =
                    page.keys.iter().filter(|key| **key != prefix).count() + page.prefixes.len();
                if others > 0 {
                    reply.error(Errno::ENOTEMPTY);
                    return;
                }
            }
            Err(e) => {
                let err = errno_for_obs(&e);
                reply.error(err);
                return;
            }
        }
        if let Err(e) = inner.client.delete_object(&prefix) {
            let err = errno_for_obs(&e);
            reply.error(err);
            return;
        }
        inner.forget_subtree(&path);
        reply.ok();
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut inner = self.lock_namespace();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.path(&parent.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = join_path(&parent_path, &name.to_string_lossy());
        if let Err(e) = inner.prepare_detach(&path) {
            reply.error(errno_for_obs(&e));
            return;
        }
        if let Err(e) = inner.client.delete_object(&path) {
            let err = errno_for_obs(&e);
            reply.error(err);
            return;
        }
        inner.detach_path(&path);
        reply.ok();
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let mut inner = self.lock_namespace();
        let old_parent = if parent == INodeNo::ROOT {
            String::new()
        } else {
            match inner.path(&parent.0) {
                Some(p) => p.clone(),
                None => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
        };
        let new_parent = if newparent == INodeNo::ROOT {
            String::new()
        } else {
            match inner.path(&newparent.0) {
                Some(p) => p.clone(),
                None => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
        };
        let old_path = join_path(&old_parent, &name.to_string_lossy());
        let new_path = join_path(&new_parent, &newname.to_string_lossy());
        if old_path == new_path {
            reply.ok();
            return;
        }
        match inner.rename_path(&old_path, &new_path, flags.bits()) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_for_obs(&e)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let usage = self.usage_snapshot();
        let bs = STATFS_BLOCK_SIZE as u64;
        let total_blocks = usage.total / bs;
        let used_blocks = (usage.used / bs).min(total_blocks);
        let free_blocks = total_blocks - used_blocks;
        // obsfs reports 0xFFFFFFFF inodes as well; mirror it so `df -i` shows
        // a number instead of "-", which some dashboards treat as an error.
        let files = OBSFS_SYNTHETIC_BLOCKS;
        reply.statfs(
            total_blocks,
            free_blocks,
            free_blocks,
            files,
            files,
            STATFS_BLOCK_SIZE,
            STATFS_NAME_MAX,
            STATFS_BLOCK_SIZE,
        );
    }

    /// Xattr names use lowercase hex in header names; values use base64.
    fn setxattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        let mut inner = self.lock_inode(ino.0);
        let Some(path) = inner.path(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let current = match inner.ensure_meta(&path) {
            Ok(current) => current,
            Err(e) => {
                reply.error(errno_for_obs(&e));
                return;
            }
        };
        let key = xattr_key(&name.to_string_lossy());
        let mut current = current.clone();
        let exists = current.extra_meta.iter().any(|(k, _)| k == &key);
        if flags & libc::XATTR_CREATE != 0 && exists {
            reply.error(Errno::EEXIST);
            return;
        }
        if flags & libc::XATTR_REPLACE != 0 && !exists {
            reply.error(Errno::ENODATA);
            return;
        }
        current.extra_meta.retain(|(k, _)| k != &key);
        current.extra_meta.push((key, B64.encode(value)));
        if let Err(e) = inner.persist_meta(&path, current) {
            reply.error(errno_for_obs(&e));
            return;
        }
        reply.ok();
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = inner.path(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let current = match inner.ensure_meta(&path) {
            Ok(current) => current,
            Err(e) => {
                reply.error(errno_for_obs(&e));
                return;
            }
        };
        let key = xattr_key(&name.to_string_lossy());
        let Some(encoded) = current
            .extra_meta
            .iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v.clone())
        else {
            reply.error(Errno::ENODATA);
            return;
        };
        let value = B64
            .decode(encoded.as_bytes())
            .unwrap_or_else(|_| encoded.into_bytes());
        if size == 0 {
            reply.size(value.len() as u32);
        } else if (size as usize) < value.len() {
            reply.error(Errno::ERANGE);
        } else {
            reply.data(&value);
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = inner.path(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let current = match inner.ensure_meta(&path) {
            Ok(current) => current,
            Err(e) => {
                reply.error(errno_for_obs(&e));
                return;
            }
        };
        // NUL-separated names, per the listxattr(2) convention.
        let mut names = Vec::new();
        for (k, _) in &current.extra_meta {
            if let Some(raw) = xattr_name_from_key(k) {
                names.extend_from_slice(&raw);
                names.push(0);
            }
        }
        if size == 0 {
            reply.size(names.len() as u32);
        } else if (size as usize) < names.len() {
            reply.error(Errno::ERANGE);
        } else {
            reply.data(&names);
        }
    }

    fn removexattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut inner = self.lock_inode(ino.0);
        let Some(path) = inner.path(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let current = match inner.ensure_meta(&path) {
            Ok(current) => current,
            Err(e) => {
                reply.error(errno_for_obs(&e));
                return;
            }
        };
        let mut current = current.clone();
        let key = xattr_key(&name.to_string_lossy());
        if !current.extra_meta.iter().any(|(k, _)| k == &key) {
            reply.error(Errno::ENODATA);
            return;
        }
        current.extra_meta.retain(|(k, _)| k != &key);
        if let Err(e) = inner.persist_meta(&path, current) {
            reply.error(errno_for_obs(&e));
            return;
        }
        reply.ok();
    }

    /// Create a symlink as a zero-byte object carrying `x-obs-meta-symlink-target`
    /// plus a mode of `S_IFLNK | 0777`, which is how obsfs does it.
    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let mut inner = self.lock_namespace();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.path(&parent.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = join_path(&parent_path, &link_name.to_string_lossy());
        let target_str = target.to_string_lossy().into_owned();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut meta = crate::obs::unix_meta_headers(UnixMeta {
            mode: libc::S_IFLNK | 0o777,
            uid: req.uid(),
            gid: req.gid(),
            mtime: now,
        });
        meta.push((
            format!("x-obs-meta-{}", crate::obs::meta_keys::SYMLINK_TARGET),
            target_str.clone(),
        ));
        if let Err(e) = inner.client.put_object_with_meta(&path, &[], &meta) {
            tracing::error!(path = %path, error = %e, "symlink creation failed");
            let err = errno_for_obs(&e);
            reply.error(err);
            return;
        }
        let ino = inner.alloc_ino(&path);
        let mut cached = synthetic_meta(0, false, SystemTime::now());
        cached.unix = Some(UnixAttrs {
            mode: libc::S_IFLNK | 0o777,
            uid: req.uid(),
            gid: req.gid(),
        });
        cached
            .extra_meta
            .push((crate::obs::meta_keys::SYMLINK_TARGET.into(), target_str));
        inner.meta_cache.insert(path, cached.clone());
        let attr =
            inner.attr_with_meta(req, ino, FileType::Symlink, 0, cached.mtime, Some(&cached));
        *inner.lookups.entry(ino).or_default() += 1;
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let inner = self.inner.lock().unwrap();
        let Some(path) = inner.path(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(target) = inner
            .meta_cache
            .get(&path)
            .and_then(|c| crate::obs::symlink_target(&c.extra_meta))
        {
            reply.data(target.as_bytes());
            return;
        }
        // Not cached: ask the object itself.
        match inner.client.head_object(&path) {
            Ok(Some(meta)) => {
                let target = crate::obs::symlink_target(&meta.x_obs_meta);
                match target {
                    Some(t) => reply.data(t.as_bytes()),
                    None => reply.error(Errno::EINVAL),
                }
            }
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => {
                let err = errno_for_obs(&e);
                reply.error(err);
            }
        }
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<fuser::FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        // OBS has no native permissions, but they can be persisted in object
        // metadata, so chmod/chown/utimes use SetObjectMetadata.
        // Truncation still needs the
        // data path: download -> truncate -> re-upload.
        let mut inner = self.lock_inode(ino.0);
        if let Some(mut meta) = inner
            .files
            .get(&ino.0)
            .and_then(|f| f.detached.as_ref())
            .cloned()
        {
            let staging = inner.staging_path(ino.0);
            if let Some(size) = size {
                if size > crate::obs::MAX_OBJECT_SIZE {
                    reply.error(Errno::EFBIG);
                    return;
                }
                if let Err(e) = inner.ensure_space(size.saturating_sub(meta.size)) {
                    reply.error(errno_for_obs(&e));
                    return;
                }
                if let Err(e) = OpenOptions::new()
                    .write(true)
                    .open(&staging)
                    .and_then(|f| f.set_len(size))
                {
                    reply.error(io_errno(&e));
                    return;
                }
                meta.size = size;
                meta.mtime = SystemTime::now();
            }
            let mut unix = meta.unix.unwrap_or(UnixAttrs {
                mode: libc::S_IFREG | 0o644,
                uid: req.uid(),
                gid: req.gid(),
            });
            if let Some(mode) = mode {
                unix.mode = (unix.mode & libc::S_IFMT) | (mode & 0o7777);
            }
            if let Some(uid) = uid {
                unix.uid = uid;
            }
            if let Some(gid) = gid {
                unix.gid = gid;
            }
            if let Some(time) = mtime {
                meta.mtime = match time {
                    TimeOrNow::Now => SystemTime::now(),
                    TimeOrNow::SpecificTime(t) => t,
                };
            }
            meta.unix = Some(unix);
            let mut attr = inner.attr_with_meta(
                req,
                ino.0,
                FileType::RegularFile,
                meta.size,
                meta.mtime,
                Some(&meta),
            );
            attr.nlink = 0;
            if let Some(file) = inner.files.get_mut(&ino.0) {
                file.detached = Some(meta);
            }
            reply.attr(&TTL, &attr);
            return;
        }
        let Some(path) = inner.path(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if mode.is_some() || uid.is_some() || gid.is_some() || mtime.is_some() {
            let when = mtime.map(|t| match t {
                TimeOrNow::Now => SystemTime::now(),
                TimeOrNow::SpecificTime(t) => t,
            });
            if let Err(e) = inner.update_unix_meta(&path, mode, uid, gid, when, &[]) {
                let err = errno_for_obs(&e);
                reply.error(err);
                return;
            }
        }
        if let Some(size) = size {
            if size > crate::obs::MAX_OBJECT_SIZE {
                reply.error(Errno::EFBIG);
                return;
            }
            let old_size = inner.ensure_meta(&path).map(|m| m.size).unwrap_or(0);
            if let Err(e) = inner.ensure_space(size.saturating_sub(old_size)) {
                reply.error(errno_for_obs(&e));
                return;
            }
            let staging = match inner.stage_existing(ino.0, &path, size == 0) {
                Ok(staging) => staging,
                Err(e) => {
                    reply.error(errno_for_obs(&e));
                    return;
                }
            };
            if let Err(e) = inner.mark_pending(&path, &staging) {
                reply.error(errno_for_obs(&e));
                return;
            }
            if let Err(e) = OpenOptions::new()
                .write(true)
                .open(&staging)
                .and_then(|f| f.set_len(size))
            {
                reply.error(io_errno(&e));
                return;
            }
            inner.content_changed(&path, size);
            if let Err(e) = inner.upload_staged_path(&path) {
                reply.error(errno_for_obs(&e));
                return;
            }
            inner.release_staging(ino.0);
        }
        match inner.resolve(&path) {
            Ok(Some((_, is_dir, size, mtime))) => {
                let kind = if is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                let cached = inner.meta_cache.get(&path).cloned();
                let attr = inner.attr_with_meta(req, ino.0, kind, size, mtime, cached.as_ref());
                reply.attr(&TTL, &attr);
            }
            Ok(None) => reply.error(Errno::ENOENT),
            Err(e) => reply.error(errno_for_obs(&e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detaching_open_remote_file_fetches_metadata_once() {
        let mock = crate::test_support::MockObs::new("[]");
        let mut inner = mock_inner(&mock);
        inner
            .client
            .put_object_with_meta("data", b"original", &[])
            .unwrap();
        let ino = inner.alloc_ino("data");
        let etag = inner.client.head_object("data").unwrap().unwrap().etag;
        inner.open_files.insert(
            1,
            OpenFile {
                ino,
                etag,
                size: Some(8),
                window: None,
            },
        );
        let before = mock.stats().requests["HEAD data"];
        inner.prepare_detach("data").unwrap();
        assert_eq!(mock.stats().requests["HEAD data"] - before, 1);
        assert_eq!(fs::read(inner.staging_path(ino)).unwrap(), b"original");
        inner.detach_path("data");
        assert!(inner.path(&ino).is_none());
        assert!(inner.staging_path(ino).exists());
    }
    #[test]
    fn external_mtime_and_epoch_are_preserved() {
        let mut meta = crate::obs::ObjectMeta {
            last_modified: Some("Thu, 01 Jan 1970 00:00:01 GMT".into()),
            ..Default::default()
        };
        assert_eq!(cached_from_meta(&meta, false).mtime, unix_time(1));
        meta.unix = Some(UnixMeta {
            mode: libc::S_IFREG | 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        });
        assert_eq!(cached_from_meta(&meta, false).mtime, unix_time(0));
        assert_eq!(unix_seconds(unix_time(-100)), -100);
    }

    #[test]
    fn failed_directory_copy_keeps_every_source() {
        let mock = crate::test_support::MockObs::new(
            r#"[{"method":"PUT","key":"new/b","status":200,"body":"<Error><Code>InternalError</Code></Error>"}]"#,
        );
        let mut inner = mock_inner(&mock);
        inner
            .client
            .put_object_with_meta("old/a", b"a", &[])
            .unwrap();
        inner
            .client
            .put_object_with_meta("old/b", b"b", &[])
            .unwrap();
        assert!(inner.rename_path("old", "new", 0).is_err());
        assert_eq!(inner.client.get_range("old/a", 0, 1).unwrap(), b"a");
        assert_eq!(inner.client.get_range("old/b", 0, 1).unwrap(), b"b");
    }

    #[test]
    fn rename_flags_do_not_silently_overwrite_and_metadata_limit_rolls_back() {
        let mock = crate::test_support::MockObs::new("[]");
        let mut inner = mock_inner(&mock);
        inner
            .client
            .put_object_with_meta("a", b"source", &[])
            .unwrap();
        inner
            .client
            .put_object_with_meta("b", b"target", &[])
            .unwrap();
        assert_eq!(
            errno_for_obs(
                &inner
                    .rename_path("a", "b", libc::RENAME_NOREPLACE)
                    .unwrap_err()
            ),
            Errno::EEXIST
        );
        assert_eq!(
            errno_for_obs(
                &inner
                    .rename_path("a", "b", libc::RENAME_EXCHANGE)
                    .unwrap_err()
            ),
            Errno::EOPNOTSUPP
        );
        assert_eq!(inner.client.get_range("b", 0, 6).unwrap(), b"target");
        let before = inner.ensure_meta("a").unwrap().clone();
        assert!(
            inner
                .update_unix_meta(
                    "a",
                    None,
                    None,
                    None,
                    None,
                    &[(xattr_key("user.large"), "a".repeat(8192))]
                )
                .is_err()
        );
        assert_eq!(inner.meta_cache["a"].extra_meta, before.extra_meta);
        assert_eq!(inner.client.get_range("a", 0, 6).unwrap(), b"source");
    }

    #[test]
    fn reclaim_keeps_live_inodes_and_staged_metadata_but_bounds_idle_cache() {
        let mock = crate::test_support::MockObs::new("[]");
        let mut inner = mock_inner(&mock);
        inner.cache_limit = 2;
        let pinned = inner.alloc_ino("pinned");
        inner.lookups.insert(pinned, 1);
        let staged = inner.alloc_ino("staged");
        fs::write(inner.staging_path(staged), b"data").unwrap();
        for path in ["pinned", "staged", "idle1", "idle2", "idle3"] {
            inner.alloc_ino(path);
            inner
                .meta_cache
                .insert(path.into(), synthetic_meta(0, false, unix_time(1)));
        }
        inner.reclaim();
        assert_eq!(inner.path_to_ino.get("pinned"), Some(&pinned));
        assert!(inner.meta_cache.contains_key("staged"));
        assert!(inner.meta_cache.len() <= 2);
        assert!(!inner.path_to_ino.contains_key("idle1"));
        inner.min_free_space = u64::MAX;
        assert_eq!(
            errno_for_obs(&inner.ensure_space(1).unwrap_err()),
            Errno::ENOSPC
        );
    }

    fn inner_for_test() -> Inner {
        Inner {
            client: ObsClient::new(
                "ak".into(),
                "sk".into(),
                "bucket".into(),
                "http://127.0.0.1:1".into(),
            ),
            staging_dir: std::env::temp_dir().join("obs-mount-test-staging"),
            upload: crate::obs::UploadTuning::default(),
            next_ino: 2,
            files: HashMap::new(),
            path_to_ino: HashMap::new(),
            meta_cache: HashMap::new(),
            open_files: HashMap::new(),
            next_fh: 1,
            lookups: HashMap::new(),
            directories: HashMap::new(),
            min_free_space: 0,
            cache_limit: 10_000,
            last_reclaim: Instant::now(),
            usage_cache: None,
        }
    }

    #[test]
    fn path_helpers() {
        assert_eq!(parent_path("a/b/c"), "a/b");
        assert_eq!(parent_path("a"), "");
        assert_eq!(file_name("a/b/c"), "c");
        assert_eq!(file_name("c"), "c");
        assert_eq!(join_path("", "x"), "x");
        assert_eq!(join_path("d", "x"), "d/x");
        assert_eq!(dir_prefix(""), "");
        assert_eq!(dir_prefix("d/e"), "d/e/");
    }

    #[test]
    fn read_window_never_returns_partial_data_across_its_boundary() {
        let window = ReadWindow {
            start: 100,
            data: b"abcdefgh".to_vec(),
        };
        assert_eq!(window.slice(100, 8), Some(&b"abcdefgh"[..]));
        assert_eq!(window.slice(104, 4), Some(&b"efgh"[..]));
        // This used to return "efgh", silently dropping the rest of the read.
        assert_eq!(window.slice(104, 8), None);
        assert_eq!(window.slice(99, 1), None);
        assert_eq!(window.slice(108, 1), None);
        assert_eq!(window.slice(u64::MAX, 8), None);
        assert_eq!(window.slice(101, usize::MAX), None);
    }

    /// Regression for `mv a b && cat b` returning ENOENT: a rename must keep
    /// the inode number and move it to the new path, not forget it.
    #[test]
    fn rename_keeps_inode_number() {
        let mut inner = inner_for_test();
        let ino = inner.alloc_ino("old.txt");
        inner.meta_cache.insert(
            "old.txt".into(),
            synthetic_meta(3, false, SystemTime::now()),
        );

        inner.remap_subtree("old.txt", "new.txt");

        assert_eq!(inner.path(&ino), Some(&"new.txt".to_string()));
        assert_eq!(inner.path_to_ino.get("new.txt"), Some(&ino));
        assert!(!inner.path_to_ino.contains_key("old.txt"));
        assert_eq!(
            inner.meta_cache.get("new.txt").map(|c| c.size),
            Some(3),
            "cached metadata must follow the object"
        );
        assert!(!inner.meta_cache.contains_key("old.txt"));
    }

    #[test]
    fn rename_remaps_whole_directory_subtree() {
        let mut inner = inner_for_test();
        let dir_ino = inner.alloc_ino("d");
        let file_ino = inner.alloc_ino("d/f");
        let nested_ino = inner.alloc_ino("d/s/g");

        inner.remap_subtree("d", "e");

        assert_eq!(inner.path(&dir_ino), Some(&"e".to_string()));
        assert_eq!(inner.path(&file_ino), Some(&"e/f".to_string()));
        assert_eq!(inner.path(&nested_ino), Some(&"e/s/g".to_string()));
        assert!(!inner.path_to_ino.contains_key("d/f"));
    }

    /// An open handle must upload to the new key after its file is renamed.
    #[test]
    fn rename_retargets_open_handles() {
        let mut inner = inner_for_test();
        let ino = inner.alloc_ino("a.txt");
        inner.open_files.insert(
            7,
            OpenFile {
                ino,
                size: None,
                window: None,
                ..Default::default()
            },
        );

        inner.remap_subtree("a.txt", "b.txt");

        assert_eq!(
            inner
                .open_files
                .get(&7)
                .and_then(|f| inner.path(&f.ino))
                .map(String::as_str),
            Some("b.txt")
        );
    }

    /// Encoded xattr names must remain valid HTTP header names.
    #[test]
    fn xattr_keys_are_header_safe() {
        for name in [
            "user.colour",
            "user.owner",
            "security.selinux",
            "a",
            "user.x.y",
        ] {
            let key = xattr_key(name);
            let suffix = key
                .strip_prefix(crate::obs::meta_keys::XATTR_PREFIX)
                .expect("prefix present");
            assert!(
                suffix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "key {key} is not HTTP-header safe"
            );
            // And it must round-trip back to the original name.
            assert_eq!(xattr_name_from_key(&key), Some(name.as_bytes().to_vec()));
        }
    }

    #[test]
    fn only_the_last_handle_unlinks_staging() {
        let dir = std::env::temp_dir().join("obs-mount-test-staging");
        std::fs::create_dir_all(&dir).unwrap();
        let ino = 99;
        let staging = dir.join("ino-99");
        std::fs::write(&staging, b"data").unwrap();

        let mut inner = inner_for_test();
        inner.staging_dir = dir.clone();
        for fh in 1..=2 {
            inner.open_files.insert(
                fh,
                OpenFile {
                    ino,
                    size: None,
                    window: None,
                    ..Default::default()
                },
            );
        }

        // First handle leaving must keep the file for the second one.
        inner.open_files.remove(&1);
        inner.release_staging(ino);
        assert!(staging.exists(), "staging removed while still referenced");

        inner.open_files.remove(&2);
        inner.release_staging(ino);
        assert!(
            !staging.exists(),
            "staging should be removed with the last handle"
        );
    }

    /// OBS reports a quota of 0 when none is configured, i.e. "unlimited".
    /// Treating that as a real limit would show `df` a full disk.
    #[test]
    fn zero_quota_means_unlimited_not_full() {
        let s = decide_usage(1234, Some(0));
        assert!(s.total_is_synthetic);
        assert_eq!(s.total, SYNTHETIC_TOTAL);
        assert_eq!(s.used, 1234);
    }

    #[test]
    fn no_quota_report_is_also_unlimited() {
        assert!(decide_usage(0, None).total_is_synthetic);
    }

    #[test]
    fn real_quota_is_reported_as_a_real_limit() {
        let s = decide_usage(10, Some(1000));
        assert!(!s.total_is_synthetic);
        assert_eq!(s.total, 1000);
        assert_eq!(s.used, 10);
    }

    /// Buckets can be over quota; `df` must not show negative free space.
    #[test]
    fn used_never_exceeds_total() {
        let s = decide_usage(5000, Some(1000));
        assert_eq!(s.total, 5000);
        assert_eq!(s.used, 5000);

        let bs = STATFS_BLOCK_SIZE as u64;
        let total_blocks = s.total / bs;
        let used_blocks = (s.used / bs).min(total_blocks);
        assert_eq!(total_blocks - used_blocks, 0);
    }

    #[test]
    fn xattr_round_trips_through_http_header_names() {
        for name in ["user.colour", "user.Colour", "user.中文"] {
            let key = xattr_key(name);
            let header =
                reqwest::header::HeaderName::from_bytes(xattr_header_key(&key).as_bytes()).unwrap();
            let received = header.as_str().strip_prefix("x-obs-meta-").unwrap();
            assert_eq!(received, key);
            assert_eq!(
                xattr_name_from_key(received),
                Some(name.as_bytes().to_vec())
            );
        }
        assert_ne!(xattr_key("user.colour"), xattr_key("user.Colour"));
        assert_eq!(xattr_key("user.colour"), "xdg.757365722e636f6c6f7572");
        assert_eq!(xattr_name_from_key("xdg.zz"), None);
    }

    #[test]
    fn staged_file_without_metadata_returns_error_and_preserves_data() {
        let dir = crate::staging_dir_for(&std::env::temp_dir(), crate::current_uid()).unwrap();
        let mut inner = inner_for_test();
        inner.staging_dir = dir.clone();
        let ino = inner.alloc_ino("backup");
        let staging = inner.staging_path(ino);
        fs::write(&staging, b"unsent backup").unwrap();
        // resolve can find staging even when no metadata was cached.
        let error = inner
            .update_unix_meta("backup", Some(0o600), None, None, None, &[])
            .expect_err("missing metadata must be reported rather than panicking");
        assert_eq!(errno_for_obs(&error), Errno::EIO);
        assert!(matches!(
            inner.ensure_meta("backup"),
            Err(ObsError::Other(_))
        ));
        assert_eq!(fs::read(&staging).unwrap(), b"unsent backup");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn dropping_mount_removes_only_its_empty_session_directory() {
        let empty = crate::staging_dir_for(&std::env::temp_dir(), crate::current_uid()).unwrap();
        let pending = crate::staging_dir_for(&std::env::temp_dir(), crate::current_uid()).unwrap();
        fs::write(pending.join("ino-2"), b"unsent backup").unwrap();
        let client = inner_for_test().client;
        drop(ObsFs::new(
            client.clone(),
            empty.clone(),
            crate::obs::UploadTuning::default(),
        ));
        drop(ObsFs::new(
            client,
            pending.clone(),
            crate::obs::UploadTuning::default(),
        ));
        assert!(!empty.exists());
        assert_eq!(fs::read(pending.join("ino-2")).unwrap(), b"unsent backup");
        fs::remove_dir_all(pending).unwrap();
    }

    fn mock_inner(mock: &crate::test_support::MockObs) -> Inner {
        let mut inner = inner_for_test();
        inner.client = mock.client();
        inner.staging_dir = mock.staging.clone();
        inner
    }

    #[test]
    fn failed_head_or_get_never_publishes_writable_staging() {
        for method in ["HEAD", "GET"] {
            let mock = crate::test_support::MockObs::new(&format!(
                r#"[{{"method":"{method}","key":"backup","status":403,"count":2}}]"#
            ));
            let mut inner = mock_inner(&mock);
            inner
                .client
                .put_object_with_meta("backup", b"original", &[])
                .unwrap();
            let ino = inner.alloc_ino("backup");
            assert!(inner.stage_existing(ino, "backup", false).is_err());
            assert!(!inner.staging_path(ino).exists());
            assert!(!inner.staging_path(ino).with_extension("download").exists());
            if method == "HEAD" {
                assert!(inner.stage_existing(ino, "backup", true).is_err());
                assert!(!inner.staging_path(ino).exists());
            }
            assert_eq!(inner.client.head_object("backup").unwrap().unwrap().size, 8);
        }
    }

    #[test]
    fn failed_upload_survives_last_reader_and_can_be_retried() {
        let mock =
            crate::test_support::MockObs::new(r#"[{"method":"PUT","key":"backup","status":403}]"#);
        let mut inner = mock_inner(&mock);
        let ino = inner.alloc_ino("backup");
        let staging = inner.staging_path(ino);
        fs::write(&staging, b"only copy").unwrap();
        inner
            .meta_cache
            .insert("backup".into(), synthetic_meta(9, false, SystemTime::now()));
        inner.mark_pending("backup", &staging).unwrap();
        for fh in [1, 2] {
            inner.open_files.insert(
                fh,
                OpenFile {
                    ino,
                    window: None,
                    size: None,
                    ..Default::default()
                },
            );
        }
        assert_eq!(
            errno_for_obs(&inner.upload_staged_path("backup").unwrap_err()),
            Errno::EACCES
        );
        inner.open_files.remove(&1);
        inner.release_staging(ino);
        inner.open_files.remove(&2);
        inner.release_staging(ino);
        assert_eq!(fs::read(&staging).unwrap(), b"only copy");
        assert!(
            fs::read_to_string(staging.with_extension("yaml"))
                .unwrap()
                .contains("key: backup")
        );
        assert_eq!(inner.resolve("backup").unwrap().unwrap().2, 9);
        let _second_mount = ObsFs::new(
            mock.client(),
            mock.staging.clone(),
            crate::obs::UploadTuning::default(),
        );
        assert!(
            staging.exists(),
            "constructing another filesystem must not clean old staging"
        );
        inner.upload_staged_path("backup").unwrap();
        inner.release_staging(ino);
        assert!(!staging.exists());
        assert!(!staging.with_extension("yaml").exists());
        assert_eq!(
            inner.client.get_range("backup", 0, 9).unwrap(),
            b"only copy"
        );
    }

    #[test]
    fn rewrite_truncate_and_chown_keep_all_metadata_after_fresh_head() {
        let mock = crate::test_support::MockObs::new("[]");
        let mut inner = mock_inner(&mock);
        let unix = UnixMeta {
            mode: libc::S_IFREG | 0o640,
            uid: 1234,
            gid: 5678,
            mtime: 1234567890,
        };
        let mut headers = crate::obs::unix_meta_headers(unix);
        headers.push((
            xattr_header_key(&xattr_key("user.colour")),
            B64.encode(b"blue"),
        ));
        headers.push(("x-obs-meta-backup-id".into(), "job-42".into()));
        inner
            .client
            .put_object_with_meta("backup", b"original", &headers)
            .unwrap();
        let ino = inner.alloc_ino("backup");
        let staged = inner.stage_existing(ino, "backup", false).unwrap();
        inner.mark_pending("backup", &staged).unwrap();
        fs::write(&staged, b"replacement").unwrap();
        inner.content_changed("backup", 11);
        inner
            .update_unix_meta("backup", None, Some(4321), None, None, &[])
            .unwrap();
        inner.upload_staged_path("backup").unwrap();
        inner.release_staging(ino);
        // A new HEAD, with an empty cache, must recover attributes from OBS.
        inner.meta_cache.clear();
        inner.resolve("backup").unwrap();
        let meta = inner.meta_cache.get("backup").unwrap();
        assert_eq!(meta.unix.unwrap().mode, unix.mode);
        assert_eq!(meta.unix.unwrap().uid, 4321);
        assert_eq!(meta.unix.unwrap().gid, unix.gid);
        assert!(
            meta.extra_meta
                .contains(&(xattr_key("user.colour"), B64.encode(b"blue")))
        );
        assert!(
            meta.extra_meta
                .contains(&("backup-id".into(), "job-42".into()))
        );
        let staged = inner.stage_existing(ino, "backup", false).unwrap();
        inner.mark_pending("backup", &staged).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&staged)
            .unwrap()
            .set_len(4)
            .unwrap();
        inner.content_changed("backup", 4);
        inner.upload_staged_path("backup").unwrap();
        let meta = inner.client.head_object("backup").unwrap().unwrap();
        assert_eq!(meta.unix.unwrap().mode, unix.mode);
        assert!(
            meta.x_obs_meta
                .contains(&(xattr_key("user.colour"), B64.encode(b"blue")))
        );
        assert_eq!(inner.client.get_range("backup", 0, 4).unwrap(), b"repl");
        assert_eq!(mock.stats().signature_failures, 0);
    }

    #[test]
    fn metadata_api_preserves_symlink_and_directory_metadata() {
        let mock = crate::test_support::MockObs::new("[]");
        let mut inner = mock_inner(&mock);
        let unix = UnixMeta {
            mode: libc::S_IFLNK | 0o777,
            uid: 12,
            gid: 34,
            mtime: 1234,
        };
        let mut headers = crate::obs::unix_meta_headers(unix);
        headers.push((
            xattr_header_key(crate::obs::meta_keys::SYMLINK_TARGET),
            "target".into(),
        ));
        inner
            .client
            .put_object_with_meta("link", b"", &headers)
            .unwrap();
        inner
            .update_unix_meta("link", None, Some(56), None, None, &[])
            .unwrap();
        let meta = inner.client.head_object("link").unwrap().unwrap();
        assert_eq!(
            crate::obs::symlink_target(&meta.x_obs_meta).as_deref(),
            Some("target")
        );
        assert_eq!(meta.unix.unwrap().uid, 56);
        inner
            .client
            .put_object_with_meta(
                "dir/",
                b"",
                &crate::obs::unix_meta_headers(UnixMeta {
                    mode: libc::S_IFDIR | 0o750,
                    ..unix
                }),
            )
            .unwrap();
        inner
            .update_unix_meta("dir", Some(0o700), None, None, None, &[])
            .unwrap();
        assert_eq!(
            inner
                .client
                .head_object("dir/")
                .unwrap()
                .unwrap()
                .unix
                .unwrap()
                .mode,
            libc::S_IFDIR | 0o700
        );
    }
    mod mounted {
        use super::*;
        use crate::test_support::{MockObs, MountProcess};
        use std::ffi::{CStr, CString};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, chown, symlink};
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        fn concurrent_writeback(mock: &MockObs, root: &Path) {
            use std::sync::mpsc;
            use std::thread;
            mock.client()
                .put_object_with_meta("parallel-read", b"readable", &[])
                .unwrap();
            let mut reader = File::open(root.join("parallel-read")).unwrap();
            let mut other = File::create(root.join("parallel-other")).unwrap();
            let mut writer = File::create(root.join("parallel-upload")).unwrap();
            writer.write_all(b"first").unwrap();
            let syncing = writer.try_clone().unwrap();
            thread::scope(|scope| {
                let upload = scope.spawn(move || syncing.sync_all().unwrap());
                let deadline = Instant::now() + Duration::from_secs(5);
                while mock
                    .stats()
                    .requests
                    .get("PUT parallel-upload")
                    .copied()
                    .unwrap_or(0)
                    == 0
                {
                    assert!(Instant::now() < deadline, "upload did not reach OBS");
                    thread::sleep(Duration::from_millis(10));
                }
                let (same_tx, same_rx) = mpsc::channel();
                let same = scope.spawn(move || {
                    writer.write_all(b"-later").unwrap();
                    same_tx.send(()).unwrap();
                    writer.sync_all().unwrap();
                });
                let (other_tx, other_rx) = mpsc::channel();
                let independent = scope.spawn(move || {
                    let mut bytes = Vec::new();
                    reader.read_to_end(&mut bytes).unwrap();
                    assert_eq!(bytes, b"readable");
                    other.write_all(b"independent").unwrap();
                    other.sync_all().unwrap();
                    other_tx.send(()).unwrap();
                });
                let unrelated = other_rx.recv_timeout(Duration::from_secs(1));
                let same_blocked = same_rx.try_recv().is_err();
                upload.join().unwrap();
                same.join().unwrap();
                independent.join().unwrap();
                assert!(unrelated.is_ok(), "unrelated read/write blocked by upload");
                assert!(
                    same_blocked,
                    "same-inode write changed in-flight upload bytes"
                );
            });
            assert_eq!(
                fs::read(root.join("parallel-upload")).unwrap(),
                b"first-later"
            );
            assert_eq!(
                fs::read(root.join("parallel-other")).unwrap(),
                b"independent"
            );
        }

        fn lifecycle_regressions(mock: &MockObs, root: &Path) {
            // Publish a still-open temporary file under its final name.
            let old = root.join("open.tmp");
            let new = root.join("open.final");
            let mut file = File::create(&old).unwrap();
            file.write_all(b"first").unwrap();
            fs::rename(&old, &new).unwrap();
            file.write_all(b"second").unwrap();
            file.sync_all().unwrap();
            drop(file);
            assert_eq!(fs::read(&new).unwrap(), b"firstsecond");
            assert!(mock.client().head_object("open.tmp").unwrap().is_none());

            // Unlinked descriptors remain usable and cannot overwrite a new file.
            let path = root.join("unlinked");
            let mut old = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            old.write_all(b"old data").unwrap();
            fs::remove_file(&path).unwrap();
            assert_eq!(old.metadata().unwrap().nlink(), 0);
            write_file(&path, b"new data");
            old.set_len(3).unwrap();
            old.seek(SeekFrom::Start(0)).unwrap();
            old.write_all(b"OLD").unwrap();
            old.sync_all().unwrap();
            old.seek(SeekFrom::Start(0)).unwrap();
            let mut data = Vec::new();
            old.read_to_end(&mut data).unwrap();
            assert_eq!(data, b"OLD");
            drop(old);
            assert_eq!(fs::read(&path).unwrap(), b"new data");

            // Overwriting an open destination detaches its old writer too.
            let dst = root.join("replace-target");
            write_file(&dst, b"old target");
            let mut target = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&dst)
                .unwrap();
            write_file(&root.join("replace-source"), b"source");
            fs::rename(root.join("replace-source"), &dst).unwrap();
            let mut replacement = OpenOptions::new().append(true).open(&dst).unwrap();
            replacement.write_all(b" appended").unwrap();
            target.seek(SeekFrom::Start(0)).unwrap();
            target.write_all(b"changed").unwrap();
            target.sync_all().unwrap();
            drop(target);
            replacement.sync_all().unwrap();
            drop(replacement);
            assert_eq!(fs::read(&dst).unwrap(), b"source appended");

            // A remote deletion must disappear from newly opened directories.
            write_file(&root.join("external-deletion"), b"gone");
            let _ = fs::read_dir(root).unwrap().collect::<Vec<_>>();
            mock.client().delete_object("external-deletion").unwrap();
            assert!(
                !fs::read_dir(root)
                    .unwrap()
                    .any(|e| e.unwrap().file_name() == "external-deletion")
            );

            // The same remote read handle must never mix object generations.
            let client = mock.client();
            client
                .put_object_with_meta("snapshot", &vec![b'A'; 16 * 1024 * 1024], &[])
                .unwrap();
            let mut reader = File::open(root.join("snapshot")).unwrap();
            let mut buf = [0; 4096];
            reader.read_exact(&mut buf).unwrap();
            assert!(buf.iter().all(|b| *b == b'A'));
            client
                .put_object_with_meta("snapshot", &vec![b'B'; 16 * 1024 * 1024], &[])
                .unwrap();
            let mut fresh = File::open(root.join("snapshot")).unwrap();
            fresh.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
            fresh.read_exact(&mut buf).unwrap();
            assert!(buf.iter().all(|b| *b == b'B'));
            drop(fresh);
            reader.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
            if reader.read_exact(&mut buf).is_ok() {
                assert!(buf.iter().all(|b| *b == b'A'));
            }
            drop(reader);
        }
        fn c_path(path: &Path) -> CString {
            CString::new(path.as_os_str().as_bytes()).unwrap()
        }

        fn volume(path: &Path) -> libc::statvfs {
            let mut info = std::mem::MaybeUninit::uninit();
            assert_eq!(
                unsafe { libc::statvfs(c_path(path).as_ptr(), info.as_mut_ptr()) },
                0
            );
            unsafe { info.assume_init() }
        }

        fn set_xattr(path: &Path, name: &CStr, value: &[u8]) {
            let result = unsafe {
                libc::setxattr(
                    c_path(path).as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            };
            assert_eq!(result, 0, "setxattr: {}", std::io::Error::last_os_error());
        }

        fn get_xattr(path: &Path, name: &CStr) -> std::io::Result<Vec<u8>> {
            let mut value = vec![0; 4096];
            let length = unsafe {
                libc::getxattr(
                    c_path(path).as_ptr(),
                    name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            if length < 0 {
                return Err(std::io::Error::last_os_error());
            }
            value.truncate(length as usize);
            Ok(value)
        }

        fn list_xattrs(path: &Path) -> Vec<String> {
            let mut value = vec![0u8; 4096];
            let length = unsafe {
                libc::listxattr(
                    c_path(path).as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            assert!(
                length >= 0,
                "listxattr: {}",
                std::io::Error::last_os_error()
            );
            value[..length as usize]
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8(s.to_vec()).unwrap())
                .collect()
        }

        fn write_file(path: &Path, data: &[u8]) {
            let mut file = File::create(path).unwrap();
            file.write_all(data).unwrap();
            file.sync_all().unwrap();
        }

        fn read_as_other_user(path: &Path) -> Vec<u8> {
            let output = Command::new("cat")
                .arg(path)
                .uid(65534)
                .gid(65534)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        }

        fn write_as_other_user(path: &Path, data: &[u8]) {
            let mut child = Command::new("tee")
                .arg(path)
                .uid(65534)
                .gid(65534)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(data).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        #[test]
        #[ignore = "requires /dev/fuse, fusermount3 and a built obs-mount binary"]
        fn round_trip() {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/fuse")
                .expect("this test requires an accessible /dev/fuse");
            let mock = MockObs::new(
                r#"[{"method":"PUT","key":"parallel-upload","status":503,"delay_ms":3000}]"#,
            );
            // All test data stays inside this fresh directory. Use a numeric
            // unprivileged UID for cross-user checks; never create OS accounts.
            fs::set_permissions(&mock.staging, fs::Permissions::from_mode(0o755)).unwrap();
            let mut mount = MountProcess::spawn(&mock, "mnt", None);
            assert!(mount.wait_mounted(), "mount failed: {}", mount.log());
            let root = &mount.mountpoint;
            lifecycle_regressions(&mock, root);
            concurrent_writeback(&mock, root);

            write_file(&root.join("small.txt"), b"hello\n");
            assert_eq!(fs::read(root.join("small.txt")).unwrap(), b"hello\n");
            assert_eq!(fs::metadata(root.join("small.txt")).unwrap().len(), 6);
            for i in 1..=5 {
                write_file(&root.join("over.txt"), format!("v{i}").as_bytes());
            }
            assert_eq!(fs::read(root.join("over.txt")).unwrap(), b"v5");
            write_file(&root.join("append.txt"), b"a\n");
            {
                let mut file = OpenOptions::new()
                    .append(true)
                    .open(root.join("append.txt"))
                    .unwrap();
                file.write_all(b"b\n").unwrap();
                file.sync_all().unwrap();
            }
            assert_eq!(fs::read(root.join("append.txt")).unwrap(), b"a\nb\n");

            fs::create_dir_all(root.join("dir/sub/deep")).unwrap();
            write_file(&root.join("dir/sub/deep/file"), b"nested");
            assert_eq!(fs::read_dir(root.join("dir/sub/deep")).unwrap().count(), 1);
            fs::rename(root.join("small.txt"), root.join("renamed.txt")).unwrap();
            assert_eq!(fs::read(root.join("renamed.txt")).unwrap(), b"hello\n");
            fs::rename(root.join("dir"), root.join("moved")).unwrap();
            assert_eq!(
                fs::read(root.join("moved/sub/deep/file")).unwrap(),
                b"nested"
            );

            write_file(&root.join("truncate.txt"), b"0123456789");
            OpenOptions::new()
                .write(true)
                .open(root.join("truncate.txt"))
                .unwrap()
                .set_len(4)
                .unwrap();
            assert_eq!(fs::read(root.join("truncate.txt")).unwrap(), b"0123");
            write_file(&root.join("range.txt"), b"ABCDEFGHIJ");
            {
                let mut file = File::open(root.join("range.txt")).unwrap();
                file.seek(SeekFrom::Start(3)).unwrap();
                let mut range = [0; 4];
                file.read_exact(&mut range).unwrap();
                assert_eq!(&range, b"DEFG");
            }

            // Compare uploads with independent source files, including the
            // exact multipart threshold. A fresh mount below also rereads OBS.
            for (name, size) in [
                ("big.bin", 30 * 1024 * 1024),
                ("exact.bin", 25 * 1024 * 1024),
            ] {
                let data: Vec<_> = (0..size)
                    .map(|i| ((i * 31 + i / 257) % 251) as u8)
                    .collect();
                let source = mock.staging.join(name);
                fs::write(&source, data).unwrap();
                fs::copy(&source, root.join(name)).unwrap();
                assert_eq!(
                    crate::obs::md5_base64(&fs::read(root.join(name)).unwrap()),
                    crate::obs::md5_base64(&fs::read(source).unwrap())
                );
            }
            fs::remove_file(root.join("renamed.txt")).unwrap();
            assert!(!root.join("renamed.txt").exists());
            fs::create_dir(root.join("empty")).unwrap();
            fs::remove_dir(root.join("empty")).unwrap();
            assert!(!root.join("empty").exists());
            assert_eq!(
                fs::remove_dir(root.join("moved"))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ENOTEMPTY)
            );
            for name in ["a b.txt", "中文.txt"] {
                write_file(&root.join(name), b"special");
                assert_eq!(fs::read(root.join(name)).unwrap(), b"special");
            }

            let usage = volume(root);
            assert_eq!(usage.f_frsize, 4096);
            assert_eq!(usage.f_blocks * usage.f_frsize, SYNTHETIC_TOTAL);
            assert!(usage.f_bavail > 0);

            let meta = root.join("meta.txt");
            write_file(&meta, b"metadata");
            fs::set_permissions(&meta, fs::Permissions::from_mode(0o640)).unwrap();
            assert_eq!(fs::metadata(&meta).unwrap().mode() & 0o777, 0o640);
            if crate::current_uid() == 0 {
                chown(&meta, Some(1234), Some(5678)).unwrap();
                assert_eq!(
                    (
                        fs::metadata(&meta).unwrap().uid(),
                        fs::metadata(&meta).unwrap().gid()
                    ),
                    (1234, 5678)
                );
            }
            let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_577_934_245);
            File::open(&meta)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(modified))
                .unwrap();
            assert_eq!(fs::metadata(&meta).unwrap().modified().unwrap(), modified);
            write_file(&root.join("real.txt"), b"target");
            symlink("real.txt", root.join("link.txt")).unwrap();
            assert_eq!(
                fs::read_link(root.join("link.txt")).unwrap(),
                PathBuf::from("real.txt")
            );
            assert_eq!(fs::read(root.join("link.txt")).unwrap(), b"target");

            // Direct syscalls keep xattr coverage independent of external tools.
            set_xattr(&meta, c"user.colour", b"blue");
            assert_eq!(get_xattr(&meta, c"user.colour").unwrap(), b"blue");
            assert!(list_xattrs(&meta).contains(&"user.colour".to_string()));
            std::thread::sleep(Duration::from_secs(6));
            assert_eq!(get_xattr(&meta, c"user.colour").unwrap(), b"blue");
            let before = fs::metadata(&meta).unwrap();
            {
                let mut file = OpenOptions::new().append(true).open(&meta).unwrap();
                file.write_all(b"more").unwrap();
                file.sync_all().unwrap();
                file.set_len(3).unwrap();
            }
            std::thread::sleep(Duration::from_secs(6));
            let after = fs::metadata(&meta).unwrap();
            assert_eq!(after.mode() & 0o777, 0o640);
            assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
            assert_eq!(get_xattr(&meta, c"user.colour").unwrap(), b"blue");
            set_xattr(&meta, c"user.owner", b"alice");
            let names = list_xattrs(&meta);
            assert!(
                names.contains(&"user.colour".to_string())
                    && names.contains(&"user.owner".to_string())
            );
            assert!(names.iter().all(|name| !name.starts_with("xdg.")));
            assert_eq!(
                unsafe { libc::removexattr(c_path(&meta).as_ptr(), c"user.colour".as_ptr()) },
                0
            );
            assert!(!list_xattrs(&meta).contains(&"user.colour".to_string()));
            assert_eq!(
                get_xattr(&meta, c"user.nope").unwrap_err().raw_os_error(),
                Some(libc::ENODATA)
            );

            let mut fresh = MountProcess::spawn(&mock, "fresh", None);
            assert!(fresh.wait_mounted(), "fresh mount failed: {}", fresh.log());
            let usage = volume(&fresh.mountpoint);
            assert!(
                usage.f_blocks > usage.f_bfree,
                "fresh mount must report used space"
            );
            assert_eq!(
                crate::obs::md5_base64(&fs::read(fresh.mountpoint.join("big.bin")).unwrap()),
                crate::obs::md5_base64(&fs::read(mock.staging.join("big.bin")).unwrap())
            );
            write_file(&fresh.mountpoint.join("fresh.txt"), b"path-style");
            assert_eq!(
                fs::read(fresh.mountpoint.join("fresh.txt")).unwrap(),
                b"path-style"
            );
            fresh.terminate();

            if crate::current_uid() == 0 {
                assert_eq!(read_as_other_user(&root.join("real.txt")), b"target");
                write_as_other_user(&root.join("shared.txt"), b"from-other");
                assert_eq!(fs::read(root.join("shared.txt")).unwrap(), b"from-other");
                let mut unprivileged =
                    MountProcess::spawn(&mock, "unprivileged", Some((65534, 65534)));
                if unprivileged.wait_mounted() {
                    write_as_other_user(&unprivileged.mountpoint.join("user.txt"), b"non-root");
                    assert_eq!(
                        read_as_other_user(&unprivileged.mountpoint.join("user.txt")),
                        b"non-root"
                    );
                    unprivileged.terminate();
                } else {
                    let allowed = fs::read_to_string("/etc/fuse.conf")
                        .unwrap_or_default()
                        .lines()
                        .any(|line| {
                            line.split('#').next().unwrap_or("").trim() == "user_allow_other"
                        });
                    assert!(
                        !allowed,
                        "unprivileged mount failed despite user_allow_other: {}",
                        unprivileged.log()
                    );
                    assert!(
                        unprivileged.log().contains("user_allow_other"),
                        "missing configuration hint: {}",
                        unprivileged.log()
                    );
                }
            } else {
                eprintln!("SKIP: cross-user checks require root");
            }
            // Stop with a live unsynced writer: detach promptly, retain bytes.
            let mut pending = File::create(root.join("shutdown-pending")).unwrap();
            pending.write_all(b"recover after shutdown").unwrap();
            mount.terminate();
            drop(pending);
            let mut recovered = false;
            for session in fs::read_dir(mock.staging.join("mnt-tmp"))
                .unwrap()
                .flatten()
            {
                if !session.path().is_dir() {
                    continue;
                }
                for entry in fs::read_dir(session.path()).unwrap().flatten() {
                    if entry.file_name().to_string_lossy().starts_with("ino-")
                        && entry.path().extension().is_none()
                        && fs::read(entry.path()).unwrap() == b"recover after shutdown"
                    {
                        recovered = true;
                    }
                }
            }
            assert!(recovered, "SIGTERM discarded unsynced staging");
            assert_eq!(mock.stats().signature_failures, 0);
        }
    }
}
