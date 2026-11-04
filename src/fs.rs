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
//! state lives behind one Mutex. The lock is held for the duration of each
//! request (including the OBS round-trip), which serialises requests: a
//! deliberate v1 trade-off for a backup mount, not a high-concurrency disk.

use crate::obs::{ObsClient, ObsError, UnixMeta};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use fuser::{
    BsdFileFlags, Errno, FileAttr, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, OpenAccMode, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, TimeOrNow, WriteFlags,
};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
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
    /// Attributes read from object metadata. `None` means the object carries
    /// none (uploaded by some other tool, or by an older build), in which
    /// case defaults are rendered.
    unix: Option<UnixMeta>,
    /// `<symlink target>` when this object is a symlink created by us.
    symlink_target: Option<String>,
    /// All non-Unix object metadata, including xattrs and symlink targets.
    extra_meta: Vec<(String, String)>,
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

struct OpenFile {
    key: String,
    staging: Option<PathBuf>,
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

struct Inner {
    client: ObsClient,
    staging_dir: PathBuf,
    upload: crate::obs::UploadTuning,
    next_ino: u64,
    ino_to_path: HashMap<u64, String>,
    path_to_ino: HashMap<String, u64>,
    meta_cache: HashMap<String, CachedMeta>,
    open_files: HashMap<u64, OpenFile>,
    next_fh: u64,
    /// File-level dirty state survives a failed close and sibling releases.
    pending: HashSet<PathBuf>,
    /// Cached answer for statfs; `df` is cheap to call and usually polled by
    /// monitoring, so the bucket is queried at most once per TTL instead of
    /// once per request.
    usage_cache: Option<(Instant, UsageSnapshot)>,
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
        .chunks_exact(2)
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
    let symlink_target = meta
        .x_obs_meta
        .iter()
        .find(|(k, _)| k == crate::obs::meta_keys::SYMLINK_TARGET)
        .map(|(_, v)| v.clone());
    CachedMeta {
        size: meta.size,
        is_dir,
        mtime: unix_mtime_or_now(meta.unix),
        expires: Instant::now() + Duration::from_secs(5),
        unix: meta.unix,
        symlink_target,
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
        symlink_target: None,
        extra_meta: Vec::new(),
    }
}

/// mtime from persisted metadata, falling back to "now" the way the previous
/// implementation did (OBS Last-Modified is not parsed into SystemTime here).
fn unix_mtime_or_now(unix: Option<UnixMeta>) -> SystemTime {
    match unix {
        Some(u) if u.mtime > 0 => SystemTime::UNIX_EPOCH + Duration::from_secs(u.mtime as u64),
        _ => SystemTime::now(),
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
            inner: Mutex::new(Inner {
                client,
                staging_dir,
                upload,
                next_ino: 2,
                ino_to_path: HashMap::new(),
                path_to_ino: HashMap::new(),
                meta_cache: HashMap::new(),
                open_files: HashMap::new(),
                next_fh: 1,
                pending: HashSet::new(),
                usage_cache: None,
            }),
        }
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
    fn alloc_ino(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.ino_to_path.insert(ino, path.to_string());
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
                self.ino_to_path.remove(&ino);
            }
            self.meta_cache.remove(&p);
        }
    }

    /// How many open handles still reference this staging file. Staging files
    /// are shared by every handle of one inode (the path is `ino-<n>`), so a
    /// handle must not unlink one that another handle is still writing to.
    fn staging_refs(&self, staging: &Path) -> usize {
        self.open_files
            .values()
            .filter(|f| f.staging.as_deref() == Some(staging))
            .count()
    }

    /// Drop a staging file only when no handle references it any more.
    fn release_staging(&mut self, staging: &Path) {
        if self.staging_refs(staging) == 0 && !self.pending.contains(staging) {
            let _ = fs::remove_file(staging);
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
            self.ino_to_path.insert(ino, new_path.clone());
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
            // Open handles carry the key they upload to: retarget them so a
            // file renamed while open still lands on the new key.
            for f in self.open_files.values_mut() {
                if f.key == old_path {
                    f.key = new_path.clone();
                }
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
    /// When an object carries no `x-obs-meta-mode` (uploaded by another tool,
    /// or by a build before this feature), fall back to a fixed default
    /// rather than inventing values: 0755/0644 owned by the requesting
    /// user, which is what this program used to report unconditionally.
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
        let mtime = match unix {
            Some(u) if u.mtime > 0 => SystemTime::UNIX_EPOCH + Duration::from_secs(u.mtime as u64),
            _ => mtime,
        };
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
        if truncate {
            File::create(&staging)?;
        } else {
            self.client.download_to(path, &staging, &meta)?;
        }
        self.meta_cache
            .insert(path.into(), cached_from_meta(&meta, false));
        // Readers opened before the writer must follow the shared copy too.
        for open in self.open_files.values_mut().filter(|f| f.key == path) {
            open.staging = Some(staging.clone());
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
            headers.extend(crate::obs::unix_meta_headers(unix));
        }
        if let Some(target) = &cached.symlink_target {
            let key = xattr_header_key(crate::obs::meta_keys::SYMLINK_TARGET);
            headers.retain(|(k, _)| k != &key);
            headers.push((key, target.clone()));
        }
        Ok(headers)
    }

    /// A durable sidecar makes retained data identifiable after a restart.
    /// It contains no credentials and is inside the private session directory.
    fn save_recovery(&self, path: &str, staging: &Path) -> Result<(), ObsError> {
        #[derive(serde::Serialize)]
        struct Recovery<'a> {
            bucket: &'a str,
            key: &'a str,
            metadata: Vec<(String, String)>,
        }
        let record = Recovery {
            bucket: self.client.bucket(),
            key: path,
            metadata: self.metadata_headers(path)?,
        };
        let yaml = serde_yaml::to_string(&record).map_err(|e| ObsError::Other(e.to_string()))?;
        let temp = staging.with_extension("yaml.tmp");
        let mut file = File::create(&temp)?;
        file.write_all(yaml.as_bytes())?;
        file.sync_all()?;
        fs::rename(temp, staging.with_extension("yaml"))?;
        File::open(&self.staging_dir)?.sync_all()?;
        Ok(())
    }

    fn mark_pending(&mut self, path: &str, staging: &Path) -> Result<(), ObsError> {
        if self.pending.contains(staging) {
            return Ok(());
        }
        self.save_recovery(path, staging)?;
        self.pending.insert(staging.to_owned());
        Ok(())
    }

    fn content_changed(&mut self, path: &str, size: u64) {
        if let Some(meta) = self.meta_cache.get_mut(path) {
            meta.size = size;
            meta.mtime = SystemTime::now();
            if let Some(unix) = meta.unix.as_mut() {
                unix.mtime = meta
                    .mtime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
            }
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
            return Ok(Some((ino, false, size, SystemTime::now())));
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
            self.meta_cache
                .insert(path.to_string(), cached_from_meta(&meta, true));
            let ino = self.alloc_ino(path);
            return Ok(Some((ino, true, 4096, SystemTime::now())));
        }
        // Any key below this prefix?
        match self.client.list_objects(&dir_prefix(path), "/", None, 1) {
            Ok(page) if !page.objects.is_empty() || !page.prefixes.is_empty() => {
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
    fn usage_snapshot(&mut self) -> UsageSnapshot {
        if let Some((at, cached)) = self.usage_cache
            && at.elapsed() < USAGE_TTL
        {
            return cached;
        }
        let used = self
            .client
            .bucket_storage_info()
            .ok()
            .and_then(|u| u.size)
            .or_else(|| self.usage_cache.map(|(_, c)| c.used))
            .unwrap_or(0);
        let quota = self
            .client
            .bucket_quota()
            .ok()
            .and_then(|q| q.quota)
            .filter(|q| *q > 0);
        let snapshot = decide_usage(used, quota);
        if snapshot.total_is_synthetic {
            tracing::debug!(
                used,
                synthetic_total = SYNTHETIC_TOTAL,
                "no bucket quota configured; statfs reports a synthetic capacity"
            );
        }
        self.usage_cache = Some((Instant::now(), snapshot));
        snapshot
    }

    /// Merge attribute changes into the object's persisted metadata and write
    /// it back with a self-copy (`x-obs-metadata-directive: REPLACE`), the
    /// only way OBS lets metadata change without re-uploading the body.
    /// obsfs does the same for chmod/chown/setxattr.
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
        let base = current.unix.unwrap_or(UnixMeta {
            mode: if current.is_dir {
                libc::S_IFDIR | 0o755
            } else {
                libc::S_IFREG | 0o644
            },
            uid: 0,
            gid: 0,
            mtime: 0,
        });
        current.unix = Some(UnixMeta {
            mode: mode
                .map(|m| (base.mode & libc::S_IFMT) | (m & 0o7777))
                .unwrap_or(base.mode),
            uid: uid.unwrap_or(base.uid),
            gid: gid.unwrap_or(base.gid),
            mtime: mtime
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(base.mtime),
        });
        current.mtime = unix_mtime_or_now(current.unix);
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
                self.pending.insert(staging);
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

    fn upload_staged_path(&mut self, key: &str, staging: &Path) -> Result<(), ObsError> {
        self.save_recovery(key, staging)?;
        File::open(staging)?.sync_all()?;
        let meta = self.metadata_headers(key)?;
        tracing::info!(key, path = %staging.display(), "uploading staged file to OBS");
        self.client
            .upload_file_with_meta(key, staging, self.upload, &meta)?;
        self.pending.remove(staging);
        Ok(())
    }

    fn upload_error_reply(&self, e: &ObsError) -> Errno {
        errno_for_obs(e)
    }

    /// Shared flush/fsync body; dirty state belongs to the shared staging
    /// file, so any handle can flush it. Failed uploads remain pending.
    fn flush_handle(&mut self, fh: u64) -> Option<Errno> {
        let Some(open) = self.open_files.get(&fh) else {
            return Some(Errno::EBADF);
        };
        let staging = open.staging.clone()?;
        if !self.pending.contains(&staging) {
            return None;
        }
        let key = open.key.clone();
        match self.upload_staged_path(&key, &staging) {
            Ok(()) => None,
            Err(e) => {
                tracing::error!(error = %e, path = %staging.display(), "upload failed; data and recovery metadata retained");
                Some(self.upload_error_reply(&e))
            }
        }
    }
}

impl Filesystem for ObsFs {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.ino_to_path.get(&parent.0).cloned()
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
        let Some(path) = inner.ino_to_path.get(&ino.0).cloned() else {
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
        _fh: fuser::FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = (if ino == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.ino_to_path.get(&ino.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let prefix = dir_prefix(&path);
        let page = match inner.client.list_dir(&prefix) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(path, error = %e, "list_dir failed");
                let err = inner.upload_error_reply(&e);
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
        for o in &page.objects {
            if let Some(rest) = o.key.strip_prefix(&prefix) {
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
            if parent_path(known) == path {
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
        let parent_ino = if path.is_empty() {
            ROOT_INO
        } else {
            inner
                .path_to_ino
                .get(&parent_path(&path))
                .copied()
                .unwrap_or(ROOT_INO)
        };
        let mut all: Vec<(u64, FileType, String)> = vec![
            (ino.0, FileType::Directory, ".".to_string()),
            (parent_ino, FileType::Directory, "..".to_string()),
        ];
        for (name, kind) in entries {
            let child = join_path(&path, &name);
            let child_ino = inner.alloc_ino(&child);
            all.push((child_ino, kind, name));
        }
        for (i, (child_ino, kind, name)) in all.into_iter().enumerate() {
            if (i as u64) < offset {
                continue;
            }
            // offset for the next entry is i+1, per the FUSE convention.
            if reply.add(INodeNo(child_ino), (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = inner.ino_to_path.get(&ino.0).cloned() else {
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
            // Resolve the size once here so `read` never needs its own HEAD.
            let size = match inner.meta_cache.get(&path) {
                Some(c) if c.expires > Instant::now() => Some(c.size),
                _ => match inner.client.head_object(&path) {
                    Ok(Some(m)) => Some(m.size),
                    Ok(None) => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                    Err(e) => {
                        let err = inner.upload_error_reply(&e);
                        reply.error(err);
                        return;
                    }
                },
            };
            let fh = inner.next_fh;
            inner.next_fh += 1;
            inner.open_files.insert(
                fh,
                OpenFile {
                    key: path,
                    staging: None,
                    size,
                    window: None,
                },
            );
            reply.opened(fuser::FileHandle(fh), FopenFlags::empty());
            return;
        }
        if !write_mode {
            let fh = inner.next_fh;
            inner.next_fh += 1;
            inner.open_files.insert(
                fh,
                OpenFile {
                    key: path,
                    staging: Some(staging.clone()),
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
                key: path,
                staging: Some(staging),
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
        let (key, file_size, staging) = {
            let inner = self.inner.lock().unwrap();
            match inner.open_files.get(&fh.0) {
                Some(open) => match open.size {
                    Some(file_size) => (open.key.clone(), file_size, open.staging.clone()),
                    // Size unknown (write handle): fall back to the locked path.
                    None => (String::new(), 0, open.staging.clone()),
                },
                None => {
                    reply.error(Errno::EBADF);
                    return;
                }
            }
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
        let client = self.client.clone();
        let data = match client.get_range(&key, offset, fetch_len) {
            Ok(d) => d,
            Err(e) => {
                reply.error(errno_for_obs(&e));
                return;
            }
        };
        if data.len() != fetch_len {
            tracing::error!(
                key,
                offset,
                expected = fetch_len,
                received = data.len(),
                "incomplete range read"
            );
            reply.error(Errno::EIO);
            return;
        }
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(open) = inner.open_files.get_mut(&fh.0) {
                open.window = Some(ReadWindow {
                    start: offset,
                    data: data.clone(),
                });
            }
        }
        reply.data(&data[..want]);
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let Some(open) = inner.open_files.get(&fh.0) else {
            reply.error(Errno::EBADF);
            return;
        };
        let Some(staging) = open.staging.clone() else {
            reply.error(Errno::EBADF);
            return;
        };
        let key = open.key.clone();
        if let Err(e) = inner.mark_pending(&key, &staging) {
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
                inner.content_changed(&key, size);
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
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.ino_to_path.get(&parent.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name = name.to_string_lossy().into_owned();
        let path = join_path(&parent_path, &name);
        let ino = inner.alloc_ino(&path);
        let staging = inner.staging_path(ino);
        if let Err(e) = fs::write(&staging, []) {
            reply.error(io_errno(&e));
            return;
        }
        let mut cached = synthetic_meta(0, false, SystemTime::now());
        cached.unix = Some(UnixMeta {
            mode: libc::S_IFREG | (mode & !umask & 0o7777),
            uid: req.uid(),
            gid: req.gid(),
            mtime: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
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
                key: path.clone(),
                staging: Some(staging),
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
        let mut inner = self.inner.lock().unwrap();
        match inner.flush_handle(fh.0) {
            Some(err) => reply.error(err),
            None => reply.ok(),
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
        let mut inner = self.inner.lock().unwrap();
        match inner.flush_handle(fh.0) {
            Some(err) => reply.error(err),
            None => reply.ok(),
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
        let mut inner = self.inner.lock().unwrap();
        let error = inner.flush_handle(fh.0);
        if let Some(open) = inner.open_files.remove(&fh.0)
            && let Some(staging) = open.staging
        {
            inner.release_staging(&staging);
        }
        match error {
            Some(e) => reply.error(e),
            None => reply.ok(),
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
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.ino_to_path.get(&parent.0).cloned()
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
            let err = inner.upload_error_reply(&e);
            reply.error(err);
            return;
        }
        let ino = inner.alloc_ino(&path);
        let mut cached = synthetic_meta(4096, true, SystemTime::now());
        cached.unix = Some(UnixMeta {
            mode: libc::S_IFDIR | (mode & !umask & 0o7777),
            uid: req.uid(),
            gid: req.gid(),
            mtime: now,
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
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.ino_to_path.get(&parent.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = join_path(&parent_path, &name.to_string_lossy());
        let prefix = dir_prefix(&path);
        match inner.client.list_dir(&prefix) {
            Ok(page) => {
                // The directory's own placeholder object does not count.
                let others =
                    page.objects.iter().filter(|o| o.key != prefix).count() + page.prefixes.len();
                if others > 0 {
                    reply.error(Errno::ENOTEMPTY);
                    return;
                }
            }
            Err(e) => {
                let err = inner.upload_error_reply(&e);
                reply.error(err);
                return;
            }
        }
        if let Err(e) = inner.client.delete_object(&prefix) {
            let err = inner.upload_error_reply(&e);
            reply.error(err);
            return;
        }
        inner.forget_subtree(&path);
        reply.ok();
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.ino_to_path.get(&parent.0).cloned()
        }) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let path = join_path(&parent_path, &name.to_string_lossy());
        if let Err(e) = inner.client.delete_object(&path) {
            let err = inner.upload_error_reply(&e);
            reply.error(err);
            return;
        }
        inner.forget_subtree(&path);
        reply.ok();
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let mut inner = self.inner.lock().unwrap();
        let old_parent = if parent == INodeNo::ROOT {
            String::new()
        } else {
            match inner.ino_to_path.get(&parent.0) {
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
            match inner.ino_to_path.get(&newparent.0) {
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
        tracing::warn!(old = %old_path, new = %new_path, "rename is Copy+Delete, not atomic");
        // Directory? Check placeholder or any key below it.
        let is_dir = inner
            .client
            .head_object(&format!("{old_path}/"))
            .map(|o| o.is_some())
            .unwrap_or(false)
            || inner
                .client
                .list_objects(&dir_prefix(&old_path), "/", None, 1)
                .map(|p| !p.objects.is_empty() || !p.prefixes.is_empty())
                .unwrap_or(false);
        if is_dir {
            match inner.client.list_all_keys(&dir_prefix(&old_path)) {
                Ok(keys) => {
                    for key in keys {
                        let suffix = &key[dir_prefix(&old_path).len()..];
                        // dir_prefix(new) + suffix, handling the placeholder:
                        let dst = if suffix.is_empty() {
                            dir_prefix(&new_path)
                        } else {
                            format!("{}/{}", dir_prefix(&new_path).trim_end_matches('/'), suffix)
                        };
                        if let Err(e) = inner.client.copy_object(&key, &dst) {
                            // Copy+Delete is not atomic: keys already moved
                            // stay moved. Say so instead of pretending only
                            // the failed key was affected.
                            tracing::error!(
                                old = %old_path,
                                new = %new_path,
                                failed_key = %key,
                                "directory rename aborted mid-way; already-copied keys were left at the destination"
                            );
                            let err = inner.upload_error_reply(&e);
                            reply.error(err);
                            return;
                        }
                        let _ = inner.client.delete_object(&key);
                    }
                    // Keep the inode mapping, just re-point it at the new
                    // path: dropping it made the kernel's cached dentry point
                    // at an inode we no longer know, so `mv a b && cat b`
                    // failed with ENOENT until the TTL expired.
                    inner.remap_subtree(&old_path, &new_path);
                    reply.ok();
                }
                Err(e) => {
                    let err = inner.upload_error_reply(&e);
                    reply.error(err);
                }
            }
        } else {
            match inner.client.copy_object(&old_path, &new_path) {
                Ok(()) => {
                    let _ = inner.client.delete_object(&old_path);
                    // Same as the directory branch: re-point the inode, do
                    // not forget it (the kernel still holds that inode).
                    inner.remap_subtree(&old_path, &new_path);
                    reply.ok();
                }
                Err(e) => {
                    let err = inner.upload_error_reply(&e);
                    reply.error(err);
                }
            }
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let mut inner = self.inner.lock().unwrap();
        let usage = inner.usage_snapshot();
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
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = inner.ino_to_path.get(&ino.0).cloned() else {
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
        let Some(path) = inner.ino_to_path.get(&ino.0).cloned() else {
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
        let Some(path) = inner.ino_to_path.get(&ino.0).cloned() else {
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
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = inner.ino_to_path.get(&ino.0).cloned() else {
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
        let mut inner = self.inner.lock().unwrap();
        let Some(parent_path) = (if parent == INodeNo::ROOT {
            Some(String::new())
        } else {
            inner.ino_to_path.get(&parent.0).cloned()
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
            let err = inner.upload_error_reply(&e);
            reply.error(err);
            return;
        }
        let ino = inner.alloc_ino(&path);
        let mut cached = synthetic_meta(0, false, SystemTime::now());
        cached.unix = Some(UnixMeta {
            mode: libc::S_IFLNK | 0o777,
            uid: req.uid(),
            gid: req.gid(),
            mtime: now,
        });
        cached.symlink_target = Some(target_str);
        inner.meta_cache.insert(path, cached.clone());
        let attr =
            inner.attr_with_meta(req, ino, FileType::Symlink, 0, cached.mtime, Some(&cached));
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let inner = self.inner.lock().unwrap();
        let Some(path) = inner.ino_to_path.get(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(target) = inner
            .meta_cache
            .get(&path)
            .and_then(|c| c.symlink_target.clone())
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
                let err = inner.upload_error_reply(&e);
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
        // metadata (as obsfs does), so chmod/chown/utimes are honoured by
        // rewriting the metadata via a self-copy. Truncation still needs the
        // data path: download -> truncate -> re-upload.
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = inner.ino_to_path.get(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if mode.is_some() || uid.is_some() || gid.is_some() || mtime.is_some() {
            let when = mtime.map(|t| match t {
                TimeOrNow::Now => SystemTime::now(),
                TimeOrNow::SpecificTime(t) => t,
            });
            if let Err(e) = inner.update_unix_meta(&path, mode, uid, gid, when, &[]) {
                let err = inner.upload_error_reply(&e);
                reply.error(err);
                return;
            }
        }
        if let Some(size) = size {
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
            if let Err(e) = inner.upload_staged_path(&path, &staging) {
                reply.error(errno_for_obs(&e));
                return;
            }
            inner.release_staging(&staging);
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
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
            meta_cache: HashMap::new(),
            open_files: HashMap::new(),
            next_fh: 1,
            pending: HashSet::new(),
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

        assert_eq!(inner.ino_to_path.get(&ino), Some(&"new.txt".to_string()));
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

        assert_eq!(inner.ino_to_path.get(&dir_ino), Some(&"e".to_string()));
        assert_eq!(inner.ino_to_path.get(&file_ino), Some(&"e/f".to_string()));
        assert_eq!(
            inner.ino_to_path.get(&nested_ino),
            Some(&"e/s/g".to_string())
        );
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
                key: "a.txt".into(),
                staging: Some(inner.staging_path(ino)),
                size: None,
                window: None,
            },
        );

        inner.remap_subtree("a.txt", "b.txt");

        assert_eq!(
            inner.open_files.get(&7).map(|f| f.key.as_str()),
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
        let staging = dir.join("ino-99");
        std::fs::write(&staging, b"data").unwrap();

        let mut inner = inner_for_test();
        inner.staging_dir = dir.clone();
        for fh in 1..=2 {
            inner.open_files.insert(
                fh,
                OpenFile {
                    key: "k".into(),
                    staging: Some(staging.clone()),
                    size: None,
                    window: None,
                },
            );
        }

        // First handle leaving must keep the file for the second one.
        inner.open_files.remove(&1);
        inner.release_staging(&staging);
        assert!(staging.exists(), "staging removed while still referenced");

        inner.open_files.remove(&2);
        inner.release_staging(&staging);
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
                    key: "backup".into(),
                    staging: Some(staging.clone()),
                    window: None,
                    size: None,
                },
            );
        }
        assert_eq!(inner.flush_handle(1), Some(Errno::EACCES));
        inner.open_files.remove(&1);
        inner.release_staging(&staging);
        inner.open_files.remove(&2);
        inner.release_staging(&staging);
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
        inner.upload_staged_path("backup", &staging).unwrap();
        inner.release_staging(&staging);
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
        inner.upload_staged_path("backup", &staged).unwrap();
        inner.release_staging(&staged);
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
        inner.upload_staged_path("backup", &staged).unwrap();
        let meta = inner.client.head_object("backup").unwrap().unwrap();
        assert_eq!(meta.unix.unwrap().mode, unix.mode);
        assert!(
            meta.x_obs_meta
                .contains(&(xattr_key("user.colour"), B64.encode(b"blue")))
        );
        assert_eq!(inner.client.get_range("backup", 0, 4).unwrap(), b"repl");
        assert!(mock.stats().contains("\"signature_failures\": 0"));
    }

    #[test]
    fn metadata_self_copy_preserves_symlink_and_directory_metadata() {
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
}
