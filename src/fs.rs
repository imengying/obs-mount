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
//!   Copy+Delete and is NOT atomic for directories. Permissions/owners are
//!   not stored on OBS; `setattr` only honours truncation and ignores
//!   mode/owner changes rather than failing the copy.
//!
//! fuser 0.18 calls the Filesystem trait through `&self`, so all mutable
//! state lives behind one Mutex. The lock is held for the duration of each
//! request (including the OBS round-trip), which serialises requests: a
//! deliberate v1 trade-off for a backup mount, not a high-concurrency disk.

use crate::obs::{ObjectMeta, ObsClient, ObsError};
use fuser::{
    BsdFileFlags, Errno, FileAttr, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, OpenAccMode, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
    WriteFlags,
};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

const TTL: Duration = Duration::from_secs(1);
/// How long a statfs answer is reused before asking OBS again. `df` is often
/// polled by monitoring every few seconds and each miss costs two requests.
const USAGE_TTL: Duration = Duration::from_secs(60);
/// Capacity reported when the bucket has no quota configured. It is not a
/// real limit -- it only keeps tools that precheck free space from treating
/// the mount as full. 1 PiB is far beyond any single OBS bucket quota.
const SYNTHETIC_TOTAL: u64 = 1 << 50;
const STATFS_BLOCK_SIZE: u32 = 4096;
/// OBS keys are limited to 1023 bytes.
const STATFS_NAME_MAX: u32 = 1023;
const ROOT_INO: u64 = 1;

#[derive(Clone)]
struct CachedMeta {
    size: u64,
    is_dir: bool,
    mtime: SystemTime,
    expires: Instant,
}

struct OpenFile {
    key: String,
    staging: Option<PathBuf>,
    dirty: bool,
}

struct Inner {
    client: ObsClient,
    staging_dir: PathBuf,
    multipart_threshold: u64,
    next_ino: u64,
    ino_to_path: HashMap<u64, String>,
    path_to_ino: HashMap<String, u64>,
    meta_cache: HashMap<String, CachedMeta>,
    open_files: HashMap<u64, OpenFile>,
    next_fh: u64,
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

fn system_time_from(s: Option<&str>) -> SystemTime {
    // OBS Last-Modified is RFC 1123; parsing it exactly is nice-to-have.
    // Fall back to now so a parse failure never breaks getattr.
    let _ = s;
    SystemTime::now()
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
    pub fn new(client: ObsClient, staging_dir: PathBuf, multipart_threshold: u64) -> Self {
        let _ = fs::create_dir_all(&staging_dir);
        // Clean start, no legacy state: drop staging files left by a
        // previous (possibly crashed) run. Reusing them would be wrong —
        // the inode numbers restart at 2 on every run, so an old
        // `ino-<n>` file could be mistaken for the current file's staged
        // content. A single mount instance owns this directory.
        if let Ok(entries) = fs::read_dir(&staging_dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("ino-") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        Self {
            inner: Mutex::new(Inner {
                client,
                staging_dir,
                multipart_threshold,
                next_ino: 2,
                ino_to_path: HashMap::new(),
                path_to_ino: HashMap::new(),
                meta_cache: HashMap::new(),
                open_files: HashMap::new(),
                next_fh: 1,
                usage_cache: None,
            }),
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
        if self.staging_refs(staging) == 0 {
            let _ = fs::remove_file(staging);
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
        FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: SystemTime::now(),
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm: if kind == FileType::Directory {
                0o755
            } else {
                0o644
            },
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid: req.uid(),
            gid: req.gid(),
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn staging_size(&self, path: &str) -> Option<u64> {
        self.open_files
            .values()
            .find(|f| f.key == path && f.staging.is_some())
            .and_then(|f| f.staging.as_ref())
            .and_then(|p| fs::metadata(p).ok())
            .map(|m| m.len())
    }

    /// Resolve a path to (ino, is_dir, size). Uses the cache, then HEAD,
    /// then a one-entry directory probe. Returns None when absent.
    fn resolve(&mut self, path: &str) -> Option<(u64, bool, u64, SystemTime)> {
        if path.is_empty() {
            return Some((ROOT_INO, true, 4096, SystemTime::now()));
        }
        if let Some(size) = self.staging_size(path) {
            let ino = self.alloc_ino(path);
            return Some((ino, false, size, SystemTime::now()));
        }
        // Copy the cached entry out first so the borrow does not overlap
        // the mutable alloc_ino() call below.
        if let Some(c) = self.meta_cache.get(path).cloned()
            && c.expires > Instant::now()
        {
            let ino = self.alloc_ino(path);
            return Some((ino, c.is_dir, c.size, c.mtime));
        }
        // File?
        match self.client.head_object(path) {
            Ok(Some(meta)) => {
                let mtime = system_time_from(meta.last_modified.as_deref());
                self.meta_cache.insert(
                    path.to_string(),
                    CachedMeta {
                        size: meta.size,
                        is_dir: false,
                        mtime,
                        expires: Instant::now() + Duration::from_secs(5),
                    },
                );
                let ino = self.alloc_ino(path);
                return Some((ino, false, meta.size, mtime));
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(path, error = %e, "HEAD failed during resolve");
            }
        }
        // Directory placeholder object?
        let placeholder = format!("{path}/");
        if let Ok(Some(_)) = self.client.head_object(&placeholder) {
            self.meta_cache.insert(
                path.to_string(),
                CachedMeta {
                    size: 4096,
                    is_dir: true,
                    mtime: SystemTime::now(),
                    expires: Instant::now() + Duration::from_secs(5),
                },
            );
            let ino = self.alloc_ino(path);
            return Some((ino, true, 4096, SystemTime::now()));
        }
        // Any key below this prefix?
        match self.client.list_objects(&dir_prefix(path), "/", None, 1) {
            Ok(page) if !page.objects.is_empty() || !page.prefixes.is_empty() => {
                self.meta_cache.insert(
                    path.to_string(),
                    CachedMeta {
                        size: 4096,
                        is_dir: true,
                        mtime: SystemTime::now(),
                        expires: Instant::now() + Duration::from_secs(5),
                    },
                );
                let ino = self.alloc_ino(path);
                Some((ino, true, 4096, SystemTime::now()))
            }
            _ => None,
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

    fn upload_staging(&self, fh: u64) -> Result<(), ObsError> {
        let Some(open) = self.open_files.get(&fh) else {
            return Ok(());
        };
        let Some(staging) = open.staging.clone() else {
            return Ok(());
        };
        let data = fs::read(&staging)?;
        tracing::info!(key = %open.key, bytes = data.len(), "uploading staged file to OBS");
        self.client
            .upload_file(&open.key, &data, self.multipart_threshold)?;
        Ok(())
    }

    fn upload_error_reply(&self, e: &ObsError) -> Errno {
        match e {
            ObsError::Http { status: 403, .. } => Errno::EACCES,
            ObsError::Http { status: 404, .. } => Errno::ENOENT,
            _ => Errno::EIO,
        }
    }

    /// Shared flush/fsync body: upload the staging file if dirty, and
    /// refresh the size cache. Returns the errno to reply with, if any.
    fn flush_handle(&mut self, fh: u64) -> Option<Errno> {
        let dirty = self.open_files.get(&fh).map(|f| f.dirty).unwrap_or(false);
        if !dirty {
            return None;
        }
        match self.upload_staging(fh) {
            Ok(()) => {
                if let Some(open) = self.open_files.get_mut(&fh) {
                    open.dirty = false;
                }
                if let Some(open) = self.open_files.get(&fh) {
                    let key = open.key.clone();
                    if let Some(staging) = open.staging.clone()
                        && let Ok(m) = fs::metadata(&staging)
                    {
                        self.meta_cache.insert(
                            key,
                            CachedMeta {
                                size: m.len(),
                                is_dir: false,
                                mtime: SystemTime::now(),
                                expires: Instant::now() + Duration::from_secs(5),
                            },
                        );
                    }
                }
                None
            }
            Err(e) => {
                tracing::error!(error = %e, "flush upload failed");
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
            Some((ino, is_dir, size, mtime)) => {
                let kind = if is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                let attr = inner.attr(req, ino, kind, size, mtime);
                reply.entry(&TTL, &attr, Generation(0));
            }
            None => reply.error(Errno::ENOENT),
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
            Some((_, is_dir, size, mtime)) => {
                let kind = if is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                let attr = inner.attr(req, ino.0, kind, size, mtime);
                reply.attr(&TTL, &attr);
            }
            None => reply.error(Errno::ENOENT),
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
            let fh = inner.next_fh;
            inner.next_fh += 1;
            inner.open_files.insert(
                fh,
                OpenFile {
                    key: path,
                    staging: None,
                    dirty: false,
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
                    staging: Some(staging),
                    dirty: false,
                },
            );
            reply.opened(fuser::FileHandle(fh), FopenFlags::empty());
            return;
        }
        let trunc = flags.0 & libc::O_TRUNC != 0;
        if !staging.exists() {
            // Stage the current remote content (if any) for read-modify-write,
            // unless the caller truncated (then start empty).
            let mut data: Vec<u8> = Vec::new();
            if !trunc
                && let Ok(Some(meta)) = inner.client.head_object(&path)
                && meta.size > 0
            {
                match inner.client.get_range(&path, 0, meta.size as usize) {
                    Ok(d) => data = d,
                    Err(e) => {
                        tracing::warn!(path, error = %e, "staging download failed");
                        let err = inner.upload_error_reply(&e);
                        reply.error(err);
                        return;
                    }
                }
            }
            if let Err(e) = fs::write(&staging, &data) {
                reply.error(io_errno(&e));
                return;
            }
        } else if trunc && let Err(e) = fs::write(&staging, []) {
            reply.error(io_errno(&e));
            return;
        }
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.open_files.insert(
            fh,
            OpenFile {
                key: path,
                staging: Some(staging),
                dirty: trunc,
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
        let inner = self.inner.lock().unwrap();
        let open = inner.open_files.get(&fh.0);
        if let Some(open) = open {
            if let Some(staging) = &open.staging {
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
                    Ok(n) => {
                        reply.data(&buf[..n]);
                    }
                    Err(e) => reply.error(io_errno(&e)),
                }
                return;
            }
            let key = open.key.clone();
            // Remote size first, so a read past EOF returns empty, not an error.
            let meta = match inner.client.head_object(&key) {
                Ok(Some(m)) => m,
                Ok(None) => {
                    reply.error(Errno::ENOENT);
                    return;
                }
                Err(e) => {
                    let err = inner.upload_error_reply(&e);
                    reply.error(err);
                    return;
                }
            };
            if offset >= meta.size {
                reply.data(&[]);
                return;
            }
            let want = (size as u64).min(meta.size - offset) as usize;
            match inner.client.get_range(&key, offset, want) {
                Ok(data) => reply.data(&data),
                Err(e) => {
                    let err = inner.upload_error_reply(&e);
                    reply.error(err);
                }
            }
            return;
        }
        reply.error(Errno::EBADF);
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
        let Some(open) = inner.open_files.get_mut(&fh.0) else {
            reply.error(Errno::EBADF);
            return;
        };
        let Some(staging) = open.staging.clone() else {
            reply.error(Errno::EBADF);
            return;
        };
        let mut f = match OpenOptions::new().write(true).open(&staging) {
            Ok(f) => f,
            Err(e) => {
                reply.error(io_errno(&e));
                return;
            }
        };
        let pos = if flags.0 & libc::O_APPEND != 0 {
            f.seek(SeekFrom::End(0))
        } else {
            f.seek(SeekFrom::Start(offset))
        };
        if pos.is_err() {
            reply.error(Errno::EIO);
            return;
        }
        match f.write_all(data) {
            Ok(()) => {
                open.dirty = true;
                // Invalidate the cached size so getattr sees the staged size.
                let key = open.key.clone();
                inner.meta_cache.remove(&key);
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
        _mode: u32,
        _umask: u32,
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
        inner.meta_cache.insert(
            path.clone(),
            CachedMeta {
                size: 0,
                is_dir: false,
                mtime: SystemTime::now(),
                expires: Instant::now() + Duration::from_secs(5),
            },
        );
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.open_files.insert(
            fh,
            OpenFile {
                key: path.clone(),
                staging: Some(staging),
                dirty: true,
            },
        );
        // dirty=true so that closing an empty created file still uploads a
        // zero-byte object (a backup tool's `touch` must be visible in OBS).
        let attr = inner.attr(req, ino, FileType::RegularFile, 0, SystemTime::now());
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
        let dirty = inner
            .open_files
            .get(&fh.0)
            .map(|f| f.dirty)
            .unwrap_or(false);
        if dirty && let Err(e) = inner.upload_staging(fh.0) {
            tracing::error!(error = %e, "release upload failed");
            let err = inner.upload_error_reply(&e);
            // Drop the handle anyway but keep the staging file: it may be
            // the only copy of the data, and leaving it in place keeps it
            // discoverable via the inode path.
            inner.open_files.remove(&fh.0);
            reply.error(err);
            return;
        }
        if let Some(open) = inner.open_files.remove(&fh.0)
            && let Some(staging) = open.staging
        {
            // Several handles can share one staging file (same inode);
            // only the last one out may unlink it, otherwise a sibling
            // handle's next write hits ENOENT. Read-only handles also
            // reference the file, so every handle releases it.
            inner.release_staging(&staging);
        }
        reply.ok();
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
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
        if let Err(e) = inner.client.put_object(&placeholder, &[]) {
            tracing::error!(error = %e, "mkdir placeholder upload failed");
            let err = inner.upload_error_reply(&e);
            reply.error(err);
            return;
        }
        let ino = inner.alloc_ino(&path);
        inner.meta_cache.insert(
            path.clone(),
            CachedMeta {
                size: 4096,
                is_dir: true,
                mtime: SystemTime::now(),
                expires: Instant::now() + Duration::from_secs(5),
            },
        );
        let attr = inner.attr(req, ino, FileType::Directory, 4096, SystemTime::now());
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
        // No per-file limit is meaningful here, so report the standard
        // "no limit" pair rather than inventing numbers that `df -i` would
        // chart.
        reply.statfs(
            total_blocks,
            free_blocks,
            free_blocks,
            u64::MAX,
            u64::MAX,
            STATFS_BLOCK_SIZE,
            STATFS_NAME_MAX,
            STATFS_BLOCK_SIZE,
        );
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<fuser::FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        // OBS stores no Unix mode/owner: those are deliberately ignored
        // (returning the current attr) so `cp -p`-style tools do not fail.
        // Only truncation is honoured, via download -> truncate -> upload.
        let mut inner = self.inner.lock().unwrap();
        let Some(path) = inner.ino_to_path.get(&ino.0).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(size) = size {
            let staging = inner.staging_path(ino.0);
            // Truncation normally arrives right after `open`, whose staging
            // file is still referenced by the returned handle. Uploading and
            // then unlinking it here is what used to break plain
            // `echo x > existing` (the following `write` hit ENOENT); keep
            // the file and let `release` unlink it once the last handle goes.
            let had_staging = staging.exists();
            if !had_staging {
                let mut data: Vec<u8> = Vec::new();
                if let Ok(Some(meta)) = inner.client.head_object(&path)
                    && meta.size > 0
                    && let Ok(d) = inner.client.get_range(&path, 0, meta.size as usize)
                {
                    data = d;
                }
                if let Err(e) = fs::write(&staging, &data) {
                    reply.error(io_errno(&e));
                    return;
                }
            }
            if let Err(e) = (|| -> std::io::Result<()> {
                let f = OpenOptions::new().write(true).open(&staging)?;
                f.set_len(size)?;
                Ok(())
            })() {
                reply.error(io_errno(&e));
                return;
            }
            let data = match fs::read(&staging) {
                Ok(d) => d,
                Err(e) => {
                    reply.error(io_errno(&e));
                    return;
                }
            };
            if let Err(e) = inner
                .client
                .upload_file(&path, &data, inner.multipart_threshold)
            {
                let err = inner.upload_error_reply(&e);
                reply.error(err);
                return;
            }
            if !had_staging {
                // Nothing references this file, so it is safe to drop.
                let _ = fs::remove_file(&staging);
            } else {
                // A handle is still using it: it now reflects what was just
                // uploaded, so mark all its handles clean.
                for f in inner.open_files.values_mut() {
                    if f.staging.as_deref() == Some(staging.as_path()) {
                        f.dirty = false;
                    }
                }
            }
            inner.meta_cache.insert(
                path.clone(),
                CachedMeta {
                    size,
                    is_dir: false,
                    mtime: SystemTime::now(),
                    expires: Instant::now() + Duration::from_secs(5),
                },
            );
            let attr = inner.attr(req, ino.0, FileType::RegularFile, size, SystemTime::now());
            reply.attr(&TTL, &attr);
            return;
        }
        match inner.resolve(&path) {
            Some((_, is_dir, size, mtime)) => {
                let kind = if is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };
                let attr = inner.attr(req, ino.0, kind, size, mtime);
                reply.attr(&TTL, &attr);
            }
            None => reply.error(Errno::ENOENT),
        }
    }
}

pub fn _unused(_: &Path) {
    let _ = ObjectMeta {
        size: 0,
        last_modified: None,
        etag: None,
    };
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
            multipart_threshold: 8 * 1024 * 1024,
            next_ino: 2,
            ino_to_path: HashMap::new(),
            path_to_ino: HashMap::new(),
            meta_cache: HashMap::new(),
            open_files: HashMap::new(),
            next_fh: 1,
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

    /// Regression for `mv a b && cat b` returning ENOENT: a rename must keep
    /// the inode number and move it to the new path, not forget it.
    #[test]
    fn rename_keeps_inode_number() {
        let mut inner = inner_for_test();
        let ino = inner.alloc_ino("old.txt");
        inner.meta_cache.insert(
            "old.txt".into(),
            CachedMeta {
                size: 3,
                is_dir: false,
                mtime: SystemTime::now(),
                expires: Instant::now() + Duration::from_secs(5),
            },
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
                dirty: true,
            },
        );

        inner.remap_subtree("a.txt", "b.txt");

        assert_eq!(
            inner.open_files.get(&7).map(|f| f.key.as_str()),
            Some("b.txt")
        );
    }

    /// Regression for `echo x > existing` failing from the second run on:
    /// truncation used to unlink the staging file that the open handle was
    /// still writing to. Only the last handle may remove it.
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
                    dirty: false,
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
}
